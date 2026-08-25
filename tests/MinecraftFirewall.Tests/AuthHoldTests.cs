using System.Buffers.Binary;
using System.Net;
using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Inspection;
using MinecraftFirewall.Proxy.Messages;
using MinecraftFirewall.Proxy.Policy;
using MinecraftFirewall.Proxy.Protocol;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Holding a player at the login prompt without lying to them about it.
///
/// Refusing a held player's packets was never the hard part — that already worked, and the server
/// genuinely never saw them move. The problem was everything the player could see. Minecraft predicts
/// its own movement locally and only corrects when the server contradicts it, so a held player walked
/// around their own screen and then snapped back; the coordinates on their HUD were their real ones,
/// visible to anyone watching before they had proved who they were; and mobs went on hitting them
/// while they read the prompt. All three came out of somebody playing on a live server, not from a
/// test, which is why these exist.
/// </summary>
public class AuthHoldTests
{
    private static readonly IPAddress Player = IPAddress.Parse("203.0.113.61");

    /// <summary>The compression threshold these tests pretend the backend negotiated.
    ///
    /// It has to be a real one rather than "off", because the two produce different frame layouts and
    /// everything here reads the proxy's output back with the compressed-frame reader. Vanilla's
    /// default, so the frames are the shape a real connection produces.</summary>
    private const int Threshold = 256;

    private static PlayStatePacketIds IdsFor(int protocol)
    {
        Assert.True(ProtocolVersionRegistry.TryGet(protocol, out PlayStatePacketIds ids));
        return ids;
    }

    // ---- the packet the whole hold rests on -------------------------------------------------------

    [Theory]
    [InlineData(764)] // 1.20.2 — position first, teleport id last
    [InlineData(767)] // 1.21   — the last version of that shape
    [InlineData(768)] // 1.21.2 — the reorder
    [InlineData(774)] // 1.21.11
    public void APositionTheProxyWritesIsOneItCanReadBack(int protocol)
    {
        // Minecraft reordered Synchronize Player Position in 1.21.2, and this packet is written by the
        // proxy rather than merely forwarded. A wrong field order would not be a missed detection, it
        // would be a mangled join for every player on that version — so both shapes are exercised
        // against real registry entries rather than against a constant.
        PlayStatePacketIds ids = IdsFor(protocol);

        byte[] frame = FrameWriter.WritePlayerPositionFrame(
            ids.PlayPlayerPositionClientbound, ids.PositionLayout,
            x: 1234.5, y: -64.25, z: -9876.75, yaw: 90.5f, pitch: -12.25f, teleportId: 0x4000_0001, compressionThreshold: Threshold);

        DecodedPacket decoded = CompressedPacketReader.Decode(ToFrame(frame));
        Assert.Equal(ids.PlayPlayerPositionClientbound, decoded.PacketId);

        PlayerPosition? read = ClientboundRelay.TryReadPosition(decoded.Fields, ids.PositionLayout);

        Assert.NotNull(read);
        Assert.Equal(1234.5, read.Value.X);
        Assert.Equal(-64.25, read.Value.Y);
        Assert.Equal(-9876.75, read.Value.Z);
        Assert.Equal(90.5f, read.Value.Yaw);
        Assert.Equal(-12.25f, read.Value.Pitch);
    }

    [Fact]
    public void TheTwoLayoutsAreGenuinelyDifferentOnTheWire()
    {
        // Guards against the layout switch quietly becoming a no-op. If a refactor made both branches
        // emit the same bytes, every test above would still pass and one whole band of versions would
        // silently break.
        byte[] older = FrameWriter.WritePlayerPositionFrame(0x40, PositionLayout.TeleportIdLast, 1, 2, 3, 0, 0, 7, Threshold);
        byte[] newer = FrameWriter.WritePlayerPositionFrame(0x40, PositionLayout.TeleportIdFirst, 1, 2, 3, 0, 0, 7, Threshold);

        Assert.NotEqual(older, newer);
    }

    [Fact]
    public void ARelativeTeleportIsIgnoredRatherThanMisread()
    {
        // A relative teleport is an offset from wherever the client currently is — and while the hold
        // is on, that is the origin rather than the player's real position. Believing one would record
        // a location the backend never meant, and then put the player there when they logged in.
        PlayStatePacketIds ids = IdsFor(774);

        byte[] fields =
        [
            .. VarInt.Encode(1),
            .. new byte[8 * 6],
            .. new byte[4 * 2],
            .. RelativeFlags(0x1F),
        ];

        Assert.Null(ClientboundRelay.TryReadPosition(fields, ids.PositionLayout));
    }

    [Fact]
    public void ATruncatedPositionPacketIsIgnoredRatherThanThrowing()
    {
        // This side of the connection is observed, never filtered. A packet the proxy cannot read is
        // still a packet the client is entitled to receive.
        Assert.Null(ClientboundRelay.TryReadPosition([1, 2, 3], PositionLayout.TeleportIdFirst));
        Assert.Null(ClientboundRelay.TryReadPosition([1, 2, 3], PositionLayout.TeleportIdLast));
    }

    // ---- teleport ids ------------------------------------------------------------------------------

    [Fact]
    public void TheProxyRecognisesItsOwnTeleportsAndNobodyElses()
    {
        var hold = new AuthHold();

        int mine = hold.NextProxyTeleportId();

        Assert.True(hold.IsProxyTeleport(mine));

        // The ids a server issues start at zero and count up. Confusing one for the proxy's own would
        // mean swallowing a confirmation the backend is waiting on, which leaves the player unable to
        // move even after they log in.
        Assert.False(hold.IsProxyTeleport(0));
        Assert.False(hold.IsProxyTeleport(1));
        Assert.False(hold.IsProxyTeleport(42));
    }

    [Fact]
    public void TheTeleportIdSetDoesNotGrowForeverWhileSomebodySits()
    {
        // A held player is re-pinned several times a second. Without a bound, somebody who walks away
        // from their keyboard at the prompt is a slow memory leak.
        var hold = new AuthHold();

        int first = hold.NextProxyTeleportId();
        for (int i = 0; i < 500; i++)
            hold.NextProxyTeleportId();

        Assert.False(hold.IsProxyTeleport(first));
        Assert.True(hold.IsProxyTeleport(hold.NextProxyTeleportId()));
    }

    // ---- what the held player actually sees --------------------------------------------------------

    [Fact]
    public async Task AHeldPlayerIsToldWhereTheyAreRatherThanLeftToDrift()
    {
        // The bug this closes: their packets were refused, so the server had them standing still, but
        // nothing ever said so to the client — which went on predicting movement and gravity, and then
        // snapped back. That reads as a broken server, not as a prompt.
        Harness harness = Create(out AuthHold hold, out _);
        hold.RecordBackendPosition(new PlayerPosition(100, 70, -200, 0, 0));

        await RunAsync(harness, Movement(1), Movement(2));

        Assert.Contains(ClientboundPackets(harness), id => id == harness.Ids.PlayPlayerPositionClientbound);
    }

    [Fact]
    public async Task ThePinIsTheConfiguredPlaceAndNotTheirRealOne()
    {
        // Coordinates sit on the HUD where anyone watching a stream can read them. Somebody who has
        // not yet proved they own this name should not be leaking a base location to whoever is
        // currently wearing it.
        Harness harness = Create(out AuthHold hold, out _);
        hold.RecordBackendPosition(new PlayerPosition(1337, 70, -4242, 15f, 30f));

        await RunAsync(harness, Movement(1));

        PlayerPosition sent = Assert.Single(SentPositions(harness));
        Assert.Equal(0, sent.X);
        Assert.Equal(0, sent.Y);
        Assert.Equal(0, sent.Z);
    }

    [Fact]
    public async Task NothingIsMovedUntilTheBackendHasSaidWhereTheyAre()
    {
        // Until then there is no position to put them back to, and moving somebody the proxy cannot
        // restore would be worse than leaving them where they are.
        Harness harness = Create(out AuthHold _, out _);

        await RunAsync(harness, Movement(1), Movement(2));

        Assert.Empty(SentPositions(harness));
    }

    [Fact]
    public async Task LoggingInPutsThemBackWhereTheBackendHasThem()
    {
        // Server-side they never moved, so their real position is still whatever it was at join. It is
        // only their client that has been standing at the origin, and leaving it there would mean the
        // first step they took got corrected out from under them.
        var entry = new IdentityEntry { Username = "Steve", PasswordHash = PasswordHasher.Hash("correcthorse") };
        Harness harness = Create(out AuthHold hold, out _, new GraceAuthRequirement(entry, entry.PasswordHash));
        hold.RecordBackendPosition(new PlayerPosition(100, 70, -200, 45f, 10f));

        await RunAsync(harness, Command("login correcthorse"));

        PlayerPosition restored = SentPositions(harness)[^1];
        Assert.Equal(100, restored.X);
        Assert.Equal(70, restored.Y);
        Assert.Equal(-200, restored.Z);
        Assert.True(hold.Released);
    }

    [Fact]
    public async Task MovementIsStillHeldUntilTheClientAgreesItHasBeenMovedBack()
    {
        // Closes a race rather than a hole. The client cannot know it has been released until the
        // restoring teleport reaches it, so any movement packet already on its way was composed while
        // it still believed it was standing at the origin — and forwarding one of those is a player
        // apparently crossing the world in a single tick, which a server quite reasonably rejects.
        var entry = new IdentityEntry { Username = "Steve", PasswordHash = PasswordHasher.Hash("correcthorse") };
        Harness harness = Create(out AuthHold hold, out _, new GraceAuthRequirement(entry, entry.PasswordHash));
        hold.RecordBackendPosition(new PlayerPosition(100, 70, -200, 0, 0));

        await RunAsync(harness, Command("login correcthorse"), Movement(1));

        Assert.Equal(PrologueLength(harness.Ids), harness.Backend.Length);
    }

    [Fact]
    public async Task AndFlowsAgainOnceTheyDo()
    {
        var entry = new IdentityEntry { Username = "Steve", PasswordHash = PasswordHasher.Hash("correcthorse") };
        Harness harness = Create(out AuthHold hold, out _, new GraceAuthRequirement(entry, entry.PasswordHash));
        hold.RecordBackendPosition(new PlayerPosition(100, 70, -200, 0, 0));

        // Which teleport id the restore uses is not predictable from outside: the periodic pinning
        // draws from the same sequence, so it depends on how many times the player was re-pinned on
        // the way. Discovered by running the same sequence once and reading what was actually sent,
        // which is exactly what a real client does.
        Harness probe = Create(out AuthHold probeHold, out _,
            new GraceAuthRequirement(new IdentityEntry { Username = "Steve", PasswordHash = PasswordHasher.Hash("correcthorse") },
                PasswordHasher.Hash("correcthorse")));
        probeHold.RecordBackendPosition(new PlayerPosition(100, 70, -200, 0, 0));
        await RunAsync(probe, Command("login correcthorse"));

        int restoreId = LastTeleportId(probe);
        byte[] afterAuth = Movement(5);

        await RunAsync(harness, Command("login correcthorse"), TeleportConfirm(harness.Ids, restoreId), afterAuth);

        Assert.Equal(PrologueLength(harness.Ids) + afterAuth.Length, harness.Backend.Length);
    }

    [Fact]
    public async Task TheProxysOwnTeleportConfirmationsNeverReachTheBackend()
    {
        // The backend never sent those teleports. A confirmation for one it knows nothing about
        // desynchronises it.
        Harness harness = Create(out AuthHold hold, out _);
        hold.RecordBackendPosition(new PlayerPosition(0, 64, 0, 0, 0));

        int proxyId = hold.NextProxyTeleportId();
        await RunAsync(harness, TeleportConfirm(harness.Ids, proxyId));

        Assert.Equal(PrologueLength(harness.Ids), harness.Backend.Length);
    }

    [Fact]
    public async Task TheBackendsOwnTeleportConfirmationsStillGetThrough()
    {
        // The other half of the same rule, and the more dangerous one to get wrong: a backend still
        // waiting on an unanswered teleport will not let the player move afterwards. Being held is
        // meant to be temporary.
        Harness harness = Create(out AuthHold _, out _);

        byte[] confirm = TeleportConfirm(harness.Ids, 3);
        await RunAsync(harness, confirm);

        Assert.Equal(PrologueLength(harness.Ids) + confirm.Length, harness.Backend.Length);
    }

    // ---- damage ------------------------------------------------------------------------------------

    [Fact]
    public async Task AHeldPlayerBeingHurtIsPulledOutBeforeTheyDie()
    {
        // A firewall in front of a server cannot stop a creeper: the player really is standing in the
        // world, and only the server decides their health. What it can do is notice in time — a kick
        // costs them a reconnect, a death costs them everything they were carrying.
        Harness harness = Create(out AuthHold _, out _);

        harness.Inspector.NoteBackendHealth(20f); // announced on join
        harness.Inspector.NoteBackendHealth(14f); // something hit them
        string? disconnect = await RunAsync(harness, Movement(1));

        Assert.Equal(new MessagesOptions().DamagedWhileAuthenticating, disconnect);
    }

    [Fact]
    public async Task SomebodyWhoSimplyLoggedOffWoundedIsNotKicked()
    {
        // The reason this measures a fall rather than a level. A server announces a player's health as
        // they join, so against a fixed threshold anyone who logged out hurt would be kicked the
        // instant they came back — and told that something had attacked them, when nothing had.
        Harness harness = Create(out AuthHold _, out _);

        harness.Inspector.NoteBackendHealth(4f);
        string? disconnect = await RunAsync(harness, Movement(1));

        Assert.Null(disconnect);
    }

    [Fact]
    public async Task HealingIsNotDamage()
    {
        Harness harness = Create(out AuthHold _, out _);

        harness.Inspector.NoteBackendHealth(9f);
        harness.Inspector.NoteBackendHealth(11f);
        string? disconnect = await RunAsync(harness, Movement(1));

        Assert.Null(disconnect);
    }

    [Fact]
    public async Task TheDamageRescueCanBeSwitchedOff()
    {
        // Some servers put spawn somewhere safe and would rather nobody was ever kicked for it.
        Harness harness = Create(out AuthHold _, out _,
            identity: new IdentityOptions { DisconnectIfDamagedWhileAuthenticating = false });

        harness.Inspector.NoteBackendHealth(20f);
        harness.Inspector.NoteBackendHealth(1f);
        string? disconnect = await RunAsync(harness, Movement(1));

        Assert.Null(disconnect);
    }

    // ---- what the player types ----------------------------------------------------------------------

    [Fact]
    public async Task TheWordsWorkWithoutASlash()
    {
        // Minecraft paints a command red in the input box when the server has not declared it, and
        // these are commands the backend never sees because the firewall answers them first. Players
        // reported them as broken while they were working.
        var entry = new IdentityEntry { Username = "Steve" };
        Harness harness = Create(out AuthHold _, out _, new GraceAuthRequirement(entry, null));

        await RunAsync(harness, Chat(harness.Ids, "register hunter22"));

        Assert.NotNull(entry.PasswordHash);
    }

    [Fact]
    public async Task APasswordTypedAsPlainChatStillNeverReachesTheBackend()
    {
        // The reason accepting plain chat is safe: everything typed during the hold is consumed here,
        // command or not. If this ever regressed, passwords would be broadcast to the whole server.
        var entry = new IdentityEntry { Username = "Steve" };
        Harness harness = Create(out AuthHold _, out _, new GraceAuthRequirement(entry, null));

        await RunAsync(harness, Chat(harness.Ids, "register hunter22"));

        Assert.Equal(PrologueLength(harness.Ids), harness.Backend.Length);
    }

    [Fact]
    public async Task SomebodyRegisteringCanAskAboutLockingTheirNameInstead()
    {
        // Until this was answered from inside the hold, the only way to find the premium route was to
        // already be past the prompt that was asking for a password.
        var entry = new IdentityEntry { Username = "Steve" };
        Harness harness = Create(out AuthHold _, out _, new GraceAuthRequirement(entry, null));

        string? disconnect = await RunAsync(harness, Chat(harness.Ids, "premium"));

        // Answered, not acted on: locking a name is permanent, so they are told what it means first.
        Assert.Null(disconnect);
        Assert.Null(entry.PasswordHash);
    }

    [Fact]
    public async Task AndCanConfirmIt()
    {
        var profile = TestProfile();
        var entry = profile.IdentityStore.GetOrCreate("Steve");
        Harness harness = Create(out AuthHold _, out _, new GraceAuthRequirement(entry, null), profile: profile);

        await RunAsync(harness, Chat(harness.Ids, "premium confirm"));

        Assert.NotNull(entry.PremiumClaimRequested);
    }

    // ---- harness -------------------------------------------------------------------------------------

    private sealed record Harness(PlayStateInspector Inspector, MemoryStream Backend, PlayStatePacketIds Ids)
    {
        public DuplexTestStream? Client { get; set; }
    }

    private static ServerProfile TestProfile() =>
        new() { Name = "test", PublicPort = 25565, BackendHost = "127.0.0.1", BackendPort = 25566 };

    private static Harness Create(out AuthHold hold, out MessagesOptions messages,
        GraceAuthRequirement? grace = null, IdentityOptions? identity = null, ServerProfile? profile = null)
    {
        PlayStatePacketIds ids = IdsFor(774);
        hold = new AuthHold();
        messages = new MessagesOptions();

        var banOptions = Options.Create(new FirewallBanOptions { StrikesBeforeBan = 100 });
        var banService = new FirewallBanService(banOptions, new NeverBanList(Options.Create(new NeverBanOptions())),
            new FakeWindowsFirewallGateway(), new RecordingAlertSender(), NullLogger<FirewallBanService>.Instance);

        // Established, because the inspector deliberately says nothing at all until the backend has
        // announced a threshold — a frame encoded for the wrong one disconnects the client.
        var compression = new ConnectionCompression();
        compression.UseThreshold(Threshold);

        var inspector = new PlayStateInspector(
            profile ?? TestProfile(), "Steve", Player, ids,
            grace ?? new GraceAuthRequirement(new IdentityEntry { Username = "Steve" }, null),
            startsTrusted: false,
            identity ?? new IdentityOptions(), [], messages,
            DefenseTestFactory.CreatePolicyEngine(banService, banOptions: new FirewallBanOptions { StrikesBeforeBan = 100 }),
            new InspectionOptions(), NullLogger.Instance, hold, compression);

        return new Harness(inspector, new MemoryStream(), ids);
    }

    private static async Task<string?> RunAsync(Harness harness, params byte[][] playFrames)
    {
        byte[] prologue =
        [
            .. MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(0x03),
            .. MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(harness.Ids.ConfigurationFinishConfigurationServerbound),
        ];

        var client = new DuplexTestStream([.. prologue, .. playFrames.SelectMany(f => f)]);
        harness.Client = client;

        try
        {
            await harness.Inspector.RunAsync(client, harness.Backend, CancellationToken.None);
        }
        catch (EndOfStreamException)
        {
            // Running out of input is how these tests end.
        }

        return harness.Inspector.DisconnectReason;
    }

    /// <summary>Every packet id the proxy sent to the player, in order.</summary>
    private static List<int> ClientboundPackets(Harness harness)
    {
        var ids = new List<int>();
        ReadOnlySpan<byte> remaining = harness.Client!.Written;

        while (!remaining.IsEmpty)
        {
            int length = VarInt.Decode(remaining, out int prefix);
            if (length <= 0 || prefix + length > remaining.Length)
                break;

            byte[] frame = remaining[..(prefix + length)].ToArray();
            ids.Add(CompressedPacketReader.Decode(ToFrame(frame)).PacketId);
            remaining = remaining[(prefix + length)..];
        }

        return ids;
    }

    private static List<PlayerPosition> SentPositions(Harness harness)
    {
        var positions = new List<PlayerPosition>();
        ReadOnlySpan<byte> remaining = harness.Client!.Written;

        while (!remaining.IsEmpty)
        {
            int length = VarInt.Decode(remaining, out int prefix);
            if (length <= 0 || prefix + length > remaining.Length)
                break;

            DecodedPacket packet = CompressedPacketReader.Decode(ToFrame(remaining[..(prefix + length)].ToArray()));
            if (packet.PacketId == harness.Ids.PlayPlayerPositionClientbound &&
                ClientboundRelay.TryReadPosition(packet.Fields, harness.Ids.PositionLayout) is { } position)
            {
                positions.Add(position);
            }

            remaining = remaining[(prefix + length)..];
        }

        return positions;
    }

    private static Frame ToFrame(byte[] raw)
    {
        _ = VarInt.Decode(raw, out int prefix);
        return new Frame { Raw = raw, PayloadOffset = prefix, PayloadLength = raw.Length - prefix };
    }

    private static byte[] RelativeFlags(int value)
    {
        var buffer = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(buffer, value);
        return buffer;
    }

    /// <summary>The teleport id on the last position packet the proxy sent, which for these versions
    /// is the leading VarInt of the packet's fields.</summary>
    private static int LastTeleportId(Harness harness)
    {
        int last = -1;
        ReadOnlySpan<byte> remaining = harness.Client!.Written;

        while (!remaining.IsEmpty)
        {
            int length = VarInt.Decode(remaining, out int prefix);
            if (length <= 0 || prefix + length > remaining.Length)
                break;

            DecodedPacket packet = CompressedPacketReader.Decode(ToFrame(remaining[..(prefix + length)].ToArray()));
            if (packet.PacketId == harness.Ids.PlayPlayerPositionClientbound)
                last = VarInt.Decode(packet.Fields, out _);

            remaining = remaining[(prefix + length)..];
        }

        Assert.NotEqual(-1, last);
        return last;
    }

    private static byte[] Movement(double x) =>
        MinecraftPacketBuilder.BuildMovementFrame(IdsFor(774).PlayMovePlayerPosServerbound, x, 64, 0);

    private static byte[] Command(string text) =>
        MinecraftPacketBuilder.BuildCompressedStringPacketFrame(IdsFor(774).PlayChatCommandServerbound, text);

    private static byte[] Chat(PlayStatePacketIds ids, string text) =>
        MinecraftPacketBuilder.BuildCompressedStringPacketFrame(ids.PlayChatServerbound, text);

    private static byte[] TeleportConfirm(PlayStatePacketIds ids, int teleportId) =>
        FrameWriter.WriteCompressedFrameUncompressedPayload(ids.PlayAcceptTeleportationServerbound, [.. VarInt.Encode(teleportId)]);

    private static int PrologueLength(PlayStatePacketIds ids) =>
        MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(0x03).Length +
        MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(ids.ConfigurationFinishConfigurationServerbound).Length;
}
