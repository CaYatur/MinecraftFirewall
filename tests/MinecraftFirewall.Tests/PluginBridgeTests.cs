using System.Net;
using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Bridge;
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
/// Talking to the optional server plugin.
///
/// Two properties matter more than anything else here, and both are about what must NOT happen.
///
/// A client must never be able to speak on this channel. The plugin cannot tell a message the
/// firewall injected from one a player sent — they arrive identically — so if a player's own message
/// were forwarded, anyone could tell the plugin to freeze anyone, or to release themselves. That check
/// is unconditional and is the boundary the whole feature rests on.
///
/// And a server without the plugin must behave exactly as it did before the plugin existed. Nothing
/// waits for a reply, and no message the player sees depends on it being there.
/// </summary>
public class PluginBridgeTests
{
    private const int Threshold = 256;
    private static readonly IPAddress Player = IPAddress.Parse("203.0.113.90");

    private static PlayStatePacketIds Ids()
    {
        Assert.True(ProtocolVersionRegistry.TryGet(774, out PlayStatePacketIds ids));
        return ids;
    }

    // ---- the message itself ------------------------------------------------------------------------

    [Fact]
    public void TheInstructionCannotNameAPlayer()
    {
        // The most important property of the format, and the reason it is two bytes. The plugin knows
        // who a message applies to because of the connection it arrived on; there is no field to say
        // otherwise, so there is nothing for an attacker to aim somewhere else.
        byte[] frame = PluginBridge.BuildHold(Ids().PlayCustomPayloadServerbound, Threshold);
        DecodedPacket packet = Decode(frame);

        string channel = MinecraftPrimitives.ReadString(packet.Fields, out int channelLength);
        byte[] payload = packet.Fields[channelLength..];

        Assert.Equal(PluginBridge.Channel, channel);
        Assert.Equal(2, payload.Length); // a version and an opcode, and nothing else
    }

    [Fact]
    public void HoldAndReleaseAreDistinguishable()
    {
        byte[] hold = Decode(PluginBridge.BuildHold(Ids().PlayCustomPayloadServerbound, Threshold)).Fields;
        byte[] release = Decode(PluginBridge.BuildRelease(Ids().PlayCustomPayloadServerbound, Threshold)).Fields;

        Assert.NotEqual(hold, release);
        Assert.Equal(hold[..^1], release[..^1]); // same channel and version; only the opcode differs
    }

    [Fact]
    public void TheChannelIsRecognisedOnTheWayBackIn()
    {
        byte[] fields = Decode(PluginBridge.BuildHold(Ids().PlayCustomPayloadServerbound, Threshold)).Fields;

        Assert.True(PluginBridge.IsBridgeChannel(fields));
    }

    [Fact]
    public void AnotherPluginsChannelIsNotMistakenForThisOne()
    {
        // A server runs many plugins and they all use this packet. Matching too eagerly would mean
        // silently eating another plugin's traffic, which is a bug nobody could diagnose from inside
        // the game.
        byte[] other = MinecraftPacketBuilder.EncodeString("minecraft:brand");

        Assert.False(PluginBridge.IsBridgeChannel(other));
        Assert.False(PluginBridge.IsBridgeChannel([]));
        Assert.False(PluginBridge.IsBridgeChannel([0xFF, 0xFF, 0xFF]));
    }

    // ---- the trust boundary --------------------------------------------------------------------------

    [Fact]
    public async Task AClientCannotSpeakToThePluginEvenWithAPerfectlyFormedMessage()
    {
        // Built with the firewall's own builder, so this is the strongest version of the attack: a
        // byte-identical instruction, sent by the player instead of by the firewall. It must not reach
        // the server, or "hold" and "release" become things any player can say about themselves.
        Harness harness = Create();

        byte[] forged = PluginBridge.BuildHold(harness.Ids.PlayCustomPayloadServerbound, Threshold);
        await RunAsync(harness, forged);

        Assert.Equal(PrologueLength(harness.Ids), harness.Backend.Length);
    }

    [Fact]
    public async Task AndIsNotDisconnectedForTrying()
    {
        // Dropped, not punished. The check exists to make the channel unusable, and a kick would turn
        // a mistyped mod into a support request.
        Harness harness = Create();

        string? disconnect = await RunAsync(harness,
            PluginBridge.BuildRelease(harness.Ids.PlayCustomPayloadServerbound, Threshold));

        Assert.Null(disconnect);
    }

    [Fact]
    public async Task TheCheckDoesNotDependOnPacketInspectionBeingSwitchedOn()
    {
        // It is not an inspection setting. Somebody who turns deep inspection off is asking for fewer
        // opinions about their players' packets, not for the plugin to start taking orders from them.
        Harness harness = Create(inspection: new InspectionOptions { Enabled = false });

        await RunAsync(harness, PluginBridge.BuildHold(harness.Ids.PlayCustomPayloadServerbound, Threshold));

        Assert.Equal(PrologueLength(harness.Ids), harness.Backend.Length);
    }

    [Fact]
    public async Task AnOrdinaryPluginMessageStillReachesTheServer()
    {
        // The other half: this must cost nothing for every other plugin on the server.
        Harness harness = Create();

        byte[] brand = FrameWriter.WritePlayFrame(harness.Ids.PlayCustomPayloadServerbound,
            [.. MinecraftPacketBuilder.EncodeString("minecraft:brand"), .. "vanilla"u8], Threshold);

        await RunAsync(harness, brand);

        Assert.Equal(PrologueLength(harness.Ids) + brand.Length, harness.Backend.Length);
    }

    // ---- telling the plugin --------------------------------------------------------------------------

    [Fact]
    public async Task AHeldPlayerIsAnnouncedToThePlugin()
    {
        Harness harness = Create(useServerPlugin: true);

        await RunAsync(harness, Movement());

        Assert.Contains(BridgePayloads(harness), payload => payload[1] == 1); // hold
    }

    [Fact]
    public async Task AndReleasedWhenTheyAuthenticate()
    {
        var entry = new IdentityEntry { Username = "Steve", PasswordHash = PasswordHasher.Hash("correcthorse") };
        Harness harness = Create(useServerPlugin: true, grace: new GraceAuthRequirement(entry, entry.PasswordHash));

        await RunAsync(harness, Command(harness.Ids, "login correcthorse"));

        List<byte[]> payloads = BridgePayloads(harness);
        Assert.Contains(payloads, payload => payload[1] == 1); // hold
        Assert.Contains(payloads, payload => payload[1] == 2); // release
    }

    [Fact]
    public async Task WithTheOptionOffNothingIsSentAtAll()
    {
        // A server that never asked for the plugin must see exactly the traffic it saw before it
        // existed.
        Harness harness = Create(useServerPlugin: false);

        await RunAsync(harness, Movement(), Movement());

        Assert.Empty(BridgePayloads(harness));
    }

    // ---- harness ---------------------------------------------------------------------------------------

    private sealed record Harness(PlayStateInspector Inspector, MemoryStream Backend, PlayStatePacketIds Ids);

    private static Harness Create(bool useServerPlugin = false, GraceAuthRequirement? grace = null,
        InspectionOptions? inspection = null)
    {
        PlayStatePacketIds ids = Ids();

        var compression = new ConnectionCompression();
        compression.UseThreshold(Threshold);

        var banOptions = Options.Create(new FirewallBanOptions { StrikesBeforeBan = 100 });
        var banService = new FirewallBanService(banOptions, new NeverBanList(Options.Create(new NeverBanOptions())),
            new FakeWindowsFirewallGateway(), new RecordingAlertSender(), NullLogger<FirewallBanService>.Instance);

        var inspector = new PlayStateInspector(
            new ServerProfile { Name = "test", PublicPort = 25565, BackendHost = "127.0.0.1", BackendPort = 25566 },
            "Steve", Player, ids,
            grace ?? new GraceAuthRequirement(new IdentityEntry { Username = "Steve" }, null),
            startsTrusted: false,
            new IdentityOptions { UseServerPlugin = useServerPlugin }, [], new MessagesOptions(),
            DefenseTestFactory.CreatePolicyEngine(banService, banOptions: new FirewallBanOptions { StrikesBeforeBan = 100 }),
            inspection ?? new InspectionOptions(), NullLogger.Instance, new AuthHold(), compression);

        return new Harness(inspector, new MemoryStream(), ids);
    }

    private static async Task<string?> RunAsync(Harness harness, params byte[][] playFrames)
    {
        byte[] prologue =
        [
            .. MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(0x03),
            .. MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(harness.Ids.ConfigurationFinishConfigurationServerbound),
        ];

        using var client = new DuplexTestStream([.. prologue, .. playFrames.SelectMany(f => f)]);

        try
        {
            await harness.Inspector.RunAsync(client, harness.Backend, CancellationToken.None);
        }
        catch (EndOfStreamException)
        {
        }

        return harness.Inspector.DisconnectReason;
    }

    /// <summary>The bridge payloads the proxy wrote to the backend, with the channel stripped.</summary>
    private static List<byte[]> BridgePayloads(Harness harness)
    {
        var payloads = new List<byte[]>();
        ReadOnlySpan<byte> remaining = harness.Backend.ToArray();

        while (!remaining.IsEmpty)
        {
            int length = VarInt.Decode(remaining, out int prefix);
            if (length <= 0 || prefix + length > remaining.Length)
                break;

            DecodedPacket packet = Decode(remaining[..(prefix + length)].ToArray());
            if (packet.PacketId == harness.Ids.PlayCustomPayloadServerbound && PluginBridge.IsBridgeChannel(packet.Fields))
            {
                _ = MinecraftPrimitives.ReadString(packet.Fields, out int channelLength);
                payloads.Add(packet.Fields[channelLength..]);
            }

            remaining = remaining[(prefix + length)..];
        }

        return payloads;
    }

    private static DecodedPacket Decode(byte[] frame)
    {
        _ = VarInt.Decode(frame, out int prefix);
        return CompressedPacketReader.Decode(new Frame { Raw = frame, PayloadOffset = prefix, PayloadLength = frame.Length - prefix });
    }

    private static byte[] Movement() =>
        MinecraftPacketBuilder.BuildMovementFrame(Ids().PlayMovePlayerPosServerbound, 1, 64, 0);

    private static byte[] Command(PlayStatePacketIds ids, string text) =>
        MinecraftPacketBuilder.BuildCompressedStringPacketFrame(ids.PlayChatCommandServerbound, text);

    private static int PrologueLength(PlayStatePacketIds ids) =>
        MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(0x03).Length +
        MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(ids.ConfigurationFinishConfigurationServerbound).Length;
}
