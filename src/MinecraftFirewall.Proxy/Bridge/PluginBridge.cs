using System.Text;
using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Proxy.Bridge;

/// <summary>
/// The firewall's side of the conversation with its optional server plugin.
///
/// The plugin exists to do the one thing a proxy cannot: stop a held player being hurt. A player
/// waiting at the login prompt is genuinely standing in the world, and only the server decides their
/// health — so the part that protects them has to be inside the server. Everything else works exactly
/// the same whether the plugin is there or not, and the firewall never waits to find out.
///
/// <para>
/// The protocol is two bytes and cannot name anybody, and that is its most important property. A
/// message is delivered on the player's own connection, so the plugin knows who it applies to
/// without being told — which means there is no field an attacker could use to aim it at somebody
/// else. A protocol that could address another player would let anyone freeze anyone.
/// </para>
///
/// <para>
/// The other half of that guarantee is here rather than in the plugin: anything a client sends on
/// this channel is dropped and never forwarded. The plugin cannot tell a proxy-injected message from
/// a client-sent one, so the plugin must never see a client-sent one. That check is unconditional —
/// it is not an inspection setting, it is the boundary the feature rests on.
/// </para>
/// </summary>
public static class PluginBridge
{
    /// <summary>Must match CHANNEL in the plugin's FirewallBridgePlugin.java.</summary>
    public const string Channel = "mcfirewall:auth";

    private const byte ProtocolVersion = 1;

    private const byte OpcodeHold = 1;
    private const byte OpcodeRelease = 2;

    /// <summary>
    /// Tells the plugin to protect and freeze the player this connection belongs to.
    ///
    /// Written into the client-to-server direction, because that is the direction a serverbound
    /// plugin message travels — the firewall is speaking to the server as though it were the client,
    /// on a channel no real client is allowed to use.
    /// </summary>
    public static byte[] BuildHold(int customPayloadPacketId, int compressionThreshold) =>
        Build(customPayloadPacketId, OpcodeHold, compressionThreshold);

    /// <summary>Tells the plugin the player has authenticated and is an ordinary player again.</summary>
    public static byte[] BuildRelease(int customPayloadPacketId, int compressionThreshold) =>
        Build(customPayloadPacketId, OpcodeRelease, compressionThreshold);

    private static byte[] Build(int customPayloadPacketId, byte opcode, int compressionThreshold)
    {
        byte[] channel = Encoding.UTF8.GetBytes(Channel);

        // Serverbound plugin message: the channel as a length-prefixed string, then the payload as
        // the remainder of the packet.
        byte[] fields =
        [
            .. VarInt.Encode(channel.Length),
            .. channel,
            ProtocolVersion,
            opcode,
        ];

        return FrameWriter.WritePlayFrame(customPayloadPacketId, fields, compressionThreshold);
    }

    /// <summary>
    /// True when a serverbound plugin message is addressed to the bridge, which means a client sent
    /// it and it must be dropped.
    ///
    /// The firewall's own messages are written straight to the backend and never pass through the
    /// inspector, so anything reaching this check came from the player. There is no legitimate reason
    /// for a client to speak on this channel, and every illegitimate one ends with the plugin taking
    /// instructions from whoever asked.
    ///
    /// Unreadable fields are not treated as a match: this is a comparison, and a packet that cannot
    /// be decoded is handled by the ordinary plugin-message inspection rather than here.
    /// </summary>
    public static bool IsBridgeChannel(ReadOnlySpan<byte> fields)
    {
        try
        {
            return string.Equals(MinecraftPrimitives.ReadString(fields, out _), Channel, StringComparison.Ordinal);
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            return false;
        }
    }
}
