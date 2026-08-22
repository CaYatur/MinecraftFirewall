using System.Text;
using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Tests.TestDoubles;

/// <summary>Builds raw, length-prefixed Handshake/Login Start frames for driving the proxy in integration tests.</summary>
public static class MinecraftPacketBuilder
{
    public static byte[] BuildHandshakeFrame(int protocolVersion, string serverAddress, ushort serverPort, int nextState)
    {
        byte[] payload =
        [
            .. VarInt.Encode(0x00),
            .. VarInt.Encode(protocolVersion),
            .. EncodeString(serverAddress),
            (byte)(serverPort >> 8),
            (byte)(serverPort & 0xFF),
            .. VarInt.Encode(nextState),
        ];
        return WrapFrame(payload);
    }

    public static byte[] BuildLoginStartFrame(string username)
    {
        byte[] payload = [.. VarInt.Encode(0x00), .. EncodeString(username)];
        return WrapFrame(payload);
    }

    /// <summary>Builds an uncompressed (dataLength=0) compressed-phase frame carrying a single String
    /// field — the shape of Play chat/chat_command/chat_command_signed as far as this project reads them.</summary>
    public static byte[] BuildCompressedStringPacketFrame(int packetId, string text) =>
        MinecraftFirewall.Proxy.Protocol.FrameWriter.WriteCompressedFrameUncompressedPayload(packetId, EncodeString(text));

    /// <summary>Builds an uncompressed (dataLength=0) compressed-phase frame with no fields — the
    /// shape of Configuration's (Acknowledge) Finish Configuration.</summary>
    public static byte[] BuildCompressedEmptyPacketFrame(int packetId) =>
        MinecraftFirewall.Proxy.Protocol.FrameWriter.WriteCompressedFrameUncompressedPayload(packetId, []);

    private static byte[] WrapFrame(byte[] payload) => [.. VarInt.Encode(payload.Length), .. payload];

    public static byte[] EncodeString(string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        return [.. VarInt.Encode(bytes.Length), .. bytes];
    }
}
