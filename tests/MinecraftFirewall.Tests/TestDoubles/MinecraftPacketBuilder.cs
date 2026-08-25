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

    /// <summary>Builds a Play-state move_player_pos frame: three big-endian doubles then a flags byte,
    /// which is protocol 774's layout (since 1.21.2 the trailing field is flags, not a bare
    /// on-ground boolean).</summary>
    public static byte[] BuildMovementFrame(int packetId, double x, double y, double z, byte flags = 1)
    {
        var fields = new byte[25];
        System.Buffers.Binary.BinaryPrimitives.WriteDoubleBigEndian(fields.AsSpan(0, 8), x);
        System.Buffers.Binary.BinaryPrimitives.WriteDoubleBigEndian(fields.AsSpan(8, 8), y);
        System.Buffers.Binary.BinaryPrimitives.WriteDoubleBigEndian(fields.AsSpan(16, 8), z);
        fields[24] = flags;

        return MinecraftFirewall.Proxy.Protocol.FrameWriter.WriteCompressedFrameUncompressedPayload(packetId, fields);
    }

    /// <summary>Builds a rotation-only movement frame — yaw, pitch, flags. Nine bytes, so it must not
    /// be mistaken for a position packet.</summary>
    public static byte[] BuildRotationFrame(int packetId) =>
        MinecraftFirewall.Proxy.Protocol.FrameWriter.WriteCompressedFrameUncompressedPayload(packetId, new byte[9]);

    /// <summary>Builds a Sign Update frame: a block position, a front/back flag, then four lines.</summary>
    public static byte[] BuildSignUpdateFrame(int packetId, params string[] lines)
    {
        var fields = new List<byte>(new byte[8 + 1]);
        foreach (string line in lines)
            fields.AddRange(EncodeString(line));

        return MinecraftFirewall.Proxy.Protocol.FrameWriter.WriteCompressedFrameUncompressedPayload(packetId, [.. fields]);
    }

    /// <summary>Builds a plugin-message frame: a channel identifier then opaque bytes.</summary>
    public static byte[] BuildPluginMessageFrame(int packetId, string channel, int payloadBytes = 4)
    {
        byte[] fields = [.. EncodeString(channel), .. new byte[payloadBytes]];
        return MinecraftFirewall.Proxy.Protocol.FrameWriter.WriteCompressedFrameUncompressedPayload(packetId, fields);
    }

    private static byte[] WrapFrame(byte[] payload) => [.. VarInt.Encode(payload.Length), .. payload];

    public static byte[] EncodeString(string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        return [.. VarInt.Encode(bytes.Length), .. bytes];
    }
}
