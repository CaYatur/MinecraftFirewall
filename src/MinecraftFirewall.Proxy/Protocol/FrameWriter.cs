namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>
/// Encodes the small number of packets this proxy ever originates itself (kick/disconnect messages).
/// Never used for anything the proxy is merely forwarding — those go out as the exact bytes that were
/// read in. Outbound synthetic packets here are always small, so they're sent uncompressed
/// (dataLength=0), which the compressed-frame format permits regardless of the negotiated threshold.
/// </summary>
public static class FrameWriter
{
    /// <summary>Encodes a packet for the pre-compression phase (Login, before Set Compression) — just [length][packetId][fields].</summary>
    public static byte[] WriteUncompressed(int packetId, byte[] fields)
    {
        byte[] payload = [.. VarInt.Encode(packetId), .. fields];
        return [.. VarInt.Encode(payload.Length), .. payload];
    }

    /// <summary>Encodes a packet for the post-compression phase (Configuration/Play) as an uncompressed (dataLength=0) frame.</summary>
    public static byte[] WriteCompressedFrameUncompressedPayload(int packetId, byte[] fields)
    {
        byte[] inner = [.. VarInt.Encode(packetId), .. fields];
        byte[] payload = [.. VarInt.Encode(0), .. inner];
        return [.. VarInt.Encode(payload.Length), .. payload];
    }

    /// <summary>
    /// A clientbound System Chat message: an NBT text component followed by an "overlay" boolean.
    /// False puts it in the chat box rather than across the action bar, which is where a message the
    /// player is expected to read and act on belongs.
    ///
    /// This is the only thing the proxy ever says to a player without ending their connection. It
    /// exists for the premium self-lock flow, where kicking somebody for asking a question would be an
    /// odd way to answer it.
    /// </summary>
    public static byte[] WriteSystemChatFrame(int packetId, string text) =>
        WriteCompressedFrameUncompressedPayload(packetId, [.. NbtTextComponent.BuildLiteral(text), 0x00]);

    /// <summary>
    /// A clientbound title: large text across the middle of the screen, with a smaller line beneath.
    ///
    /// This exists because chat is a bad place to put an instruction somebody has to act on. A player
    /// who has never met a login-required server does not read chat, and the message scrolls away
    /// while they are looking at their inventory — which is exactly what happened when the prompt was
    /// chat-only. A title is unmissable and stays put.
    ///
    /// Three packets rather than one: the timing has to be sent first, because a title already on
    /// screen keeps the timing it was shown with. The stay duration is set far longer than the prompt
    /// interval so the text never blinks out between reminders.
    /// </summary>
    public static byte[] WriteTitleFrames(int animationPacketId, int titlePacketId, int subtitlePacketId,
        string title, string subtitle, int stayTicks)
    {
        Span<byte> timing = stackalloc byte[12];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(timing[..4], 0);          // fade in
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(timing[4..8], stayTicks); // stay
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(timing[8..], 0);          // fade out

        return
        [
            .. WriteCompressedFrameUncompressedPayload(animationPacketId, timing.ToArray()),
            .. WriteCompressedFrameUncompressedPayload(subtitlePacketId, NbtTextComponent.BuildLiteral(subtitle)),
            .. WriteCompressedFrameUncompressedPayload(titlePacketId, NbtTextComponent.BuildLiteral(title)),
        ];
    }
}
