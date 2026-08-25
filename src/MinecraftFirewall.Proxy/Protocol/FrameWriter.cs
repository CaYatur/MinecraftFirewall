using System.IO.Compression;

namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>
/// Encodes the small number of packets this proxy ever originates itself. Never used for anything it
/// is merely forwarding — those go out as the exact bytes that were read in.
///
/// Every one of these has to respect the connection's compression threshold, and that is less
/// forgiving than it looks. A payload at or above the threshold **must** be compressed; one below it
/// must **not** be; and if the backend never enabled compression, frames carry no length field at all.
/// The client enforces all three and disconnects rather than complaining.
///
/// This class used to send everything uncompressed, on the stated belief that the format allowed it
/// whatever the threshold was. It does not, and the cost was a live disconnect: the explanation of
/// what locking your name means is 312 bytes, the default threshold is 256, and asking the question
/// kicked you.
/// </summary>
public static class FrameWriter
{
    /// <summary>Encodes a packet for the pre-compression phase (Login, before Set Compression) — just [length][packetId][fields].</summary>
    public static byte[] WriteUncompressed(int packetId, byte[] fields)
    {
        byte[] payload = [.. VarInt.Encode(packetId), .. fields];
        return [.. VarInt.Encode(payload.Length), .. payload];
    }

    /// <summary>Encodes a packet for the post-compression phase (Configuration/Play) as an uncompressed
    /// (dataLength=0) frame. Only correct for payloads below the negotiated threshold — prefer
    /// <see cref="WritePlayFrame"/>, which picks the right encoding for you.</summary>
    public static byte[] WriteCompressedFrameUncompressedPayload(int packetId, byte[] fields)
    {
        byte[] inner = [.. VarInt.Encode(packetId), .. fields];
        byte[] payload = [.. VarInt.Encode(0), .. inner];
        return [.. VarInt.Encode(payload.Length), .. payload];
    }

    /// <summary>
    /// Encodes a packet the proxy is sending to a player, in whichever of the three forms this
    /// connection actually negotiated.
    ///
    /// The boundary is inclusive, and that is not a guess: the client refuses an uncompressed frame
    /// whose payload is "greater than threshold", and refuses a compressed one whose declared length
    /// is "below threshold". A payload of exactly the threshold is therefore legal compressed and
    /// illegal uncompressed, so that is where the comparison sits.
    /// </summary>
    /// <param name="compressionThreshold">Payloads this size or larger are compressed. Negative means
    /// the backend never enabled compression, so frames carry no declared-length field.</param>
    public static byte[] WritePlayFrame(int packetId, byte[] fields, int compressionThreshold)
    {
        byte[] inner = [.. VarInt.Encode(packetId), .. fields];

        if (compressionThreshold < 0)
            return [.. VarInt.Encode(inner.Length), .. inner];

        if (inner.Length < compressionThreshold)
        {
            byte[] small = [.. VarInt.Encode(0), .. inner];
            return [.. VarInt.Encode(small.Length), .. small];
        }

        byte[] deflated = Deflate(inner);
        byte[] payload = [.. VarInt.Encode(inner.Length), .. deflated];
        return [.. VarInt.Encode(payload.Length), .. payload];
    }

    /// <summary>zlib, matching what the reader on the other side expects — the same format
    /// CompressedPacketReader inflates in the opposite direction.</summary>
    private static byte[] Deflate(byte[] data)
    {
        using var output = new MemoryStream();

        using (var zlib = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true))
            zlib.Write(data);

        return output.ToArray();
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
    public static byte[] WriteSystemChatFrame(int packetId, string text, int compressionThreshold) =>
        WritePlayFrame(packetId, [.. NbtTextComponent.Build(text), 0x00], compressionThreshold);

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
        string title, string subtitle, int stayTicks, int compressionThreshold)
    {
        Span<byte> timing = stackalloc byte[12];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(timing[..4], 0);          // fade in
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(timing[4..8], stayTicks); // stay
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(timing[8..], 0);          // fade out

        return
        [
            .. WritePlayFrame(animationPacketId, timing.ToArray(), compressionThreshold),
            .. WritePlayFrame(subtitlePacketId, NbtTextComponent.Build(subtitle), compressionThreshold),
            .. WritePlayFrame(titlePacketId, NbtTextComponent.Build(title), compressionThreshold),
        ];
    }

    /// <summary>
    /// A clientbound Synchronize Player Position: moves where the *client* believes it is, without
    /// the server being told anything.
    ///
    /// This is how a player waiting at the login prompt is pinned in place. Swallowing their movement
    /// packets alone does not work — the client predicts its own movement locally and only corrects
    /// when the server contradicts it, so a held player watches themselves walk around and then snap
    /// back, which reads as a broken server rather than as a prompt. Contradicting them here is the
    /// correction, and sending the origin rather than their real position also keeps their coordinates
    /// off a screen anyone could be watching before they have proved who they are.
    ///
    /// Two layouts, because Minecraft reordered this packet in 1.21.2. Which one applies comes from
    /// the generated tables (see <see cref="PositionLayout"/>) and is never guessed: writing the wrong
    /// field order would not fail safely, it would mangle the join for every player on that version.
    ///
    /// Flags are all-zero in both shapes, meaning every value is absolute rather than relative — and
    /// in the newer shape the three delta fields are zero too, which lands the player stationary
    /// instead of carrying their momentum into the hold.
    /// </summary>
    public static byte[] WritePlayerPositionFrame(int packetId, PositionLayout layout,
        double x, double y, double z, float yaw, float pitch, int teleportId, int compressionThreshold)
    {
        var fields = new List<byte>(48);

        void Double(double value)
        {
            Span<byte> buffer = stackalloc byte[8];
            System.Buffers.Binary.BinaryPrimitives.WriteDoubleBigEndian(buffer, value);
            fields.AddRange(buffer);
        }

        void Single(float value)
        {
            Span<byte> buffer = stackalloc byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteSingleBigEndian(buffer, value);
            fields.AddRange(buffer);
        }

        if (layout == PositionLayout.TeleportIdFirst)
        {
            // 1.21.2 and later: teleport id, position, delta movement, rotation, 32-bit relative flags.
            fields.AddRange(VarInt.Encode(teleportId));
            Double(x); Double(y); Double(z);
            Double(0); Double(0); Double(0);
            Single(yaw); Single(pitch);

            Span<byte> relatives = stackalloc byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(relatives, 0);
            fields.AddRange(relatives);
        }
        else
        {
            // 1.20.2 to 1.21.1: position, rotation, one flags byte, then the teleport id.
            Double(x); Double(y); Double(z);
            Single(yaw); Single(pitch);
            fields.Add(0x00);
            fields.AddRange(VarInt.Encode(teleportId));
        }

        return WritePlayFrame(packetId, [.. fields], compressionThreshold);
    }
}
