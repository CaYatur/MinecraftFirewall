namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>
/// Reads Minecraft's length-prefixed packet frames from a stream during the pre-login phase
/// (Handshake / Login Start), where compression is never active — the backend only sends
/// Set Compression *after* Login Start, so frames up to that point are always [VarInt length][payload].
/// Stage 3 adds a compression-aware reader for Play-state inspection; this one is intentionally
/// scoped to the phase where the wire format is guaranteed simple.
/// </summary>
public static class FrameReader
{
    /// <summary>
    /// Defends against a malicious/broken client claiming an enormous frame length during the
    /// pre-login phase, where real Handshake/Login Start packets are at most a few hundred bytes.
    /// </summary>
    public const int MaxPreLoginFrameSize = 4096;

    public static async Task<Frame> ReadFrameAsync(Stream stream, int maxFrameSize, CancellationToken ct)
    {
        // The length prefix itself is a VarInt; read it byte-by-byte while remembering the raw bytes
        // so the whole frame (prefix + payload) can be replayed verbatim to the backend.
        var lengthPrefixBytes = new byte[VarInt.MaxBytes];
        int lengthPrefixByteCount = 0;
        int length = 0;
        int shift = 0;
        var single = new byte[1];

        while (true)
        {
            await stream.ReadExactlyAsync(single, 0, 1, ct).ConfigureAwait(false);
            byte b = single[0];
            lengthPrefixBytes[lengthPrefixByteCount++] = b;

            length |= (b & 0x7F) << shift;

            if ((b & 0x80) == 0)
                break;

            shift += 7;
            if (shift >= 32 || lengthPrefixByteCount >= VarInt.MaxBytes)
                throw new InvalidDataException("Frame length VarInt is malformed or too large.");
        }

        if (length < 0 || length > maxFrameSize)
            throw new InvalidDataException($"Frame length {length} exceeds the allowed maximum of {maxFrameSize}.");

        var raw = new byte[lengthPrefixByteCount + length];
        Array.Copy(lengthPrefixBytes, raw, lengthPrefixByteCount);

        if (length > 0)
            await stream.ReadExactlyAsync(raw, lengthPrefixByteCount, length, ct).ConfigureAwait(false);

        return new Frame
        {
            Raw = raw,
            PayloadOffset = lengthPrefixByteCount,
            PayloadLength = length,
        };
    }
}
