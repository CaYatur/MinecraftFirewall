using System.IO.Compression;

namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>One decoded packet: its numeric ID, the fields that follow, and the exact raw frame bytes
/// (for verbatim pass-through — Stage 3 never re-serializes a frame it isn't actively replacing).</summary>
public sealed record DecodedPacket(int PacketId, byte[] Fields, byte[] RawFrame);

/// <summary>
/// Reads Play/Configuration-state frames once compression is active. Confirmed empirically against a
/// real Paper 1.21.11 server (see docs/plan.md Stage 2 and docs/protocol/README.md): frame format is
/// [frameLength][dataLength][payload], dataLength=0 meaning the payload follows uncompressed,
/// dataLength>0 meaning the rest is zlib/deflate-compressed to that length.
///
/// Both numbers in that header are attacker-controlled, so both are bounded before a single byte is
/// allocated for them — see <see cref="DefaultMaxUncompressedSize"/>.
/// </summary>
public static class CompressedPacketReader
{
    /// <summary>
    /// Ceiling on what one frame may inflate to. Matches vanilla's own
    /// <c>CompressionDecoder.MAXIMUM_UNCOMPRESSED_LENGTH</c> (8 MiB), so nothing a real client or
    /// server legitimately sends is affected.
    ///
    /// This bound is what stops a decompression bomb: <c>dataLength</c> and the compressed payload
    /// are two independent attacker-chosen values, and a few dozen kilobytes of zeros deflate to
    /// gigabytes. Neither the declared length nor the actual inflated stream may exceed this.
    /// </summary>
    public const int DefaultMaxUncompressedSize = 8 * 1024 * 1024;

    public static async Task<DecodedPacket> ReadAsync(Stream stream, int maxFrameSize, CancellationToken ct,
        int maxUncompressedSize = DefaultMaxUncompressedSize)
    {
        Frame frame = await FrameReader.ReadFrameAsync(stream, maxFrameSize, ct).ConfigureAwait(false);
        return Decode(frame, maxUncompressedSize);
    }

    public static DecodedPacket Decode(Frame frame, int maxUncompressedSize = DefaultMaxUncompressedSize)
    {
        ReadOnlySpan<byte> payload = frame.Payload;
        int dataLength = VarInt.Decode(payload, out int dataLenPrefixLen);
        ReadOnlySpan<byte> rest = payload[dataLenPrefixLen..];

        // Checked before allocating anything sized by it. A frame is free to claim it inflates to
        // 2 GB; believing that claim far enough to reserve the buffer is itself the denial of service.
        if (dataLength < 0 || dataLength > maxUncompressedSize)
        {
            throw new InvalidDataException(
                $"Declared uncompressed length {dataLength} is outside the allowed range of 0..{maxUncompressedSize}.");
        }

        byte[] logical = dataLength == 0 ? rest.ToArray() : Inflate(rest, dataLength);

        int packetId = VarInt.Decode(logical, out int idLen);
        byte[] fields = logical[idLen..];

        return new DecodedPacket(packetId, fields, frame.Raw);
    }

    /// <summary>
    /// Inflates into a buffer of exactly the declared size and refuses to grow past it, rather than
    /// decompressing to completion and comparing lengths afterwards. The difference matters: the
    /// comparison can only run once the bomb has already been allocated.
    /// </summary>
    private static byte[] Inflate(ReadOnlySpan<byte> compressed, int expectedLength)
    {
        using var input = new MemoryStream(compressed.ToArray(), writable: false);
        using var zlib = new ZLibStream(input, CompressionMode.Decompress);

        var result = new byte[expectedLength];
        int total = 0;

        while (total < expectedLength)
        {
            int read = zlib.Read(result, total, expectedLength - total);
            if (read == 0)
            {
                throw new InvalidDataException(
                    $"Compressed payload inflated to {total} bytes, short of the declared dataLength {expectedLength}.");
            }

            total += read;
        }

        // The declared length has been satisfied exactly. Anything still left in the stream means the
        // header understated the real size — the signature of a bomb, and a protocol violation even
        // when it isn't one, since the frame would no longer decode to what it claims.
        Span<byte> overflowProbe = stackalloc byte[1];
        if (zlib.Read(overflowProbe) != 0)
        {
            throw new InvalidDataException(
                $"Compressed payload inflates past its declared dataLength of {expectedLength} — refusing (decompression bomb).");
        }

        return result;
    }
}
