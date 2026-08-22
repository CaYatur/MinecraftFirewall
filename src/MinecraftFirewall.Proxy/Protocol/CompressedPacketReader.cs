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
/// </summary>
public static class CompressedPacketReader
{
    public static async Task<DecodedPacket> ReadAsync(Stream stream, int maxFrameSize, CancellationToken ct)
    {
        Frame frame = await FrameReader.ReadFrameAsync(stream, maxFrameSize, ct).ConfigureAwait(false);
        return Decode(frame);
    }

    public static DecodedPacket Decode(Frame frame)
    {
        ReadOnlySpan<byte> payload = frame.Payload;
        int dataLength = VarInt.Decode(payload, out int dataLenPrefixLen);
        ReadOnlySpan<byte> rest = payload[dataLenPrefixLen..];

        byte[] logical = dataLength == 0 ? rest.ToArray() : Inflate(rest, dataLength);

        int packetId = VarInt.Decode(logical, out int idLen);
        byte[] fields = logical[idLen..];

        return new DecodedPacket(packetId, fields, frame.Raw);
    }

    private static byte[] Inflate(ReadOnlySpan<byte> compressed, int expectedLength)
    {
        using var input = new MemoryStream(compressed.ToArray());
        using var zlib = new ZLibStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream(expectedLength);
        zlib.CopyTo(output);

        byte[] result = output.ToArray();
        if (result.Length != expectedLength)
            throw new InvalidDataException($"Decompressed length {result.Length} did not match declared dataLength {expectedLength}.");

        return result;
    }
}
