using System.IO.Compression;
using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Tests;

public class CompressedPacketReaderTests
{
    [Fact]
    public async Task ReadAsync_UncompressedFrame_DecodesPacketIdAndFields()
    {
        byte[] fields = [0xAA, 0xBB, 0xCC];
        byte[] frameBytes = BuildUncompressedFrame(packetId: 0x08, fields);
        using var stream = new MemoryStream(frameBytes);

        var packet = await CompressedPacketReader.ReadAsync(stream, maxFrameSize: 4096, CancellationToken.None);

        Assert.Equal(0x08, packet.PacketId);
        Assert.Equal<byte>(fields, packet.Fields);
    }

    [Fact]
    public async Task ReadAsync_CompressedFrame_InflatesAndDecodesCorrectly()
    {
        byte[] packetIdBytes = VarInt.Encode(0x07);
        byte[] fields = new byte[500]; // large enough that a real server would actually compress it
        new Random(42).NextBytes(fields);
        byte[] uncompressedInner = [.. packetIdBytes, .. fields];

        byte[] compressed = Deflate(uncompressedInner);
        byte[] frameBytes = BuildCompressedFrame(dataLength: uncompressedInner.Length, compressed);
        using var stream = new MemoryStream(frameBytes);

        var packet = await CompressedPacketReader.ReadAsync(stream, maxFrameSize: 4096, CancellationToken.None);

        Assert.Equal(0x07, packet.PacketId);
        Assert.Equal<byte>(fields, packet.Fields);
    }

    [Fact]
    public async Task ReadAsync_CompressedFrame_DeclaredLengthMismatch_Throws()
    {
        byte[] uncompressedInner = [.. VarInt.Encode(0x01), 1, 2, 3];
        byte[] compressed = Deflate(uncompressedInner);
        // Declare a dataLength that doesn't match what the compressed bytes actually inflate to.
        byte[] frameBytes = BuildCompressedFrame(dataLength: uncompressedInner.Length + 10, compressed);
        using var stream = new MemoryStream(frameBytes);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            CompressedPacketReader.ReadAsync(stream, maxFrameSize: 4096, CancellationToken.None));
    }

    [Fact]
    public async Task ReadAsync_RawFrame_MatchesOriginalBytesExactly()
    {
        // RawFrame must be exactly what was on the wire, unchanged — this is what lets the proxy
        // forward untouched packets byte-for-byte instead of re-serializing them.
        byte[] frameBytes = BuildUncompressedFrame(packetId: 0x3F, [1, 2, 3, 4, 5]);
        using var stream = new MemoryStream(frameBytes);

        var packet = await CompressedPacketReader.ReadAsync(stream, maxFrameSize: 4096, CancellationToken.None);

        Assert.Equal<byte>(frameBytes, packet.RawFrame);
    }

    private static byte[] BuildUncompressedFrame(int packetId, byte[] fields)
    {
        byte[] inner = [.. VarInt.Encode(packetId), .. fields];
        byte[] payload = [.. VarInt.Encode(0), .. inner];
        return [.. VarInt.Encode(payload.Length), .. payload];
    }

    private static byte[] BuildCompressedFrame(int dataLength, byte[] compressedBytes)
    {
        byte[] payload = [.. VarInt.Encode(dataLength), .. compressedBytes];
        return [.. VarInt.Encode(payload.Length), .. payload];
    }

    private static byte[] Deflate(byte[] data)
    {
        using var output = new MemoryStream();
        using (var zlib = new ZLibStream(output, CompressionMode.Compress, leaveOpen: true))
            zlib.Write(data);
        return output.ToArray();
    }
}
