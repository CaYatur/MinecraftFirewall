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

    [Fact]
    public async Task ReadAsync_DecompressionBomb_RefusedWithoutAllocatingTheBomb()
    {
        // 32 MiB of zeros deflates to a few dozen kilobytes — comfortably inside any sane frame-size
        // cap. Before the bounded inflate, this frame inflated to completion (allocating all 32 MiB)
        // and only then compared lengths, so a handful of these from one unauthenticated client was
        // enough to take the service down. Nothing here should ever allocate more than the declared
        // dataLength.
        byte[] bomb = new byte[32 * 1024 * 1024];
        byte[] compressed = Deflate(bomb);

        Assert.True(compressed.Length < 64 * 1024, "the bomb must stay small on the wire, or it proves nothing");

        // Declare a modest size so the frame looks entirely ordinary from its header.
        byte[] frameBytes = BuildCompressedFrame(dataLength: 512, compressed);
        using var stream = new MemoryStream(frameBytes);

        var ex = await Assert.ThrowsAsync<InvalidDataException>(() =>
            CompressedPacketReader.ReadAsync(stream, maxFrameSize: 2 * 1024 * 1024, CancellationToken.None));

        Assert.Contains("decompression bomb", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ReadAsync_DeclaredLengthAboveTheCap_RejectedBeforeAllocating()
    {
        // The other half of the same attack: the declared length is itself attacker-chosen, so a frame
        // claiming it inflates to 2 GB must be refused on the claim alone. Allocating the buffer to
        // find out is the denial of service.
        byte[] frameBytes = BuildCompressedFrame(dataLength: int.MaxValue, Deflate([0x00]));
        using var stream = new MemoryStream(frameBytes);

        var ex = await Assert.ThrowsAsync<InvalidDataException>(() =>
            CompressedPacketReader.ReadAsync(stream, maxFrameSize: 4096, CancellationToken.None));

        Assert.Contains("outside the allowed range", ex.Message);
    }

    [Fact]
    public async Task ReadAsync_HonoursATighterCallerSuppliedCap()
    {
        byte[] inner = [.. VarInt.Encode(0x01), .. new byte[4096]];
        byte[] frameBytes = BuildCompressedFrame(inner.Length, Deflate(inner));
        using var stream = new MemoryStream(frameBytes);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            CompressedPacketReader.ReadAsync(stream, maxFrameSize: 8192, CancellationToken.None, maxUncompressedSize: 1024));
    }

    [Fact]
    public async Task ReadAsync_LegitimateFrameAtExactlyTheCap_StillDecodes()
    {
        // The guard must bound the bomb without clipping a frame that genuinely is that big.
        const int cap = 4096;
        byte[] fields = new byte[cap - 1]; // + 1 byte of packet ID = exactly `cap`
        new Random(7).NextBytes(fields);
        byte[] inner = [.. VarInt.Encode(0x09), .. fields];

        Assert.Equal(cap, inner.Length);

        byte[] frameBytes = BuildCompressedFrame(inner.Length, Deflate(inner));
        using var stream = new MemoryStream(frameBytes);

        var packet = await CompressedPacketReader.ReadAsync(stream, maxFrameSize: 65536, CancellationToken.None, maxUncompressedSize: cap);

        Assert.Equal(0x09, packet.PacketId);
        Assert.Equal<byte>(fields, packet.Fields);
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
