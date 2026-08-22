using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Tests;

public class VarIntTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(255)]
    [InlineData(25565)]
    [InlineData(2097151)]
    [InlineData(int.MaxValue)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void EncodeThenDecode_RoundTrips(int value)
    {
        byte[] encoded = VarInt.Encode(value);
        Assert.Equal(VarInt.GetSize(value), encoded.Length);

        int decoded = VarInt.Decode(encoded, out int bytesRead);

        Assert.Equal(value, decoded);
        Assert.Equal(encoded.Length, bytesRead);
    }

    [Fact]
    public async Task ReadAsync_MatchesDecode_ForSameBytes()
    {
        byte[] encoded = VarInt.Encode(25565);
        using var stream = new MemoryStream(encoded);

        int value = await VarInt.ReadAsync(stream, CancellationToken.None);

        Assert.Equal(25565, value);
    }

    [Fact]
    public void Decode_TooManyBytes_Throws()
    {
        // 5 bytes, all with the continuation bit set — never terminates within 32 bits.
        byte[] malformed = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

        Assert.Throws<InvalidDataException>(() => VarInt.Decode(malformed, out _));
    }

    [Fact]
    public void GetSize_MatchesKnownBoundaries()
    {
        Assert.Equal(1, VarInt.GetSize(0));
        Assert.Equal(1, VarInt.GetSize(127));
        Assert.Equal(2, VarInt.GetSize(128));
        Assert.Equal(2, VarInt.GetSize(16383));
        Assert.Equal(3, VarInt.GetSize(16384));
    }
}
