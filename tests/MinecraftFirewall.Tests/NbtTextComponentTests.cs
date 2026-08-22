using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Tests;

public class NbtTextComponentTests
{
    [Fact]
    public void BuildLiteral_ProducesExpectedByteStructure()
    {
        byte[] result = NbtTextComponent.BuildLiteral("Hi");

        byte[] expected =
        [
            0x0A,             // TAG_Compound (root, unnamed)
            0x08,             // TAG_String
            0x00, 0x04,       // name length = 4 (big-endian)
            (byte)'t', (byte)'e', (byte)'x', (byte)'t',
            0x00, 0x02,       // value length = 2 (big-endian)
            (byte)'H', (byte)'i',
            0x00,             // TAG_End
        ];

        Assert.Equal<byte>(expected, result);
    }

    [Fact]
    public void BuildLiteral_EmptyString_StillProducesValidStructure()
    {
        byte[] result = NbtTextComponent.BuildLiteral("");

        Assert.Equal(0x0A, result[0]);
        Assert.Equal(0x00, result[^1]); // TAG_End
        Assert.Equal(1 + 1 + 2 + 4 + 2 + 0 + 1, result.Length); // compound+string+namelen+"text"+vallen+""+end
    }

    [Fact]
    public void BuildLiteral_HandlesNonAsciiText()
    {
        // Turkish disconnect messages are a real use case for this project — confirm the UTF-8 byte
        // length accounting (not char count) is used for the value-length prefix.
        string text = "Kimlik doğrulama başarısız.";
        byte[] result = NbtTextComponent.BuildLiteral(text);

        int utf8Length = System.Text.Encoding.UTF8.GetByteCount(text);
        int valueLengthFieldOffset = 1 + 1 + 2 + 4; // compound + string-type + namelen + "text"
        int declaredValueLength = (result[valueLengthFieldOffset] << 8) | result[valueLengthFieldOffset + 1];

        Assert.Equal(0x0A, result[0]);
        Assert.Equal(0x00, result[^1]);
        Assert.Equal(utf8Length, declaredValueLength);
    }

    [Fact]
    public void BuildLiteral_TooLong_Throws()
    {
        string tooLong = new string('a', ushort.MaxValue + 1);

        Assert.Throws<ArgumentException>(() => NbtTextComponent.BuildLiteral(tooLong));
    }
}
