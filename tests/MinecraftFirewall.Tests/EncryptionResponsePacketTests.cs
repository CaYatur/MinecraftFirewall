using MinecraftFirewall.Proxy.Identity.Premium;
using MinecraftFirewall.Proxy.Protocol;
using Xunit;

namespace MinecraftFirewall.Tests;

public class EncryptionResponsePacketTests
{
    [Fact]
    public void Parse_ReadsBothPrefixedByteArrays_InOrder()
    {
        byte[] sharedSecret = [1, 2, 3, 4, 5];
        byte[] verifyToken = [0xAA, 0xBB, 0xCC, 0xDD];
        byte[] fields = [.. VarInt.Encode(sharedSecret.Length), .. sharedSecret, .. VarInt.Encode(verifyToken.Length), .. verifyToken];

        var result = EncryptionResponsePacket.Parse(fields);

        Assert.Equal(sharedSecret, result.EncryptedSharedSecret);
        Assert.Equal(verifyToken, result.EncryptedVerifyToken);
    }

    [Fact]
    public void Parse_EmptyArrays_DoesNotThrow()
    {
        byte[] fields = [.. VarInt.Encode(0), .. VarInt.Encode(0)];

        var result = EncryptionResponsePacket.Parse(fields);

        Assert.Empty(result.EncryptedSharedSecret);
        Assert.Empty(result.EncryptedVerifyToken);
    }

    [Fact]
    public void Parse_TruncatedBuffer_ThrowsInvalidDataException()
    {
        byte[] fields = [.. VarInt.Encode(10), 1, 2, 3]; // claims 10 bytes, only has 3

        Assert.Throws<InvalidDataException>(() => EncryptionResponsePacket.Parse(fields));
    }

    [Fact]
    public void Parse_HostileOversizedLength_ThrowsInvalidDataException()
    {
        byte[] fields = [.. VarInt.Encode(int.MaxValue)];

        Assert.Throws<InvalidDataException>(() => EncryptionResponsePacket.Parse(fields));
    }
}
