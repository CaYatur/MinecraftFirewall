using MinecraftFirewall.Proxy.Identity.Premium;
using MinecraftFirewall.Proxy.Protocol;
using Xunit;

namespace MinecraftFirewall.Tests;

public class EncryptionRequestPacketTests
{
    [Fact]
    public void GenerateVerifyToken_Returns4Bytes_MatchingRealPaperServerObservedLength()
    {
        byte[] token = EncryptionRequestPacket.GenerateVerifyToken();

        Assert.Equal(4, token.Length);
    }

    [Fact]
    public void GenerateVerifyToken_IsNotTheSameEveryCall()
    {
        byte[] a = EncryptionRequestPacket.GenerateVerifyToken();
        byte[] b = EncryptionRequestPacket.GenerateVerifyToken();

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void BuildFields_RoundTrips_ServerIdPublicKeyVerifyTokenAndShouldAuthenticate()
    {
        byte[] publicKeyDer = [0x30, 0x81, 0x9F, 1, 2, 3];
        byte[] verifyToken = [0xAA, 0xBB, 0xCC, 0xDD];

        byte[] fields = EncryptionRequestPacket.BuildFields(publicKeyDer, verifyToken);

        int offset = 0;
        string serverId = MinecraftPrimitives.ReadString(fields, out int serverIdLen);
        offset += serverIdLen;
        Assert.Equal("", serverId);

        int pubKeyLen = VarInt.Decode(fields.AsSpan(offset), out int pubKeyLenSize);
        offset += pubKeyLenSize;
        Assert.Equal(publicKeyDer, fields.AsSpan(offset, pubKeyLen).ToArray());
        offset += pubKeyLen;

        int tokenLen = VarInt.Decode(fields.AsSpan(offset), out int tokenLenSize);
        offset += tokenLenSize;
        Assert.Equal(verifyToken, fields.AsSpan(offset, tokenLen).ToArray());
        offset += tokenLen;

        Assert.Equal(1, fields[offset]); // Should Authenticate = true
        Assert.Equal(fields.Length, offset + 1); // no trailing bytes
    }
}
