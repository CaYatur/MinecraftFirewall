using MinecraftFirewall.Proxy.Identity;

namespace MinecraftFirewall.Tests;

public class PasswordHasherTests
{
    [Fact]
    public void Verify_CorrectPassword_ReturnsTrue()
    {
        string hash = PasswordHasher.Hash("hunter2");

        Assert.True(PasswordHasher.Verify("hunter2", hash));
    }

    [Fact]
    public void Verify_WrongPassword_ReturnsFalse()
    {
        string hash = PasswordHasher.Hash("hunter2");

        Assert.False(PasswordHasher.Verify("wrongpassword", hash));
    }

    [Fact]
    public void Hash_SamePasswordTwice_ProducesDifferentEncodedHashes()
    {
        // Different random salts each time — this is what defeats rainbow tables.
        string hash1 = PasswordHasher.Hash("hunter2");
        string hash2 = PasswordHasher.Hash("hunter2");

        Assert.NotEqual(hash1, hash2);
        Assert.True(PasswordHasher.Verify("hunter2", hash1));
        Assert.True(PasswordHasher.Verify("hunter2", hash2));
    }

    [Fact]
    public void Hash_DoesNotContainThePlaintextPassword()
    {
        string password = "correcthorsebatterystaple";
        string hash = PasswordHasher.Hash(password);

        Assert.DoesNotContain(password, hash, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-valid-encoded-hash")]
    [InlineData("abc:def")]
    public void Verify_MalformedEncodedHash_ReturnsFalseRatherThanThrowing(string malformed)
    {
        Assert.False(PasswordHasher.Verify("anything", malformed));
    }
}
