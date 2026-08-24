using System.Security.Cryptography;
using System.Text;
using MinecraftFirewall.Proxy.Identity.Premium;
using Xunit;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Verifies the risky part of PremiumSessionHash — the Java `new BigInteger(digest).toString(16)`
/// formatting quirk (signed, two's-complement, no leading-zero padding) — against the published
/// known-answer vectors for this exact function (widely reproduced across third-party Minecraft
/// server implementations' own test suites). A round-trip test of this code against itself would
/// pass even with the sign/endianness handling completely wrong, so these fixed vectors are the
/// actual correctness signal, not a sanity check.
/// </summary>
public class PremiumSessionHashTests
{
    [Theory]
    [InlineData("Notch", "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48")]
    [InlineData("jeb_", "-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1")]
    [InlineData("simon", "88e16a1019277b15d58faf0541e11910eb756f6")]
    public void ToJavaHexBigInteger_MatchesPublishedKnownAnswerVectors(string input, string expectedHex)
    {
        byte[] digest = SHA1.HashData(Encoding.ASCII.GetBytes(input));

        string actual = PremiumSessionHash.ToJavaHexBigInteger(digest);

        Assert.Equal(expectedHex, actual);
    }

    [Fact]
    public void Compute_IsDeterministic_ForTheSameInputs()
    {
        byte[] sharedSecret = [1, 2, 3, 4];
        byte[] publicKeyDer = [5, 6, 7, 8];

        string first = PremiumSessionHash.Compute("", sharedSecret, publicKeyDer);
        string second = PremiumSessionHash.Compute("", sharedSecret, publicKeyDer);

        Assert.Equal(first, second);
    }

    [Fact]
    public void Compute_DiffersWhenSharedSecretDiffers()
    {
        byte[] publicKeyDer = [5, 6, 7, 8];

        string a = PremiumSessionHash.Compute("", [1, 2, 3, 4], publicKeyDer);
        string b = PremiumSessionHash.Compute("", [9, 9, 9, 9], publicKeyDer);

        Assert.NotEqual(a, b);
    }
}
