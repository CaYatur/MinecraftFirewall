using System.Security.Cryptography;
using MinecraftFirewall.Proxy.Identity.Premium;
using Xunit;

namespace MinecraftFirewall.Tests;

public class RsaServerKeyPairTests
{
    [Fact]
    public void PublicKeyDer_IsAValidX509SubjectPublicKeyInfo_ImportableByAnotherRsaInstance()
    {
        using var keyPair = new RsaServerKeyPair();

        using RSA imported = RSA.Create();
        imported.ImportSubjectPublicKeyInfo(keyPair.PublicKeyDer, out int bytesRead);

        Assert.Equal(keyPair.PublicKeyDer.Length, bytesRead);
        Assert.Equal(1024, imported.KeySize);
    }

    [Fact]
    public void PublicKeyDer_Length_MatchesTheLengthObservedLiveAgainstARealPaperServer()
    {
        // A live encryption-probe run against a real Paper 1.21.11 (protocol 774) server returned a
        // 162-byte SubjectPublicKeyInfo DER for its Encryption Request — see
        // tools/MinecraftFirewall.ProtocolSpike's "encryption-probe" mode and docs/plan.md's Stage 4
        // note. 1024-bit RSA keys serialize to this exact length; asserting it here means a future
        // change to the key size would fail loudly instead of silently drifting from what a real
        // client expects.
        using var keyPair = new RsaServerKeyPair();

        Assert.Equal(162, keyPair.PublicKeyDer.Length);
    }

    [Fact]
    public void Decrypt_RoundTrips_DataEncryptedWithItsOwnPublicKey()
    {
        using var keyPair = new RsaServerKeyPair();
        byte[] original = [1, 2, 3, 4, 5, 6, 7, 8];

        using RSA encryptor = RSA.Create();
        encryptor.ImportSubjectPublicKeyInfo(keyPair.PublicKeyDer, out _);
        byte[] encrypted = encryptor.Encrypt(original, RSAEncryptionPadding.Pkcs1);

        byte[] decrypted = keyPair.Decrypt(encrypted);

        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void Decrypt_GarbageCiphertext_ThrowsCryptographicException()
    {
        using var keyPair = new RsaServerKeyPair();
        byte[] garbage = new byte[128]; // right length for a 1024-bit key, but not real ciphertext
        Random.Shared.NextBytes(garbage);

        Assert.Throws<CryptographicException>(() => keyPair.Decrypt(garbage));
    }
}
