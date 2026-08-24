using System.Security.Cryptography;
using MinecraftFirewall.Proxy.Identity.Premium;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace MinecraftFirewall.Tests;

/// <summary>
/// PremiumVerifier is pure logic — no sockets — so these tests act as a real client would at the
/// crypto layer (encrypt a shared secret + the server's own verify token with the server's real
/// public key) without needing an actual TCP connection or a real Microsoft account. The Mojang
/// hasJoined call is swapped for FakePremiumSessionClient; everything else is the real
/// implementation, including real RSA and the real session-hash computation.
/// </summary>
public class PremiumVerifierTests
{
    private static (RsaServerKeyPair KeyPair, byte[] VerifyToken, EncryptionResponseFields Response, byte[] SharedSecret) BuildValidClientResponse(RsaServerKeyPair keyPair, byte[] verifyToken)
    {
        using RSA clientSideEncryptor = RSA.Create();
        clientSideEncryptor.ImportSubjectPublicKeyInfo(keyPair.PublicKeyDer, out _);

        byte[] sharedSecret = RandomNumberGenerator.GetBytes(16);
        byte[] encryptedSharedSecret = clientSideEncryptor.Encrypt(sharedSecret, RSAEncryptionPadding.Pkcs1);
        byte[] encryptedVerifyToken = clientSideEncryptor.Encrypt(verifyToken, RSAEncryptionPadding.Pkcs1);

        return (keyPair, verifyToken, new EncryptionResponseFields(encryptedSharedSecret, encryptedVerifyToken), sharedSecret);
    }

    [Fact]
    public async Task VerifyAsync_ValidResponseAndSuccessfulHasJoined_ReturnsSuccessWithMojangsUuid()
    {
        using var keyPair = new RsaServerKeyPair();
        byte[] verifyToken = EncryptionRequestPacket.GenerateVerifyToken();
        var (_, _, response, _) = BuildValidClientResponse(keyPair, verifyToken);

        var sessionClient = new FakePremiumSessionClient();
        var realUuid = Guid.NewGuid();
        sessionClient.SucceedWith(realUuid, "RealPremiumPlayer");

        var verifier = new PremiumVerifier(sessionClient, NullLogger<PremiumVerifier>.Instance);
        var result = await verifier.VerifyAsync(keyPair, verifyToken, response, "RealPremiumPlayer", CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(realUuid, result.Uuid);
        Assert.Equal(1, sessionClient.CallCount);
    }

    [Fact]
    public async Task VerifyAsync_VerifyTokenMismatch_FailsWithoutCallingHasJoined()
    {
        using var keyPair = new RsaServerKeyPair();
        byte[] realVerifyToken = EncryptionRequestPacket.GenerateVerifyToken();
        byte[] wrongVerifyTokenTheClientClaimsToHaveEncrypted = EncryptionRequestPacket.GenerateVerifyToken();
        var (_, _, response, _) = BuildValidClientResponse(keyPair, wrongVerifyTokenTheClientClaimsToHaveEncrypted);

        var sessionClient = new FakePremiumSessionClient();
        var verifier = new PremiumVerifier(sessionClient, NullLogger<PremiumVerifier>.Instance);

        var result = await verifier.VerifyAsync(keyPair, realVerifyToken, response, "SomeUser", CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(0, sessionClient.CallCount);
    }

    [Fact]
    public async Task VerifyAsync_GarbageCiphertext_FailsWithoutThrowing()
    {
        using var keyPair = new RsaServerKeyPair();
        byte[] verifyToken = EncryptionRequestPacket.GenerateVerifyToken();
        byte[] garbage = new byte[128];
        Random.Shared.NextBytes(garbage);
        var response = new EncryptionResponseFields(garbage, garbage);

        var sessionClient = new FakePremiumSessionClient();
        var verifier = new PremiumVerifier(sessionClient, NullLogger<PremiumVerifier>.Instance);

        var result = await verifier.VerifyAsync(keyPair, verifyToken, response, "SomeUser", CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(0, sessionClient.CallCount);
    }

    [Fact]
    public async Task VerifyAsync_HasJoinedRejects_FailsEvenThoughCryptoWasValid()
    {
        using var keyPair = new RsaServerKeyPair();
        byte[] verifyToken = EncryptionRequestPacket.GenerateVerifyToken();
        var (_, _, response, _) = BuildValidClientResponse(keyPair, verifyToken);

        var sessionClient = new FakePremiumSessionClient(); // defaults to NotJoined
        var verifier = new PremiumVerifier(sessionClient, NullLogger<PremiumVerifier>.Instance);

        var result = await verifier.VerifyAsync(keyPair, verifyToken, response, "CrackedUser", CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(1, sessionClient.CallCount); // crypto passed, so hasJoined WAS called — it just said no
    }

    [Fact]
    public async Task VerifyAsync_PassesTheCorrectSessionHashToHasJoined()
    {
        using var keyPair = new RsaServerKeyPair();
        byte[] verifyToken = EncryptionRequestPacket.GenerateVerifyToken();
        var (_, _, response, sharedSecret) = BuildValidClientResponse(keyPair, verifyToken);

        var sessionClient = new FakePremiumSessionClient();
        var verifier = new PremiumVerifier(sessionClient, NullLogger<PremiumVerifier>.Instance);
        await verifier.VerifyAsync(keyPair, verifyToken, response, "SomeUser", CancellationToken.None);

        string expectedHash = PremiumSessionHash.Compute("", sharedSecret, keyPair.PublicKeyDer);
        Assert.Equal(expectedHash, sessionClient.LastServerIdHash);
        Assert.Equal("SomeUser", sessionClient.LastUsername);
    }
}
