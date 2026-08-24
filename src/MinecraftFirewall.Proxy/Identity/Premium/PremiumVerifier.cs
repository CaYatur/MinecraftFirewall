using System.Security.Cryptography;

namespace MinecraftFirewall.Proxy.Identity.Premium;

public sealed record PremiumVerificationResult(bool Success, Guid Uuid, string Username, string FailureReason)
{
    public static PremiumVerificationResult Fail(string reason) => new(false, Guid.Empty, "", reason);
}

/// <summary>
/// Stage 4a: pure verification logic, no sockets. Given the client's Encryption Response and the
/// verify token this connection originally sent in its Encryption Request, decrypts the shared
/// secret, confirms the verify token round-tripped correctly, computes the Mojang session hash, and
/// checks hasJoined. NOT wired into IdentityGate/ClientConnection yet — that's Stage 4b (the login
/// splice: terminating the client's encrypted Login sequence and opening a separate plaintext login
/// to the backend). Every failure path returns Success=false; there is deliberately no fallback to
/// offline-mode access for a PremiumRequired name, ever — see docs/plan.md's Stage 4 note.
/// </summary>
public sealed class PremiumVerifier(IPremiumSessionClient sessionClient, ILogger<PremiumVerifier> logger)
{
    public async Task<PremiumVerificationResult> VerifyAsync(
        RsaServerKeyPair serverKey,
        byte[] expectedVerifyToken,
        EncryptionResponseFields response,
        string username,
        CancellationToken ct)
    {
        byte[] sharedSecret;
        byte[] decryptedVerifyToken;
        try
        {
            sharedSecret = serverKey.Decrypt(response.EncryptedSharedSecret);
            decryptedVerifyToken = serverKey.Decrypt(response.EncryptedVerifyToken);
        }
        catch (CryptographicException ex)
        {
            logger.LogWarning(ex, "Premium verification for '{Username}' failed: could not RSA-decrypt the Encryption Response.", username);
            return PremiumVerificationResult.Fail("Could not decrypt Encryption Response.");
        }

        if (!CryptographicOperations.FixedTimeEquals(decryptedVerifyToken, expectedVerifyToken))
        {
            logger.LogWarning("Premium verification for '{Username}' failed: verify token mismatch.", username);
            return PremiumVerificationResult.Fail("Verify token mismatch.");
        }

        string serverIdHash = PremiumSessionHash.Compute(serverId: "", sharedSecret, serverKey.PublicKeyDer);
        HasJoinedResult joined = await sessionClient.HasJoinedAsync(username, serverIdHash, ct).ConfigureAwait(false);

        if (!joined.Success)
        {
            logger.LogWarning("Premium verification for '{Username}' failed: Mojang hasJoined check did not confirm a valid session.", username);
            return PremiumVerificationResult.Fail("Mojang session check failed.");
        }

        logger.LogInformation("Premium verification for '{Username}' succeeded — verified UUID {Uuid}.", username, joined.Uuid);
        return new PremiumVerificationResult(true, joined.Uuid, joined.Name, "");
    }
}
