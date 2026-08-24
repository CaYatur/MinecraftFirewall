using System.Security.Cryptography;

namespace MinecraftFirewall.Proxy.Identity.Premium;

/// <param name="SharedSecret">
/// Non-null whenever the crypto half of the handshake completed — i.e. the shared secret decrypted
/// and the verify token round-tripped — even if verification then failed at the Mojang session
/// check. That distinction matters on the failure path: by the time a client has sent its Encryption
/// Response it has already switched its own cipher on, so a plaintext kick would reach it as noise.
/// Having the secret here is what lets ClientConnection send a *readable* kick to a real client that
/// simply failed verification, while a client whose crypto never validated (no secret) just gets the
/// socket closed — there is nothing meaningful that could be sent to it anyway.
/// </param>
public sealed record PremiumVerificationResult(
    bool Success,
    Guid Uuid,
    string Username,
    string FailureReason,
    byte[]? SharedSecret)
{
    public static PremiumVerificationResult Fail(string reason, byte[]? sharedSecret = null) =>
        new(false, Guid.Empty, "", reason, sharedSecret);
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
            // Deliberately no shared secret returned here: the token not matching means this side and
            // the client never actually agreed on a key, so encrypting a kick with it would produce
            // noise rather than a readable message.
            logger.LogWarning("Premium verification for '{Username}' failed: verify token mismatch.", username);
            return PremiumVerificationResult.Fail("Verify token mismatch.");
        }

        string serverIdHash = PremiumSessionHash.Compute(serverId: "", sharedSecret, serverKey.PublicKeyDer);
        HasJoinedResult joined = await sessionClient.HasJoinedAsync(username, serverIdHash, ct).ConfigureAwait(false);

        if (!joined.Success)
        {
            logger.LogWarning("Premium verification for '{Username}' failed: Mojang hasJoined check did not confirm a valid session.", username);
            return PremiumVerificationResult.Fail("Mojang session check failed.", sharedSecret);
        }

        logger.LogInformation("Premium verification for '{Username}' succeeded — verified UUID {Uuid}.", username, joined.Uuid);
        return new PremiumVerificationResult(true, joined.Uuid, joined.Name, "", sharedSecret);
    }
}
