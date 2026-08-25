using Microsoft.Extensions.Options;
using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Proxy.Identity.Premium;

/// <param name="SharedSecret">
/// Set whenever the crypto handshake itself succeeded, including on a failed outcome — see
/// <see cref="PremiumVerificationResult"/> for why the caller needs it even when denying.
/// </param>
/// <param name="PinnedToDifferentAccount">
/// True only when Mojang confirmed a genuine account but this username is already pinned to a
/// different one — the single premium failure mode that can't be an outage, and the only one the
/// PolicyEngine fast-tracks toward a ban.
/// </param>
public sealed record PremiumLoginOutcome(
    bool Success,
    byte[]? SharedSecret,
    string FailureReason,
    bool PinnedToDifferentAccount = false);

/// <summary>
/// Runs the Login-state encryption challenge for an admin-declared <c>PremiumRequired</c> username:
/// sends a real Encryption Request, reads the client's Encryption Response, hands both to
/// <see cref="PremiumVerifier"/>, and finally checks the verified UUID against this username's
/// permanent pin.
///
/// Everything here happens while the connection is still plaintext and before any backend connection
/// is opened — a failed verification must never cost the real server a socket. On success the caller
/// wraps the client stream in an <see cref="AesCfb8Stream"/> built from the returned shared secret;
/// from that point the connection is an ordinary relay again, because the backend's own Set
/// Compression and Login Success are simply forwarded through the cipher and are exactly what the
/// client expects to receive after an Encryption Response.
/// </summary>
public sealed class PremiumLoginHandshake(
    RsaServerKeyPair serverKey,
    PremiumVerifier verifier,
    IOptions<PremiumOptions> options,
    ILogger<PremiumLoginHandshake> logger)
{
    private readonly PremiumOptions _options = options.Value;

    public bool Enabled => _options.Enabled;

    /// <summary>See <see cref="PremiumOptions.AutoClaimOnVerifiedLogin"/> — off unless the operator
    /// switched it on, because it changes the login handshake for every player on the server.</summary>
    public bool AutoClaimEnabled => _options.Enabled && _options.AutoClaimOnVerifiedLogin;

    /// <summary>
    /// The opportunistic half of auto-claim: challenge a username nobody has declared, and claim it
    /// permanently only if a genuine Mojang account answers.
    ///
    /// Every failure path returns false and records NOTHING — no "this name is offline-only" marker
    /// exists anywhere, by design. The caller then continues the connection as an ordinary offline
    /// login, so a cracked client is unaffected beyond having completed a crypto handshake, and the
    /// name stays claimable by its real owner forever.
    /// </summary>
    public async Task<PremiumLoginOutcome> TryAutoClaimAsync(Stream clientStream, IdentityEntry entry, string username, CancellationToken ct)
    {
        PremiumLoginOutcome outcome = await RunAsync(clientStream, entry, username, ct).ConfigureAwait(false);

        if (outcome.Success)
        {
            entry.PremiumRequired = true;
            entry.PremiumLockedAtRuntime = true;
            logger.LogWarning(
                "'{Username}' proved ownership of a genuine Minecraft account and has been permanently claimed. Only that account can use this name from now on.",
                username);
        }

        return outcome;
    }

    public async Task<PremiumLoginOutcome> RunAsync(Stream clientStream, IdentityEntry entry, string username, CancellationToken ct)
    {
        byte[] verifyToken = EncryptionRequestPacket.GenerateVerifyToken();
        byte[] request = FrameWriter.WriteUncompressed(
            EncryptionRequestPacket.PacketId,
            EncryptionRequestPacket.BuildFields(serverKey.PublicKeyDer, verifyToken));

        await clientStream.WriteAsync(request, ct).ConfigureAwait(false);
        await clientStream.FlushAsync(ct).ConfigureAwait(false);

        Frame frame;
        try
        {
            frame = await FrameReader.ReadFrameAsync(clientStream, FrameReader.MaxPreLoginFrameSize, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or EndOfStreamException)
        {
            return new PremiumLoginOutcome(false, null, $"No valid Encryption Response: {ex.Message}");
        }

        EncryptionResponseFields fields;
        try
        {
            int packetId = VarInt.Decode(frame.Payload, out int idLength);
            if (packetId != EncryptionResponsePacket.PacketId)
                return new PremiumLoginOutcome(false, null, $"Expected Encryption Response, got packet 0x{packetId:X2}.");

            fields = EncryptionResponsePacket.Parse(frame.Payload[idLength..]);
        }
        catch (InvalidDataException ex)
        {
            return new PremiumLoginOutcome(false, null, $"Malformed Encryption Response: {ex.Message}");
        }

        PremiumVerificationResult result = await verifier
            .VerifyAsync(serverKey, verifyToken, fields, username, ct)
            .ConfigureAwait(false);

        if (!result.Success)
            return new PremiumLoginOutcome(false, result.SharedSecret, result.FailureReason);

        // The account is genuine; the remaining question is whether it's the account this NAME
        // belongs to. First success claims the pin permanently, later ones must match it.
        if (!entry.TryClaimOrMatchPinnedUuid(result.Uuid))
        {
            logger.LogWarning(
                "Premium verification for '{Username}' passed Mojang's check as UUID {Uuid}, but this username is pinned to a different account — denying.",
                username, result.Uuid);
            return new PremiumLoginOutcome(false, result.SharedSecret, "Username is pinned to a different Minecraft account.", PinnedToDifferentAccount: true);
        }

        return new PremiumLoginOutcome(true, result.SharedSecret, "");
    }
}
