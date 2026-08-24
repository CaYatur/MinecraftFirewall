namespace MinecraftFirewall.Proxy.Identity.Premium;

public sealed record HasJoinedResult(bool Success, Guid Uuid, string Name)
{
    public static readonly HasJoinedResult NotJoined = new(false, Guid.Empty, "");
}

/// <summary>
/// Calls Mojang's session-server hasJoined check. Unlike IIpInfoClient (a heuristic secondary signal
/// that fails open on any error), a failure here must always come back as "not verified" —
/// PremiumVerifier treats a timeout, a network error, and an explicit Mojang rejection identically.
/// There is deliberately no fail-open mode for this check: it is the strong gate an admin declared
/// for this username, and falling back to offline-mode access on an outage would defeat the entire
/// point of PremiumRequired.
/// </summary>
public interface IPremiumSessionClient
{
    Task<HasJoinedResult> HasJoinedAsync(string username, string serverIdHash, CancellationToken ct);
}
