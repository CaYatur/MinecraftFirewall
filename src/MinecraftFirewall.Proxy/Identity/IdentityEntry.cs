using System.Net;

namespace MinecraftFirewall.Proxy.Identity;

/// <summary>
/// One username's identity record. Fields are grouped by the stage that populates them; all of
/// them live on this single record type (not parallel per-feature stores) so the gate has exactly
/// one precedence rule to apply, described in IdentityGate.
/// </summary>
public sealed class IdentityEntry
{
    public required string Username { get; init; }

    // Stage 1
    public List<CidrRange> StaticAllowlist { get; init; } = [];

    // Stage 3 (reserved; populated starting Stage 3)
    public List<LearnedIp> LearnedIps { get; init; } = [];
    public string? PasswordHash { get; set; }

    // Stage 4 (reserved; admin-declared only, never auto-set)
    public bool PremiumRequired { get; set; }
    public Guid? PinnedUuid { get; set; }

    public bool IsIpRecognized(IPAddress address)
    {
        foreach (var range in StaticAllowlist)
        {
            if (range.Contains(address))
                return true;
        }

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        foreach (var learned in LearnedIps)
        {
            if (learned.ExpiresAtUnixSeconds > now && learned.Address.Equals(address))
                return true;
        }

        return false;
    }
}

public sealed record LearnedIp(IPAddress Address, long ExpiresAtUnixSeconds);
