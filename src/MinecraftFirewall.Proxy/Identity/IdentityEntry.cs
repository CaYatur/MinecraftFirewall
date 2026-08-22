using System.Net;

namespace MinecraftFirewall.Proxy.Identity;

/// <summary>
/// One username's identity record. Fields are grouped by the stage that populates them; all of
/// them live on this single record type (not parallel per-feature stores) so the gate has exactly
/// one precedence rule to apply, described in IdentityGate. Multiple connections for the same
/// username can race on LearnedIps concurrently, so mutation and iteration both go through _lock.
/// </summary>
public sealed class IdentityEntry
{
    private readonly Lock _lock = new();
    private readonly List<LearnedIp> _learnedIps = [];

    public required string Username { get; init; }

    // Stage 1
    public List<CidrRange> StaticAllowlist { get; init; } = [];

    // Stage 3
    public string? PasswordHash { get; set; }

    // Stage 4 (reserved; admin-declared only, never auto-set)
    public bool PremiumRequired { get; set; }
    public Guid? PinnedUuid { get; set; }

    public IReadOnlyList<LearnedIp> LearnedIps
    {
        get { lock (_lock) return _learnedIps.ToArray(); }
    }

    public bool IsIpRecognized(IPAddress address)
    {
        foreach (var range in StaticAllowlist)
        {
            if (range.Contains(address))
                return true;
        }

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        lock (_lock)
        {
            foreach (var learned in _learnedIps)
            {
                if (learned.ExpiresAtUnixSeconds > now && learned.Address.Equals(address))
                    return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Records a successful CaYaDev-Check authentication's IP as trusted for future connections.
    /// TTL-capped and count-capped (oldest-expiring evicted first) so a single account can't
    /// accumulate an unbounded, permanent list of trusted IPs — every entry ages out eventually.
    /// </summary>
    public void LearnIp(IPAddress address, TimeSpan ttl, int maxLearnedIps)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        lock (_lock)
        {
            _learnedIps.RemoveAll(ip => ip.ExpiresAtUnixSeconds <= now || ip.Address.Equals(address));
            _learnedIps.Add(new LearnedIp(address, now + (long)ttl.TotalSeconds));

            while (_learnedIps.Count > maxLearnedIps)
            {
                var oldest = _learnedIps.OrderBy(ip => ip.ExpiresAtUnixSeconds).First();
                _learnedIps.Remove(oldest);
            }
        }
    }
}

public sealed record LearnedIp(IPAddress Address, long ExpiresAtUnixSeconds);
