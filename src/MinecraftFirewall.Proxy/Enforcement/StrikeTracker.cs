using System.Collections.Concurrent;
using System.Net;

namespace MinecraftFirewall.Proxy.Enforcement;

/// <summary>
/// Counts consecutive policy violations per IP so repeat offenders escalate to a firewall ban while
/// a single rate-limit trip doesn't. Stage 3/4 triggers (passphrase failure, dangerous command) will
/// use a lower threshold via the same tracker — "fast-track" is just a smaller StrikesBeforeBan value
/// passed at the call site, not a separate mechanism.
/// </summary>
public sealed class StrikeTracker
{
    private readonly ConcurrentDictionary<IPAddress, int> _strikes = new();

    /// <summary>Registers one violation and returns the running total. A higher <paramref name="weight"/>
    /// is how Stage 3/4 triggers (grace-authentication failure, a dangerous command) fast-track a ban —
    /// they add more than 1 toward the same threshold, rather than needing a separate counter.</summary>
    public int RegisterStrike(IPAddress address, int weight = 1) =>
        _strikes.AddOrUpdate(address, weight, (_, count) => count + weight);

    public void Reset(IPAddress address) => _strikes.TryRemove(address, out _);
}
