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

    public int RegisterStrike(IPAddress address) => _strikes.AddOrUpdate(address, 1, (_, count) => count + 1);

    public void Reset(IPAddress address) => _strikes.TryRemove(address, out _);
}
