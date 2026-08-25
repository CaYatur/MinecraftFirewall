using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Enforcement;

public enum BanResult
{
    Banned,
    AlreadyBanned,
    RefusedNeverBan,
    Failed,
}

/// <summary>
/// Ban state, TTL, and never-ban policy — the part of firewall enforcement worth unit testing.
/// Actual rule mutation is delegated to IWindowsFirewallGateway (see WindowsFirewallGateway for the
/// real, COM-backed implementation) so tests can inject a fake and never touch the real firewall.
/// A ban applies to every server profile at once, since it blocks the IP from the machine, not from
/// one port.
/// </summary>
public sealed class FirewallBanService : IDisposable
{
    private readonly FirewallBanOptions _options;
    private readonly NeverBanList _neverBanList;
    private readonly IWindowsFirewallGateway _gateway;
    private readonly ILogger<FirewallBanService> _logger;
    private readonly ConcurrentDictionary<IPAddress, DateTimeOffset> _activeBans = new();
    private readonly Timer _cleanupTimer;

    public FirewallBanService(
        IOptions<FirewallBanOptions> options,
        NeverBanList neverBanList,
        IWindowsFirewallGateway gateway,
        ILogger<FirewallBanService> logger)
    {
        _options = options.Value;
        _neverBanList = neverBanList;
        _gateway = gateway;
        _logger = logger;
        _cleanupTimer = new Timer(_ => CleanupExpired(), null, _options.CleanupInterval, _options.CleanupInterval);

        if (!_gateway.CanAccessFirewall(out string? probeError))
        {
            _logger.LogWarning(
                "Cannot access the Windows Firewall ({Error}). The service is probably not running with " +
                "Administrator rights. Bans will still be tracked and enforced in-process, but the OS-level " +
                "firewall rule that should block the IP machine-wide will not be created until this is fixed.",
                probeError);
        }

        AdoptExistingBans();
    }

    /// <summary>
    /// Rebuilds ban state from the firewall rules this app already owns, so a restart doesn't orphan
    /// them. Without this, a restart left the OS rule in place and blocking (no security regression)
    /// while the service forgot its expiry entirely — so CleanupExpired could never lift it, and the
    /// IP stayed blocked forever.
    ///
    /// The firewall is used as the source of truth rather than a separate state file on purpose:
    /// there is then only one place a ban can exist, so the two can't drift. An admin who deletes a
    /// rule by hand in wf.msc gets a service that agrees with them on the next start, and an admin
    /// reading the rules sees the expiry written in the description rather than needing this app to
    /// interpret it for them.
    /// </summary>
    private void AdoptExistingBans()
    {
        int adopted = 0, undated = 0;

        foreach (var rule in _gateway.ListManagedBlockRules())
        {
            if (_neverBanList.IsProtected(rule.Address))
            {
                // The never-ban list may have grown since the rule was created — honour the current
                // list, not the one that was in effect back then.
                _logger.LogWarning("Removing leftover firewall rule for {Ip}: it is now protected by the never-ban list.", rule.Address);
                Unban(rule.Address);
                continue;
            }

            if (rule.ExpiresAt is { } expiresAt)
            {
                _activeBans[rule.Address] = expiresAt;
                adopted++;
                continue;
            }

            // A rule from a build that didn't record expiries. Its intended lifetime is unknowable,
            // so give it a fresh default TTL: that errs toward briefly over-blocking an IP something
            // already judged hostile, and — unlike leaving it untracked — guarantees it eventually
            // gets cleaned up instead of blocking forever.
            _activeBans[rule.Address] = DateTimeOffset.UtcNow + _options.DefaultBanDuration;
            undated++;
        }

        if (adopted > 0 || undated > 0)
        {
            _logger.LogInformation(
                "Adopted {Adopted} existing firewall ban(s) from previous runs. {Undated} had no recorded expiry and were given a fresh {Ttl} TTL so they don't block forever.",
                adopted, undated, _options.DefaultBanDuration);
        }
    }

    public bool IsBanned(IPAddress address) => _activeBans.ContainsKey(address);

    public BanResult Ban(IPAddress address, string reason, TimeSpan? duration = null)
    {
        if (_neverBanList.IsProtected(address))
        {
            _logger.LogWarning("Refused to ban {Ip} — protected by the never-ban list. Reason was: {Reason}", address, reason);
            return BanResult.RefusedNeverBan;
        }

        var ttl = duration ?? _options.DefaultBanDuration;
        var expiresAt = DateTimeOffset.UtcNow + ttl;
        bool alreadyBanned = _activeBans.ContainsKey(address);

        try
        {
            // Called for an extension too, not just a fresh ban: the rule's own description is what a
            // restart reads the expiry back from, so skipping this would quietly lose every extension
            // across a restart and lift the ban early.
            _gateway.AddOrUpdateBlockRule(address, reason, expiresAt);
        }
        catch (Exception ex)
        {
            // OS-level enforcement failed (commonly: not running elevated) — still record the ban
            // in-process so IsBanned() keeps denying this IP at the proxy layer. A silent no-op here
            // would mean a "banned" IP sails straight through every subsequent connection attempt.
            _activeBans[address] = expiresAt;
            _logger.LogError(ex, "Failed to create a Windows Firewall rule blocking {Ip}; falling back to in-process blocking only " +
                "(the service may not be running with Administrator rights).", address);
            return BanResult.Failed;
        }

        _activeBans[address] = expiresAt;

        if (alreadyBanned)
        {
            _logger.LogInformation("Extended ban for {Ip} to {ExpiresAt}. Reason: {Reason}", address, expiresAt, reason);
            return BanResult.AlreadyBanned;
        }

        _logger.LogWarning("Banned {Ip} until {ExpiresAt}. Reason: {Reason}", address, expiresAt, reason);
        return BanResult.Banned;
    }

    public void Unban(IPAddress address)
    {
        try
        {
            _gateway.RemoveBlockRule(address);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove the Windows Firewall rule blocking {Ip}.", address);
        }

        if (_activeBans.TryRemove(address, out _))
            _logger.LogInformation("Unbanned {Ip}.", address);
    }

    public IReadOnlyCollection<(IPAddress Address, DateTimeOffset ExpiresAt)> ListActiveBans() =>
        _activeBans.Select(kv => (kv.Key, kv.Value)).ToArray();

    /// <summary>Runs the expiry sweep immediately instead of waiting for the timer — lets tests assert
    /// that an adopted ban really is cleaned up, rather than only that it was recorded.</summary>
    internal void CleanupExpiredNow() => CleanupExpired();

    private void CleanupExpired()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var (address, expiresAt) in _activeBans.ToArray())
        {
            if (expiresAt <= now)
                Unban(address);
        }
    }

    public void Dispose() => _cleanupTimer.Dispose();
}
