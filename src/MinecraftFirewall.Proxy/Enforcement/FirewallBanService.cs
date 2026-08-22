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

        if (_activeBans.ContainsKey(address))
        {
            _activeBans[address] = expiresAt;
            _logger.LogInformation("Extended ban for {Ip} to {ExpiresAt}. Reason: {Reason}", address, expiresAt, reason);
            return BanResult.AlreadyBanned;
        }

        try
        {
            _gateway.AddBlockRule(address, reason);
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
