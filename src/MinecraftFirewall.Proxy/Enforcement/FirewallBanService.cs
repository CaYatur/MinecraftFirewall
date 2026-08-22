using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Options;
using WindowsFirewallHelper;
using WindowsFirewallHelper.Addresses;
using WindowsFirewallHelper.FirewallRules;

namespace MinecraftFirewall.Proxy.Enforcement;

public enum BanResult
{
    Banned,
    AlreadyBanned,
    RefusedNeverBan,
    Failed,
}

/// <summary>
/// Machine-wide Windows Firewall bans via the INetFwPolicy2 COM API (wrapped by WindowsFirewallHelper) —
/// never by shelling out to netsh with interpolated input, since the IP being banned arrives from
/// untrusted network traffic. A ban applies to every server profile at once, since it blocks the IP
/// from the machine, not from one port. Never-ban list is checked before every ban.
/// </summary>
public sealed class FirewallBanService : IDisposable
{
    private const string RuleNamePrefix = "MinecraftFirewall-Ban-";

    private readonly FirewallBanOptions _options;
    private readonly NeverBanList _neverBanList;
    private readonly ILogger<FirewallBanService> _logger;
    private readonly ConcurrentDictionary<IPAddress, DateTimeOffset> _activeBans = new();
    private readonly object _firewallLock = new();
    private readonly Timer _cleanupTimer;

    public FirewallBanService(IOptions<FirewallBanOptions> options, NeverBanList neverBanList, ILogger<FirewallBanService> logger)
    {
        _options = options.Value;
        _neverBanList = neverBanList;
        _logger = logger;
        _cleanupTimer = new Timer(_ => CleanupExpired(), null, _options.CleanupInterval, _options.CleanupInterval);
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

        lock (_firewallLock)
        {
            try
            {
                var rule = new FirewallWASRule(
                    RuleNameFor(address),
                    FirewallAction.Block,
                    FirewallDirection.Inbound,
                    FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public)
                {
                    Protocol = FirewallProtocol.Any,
                    RemoteAddresses = [new SingleIP(address)],
                    Description = $"MinecraftFirewall auto-ban: {reason}",
                };

                FirewallManager.Instance.Rules.Add(rule);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create a Windows Firewall rule blocking {Ip}.", address);
                return BanResult.Failed;
            }
        }

        _activeBans[address] = expiresAt;
        _logger.LogWarning("Banned {Ip} until {ExpiresAt}. Reason: {Reason}", address, expiresAt, reason);
        return BanResult.Banned;
    }

    public void Unban(IPAddress address)
    {
        lock (_firewallLock)
        {
            string name = RuleNameFor(address);
            var existing = FirewallManager.Instance.Rules.FirstOrDefault(r => r.Name == name);
            if (existing is not null)
                FirewallManager.Instance.Rules.Remove(existing);
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

    private static string RuleNameFor(IPAddress address) => $"{RuleNamePrefix}{address}";

    public void Dispose() => _cleanupTimer.Dispose();
}
