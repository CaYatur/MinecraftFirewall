using System.Net;
using WindowsFirewallHelper;
using WindowsFirewallHelper.Addresses;
using WindowsFirewallHelper.FirewallRules;

namespace MinecraftFirewall.Proxy.Enforcement;

/// <summary>
/// Real Windows Firewall access via the INetFwPolicy2 COM API (wrapped by WindowsFirewallHelper) —
/// never by shelling out to netsh with interpolated input, since the IP being banned arrives from
/// untrusted network traffic. A single COM lock serializes all rule mutations; COM objects here
/// aren't guaranteed thread-safe for concurrent calls.
/// </summary>
public sealed class WindowsFirewallGateway(ILogger<WindowsFirewallGateway> logger) : IWindowsFirewallGateway
{
    private const string RuleNamePrefix = "MinecraftFirewall-Ban-";
    private readonly object _firewallLock = new();

    public void AddBlockRule(IPAddress address, string reason)
    {
        lock (_firewallLock)
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

        logger.LogDebug("Added Windows Firewall block rule for {Ip}.", address);
    }

    public bool CanAccessFirewall(out string? errorMessage)
    {
        try
        {
            _ = FirewallManager.Instance.Rules.Count;
            errorMessage = null;
            return true;
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            return false;
        }
    }

    public void RemoveBlockRule(IPAddress address)
    {
        lock (_firewallLock)
        {
            string name = RuleNameFor(address);
            var existing = FirewallManager.Instance.Rules.FirstOrDefault(r => r.Name == name);
            if (existing is not null)
                FirewallManager.Instance.Rules.Remove(existing);
        }

        logger.LogDebug("Removed Windows Firewall block rule for {Ip} (if one existed).", address);
    }

    private static string RuleNameFor(IPAddress address) => $"{RuleNamePrefix}{address}";
}
