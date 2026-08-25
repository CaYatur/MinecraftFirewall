using System.Globalization;
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

    // The rule's own Description carries its expiry, so a restarted service can rebuild ban state
    // from the firewall instead of from a separate file that could drift out of sync with it.
    // Round-trip format, deliberately human-readable since an admin may well read it in wf.msc:
    //   "MinecraftFirewall auto-ban until 2026-08-25T04:00:00.0000000+00:00: <reason>"
    private const string ExpiryMarker = " until ";
    private const string DescriptionPrefix = "MinecraftFirewall auto-ban";

    private readonly object _firewallLock = new();

    public void AddOrUpdateBlockRule(IPAddress address, string reason, DateTimeOffset expiresAt)
    {
        string name = RuleNameFor(address);

        lock (_firewallLock)
        {
            var existing = FirewallManager.Instance.Rules.FirstOrDefault(r => r.Name == name);
            if (existing is not null)
            {
                // Update in place rather than remove-then-add: recreating would leave a brief window
                // with no rule at all for an IP already judged hostile. Description lives on the
                // concrete WAS (Windows Firewall with Advanced Security) rule type, not on
                // IFirewallRule — anything else is a pre-Vista legacy rule this app never creates.
                if (existing is FirewallWASRule was)
                    was.Description = BuildDescription(reason, expiresAt);

                logger.LogDebug("Updated Windows Firewall block rule for {Ip}, now expiring {ExpiresAt}.", address, expiresAt);
                return;
            }

            var rule = new FirewallWASRule(
                name,
                FirewallAction.Block,
                FirewallDirection.Inbound,
                FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public)
            {
                Protocol = FirewallProtocol.Any,
                RemoteAddresses = [new SingleIP(address)],
                Description = BuildDescription(reason, expiresAt),
            };

            FirewallManager.Instance.Rules.Add(rule);
        }

        logger.LogDebug("Added Windows Firewall block rule for {Ip}, expiring {ExpiresAt}.", address, expiresAt);
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

    public IReadOnlyList<ManagedBlockRule> ListManagedBlockRules()
    {
        var found = new List<ManagedBlockRule>();

        try
        {
            IFirewallRule[] rules;
            lock (_firewallLock)
                rules = [.. FirewallManager.Instance.Rules.Where(r => r.Name.StartsWith(RuleNamePrefix, StringComparison.Ordinal))];

            foreach (var rule in rules)
            {
                string addressText = rule.Name[RuleNamePrefix.Length..];
                if (!IPAddress.TryParse(addressText, out var address))
                {
                    logger.LogWarning("Firewall rule '{Rule}' matches this app's naming but its address part is unparseable — leaving it alone.", rule.Name);
                    continue;
                }

                found.Add(new ManagedBlockRule(address, ParseExpiry((rule as FirewallWASRule)?.Description)));
            }
        }
        catch (Exception ex)
        {
            // Almost always "not running elevated". Startup already warns about that separately;
            // returning nothing here just means no bans are adopted, which is the safe direction.
            logger.LogWarning(ex, "Could not enumerate existing Windows Firewall rules — previous bans will not be re-adopted.");
            return [];
        }

        return found;
    }

    private static string BuildDescription(string reason, DateTimeOffset expiresAt) =>
        $"{DescriptionPrefix}{ExpiryMarker}{expiresAt.ToString("o", CultureInfo.InvariantCulture)}: {reason}";

    private static DateTimeOffset? ParseExpiry(string? description)
    {
        if (string.IsNullOrEmpty(description) || !description.StartsWith(DescriptionPrefix + ExpiryMarker, StringComparison.Ordinal))
            return null;

        string rest = description[(DescriptionPrefix.Length + ExpiryMarker.Length)..];

        // Split on ": " (colon-SPACE), not ':'. The ISO-8601 timestamp contains colons of its own
        // (both in the time and in the UTC offset) but never a colon followed by a space, so this is
        // unambiguously the boundary between the timestamp and the free-text reason after it.
        int end = rest.IndexOf(": ", StringComparison.Ordinal);
        if (end < 0)
            return null;

        return DateTimeOffset.TryParse(rest[..end], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)
            ? parsed
            : null;
    }

    private static string RuleNameFor(IPAddress address) => $"{RuleNamePrefix}{address}";
}
