using System.Collections.Concurrent;
using System.Net;
using MinecraftFirewall.Proxy.Enforcement;

namespace MinecraftFirewall.Tests.TestDoubles;

/// <summary>In-memory stand-in for the real Windows Firewall so tests never touch the actual OS firewall.
/// Rules survive being handed to a new FirewallBanService, which is what makes it possible to test
/// restart behaviour (ban adoption) without a real firewall or elevation.</summary>
public sealed class FakeWindowsFirewallGateway : IWindowsFirewallGateway
{
    private readonly ConcurrentDictionary<IPAddress, (string Reason, DateTimeOffset? ExpiresAt)> _rules = new();

    public IReadOnlyCollection<IPAddress> RuledAddresses => _rules.Keys.ToArray();

    public bool ThrowOnAdd { get; set; }

    public void AddOrUpdateBlockRule(IPAddress address, string reason, DateTimeOffset expiresAt)
    {
        if (ThrowOnAdd)
            throw new InvalidOperationException("Simulated firewall failure (e.g. not running elevated).");

        _rules[address] = (reason, expiresAt);
    }

    /// <summary>Simulates a rule written by a build that didn't record expiries in the description.</summary>
    public void SeedRuleWithoutExpiry(IPAddress address, string reason = "legacy") => _rules[address] = (reason, null);

    public void RemoveBlockRule(IPAddress address) => _rules.TryRemove(address, out _);

    public DateTimeOffset? ExpiryFor(IPAddress address) => _rules.TryGetValue(address, out var rule) ? rule.ExpiresAt : null;

    public IReadOnlyList<ManagedBlockRule> ListManagedBlockRules() =>
        [.. _rules.Select(kv => new ManagedBlockRule(kv.Key, kv.Value.ExpiresAt))];

    public bool CanAccessFirewall(out string? errorMessage)
    {
        errorMessage = null;
        return true;
    }
}
