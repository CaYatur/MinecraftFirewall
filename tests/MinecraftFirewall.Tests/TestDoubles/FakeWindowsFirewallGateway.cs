using System.Collections.Concurrent;
using System.Net;
using MinecraftFirewall.Proxy.Enforcement;

namespace MinecraftFirewall.Tests.TestDoubles;

/// <summary>In-memory stand-in for the real Windows Firewall so tests never touch the actual OS firewall.</summary>
public sealed class FakeWindowsFirewallGateway : IWindowsFirewallGateway
{
    private readonly ConcurrentDictionary<IPAddress, string> _rules = new();

    public IReadOnlyCollection<IPAddress> RuledAddresses => _rules.Keys.ToArray();

    public void AddBlockRule(IPAddress address, string reason) => _rules[address] = reason;

    public void RemoveBlockRule(IPAddress address) => _rules.TryRemove(address, out _);

    public bool CanAccessFirewall(out string? errorMessage)
    {
        errorMessage = null;
        return true;
    }
}
