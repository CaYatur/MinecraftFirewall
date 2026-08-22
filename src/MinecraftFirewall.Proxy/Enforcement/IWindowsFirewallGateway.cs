using System.Net;

namespace MinecraftFirewall.Proxy.Enforcement;

/// <summary>
/// The only seam that actually touches the Windows Firewall. Kept as a thin interface so
/// FirewallBanService's ban/TTL/never-ban logic can be unit tested with a fake, never the real
/// firewall — see WindowsFirewallGateway for the INetFwPolicy2-backed implementation.
/// </summary>
public interface IWindowsFirewallGateway
{
    void AddBlockRule(IPAddress address, string reason);
    void RemoveBlockRule(IPAddress address);

    /// <summary>
    /// A cheap read-only probe (e.g. counting existing rules) used once at startup to detect
    /// "not running elevated" early, with a clear log message, instead of discovering it only when
    /// the first ban silently fails.
    /// </summary>
    bool CanAccessFirewall(out string? errorMessage);
}
