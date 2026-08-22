using System.Net;

namespace MinecraftFirewall.Proxy.IpIntel;

/// <summary>
/// Shared, atomically-swappable VPN/datacenter IP tables consulted by every server profile.
/// Starts empty and fails open — an unreachable list source degrades to "no VPN signal", not
/// "block everyone" (see IpListRefreshService).
/// </summary>
public sealed class VpnIntelligence
{
    private volatile Ipv4RangeTable _vpnOnly = Ipv4RangeTable.Empty;
    private volatile Ipv4RangeTable _vpnAndDatacenter = Ipv4RangeTable.Empty;

    public void UpdateVpnOnly(Ipv4RangeTable table) => _vpnOnly = table;
    public void UpdateVpnAndDatacenter(Ipv4RangeTable table) => _vpnAndDatacenter = table;

    /// <summary>Strictly known VPN networks.</summary>
    public bool IsKnownVpn(IPAddress address) => _vpnOnly.Contains(address);

    /// <summary>VPN networks and datacenter/hosting ranges ("not an eyeball network").</summary>
    public bool IsKnownVpnOrDatacenter(IPAddress address) => _vpnAndDatacenter.Contains(address);
}
