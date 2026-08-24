using MinecraftFirewall.Proxy.Identity;

namespace MinecraftFirewall.Proxy;

public enum VpnPolicy
{
    LogOnly,
    BlockForProtectedUsernamesOnly,
    BlockForEveryone,
}

/// <summary>
/// One fronted Minecraft server: its own public port, its own backend, its own identity records
/// and policy overrides. Multiple profiles share the process-wide VpnIntelligence, FirewallBanService,
/// and StrikeTracker (see Program.cs), but rate limiting and identity are profile-scoped.
/// </summary>
public sealed class ServerProfile
{
    public required string Name { get; init; }
    public required int PublicPort { get; init; }
    public required string BackendHost { get; init; }
    public required int BackendPort { get; init; }

    public VpnPolicy VpnPolicy { get; init; } = VpnPolicy.BlockForProtectedUsernamesOnly;

    /// <summary>
    /// When false (default), only the strict "known VPN" list is consulted, which has fewer false
    /// positives than the broader VPN+datacenter list. Datacenter ranges also contain some CGNAT/ISP
    /// false positives, so opting into it is a deliberate per-profile choice.
    /// </summary>
    public bool UseDatacenterList { get; init; }

    /// <summary>
    /// When non-empty, only connections whose Handshake Server Address matches one of these entries
    /// (exact, case-insensitive, or a "*.example.com" subdomain wildcard) are allowed — see
    /// Policy/HostnameMatcher.cs for the matching rules and an important caveat about what this
    /// does and does not guarantee. Empty (default) means no restriction, matching vanilla behavior.
    /// </summary>
    public IReadOnlyList<string> AllowedHostnames { get; init; } = [];

    public IdentityStore IdentityStore { get; } = new();
}
