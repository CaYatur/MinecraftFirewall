using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Network;

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

    /// <summary>
    /// How the backend is told which address a player is really connecting from.
    ///
    /// Off by default, because it is not this side alone that decides it: the backend has to be
    /// configured to expect the same thing, and a server told to read a forwarded address will
    /// believe whatever it is told. Switching this on without binding the backend to loopback would
    /// let anyone who can reach that port claim any address they like.
    ///
    /// Left off, every player on the server appears as 127.0.0.1 — in the log, in a ban, and to
    /// every plugin that reads an address.
    /// </summary>
    public IpForwardingMode IpForwarding { get; init; } = IpForwardingMode.None;

    /// <summary>
    /// Whether forwarding is currently working on this server, and the switch that turns it off by
    /// itself when it plainly is not.
    ///
    /// A mismatch between this setting and the server's own makes every connection fail on arrival,
    /// which leaves the server unjoinable for a reason nobody can see from inside the game. Rather
    /// than let that stand, the firewall notices and stops forwarding — see IpForwardingHealth.
    /// </summary>
    public IpForwardingHealth ForwardingHealth { get; } = new();

    /// <summary>
    /// The forwarding mode actually in use, which is the configured one unless it has been suspended
    /// for breaking every connection.
    ///
    /// Every decision reads this rather than <see cref="IpForwarding"/>, so that suspending it has a
    /// single meaning and cannot be half-applied — a connection that sent a PROXY header but rewrote
    /// nothing, or the reverse, would be a new failure of its own.
    /// </summary>
    public IpForwardingMode EffectiveIpForwarding =>
        ForwardingHealth.Suspended ? IpForwardingMode.None : IpForwarding;

    public IdentityStore IdentityStore { get; } = new();
}
