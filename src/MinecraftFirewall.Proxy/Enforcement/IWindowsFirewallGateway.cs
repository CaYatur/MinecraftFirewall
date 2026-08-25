using System.Net;

namespace MinecraftFirewall.Proxy.Enforcement;

/// <summary>
/// The only seam that actually touches the Windows Firewall. Kept as a thin interface so
/// FirewallBanService's ban/TTL/never-ban logic can be unit tested with a fake, never the real
/// firewall — see WindowsFirewallGateway for the INetFwPolicy2-backed implementation.
/// </summary>
/// <param name="ExpiresAt">Null when the rule is one this app created before expiries were recorded
/// in the rule itself, so its intended lifetime is genuinely unknown.</param>
public sealed record ManagedBlockRule(IPAddress Address, DateTimeOffset? ExpiresAt);

public interface IWindowsFirewallGateway
{
    /// <summary>Creates the block rule, or updates the recorded expiry if one already exists.
    /// Update-rather-than-recreate matters: a ban being extended must not briefly drop its OS-level
    /// rule, and the rule's stored expiry must stay current since it is what a restart reads back.</summary>
    void AddOrUpdateBlockRule(IPAddress address, string reason, DateTimeOffset expiresAt);

    void RemoveBlockRule(IPAddress address);

    /// <summary>
    /// Every block rule this app owns, as currently present in the OS firewall — the basis for
    /// rebuilding ban state after a restart. See FirewallBanService's constructor for why the
    /// firewall itself is used as the source of truth rather than a separate state file.
    /// </summary>
    IReadOnlyList<ManagedBlockRule> ListManagedBlockRules();

    /// <summary>
    /// A cheap read-only probe (e.g. counting existing rules) used once at startup to detect
    /// "not running elevated" early, with a clear log message, instead of discovering it only when
    /// the first ban silently fails.
    /// </summary>
    bool CanAccessFirewall(out string? errorMessage);
}
