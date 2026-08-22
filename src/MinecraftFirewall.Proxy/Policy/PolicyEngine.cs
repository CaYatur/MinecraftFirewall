using System.Net;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.IpIntel;
using MinecraftFirewall.Proxy.RateLimiting;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Policy;

public sealed record PolicyDecision(bool Allow, string Reason);

/// <summary>
/// Combines identity, VPN/datacenter signal, and rate limiting into one Allow/Deny decision per
/// connection. Shared services (VPN table, firewall bans, strike counter) are process-wide; identity
/// and rate-limit state are profile-scoped (passed in via the ServerProfile).
/// </summary>
public sealed class PolicyEngine(
    VpnIntelligence vpnIntelligence,
    ConnectionRateLimiter rateLimiter,
    FirewallBanService banService,
    StrikeTracker strikeTracker,
    IOptions<FirewallBanOptions> banOptions,
    ILogger<PolicyEngine> logger)
{
    private readonly FirewallBanOptions _banOptions = banOptions.Value;

    public PolicyDecision EvaluateStatusPing(ServerProfile profile, IPAddress remoteAddress)
    {
        if (banService.IsBanned(remoteAddress))
            return new PolicyDecision(false, "IP is currently firewall-banned.");

        if (!rateLimiter.TryRegisterAttempt(profile.Name, remoteAddress, RateLimitKind.StatusPing))
        {
            RegisterStrikeAndMaybeBan(remoteAddress, $"[{profile.Name}] status-ping rate limit exceeded");
            return new PolicyDecision(false, "Status-ping rate limit exceeded.");
        }

        strikeTracker.Reset(remoteAddress);
        return new PolicyDecision(true, "OK");
    }

    public PolicyDecision EvaluateLogin(ServerProfile profile, IPAddress remoteAddress, string username)
    {
        if (banService.IsBanned(remoteAddress))
            return new PolicyDecision(false, "IP is currently firewall-banned.");

        if (!rateLimiter.TryRegisterAttempt(profile.Name, remoteAddress, RateLimitKind.LoginAttempt))
        {
            RegisterStrikeAndMaybeBan(remoteAddress, $"[{profile.Name}] login rate limit exceeded");
            return new PolicyDecision(false, "Login rate limit exceeded.");
        }

        var entry = profile.IdentityStore.Find(username);
        var identityDecision = IdentityGate.Evaluate(entry, remoteAddress);

        if (identityDecision.Outcome == IdentityOutcome.Deny)
        {
            RegisterStrikeAndMaybeBan(remoteAddress,
                $"[{profile.Name}] protected username '{username}' denied: {identityDecision.Reason}");
            return new PolicyDecision(false, $"Protected username denied: {identityDecision.Reason}");
        }

        bool isVpnFlagged = profile.UseDatacenterList
            ? vpnIntelligence.IsKnownVpnOrDatacenter(remoteAddress)
            : vpnIntelligence.IsKnownVpn(remoteAddress);

        if (isVpnFlagged)
        {
            bool isProtectedUsername = identityDecision.Outcome == IdentityOutcome.Allow;

            bool shouldBlock = profile.VpnPolicy switch
            {
                VpnPolicy.BlockForEveryone => true,
                VpnPolicy.BlockForProtectedUsernamesOnly => isProtectedUsername,
                VpnPolicy.LogOnly => false,
                _ => false,
            };

            if (shouldBlock)
            {
                RegisterStrikeAndMaybeBan(remoteAddress,
                    $"[{profile.Name}] VPN/datacenter IP denied for username '{username}'");
                return new PolicyDecision(false, "Connection originates from a known VPN/datacenter IP.");
            }

            logger.LogInformation("[{Profile}] VPN/datacenter IP {Ip} allowed (log-only policy) for username '{Username}'.",
                profile.Name, remoteAddress, username);
        }

        // A clean, fully-allowed login clears any accumulated strikes for this IP — a legitimate
        // admin who fumbles their allowlist a few times and then connects correctly must not carry
        // those near-misses toward an eventual ban.
        strikeTracker.Reset(remoteAddress);
        return new PolicyDecision(true, "OK");
    }

    private void RegisterStrikeAndMaybeBan(IPAddress address, string reason)
    {
        int strikes = strikeTracker.RegisterStrike(address);
        if (strikes >= _banOptions.StrikesBeforeBan)
        {
            banService.Ban(address, $"{reason} (strike {strikes}/{_banOptions.StrikesBeforeBan})");
            strikeTracker.Reset(address);
        }
    }
}
