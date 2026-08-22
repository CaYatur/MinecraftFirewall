using System.Net;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.IpIntel;
using MinecraftFirewall.Proxy.RateLimiting;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Policy;

/// <summary>Carried on an Allow decision when the connection is a self-registered CaYaDev-Check
/// username on an unrecognized IP — the caller (ClientConnection/PlayStateInspector) must enforce
/// that the first Play-state message is a correct /login, per IdentityGate's AllowPendingGraceAuthentication.</summary>
public sealed record GraceAuthRequirement(IdentityEntry Entry, string PasswordHash);

public sealed record PolicyDecision(bool Allow, string Reason, GraceAuthRequirement? GraceAuth = null);

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
            // A pending-grace-auth connection is a security-relevant identity too (it has a password),
            // so it's treated the same as an outright-Allow for VPN policy purposes.
            bool isProtectedUsername = identityDecision.Outcome is IdentityOutcome.Allow or IdentityOutcome.AllowPendingGraceAuthentication;

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
        // those near-misses toward an eventual ban. A pending grace-auth isn't "clean" yet (the
        // password hasn't been checked), so strikes are only cleared once that succeeds — see
        // ClientConnection/PlayStateInspector, which calls RegisterGraceAuthSuccess itself.
        if (identityDecision.Outcome == IdentityOutcome.AllowPendingGraceAuthentication)
        {
            return new PolicyDecision(true, identityDecision.Reason, new GraceAuthRequirement(entry!, entry!.PasswordHash!));
        }

        strikeTracker.Reset(remoteAddress);
        return new PolicyDecision(true, "OK");
    }

    /// <summary>Called by PlayStateInspector when a grace-authentication first-message check succeeds.</summary>
    public void RegisterGraceAuthSuccess(IPAddress remoteAddress) => strikeTracker.Reset(remoteAddress);

    /// <summary>Called by PlayStateInspector when a grace-authentication check fails (wrong password,
    /// wrong first message, or timeout) — a much stronger signal than a generic rate-limit trip, so it
    /// weighs enough strikes to reach the ban threshold immediately rather than needing repeats.</summary>
    public void RegisterGraceAuthFailure(IPAddress remoteAddress, string profileName, string username)
    {
        RegisterStrikeAndMaybeBan(remoteAddress,
            $"[{profileName}] grace-authentication failed for registered username '{username}'",
            weight: _banOptions.StrikesBeforeBan);
    }

    /// <summary>Called by PlayStateInspector when a non-trusted connection issues a dangerous command —
    /// same fast-track reasoning as a grace-authentication failure.</summary>
    public void RegisterDangerousCommand(IPAddress remoteAddress, string profileName, string username, string command)
    {
        RegisterStrikeAndMaybeBan(remoteAddress,
            $"[{profileName}] dangerous command '{command}' from non-trusted username '{username}'",
            weight: _banOptions.StrikesBeforeBan);
    }

    private void RegisterStrikeAndMaybeBan(IPAddress address, string reason, int weight = 1)
    {
        int strikes = strikeTracker.RegisterStrike(address, weight);
        if (strikes >= _banOptions.StrikesBeforeBan)
        {
            banService.Ban(address, $"{reason} (strike {strikes}/{_banOptions.StrikesBeforeBan})");
            strikeTracker.Reset(address);
        }
    }
}
