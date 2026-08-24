using System.Net;
using MinecraftFirewall.Proxy.Identity;

namespace MinecraftFirewall.Tests;

public class IdentityGateTests
{
    [Fact]
    public void Evaluate_NoEntry_IsNotProtected()
    {
        var decision = IdentityGate.Evaluate(null, IPAddress.Parse("203.0.113.1"));

        Assert.Equal(IdentityOutcome.NotProtected, decision.Outcome);
    }

    [Fact]
    public void Evaluate_IpInStaticAllowlist_Allows()
    {
        var entry = new IdentityEntry { Username = "Admin" };
        entry.StaticAllowlist.Add(CidrRange.Parse("203.0.113.0/24"));

        var decision = IdentityGate.Evaluate(entry, IPAddress.Parse("203.0.113.55"));

        Assert.Equal(IdentityOutcome.Allow, decision.Outcome);
    }

    [Fact]
    public void Evaluate_IpNotInStaticAllowlist_Denies()
    {
        var entry = new IdentityEntry { Username = "Admin" };
        entry.StaticAllowlist.Add(CidrRange.Parse("203.0.113.0/24"));

        var decision = IdentityGate.Evaluate(entry, IPAddress.Parse("198.51.100.1"));

        Assert.Equal(IdentityOutcome.Deny, decision.Outcome);
    }

    [Fact]
    public void Evaluate_LearnedIpNotExpired_Allows()
    {
        var entry = new IdentityEntry { Username = "Admin" };
        var ip = IPAddress.Parse("198.51.100.1");
        entry.LearnIp(ip, TimeSpan.FromDays(1), maxLearnedIps: 10);

        var decision = IdentityGate.Evaluate(entry, ip);

        Assert.Equal(IdentityOutcome.Allow, decision.Outcome);
    }

    [Fact]
    public void Evaluate_LearnedIpExpired_Denies()
    {
        var entry = new IdentityEntry { Username = "Admin" };
        var ip = IPAddress.Parse("198.51.100.1");
        entry.StaticAllowlist.Add(CidrRange.Parse("203.0.113.0/24")); // give it a non-empty protection set
        entry.LearnIp(ip, TimeSpan.FromDays(-1), maxLearnedIps: 10);

        var decision = IdentityGate.Evaluate(entry, ip);

        Assert.Equal(IdentityOutcome.Deny, decision.Outcome);
    }

    [Fact]
    public void Evaluate_PremiumRequired_TakesPrecedenceOverAnAllowlistThatWouldOtherwiseAllow()
    {
        // An allowlist wide enough to match anything must still not satisfy a premium-declared name:
        // the Mojang challenge is the only thing that can.
        var entry = new IdentityEntry { Username = "Admin", PremiumRequired = true };
        entry.StaticAllowlist.Add(CidrRange.Parse("0.0.0.0/0"));

        var decision = IdentityGate.Evaluate(entry, IPAddress.Parse("203.0.113.1"));

        Assert.Equal(IdentityOutcome.PremiumVerificationRequired, decision.Outcome);
    }

    [Fact]
    public void Evaluate_PremiumRequired_WithPasswordAndMatchingLearnedIp_StillRequiresPremiumVerification()
    {
        // The precedence guarantee in its strongest form, and the one a refactor of Evaluate would
        // silently break: this entry satisfies EVERY weaker check at once — a password is set, and
        // the connecting IP is a currently-valid learned IP. Falling through to any of them would
        // both let an attacker who obtained the password bypass the Mojang gate, and (in the other
        // direction) risk prompting the genuine owner for a password, which docs/plan.md explicitly
        // guarantees never happens for a premium name.
        var ip = IPAddress.Parse("203.0.113.55");
        var entry = new IdentityEntry { Username = "Admin", PremiumRequired = true, PasswordHash = "hash" };
        entry.StaticAllowlist.Add(CidrRange.Parse("203.0.113.55/32"));
        entry.LearnIp(ip, TimeSpan.FromDays(30), maxLearnedIps: 10);

        var decision = IdentityGate.Evaluate(entry, ip);

        Assert.Equal(IdentityOutcome.PremiumVerificationRequired, decision.Outcome);
    }

    [Fact]
    public void Evaluate_PasswordSetUnrecognizedIp_RequiresGraceAuthentication()
    {
        var entry = new IdentityEntry { Username = "Player1", PasswordHash = "hash" };

        var decision = IdentityGate.Evaluate(entry, IPAddress.Parse("203.0.113.1"));

        Assert.Equal(IdentityOutcome.AllowPendingGraceAuthentication, decision.Outcome);
    }

    [Fact]
    public void Evaluate_PasswordSetRecognizedIp_AllowsOutright()
    {
        var entry = new IdentityEntry { Username = "Player1", PasswordHash = "hash" };
        var ip = IPAddress.Parse("203.0.113.1");
        entry.LearnIp(ip, TimeSpan.FromDays(30), maxLearnedIps: 5);

        var decision = IdentityGate.Evaluate(entry, ip);

        Assert.Equal(IdentityOutcome.Allow, decision.Outcome);
    }

    [Fact]
    public void Evaluate_StaticAllowlistOnly_UnrecognizedIp_DeniesStrictly_NoGraceWindow()
    {
        // Admin-declared protected names (OP/admin accounts) never get the grace-authentication
        // window that self-registered names get — that's the whole point of the distinction.
        var entry = new IdentityEntry { Username = "Admin" };
        entry.StaticAllowlist.Add(CidrRange.Parse("203.0.113.0/24"));

        var decision = IdentityGate.Evaluate(entry, IPAddress.Parse("198.51.100.1"));

        Assert.Equal(IdentityOutcome.Deny, decision.Outcome);
    }

    [Fact]
    public void Evaluate_EntryExistsWithNoProtectionConfigured_IsNotProtected()
    {
        var entry = new IdentityEntry { Username = "Player1" };

        var decision = IdentityGate.Evaluate(entry, IPAddress.Parse("203.0.113.1"));

        Assert.Equal(IdentityOutcome.NotProtected, decision.Outcome);
    }
}
