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
    public void Evaluate_PremiumRequired_AlwaysDeniesInStage1_RegardlessOfAllowlist()
    {
        // PremiumRequired (Stage 4) must take precedence over the IP allowlist and, since Stage 4
        // isn't implemented yet, fail closed rather than silently falling back to the weaker check.
        var entry = new IdentityEntry { Username = "Admin", PremiumRequired = true };
        entry.StaticAllowlist.Add(CidrRange.Parse("0.0.0.0/0"));

        var decision = IdentityGate.Evaluate(entry, IPAddress.Parse("203.0.113.1"));

        Assert.Equal(IdentityOutcome.Deny, decision.Outcome);
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
