using System.Net;
using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.IpIntel;
using MinecraftFirewall.Proxy.Policy;
using MinecraftFirewall.Proxy.RateLimiting;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Tests;

public class PolicyEngineTests
{
    private sealed record Fixture(PolicyEngine Engine, VpnIntelligence VpnIntel, FakeWindowsFirewallGateway Gateway, FirewallBanService BanService);

    private static Fixture CreateFixture(int strikesBeforeBan = 5, int loginMaxPerWindow = 100)
    {
        var vpnIntel = new VpnIntelligence();
        var rateLimiter = new ConnectionRateLimiter(Options.Create(new RateLimitOptions
        {
            LoginMaxPerWindow = loginMaxPerWindow,
            LoginWindow = TimeSpan.FromSeconds(30),
            StatusPingMaxPerWindow = loginMaxPerWindow,
            StatusPingWindow = TimeSpan.FromSeconds(30),
        }));
        var gateway = new FakeWindowsFirewallGateway();
        var neverBanList = new NeverBanList(Options.Create(new NeverBanOptions()));
        var banOptions = Options.Create(new FirewallBanOptions { StrikesBeforeBan = strikesBeforeBan });
        var banService = new FirewallBanService(banOptions, neverBanList, gateway, NullLogger<FirewallBanService>.Instance);
        var strikeTracker = new StrikeTracker();

        var engine = new PolicyEngine(vpnIntel, rateLimiter, banService, strikeTracker, banOptions, NullLogger<PolicyEngine>.Instance);
        return new Fixture(engine, vpnIntel, gateway, banService);
    }

    private static ServerProfile CreateProfile(string name = "profileA", VpnPolicy vpnPolicy = VpnPolicy.BlockForProtectedUsernamesOnly, bool useDatacenterList = false)
    {
        return new ServerProfile
        {
            Name = name,
            PublicPort = 25565,
            BackendHost = "127.0.0.1",
            BackendPort = 25566,
            VpnPolicy = vpnPolicy,
            UseDatacenterList = useDatacenterList,
        };
    }

    [Fact]
    public void EvaluateLogin_UnprotectedUsername_NoVpn_Allows()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile();

        var decision = fixture.Engine.EvaluateLogin(profile, IPAddress.Parse("203.0.113.1"), "RandomPlayer");

        Assert.True(decision.Allow);
    }

    [Fact]
    public void EvaluateLogin_ProtectedUsername_AllowlistedIp_Allows()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile();
        var entry = new IdentityEntry { Username = "Admin" };
        entry.StaticAllowlist.Add(CidrRange.Parse("203.0.113.0/24"));
        profile.IdentityStore.AddOrReplace(entry);

        var decision = fixture.Engine.EvaluateLogin(profile, IPAddress.Parse("203.0.113.5"), "Admin");

        Assert.True(decision.Allow);
    }

    [Fact]
    public void EvaluateLogin_ProtectedUsername_WrongIp_Denies()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile();
        var entry = new IdentityEntry { Username = "Admin" };
        entry.StaticAllowlist.Add(CidrRange.Parse("203.0.113.0/24"));
        profile.IdentityStore.AddOrReplace(entry);

        var decision = fixture.Engine.EvaluateLogin(profile, IPAddress.Parse("198.51.100.9"), "Admin");

        Assert.False(decision.Allow);
    }

    [Fact]
    public void EvaluateLogin_VpnFlagged_ProtectedUsername_BlockForProtectedOnly_Denies()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile(vpnPolicy: VpnPolicy.BlockForProtectedUsernamesOnly);
        var entry = new IdentityEntry { Username = "Admin" };
        entry.StaticAllowlist.Add(CidrRange.Parse("203.0.113.0/24")); // IP will be recognized...
        profile.IdentityStore.AddOrReplace(entry);
        fixture.VpnIntel.UpdateVpnOnly(Ipv4RangeTable.Parse(["203.0.113.0/24"])); // ...but is also a known VPN range

        var decision = fixture.Engine.EvaluateLogin(profile, IPAddress.Parse("203.0.113.5"), "Admin");

        Assert.False(decision.Allow);
    }

    [Fact]
    public void EvaluateLogin_VpnFlagged_UnprotectedUsername_BlockForProtectedOnly_StillAllows()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile(vpnPolicy: VpnPolicy.BlockForProtectedUsernamesOnly);
        fixture.VpnIntel.UpdateVpnOnly(Ipv4RangeTable.Parse(["203.0.113.0/24"]));

        var decision = fixture.Engine.EvaluateLogin(profile, IPAddress.Parse("203.0.113.5"), "RandomPlayer");

        Assert.True(decision.Allow);
    }

    [Fact]
    public void EvaluateLogin_VpnFlagged_BlockForEveryone_DeniesUnprotectedToo()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile(vpnPolicy: VpnPolicy.BlockForEveryone);
        fixture.VpnIntel.UpdateVpnOnly(Ipv4RangeTable.Parse(["203.0.113.0/24"]));

        var decision = fixture.Engine.EvaluateLogin(profile, IPAddress.Parse("203.0.113.5"), "RandomPlayer");

        Assert.False(decision.Allow);
    }

    [Fact]
    public void EvaluateLogin_VpnFlagged_LogOnly_AlwaysAllows()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile(vpnPolicy: VpnPolicy.LogOnly);
        var entry = new IdentityEntry { Username = "Admin" };
        entry.StaticAllowlist.Add(CidrRange.Parse("203.0.113.0/24"));
        profile.IdentityStore.AddOrReplace(entry);
        fixture.VpnIntel.UpdateVpnOnly(Ipv4RangeTable.Parse(["203.0.113.0/24"]));

        var decision = fixture.Engine.EvaluateLogin(profile, IPAddress.Parse("203.0.113.5"), "Admin");

        Assert.True(decision.Allow);
    }

    [Fact]
    public void EvaluateLogin_RateLimitExceeded_Denies()
    {
        var fixture = CreateFixture(loginMaxPerWindow: 2);
        var profile = CreateProfile();
        var ip = IPAddress.Parse("203.0.113.1");

        fixture.Engine.EvaluateLogin(profile, ip, "P1");
        fixture.Engine.EvaluateLogin(profile, ip, "P2");
        var third = fixture.Engine.EvaluateLogin(profile, ip, "P3");

        Assert.False(third.Allow);
    }

    [Fact]
    public void EvaluateLogin_AlreadyBannedIp_DeniesImmediately()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile();
        var ip = IPAddress.Parse("203.0.113.1");
        fixture.BanService.Ban(ip, "pre-existing ban");

        var decision = fixture.Engine.EvaluateLogin(profile, ip, "AnyPlayer");

        Assert.False(decision.Allow);
    }

    [Fact]
    public void EvaluateLogin_RepeatedViolations_EscalatesToFirewallBan()
    {
        var fixture = CreateFixture(strikesBeforeBan: 3, loginMaxPerWindow: 0); // every attempt is a rate-limit violation
        var profile = CreateProfile();
        var ip = IPAddress.Parse("203.0.113.1");

        for (int i = 0; i < 3; i++)
            fixture.Engine.EvaluateLogin(profile, ip, "Attacker");

        Assert.Contains(ip, fixture.Gateway.RuledAddresses);
        Assert.True(fixture.BanService.IsBanned(ip));
    }

    [Fact]
    public void EvaluateLogin_RepeatedViolations_FromNeverBanIp_NeverCreatesFirewallRule()
    {
        var fixture = CreateFixture(strikesBeforeBan: 2, loginMaxPerWindow: 0);
        var profile = CreateProfile();
        var loopback = IPAddress.Parse("127.0.0.1");

        for (int i = 0; i < 5; i++)
            fixture.Engine.EvaluateLogin(profile, loopback, "Attacker");

        Assert.Empty(fixture.Gateway.RuledAddresses);
        Assert.False(fixture.BanService.IsBanned(loopback));
    }

    [Fact]
    public void EvaluateLogin_BanTriggeredViaOneProfile_BlocksSameIpOnAnotherProfile()
    {
        // FirewallBanService/StrikeTracker are shared across every profile by design (Ban/IsBanned
        // take no profile parameter) — an attacker blocked on one fronted server must not be able to
        // walk into another server on the same box. This is the multi-server "shared ban" guarantee.
        var fixture = CreateFixture(strikesBeforeBan: 2, loginMaxPerWindow: 0);
        var profileA = CreateProfile(name: "profileA");
        var profileB = CreateProfile(name: "profileB");
        var ip = IPAddress.Parse("203.0.113.1");

        fixture.Engine.EvaluateLogin(profileA, ip, "Attacker");
        fixture.Engine.EvaluateLogin(profileA, ip, "Attacker");

        Assert.True(fixture.BanService.IsBanned(ip));

        var decisionOnB = fixture.Engine.EvaluateLogin(profileB, ip, "Attacker");

        Assert.False(decisionOnB.Allow);
    }

    [Fact]
    public void EvaluateStatusPing_RateLimitIndependentFromLogin()
    {
        var fixture = CreateFixture(loginMaxPerWindow: 1);
        var profile = CreateProfile();
        var ip = IPAddress.Parse("203.0.113.1");

        fixture.Engine.EvaluateLogin(profile, ip, "P1"); // consumes the login window
        var pingDecision = fixture.Engine.EvaluateStatusPing(profile, ip);

        Assert.True(pingDecision.Allow);
    }
}
