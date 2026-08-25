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
using MinecraftFirewall.Proxy.Defense;

namespace MinecraftFirewall.Tests;

public class PolicyEngineTests
{
    private sealed record Fixture(PolicyEngine Engine, VpnIntelligence VpnIntel, FakeWindowsFirewallGateway Gateway, FirewallBanService BanService, FakeIpInfoClient IpInfo, RecordingAlertSender Alerts);

    private static Fixture CreateFixture(int strikesBeforeBan = 5, int loginMaxPerWindow = 100, IpInfoOptions? ipInfoOptions = null)
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
        var alerts = new RecordingAlertSender();
        var banService = new FirewallBanService(banOptions, neverBanList, gateway, alerts, NullLogger<FirewallBanService>.Instance);
        var strikeTracker = new StrikeTracker();
        var ipInfo = new FakeIpInfoClient();

        var engine = new PolicyEngine(vpnIntel, rateLimiter, banService, strikeTracker, ipInfo, alerts,
            DefenseTestFactory.CreateThreatIntelligence(), DefenseTestFactory.CreateScannerDetector(), banOptions,
            Options.Create(ipInfoOptions ?? new IpInfoOptions()), Options.Create(new DdosOptions()),
            Options.Create(new BotDefenseOptions()), NullLogger<PolicyEngine>.Instance);
        return new Fixture(engine, vpnIntel, gateway, banService, ipInfo, alerts);
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
    public async Task EvaluateLogin_UnprotectedUsername_NoVpn_Allows()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile();

        var decision = await fixture.Engine.EvaluateLogin(profile, IPAddress.Parse("203.0.113.1"), "RandomPlayer");

        Assert.True(decision.Allow);
    }

    [Fact]
    public async Task EvaluateLogin_ProtectedUsername_AllowlistedIp_Allows()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile();
        var entry = new IdentityEntry { Username = "Admin" };
        entry.StaticAllowlist.Add(CidrRange.Parse("203.0.113.0/24"));
        profile.IdentityStore.AddOrReplace(entry);

        var decision = await fixture.Engine.EvaluateLogin(profile, IPAddress.Parse("203.0.113.5"), "Admin");

        Assert.True(decision.Allow);
    }

    [Fact]
    public async Task EvaluateLogin_ProtectedUsername_WrongIp_Denies()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile();
        var entry = new IdentityEntry { Username = "Admin" };
        entry.StaticAllowlist.Add(CidrRange.Parse("203.0.113.0/24"));
        profile.IdentityStore.AddOrReplace(entry);

        var decision = await fixture.Engine.EvaluateLogin(profile, IPAddress.Parse("198.51.100.9"), "Admin");

        Assert.False(decision.Allow);
    }

    [Fact]
    public async Task EvaluateLogin_VpnFlagged_ProtectedUsername_BlockForProtectedOnly_Denies()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile(vpnPolicy: VpnPolicy.BlockForProtectedUsernamesOnly);
        var entry = new IdentityEntry { Username = "Admin" };
        entry.StaticAllowlist.Add(CidrRange.Parse("203.0.113.0/24")); // IP will be recognized...
        profile.IdentityStore.AddOrReplace(entry);
        fixture.VpnIntel.UpdateVpnOnly(Ipv4RangeTable.Parse(["203.0.113.0/24"])); // ...but is also a known VPN range

        var decision = await fixture.Engine.EvaluateLogin(profile, IPAddress.Parse("203.0.113.5"), "Admin");

        Assert.False(decision.Allow);
    }

    [Fact]
    public async Task EvaluateLogin_VpnFlagged_UnprotectedUsername_BlockForProtectedOnly_StillAllows()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile(vpnPolicy: VpnPolicy.BlockForProtectedUsernamesOnly);
        fixture.VpnIntel.UpdateVpnOnly(Ipv4RangeTable.Parse(["203.0.113.0/24"]));

        var decision = await fixture.Engine.EvaluateLogin(profile, IPAddress.Parse("203.0.113.5"), "RandomPlayer");

        Assert.True(decision.Allow);
    }

    [Fact]
    public async Task EvaluateLogin_VpnFlagged_BlockForEveryone_DeniesUnprotectedToo()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile(vpnPolicy: VpnPolicy.BlockForEveryone);
        fixture.VpnIntel.UpdateVpnOnly(Ipv4RangeTable.Parse(["203.0.113.0/24"]));

        var decision = await fixture.Engine.EvaluateLogin(profile, IPAddress.Parse("203.0.113.5"), "RandomPlayer");

        Assert.False(decision.Allow);
    }

    [Fact]
    public async Task EvaluateLogin_VpnFlagged_LogOnly_AlwaysAllows()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile(vpnPolicy: VpnPolicy.LogOnly);
        var entry = new IdentityEntry { Username = "Admin" };
        entry.StaticAllowlist.Add(CidrRange.Parse("203.0.113.0/24"));
        profile.IdentityStore.AddOrReplace(entry);
        fixture.VpnIntel.UpdateVpnOnly(Ipv4RangeTable.Parse(["203.0.113.0/24"]));

        var decision = await fixture.Engine.EvaluateLogin(profile, IPAddress.Parse("203.0.113.5"), "Admin");

        Assert.True(decision.Allow);
    }

    [Fact]
    public async Task EvaluateLogin_RateLimitExceeded_Denies()
    {
        var fixture = CreateFixture(loginMaxPerWindow: 2);
        var profile = CreateProfile();
        var ip = IPAddress.Parse("203.0.113.1");

        await fixture.Engine.EvaluateLogin(profile, ip, "P1");
        await fixture.Engine.EvaluateLogin(profile, ip, "P2");
        var third = await fixture.Engine.EvaluateLogin(profile, ip, "P3");

        Assert.False(third.Allow);
    }

    [Fact]
    public async Task EvaluateLogin_AlreadyBannedIp_DeniesImmediately()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile();
        var ip = IPAddress.Parse("203.0.113.1");
        fixture.BanService.Ban(ip, "pre-existing ban");

        var decision = await fixture.Engine.EvaluateLogin(profile, ip, "AnyPlayer");

        Assert.False(decision.Allow);
    }

    [Fact]
    public async Task EvaluateLogin_RepeatedViolations_EscalatesToFirewallBan()
    {
        var fixture = CreateFixture(strikesBeforeBan: 3, loginMaxPerWindow: 0); // every attempt is a rate-limit violation
        var profile = CreateProfile();
        var ip = IPAddress.Parse("203.0.113.1");

        for (int i = 0; i < 3; i++)
            await fixture.Engine.EvaluateLogin(profile, ip, "Attacker");

        Assert.Contains(ip, fixture.Gateway.RuledAddresses);
        Assert.True(fixture.BanService.IsBanned(ip));
    }

    [Fact]
    public async Task EvaluateLogin_RepeatedViolations_FromNeverBanIp_NeverCreatesFirewallRule()
    {
        var fixture = CreateFixture(strikesBeforeBan: 2, loginMaxPerWindow: 0);
        var profile = CreateProfile();
        var loopback = IPAddress.Parse("127.0.0.1");

        for (int i = 0; i < 5; i++)
            await fixture.Engine.EvaluateLogin(profile, loopback, "Attacker");

        Assert.Empty(fixture.Gateway.RuledAddresses);
        Assert.False(fixture.BanService.IsBanned(loopback));
    }

    [Fact]
    public async Task EvaluateLogin_BanTriggeredViaOneProfile_BlocksSameIpOnAnotherProfile()
    {
        // FirewallBanService/StrikeTracker are shared across every profile by design (Ban/IsBanned
        // take no profile parameter) — an attacker blocked on one fronted server must not be able to
        // walk into another server on the same box. This is the multi-server "shared ban" guarantee.
        var fixture = CreateFixture(strikesBeforeBan: 2, loginMaxPerWindow: 0);
        var profileA = CreateProfile(name: "profileA");
        var profileB = CreateProfile(name: "profileB");
        var ip = IPAddress.Parse("203.0.113.1");

        await fixture.Engine.EvaluateLogin(profileA, ip, "Attacker");
        await fixture.Engine.EvaluateLogin(profileA, ip, "Attacker");

        Assert.True(fixture.BanService.IsBanned(ip));

        var decisionOnB = await fixture.Engine.EvaluateLogin(profileB, ip, "Attacker");

        Assert.False(decisionOnB.Allow);
    }

    [Fact]
    public async Task EvaluateLogin_IpInfoFlagsHostingIp_ProtectedUsername_DefaultScope_Denies()
    {
        var fixture = CreateFixture(); // default IpInfoOptions: ApplyToAllConnections = false
        var profile = CreateProfile(vpnPolicy: VpnPolicy.BlockForProtectedUsernamesOnly);
        var entry = new IdentityEntry { Username = "Admin" };
        entry.StaticAllowlist.Add(CidrRange.Parse("203.0.113.0/24"));
        profile.IdentityStore.AddOrReplace(entry);
        var ip = IPAddress.Parse("203.0.113.5");
        fixture.IpInfo.FlagAsHosting(ip);

        var decision = await fixture.Engine.EvaluateLogin(profile, ip, "Admin");

        Assert.False(decision.Allow);
    }

    [Fact]
    public async Task EvaluateLogin_IpInfoFlagsHostingIp_UnprotectedUsername_DefaultScope_NotChecked_Allows()
    {
        // Default scope is protected-usernames-only — an unprotected username's connection must not
        // even trigger the ipinfo lookup, let alone be denied by it.
        var fixture = CreateFixture();
        var profile = CreateProfile(vpnPolicy: VpnPolicy.BlockForEveryone);
        var ip = IPAddress.Parse("203.0.113.5");
        fixture.IpInfo.FlagAsHosting(ip);

        var decision = await fixture.Engine.EvaluateLogin(profile, ip, "RandomPlayer");

        Assert.True(decision.Allow);
        Assert.Equal(0, fixture.IpInfo.CallCount);
    }

    [Fact]
    public async Task EvaluateLogin_IpInfoFlagsHostingIp_ApplyToAllConnections_DeniesUnprotectedToo()
    {
        var fixture = CreateFixture(ipInfoOptions: new IpInfoOptions { ApplyToAllConnections = true });
        var profile = CreateProfile(vpnPolicy: VpnPolicy.BlockForEveryone);
        var ip = IPAddress.Parse("203.0.113.5");
        fixture.IpInfo.FlagAsHosting(ip);

        var decision = await fixture.Engine.EvaluateLogin(profile, ip, "RandomPlayer");

        Assert.False(decision.Allow);
        Assert.Equal(1, fixture.IpInfo.CallCount);
    }

    [Fact]
    public async Task EvaluateLogin_AlreadyFlaggedByX4BNetList_SkipsIpInfoLookup()
    {
        var fixture = CreateFixture(ipInfoOptions: new IpInfoOptions { ApplyToAllConnections = true });
        var profile = CreateProfile(vpnPolicy: VpnPolicy.LogOnly); // won't deny, just proves the lookup didn't happen
        fixture.VpnIntel.UpdateVpnOnly(Ipv4RangeTable.Parse(["203.0.113.0/24"]));
        var ip = IPAddress.Parse("203.0.113.5");

        await fixture.Engine.EvaluateLogin(profile, ip, "RandomPlayer");

        Assert.Equal(0, fixture.IpInfo.CallCount);
    }

    [Fact]
    public void EvaluateHostname_NoRestrictionConfigured_Allows()
    {
        var fixture = CreateFixture();
        var profile = CreateProfile(); // AllowedHostnames defaults to empty

        var decision = fixture.Engine.EvaluateHostname(profile, IPAddress.Parse("203.0.113.1"), "203.0.113.1");

        Assert.True(decision.Allow);
    }

    [Fact]
    public void EvaluateHostname_MatchingDomain_Allows()
    {
        var fixture = CreateFixture();
        var profile = new ServerProfile
        {
            Name = "profileA",
            PublicPort = 25565,
            BackendHost = "127.0.0.1",
            BackendPort = 25566,
            AllowedHostnames = ["mc.example.com"],
        };

        var decision = fixture.Engine.EvaluateHostname(profile, IPAddress.Parse("203.0.113.1"), "mc.example.com");

        Assert.True(decision.Allow);
    }

    [Fact]
    public void EvaluateHostname_DirectIpConnect_IsDeniedWhenAllowlistConfigured()
    {
        var fixture = CreateFixture();
        var profile = new ServerProfile
        {
            Name = "profileA",
            PublicPort = 25565,
            BackendHost = "127.0.0.1",
            BackendPort = 25566,
            AllowedHostnames = ["mc.example.com"],
        };
        var ip = IPAddress.Parse("203.0.113.1");

        var decision = fixture.Engine.EvaluateHostname(profile, ip, ip.ToString());

        Assert.False(decision.Allow);
    }

    [Fact]
    public void EvaluateHostname_RepeatedMismatches_EscalatesToFirewallBan()
    {
        var fixture = CreateFixture(strikesBeforeBan: 3);
        var profile = new ServerProfile
        {
            Name = "profileA",
            PublicPort = 25565,
            BackendHost = "127.0.0.1",
            BackendPort = 25566,
            AllowedHostnames = ["mc.example.com"],
        };
        var ip = IPAddress.Parse("203.0.113.1");

        for (int i = 0; i < 3; i++)
            fixture.Engine.EvaluateHostname(profile, ip, "not-allowed.example");

        Assert.True(fixture.BanService.IsBanned(ip));
    }

    [Fact]
    public async Task EvaluateStatusPing_RateLimitIndependentFromLogin()
    {
        var fixture = CreateFixture(loginMaxPerWindow: 1);
        var profile = CreateProfile();
        var ip = IPAddress.Parse("203.0.113.1");

        await fixture.Engine.EvaluateLogin(profile, ip, "P1"); // consumes the login window
        var pingDecision = fixture.Engine.EvaluateStatusPing(profile, ip);

        Assert.True(pingDecision.Allow);
    }
}
