using System.Net;
using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Admin;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.IpIntel;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Tests;

public class AdminCommandHandlerTests
{
    private sealed class UnreachableHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new() { Timeout = TimeSpan.FromMilliseconds(200) };
    }

    private sealed record Fixture(AdminCommandHandler Handler, ServerProfile Profile, FirewallBanService BanService, FakeWindowsFirewallGateway Gateway);

    private static Fixture CreateFixture()
    {
        var profile = new ServerProfile { Name = "TestServer", PublicPort = 25565, BackendHost = "127.0.0.1", BackendPort = 25566 };
        var gateway = new FakeWindowsFirewallGateway();
        var neverBanList = new NeverBanList(Options.Create(new NeverBanOptions()));
        var banOptions = Options.Create(new FirewallBanOptions());
        var banService = new FirewallBanService(banOptions, neverBanList, gateway, new RecordingAlertSender(), NullLogger<FirewallBanService>.Instance);

        var vpnIntelOptions = Options.Create(new VpnIntelOptions
        {
            VpnListUrl = "http://127.0.0.1:1/unreachable-vpn-list", // deliberately unroutable — forces the fail-open path fast
            DatacenterListUrl = "http://127.0.0.1:1/unreachable-datacenter-list",
            CacheDirectory = Path.Combine(Path.GetTempPath(), "MinecraftFirewallTests", Guid.NewGuid().ToString("N")),
            HttpTimeout = TimeSpan.FromMilliseconds(200),
        });
        var refreshService = new IpListRefreshService(new VpnIntelligence(), vpnIntelOptions, new UnreachableHttpClientFactory(), NullLogger<IpListRefreshService>.Instance);

        var handler = new AdminCommandHandler([profile], banService, refreshService, NullLogger<AdminCommandHandler>.Instance);
        return new Fixture(handler, profile, banService, gateway);
    }

    [Fact]
    public async Task WhitelistAddMe_ValidArgs_AddsToAllowlistAndWarnsNotPersisted()
    {
        var fixture = CreateFixture();

        var response = await fixture.Handler.HandleAsync(new AdminRequest("whitelist-add-me", ["TestServer", "Admin", "203.0.113.7"]), CancellationToken.None);

        Assert.True(response.Success);
        Assert.Contains("NOT survive a service restart", response.Message);

        var entry = fixture.Profile.IdentityStore.Find("Admin");
        Assert.NotNull(entry);
        Assert.True(entry!.IsIpRecognized(IPAddress.Parse("203.0.113.7")));
    }

    [Fact]
    public async Task WhitelistAddMe_UnknownProfile_Fails()
    {
        var fixture = CreateFixture();

        var response = await fixture.Handler.HandleAsync(new AdminRequest("whitelist-add-me", ["NoSuchProfile", "Admin", "203.0.113.7"]), CancellationToken.None);

        Assert.False(response.Success);
    }

    [Fact]
    public async Task WhitelistAddMe_InvalidCidr_Fails()
    {
        var fixture = CreateFixture();

        var response = await fixture.Handler.HandleAsync(new AdminRequest("whitelist-add-me", ["TestServer", "Admin", "not-an-ip"]), CancellationToken.None);

        Assert.False(response.Success);
    }

    [Fact]
    public async Task ListBans_NoBans_ReportsNone()
    {
        var fixture = CreateFixture();

        var response = await fixture.Handler.HandleAsync(new AdminRequest("list-bans", []), CancellationToken.None);

        Assert.True(response.Success);
        Assert.Contains("No active bans", response.Message);
    }

    [Fact]
    public async Task ListBans_WithActiveBan_ListsIt()
    {
        var fixture = CreateFixture();
        var ip = IPAddress.Parse("203.0.113.9");
        fixture.BanService.Ban(ip, "test");

        var response = await fixture.Handler.HandleAsync(new AdminRequest("list-bans", []), CancellationToken.None);

        Assert.Contains(ip.ToString(), response.Message);
    }

    [Fact]
    public async Task Unban_ActiveBan_RemovesIt()
    {
        var fixture = CreateFixture();
        var ip = IPAddress.Parse("203.0.113.9");
        fixture.BanService.Ban(ip, "test");

        var response = await fixture.Handler.HandleAsync(new AdminRequest("unban", [ip.ToString()]), CancellationToken.None);

        Assert.True(response.Success);
        Assert.False(fixture.BanService.IsBanned(ip));
    }

    [Fact]
    public async Task Unban_NotBanned_IsNoOpButStillSuccess()
    {
        var fixture = CreateFixture();

        var response = await fixture.Handler.HandleAsync(new AdminRequest("unban", ["203.0.113.9"]), CancellationToken.None);

        Assert.True(response.Success);
        Assert.Contains("was not currently banned", response.Message);
    }

    [Fact]
    public async Task RequirePremium_ValidArgs_SetsFlagAndWarnsNotPersisted()
    {
        var fixture = CreateFixture();

        var response = await fixture.Handler.HandleAsync(new AdminRequest("require-premium", ["TestServer", "Notch"]), CancellationToken.None);

        Assert.True(response.Success);
        Assert.Contains("NOT survive a service restart", response.Message);

        var entry = fixture.Profile.IdentityStore.Find("Notch");
        Assert.NotNull(entry);
        Assert.True(entry!.PremiumRequired);
    }

    [Fact]
    public async Task Reload_FailedNetworkFetch_StillReportsSuccessAndDoesNotThrow_FailOpen()
    {
        // IpListRefreshService's own RefreshOneAsync already fails open on any HTTP error — this
        // confirms the Admin CLI path surfaces that as a normal success, not an internal-error response.
        var fixture = CreateFixture();

        var response = await fixture.Handler.HandleAsync(new AdminRequest("reload", []), CancellationToken.None);

        Assert.True(response.Success);
        Assert.Contains("does not reload ServerProfiles", response.Message);
    }

    [Fact]
    public async Task ListProfiles_ReturnsConfiguredProfile()
    {
        var fixture = CreateFixture();

        var response = await fixture.Handler.HandleAsync(new AdminRequest("list-profiles", []), CancellationToken.None);

        Assert.Contains("TestServer", response.Message);
    }

    [Fact]
    public async Task UnknownCommand_ReturnsFailureWithHelp()
    {
        var fixture = CreateFixture();

        var response = await fixture.Handler.HandleAsync(new AdminRequest("not-a-real-command", []), CancellationToken.None);

        Assert.False(response.Success);
        Assert.Contains("Unknown command", response.Message);
    }
}
