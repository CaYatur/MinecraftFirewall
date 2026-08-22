using System.Net;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Tests;

public class FirewallBanServiceTests
{
    private static FirewallBanService CreateService(FakeWindowsFirewallGateway gateway, FirewallBanOptions? options = null, NeverBanOptions? neverBanOptions = null)
    {
        var neverBanList = new NeverBanList(Options.Create(neverBanOptions ?? new NeverBanOptions()));
        return new FirewallBanService(
            Options.Create(options ?? new FirewallBanOptions()),
            neverBanList,
            gateway,
            NullLogger<FirewallBanService>.Instance);
    }

    [Fact]
    public void Ban_UnknownPublicIp_AddsRuleAndMarksBanned()
    {
        var gateway = new FakeWindowsFirewallGateway();
        using var service = CreateService(gateway);
        var ip = IPAddress.Parse("203.0.113.9");

        var result = service.Ban(ip, "test reason");

        Assert.Equal(BanResult.Banned, result);
        Assert.True(service.IsBanned(ip));
        Assert.Contains(ip, gateway.RuledAddresses);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.1.2.3")]
    [InlineData("172.16.5.6")]
    [InlineData("192.168.1.50")]
    public void Ban_NeverBanAddress_IsRefusedAndNoRuleCreated(string ipText)
    {
        var gateway = new FakeWindowsFirewallGateway();
        using var service = CreateService(gateway);
        var ip = IPAddress.Parse(ipText);

        var result = service.Ban(ip, "should be refused");

        Assert.Equal(BanResult.RefusedNeverBan, result);
        Assert.False(service.IsBanned(ip));
        Assert.DoesNotContain(ip, gateway.RuledAddresses);
    }

    [Fact]
    public void Ban_ConfiguredExtraAllowlistAddress_IsRefused()
    {
        var gateway = new FakeWindowsFirewallGateway();
        var neverBanOptions = new NeverBanOptions { ExtraAllowlist = ["203.0.113.9/32"] };
        using var service = CreateService(gateway, neverBanOptions: neverBanOptions);
        var ip = IPAddress.Parse("203.0.113.9");

        var result = service.Ban(ip, "admin's own IP");

        Assert.Equal(BanResult.RefusedNeverBan, result);
    }

    [Fact]
    public void Ban_AlreadyBannedAddress_ExtendsWithoutDuplicateRule()
    {
        var gateway = new FakeWindowsFirewallGateway();
        using var service = CreateService(gateway);
        var ip = IPAddress.Parse("203.0.113.9");

        service.Ban(ip, "first");
        var second = service.Ban(ip, "second");

        Assert.Equal(BanResult.AlreadyBanned, second);
        Assert.Single(gateway.RuledAddresses);
    }

    [Fact]
    public void Unban_RemovesRuleAndClearsBannedState()
    {
        var gateway = new FakeWindowsFirewallGateway();
        using var service = CreateService(gateway);
        var ip = IPAddress.Parse("203.0.113.9");
        service.Ban(ip, "test");

        service.Unban(ip);

        Assert.False(service.IsBanned(ip));
        Assert.DoesNotContain(ip, gateway.RuledAddresses);
    }

    [Fact]
    public void ListActiveBans_ReflectsCurrentState()
    {
        var gateway = new FakeWindowsFirewallGateway();
        using var service = CreateService(gateway);
        var ip1 = IPAddress.Parse("203.0.113.1");
        var ip2 = IPAddress.Parse("203.0.113.2");

        service.Ban(ip1, "one");
        service.Ban(ip2, "two");

        var active = service.ListActiveBans();
        Assert.Equal(2, active.Count);
        Assert.Contains(active, b => b.Address.Equals(ip1));
        Assert.Contains(active, b => b.Address.Equals(ip2));
    }
}
