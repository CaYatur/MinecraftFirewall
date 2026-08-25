using System.Net;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Tests.TestDoubles;

namespace MinecraftFirewall.Tests;

public class ConnectionGovernorTests
{
    private static IPAddress Ip(string text) => IPAddress.Parse(text);

    [Fact]
    public void ConcurrentConnectionsFromOneAddress_AreCappedAndReleasedAgain()
    {
        using var governor = DefenseTestFactory.CreateGovernor(new DdosOptions { MaxConcurrentPerIp = 3 });
        var address = Ip("203.0.113.10");

        var leases = new List<ConnectionLease>();
        for (int i = 0; i < 3; i++)
        {
            AdmissionResult result = governor.TryAdmit(address);
            Assert.True(result.Admitted);
            leases.Add(result.Lease!);
        }

        AdmissionResult overLimit = governor.TryAdmit(address);
        Assert.False(overLimit.Admitted);
        Assert.Equal(AdmissionVerdict.TooManyFromAddress, overLimit.Verdict);

        // The whole point of the lease: a slot comes back when the connection ends, so a busy server
        // is not permanently poorer for having been busy.
        leases[0].Dispose();
        Assert.True(governor.TryAdmit(address).Admitted);
    }

    [Fact]
    public void ARefusalDoesNotConsumeASlot()
    {
        // If a refused attempt still counted against the cap, an address at its limit could never
        // recover: every retry would top the counter back up.
        using var governor = DefenseTestFactory.CreateGovernor(new DdosOptions { MaxConcurrentPerIp = 1 });
        var address = Ip("203.0.113.11");

        ConnectionLease lease = governor.TryAdmit(address).Lease!;
        for (int i = 0; i < 5; i++)
            Assert.False(governor.TryAdmit(address).Admitted);

        lease.Dispose();
        Assert.True(governor.TryAdmit(address).Admitted);
        Assert.Equal(1, governor.CurrentConnections);
    }

    [Fact]
    public void DisposingALeaseTwice_DoesNotGiveBackASlotItNeverHeld()
    {
        using var governor = DefenseTestFactory.CreateGovernor(new DdosOptions { MaxConcurrentPerIp = 2 });
        var address = Ip("203.0.113.12");

        ConnectionLease first = governor.TryAdmit(address).Lease!;
        ConnectionLease second = governor.TryAdmit(address).Lease!;

        first.Dispose();
        first.Dispose();
        first.Dispose();

        second.Dispose();
        Assert.Equal(0, governor.CurrentConnections);
    }

    [Fact]
    public void ADistributedFlood_IsCaughtAtTheSubnetEvenThoughNoSingleAddressIsOverItsLimit()
    {
        // This is the case a per-address cap alone cannot see: twenty addresses in one /24, each
        // opening a single connection, is invisible per-address and obvious per-subnet.
        using var governor = DefenseTestFactory.CreateGovernor(new DdosOptions
        {
            MaxConcurrentPerIp = 10,
            MaxConcurrentPerSubnet = 8,
        });

        var admitted = new List<ConnectionLease>();
        for (int host = 1; host <= 8; host++)
        {
            AdmissionResult result = governor.TryAdmit(Ip($"198.51.100.{host}"));
            Assert.True(result.Admitted, $"host {host} should have been admitted");
            admitted.Add(result.Lease!);
        }

        AdmissionResult ninth = governor.TryAdmit(Ip("198.51.100.9"));
        Assert.False(ninth.Admitted);
        Assert.Equal(AdmissionVerdict.TooManyFromSubnet, ninth.Verdict);

        // A different /24 is unaffected — the cap follows the network, not the server.
        Assert.True(governor.TryAdmit(Ip("198.51.101.9")).Admitted);
    }

    [Fact]
    public void ReconnectStorms_AreCaughtByRateEvenWhenNothingStaysOpen()
    {
        // Connect-and-drop never shows up in a concurrency count, which is exactly why it needs its
        // own limit.
        using var governor = DefenseTestFactory.CreateGovernor(new DdosOptions
        {
            MaxConcurrentPerIp = 100,
            MaxNewConnectionsPerIpPerMinute = 5,
        });

        var address = Ip("203.0.113.20");
        for (int i = 0; i < 5; i++)
        {
            AdmissionResult result = governor.TryAdmit(address);
            Assert.True(result.Admitted);
            result.Lease!.Dispose();
        }

        AdmissionResult refused = governor.TryAdmit(address);
        Assert.False(refused.Admitted);
        Assert.Equal(AdmissionVerdict.ConnectingTooFast, refused.Verdict);
    }

    [Fact]
    public void TheGlobalCeiling_AppliesHoweverWellSpreadTheSourcesAre()
    {
        using var governor = DefenseTestFactory.CreateGovernor(new DdosOptions
        {
            MaxConcurrentTotal = 4,
            MaxConcurrentPerIp = 100,
            MaxConcurrentPerSubnet = 100,
        });

        for (int i = 1; i <= 4; i++)
            Assert.True(governor.TryAdmit(Ip($"198.51.{i}.1")).Admitted);

        AdmissionResult refused = governor.TryAdmit(Ip("198.51.99.1"));
        Assert.False(refused.Admitted);
        Assert.Equal(AdmissionVerdict.ServerAtCapacity, refused.Verdict);
    }

    [Fact]
    public void LoopbackIsNeverThrottled()
    {
        // The admin CLI, the control panel and the security check all come from here. Throttling them
        // would take the tools for diagnosing an attack offline during one.
        using var governor = DefenseTestFactory.CreateGovernor(new DdosOptions
        {
            MaxConcurrentPerIp = 1,
            MaxNewConnectionsPerIpPerMinute = 1,
        });

        for (int i = 0; i < 50; i++)
            Assert.True(governor.TryAdmit(IPAddress.Loopback).Admitted);
    }

    [Fact]
    public void WhenDisabled_NothingIsEverRefused()
    {
        using var governor = DefenseTestFactory.CreateGovernor(new DdosOptions
        {
            Enabled = false,
            MaxConcurrentPerIp = 1,
            MaxConcurrentTotal = 1,
        });

        for (int i = 0; i < 20; i++)
            Assert.True(governor.TryAdmit(Ip("203.0.113.30")).Admitted);
    }

    [Fact]
    public void DefensiveMode_TightensTheLimitsOnceTheAcceptRateSpikes()
    {
        using var governor = DefenseTestFactory.CreateGovernor(new DdosOptions
        {
            AcceptsPerSecondBeforeDefensiveMode = 10,
            UnderAttackTightening = 0.5,
            MaxConcurrentPerIp = 8,
            MaxConcurrentPerSubnet = 1000,
            MaxConcurrentTotal = 1000,
            MaxNewConnectionsPerIpPerMinute = 1000,
            MaxNewConnectionsPerSubnetPerMinute = 10000,
        });

        Assert.False(governor.DefensiveMode);

        // Spread across many addresses so only the global accept rate — not a per-address limit — is
        // what trips the mode.
        for (int i = 0; i < 12; i++)
            governor.TryAdmit(Ip($"198.51.{i}.7"));

        Assert.True(governor.DefensiveMode);

        // 8 * 0.5 = 4, so the fifth concurrent connection from one address is now refused where eight
        // would have been fine a moment ago.
        var address = Ip("203.0.113.40");
        for (int i = 0; i < 4; i++)
            Assert.True(governor.TryAdmit(address).Admitted);

        Assert.False(governor.TryAdmit(address).Admitted);
    }

    [Theory]
    [InlineData("192.0.2.55", "192.0.2.0/24")]
    [InlineData("10.1.2.3", "10.1.2.0/24")]
    [InlineData("2001:db8:abcd:1234::1", "20010DB8ABCD1234::/64")]
    public void SubnetKey_GroupsByTheSmallestNormallyAllocatedBlock(string address, string expected) =>
        Assert.Equal(expected, ConnectionGovernor.SubnetKey(IPAddress.Parse(address)));

    [Fact]
    public void SubnetKey_TreatsTwoAddressesInOneIpv6Allocation_AsOne()
    {
        // A single household is routinely handed a /64, so per-address limits are meaningless for
        // IPv6 — a bot with one prefix has more addresses than it could ever need.
        Assert.Equal(
            ConnectionGovernor.SubnetKey(IPAddress.Parse("2001:db8:1:2::abcd")),
            ConnectionGovernor.SubnetKey(IPAddress.Parse("2001:db8:1:2:ffff:ffff:ffff:ffff")));
    }
}
