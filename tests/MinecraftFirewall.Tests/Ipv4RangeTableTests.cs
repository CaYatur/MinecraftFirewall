using System.Net;
using MinecraftFirewall.Proxy.IpIntel;

namespace MinecraftFirewall.Tests;

public class Ipv4RangeTableTests
{
    [Fact]
    public void Contains_MatchesAddressInsideCidr()
    {
        var table = Ipv4RangeTable.Parse(["203.0.113.0/24"]);

        Assert.True(table.Contains(IPAddress.Parse("203.0.113.55")));
        Assert.False(table.Contains(IPAddress.Parse("203.0.114.1")));
    }

    [Fact]
    public void Contains_MatchesSingleAddressWithoutPrefix()
    {
        var table = Ipv4RangeTable.Parse(["198.51.100.7"]);

        Assert.True(table.Contains(IPAddress.Parse("198.51.100.7")));
        Assert.False(table.Contains(IPAddress.Parse("198.51.100.8")));
    }

    [Fact]
    public void Parse_SkipsCommentsAndBlankLines()
    {
        var table = Ipv4RangeTable.Parse(
        [
            "# this is a comment",
            "",
            "  ",
            "203.0.113.0/24",
        ]);

        Assert.Equal(1, table.RangeCount);
    }

    [Fact]
    public void Parse_SkipsMalformedLinesWithoutThrowing()
    {
        var table = Ipv4RangeTable.Parse(
        [
            "not-an-ip/24",
            "2001:db8::/32", // IPv6 — not supported, must be skipped, not crash the whole refresh
            "203.0.113.0/24",
        ]);

        Assert.Equal(1, table.RangeCount);
        Assert.True(table.Contains(IPAddress.Parse("203.0.113.1")));
    }

    [Fact]
    public void Parse_MergesOverlappingAndAdjacentRanges()
    {
        var table = Ipv4RangeTable.Parse(
        [
            "10.0.0.0/24",   // 10.0.0.0   - 10.0.0.255
            "10.0.1.0/24",   // 10.0.1.0   - 10.0.1.255 (adjacent to the above)
            "10.0.0.128/25", // fully inside the first range
        ]);

        Assert.Equal(1, table.RangeCount);
        Assert.True(table.Contains(IPAddress.Parse("10.0.0.0")));
        Assert.True(table.Contains(IPAddress.Parse("10.0.1.255")));
        Assert.False(table.Contains(IPAddress.Parse("10.0.2.0")));
    }

    [Fact]
    public void Contains_Ipv6Address_NeverMatches()
    {
        var table = Ipv4RangeTable.Parse(["0.0.0.0/0"]);

        Assert.False(table.Contains(IPAddress.Parse("::1")));
    }

    [Fact]
    public void Empty_ContainsNothing()
    {
        Assert.False(Ipv4RangeTable.Empty.Contains(IPAddress.Parse("1.2.3.4")));
    }

    [Fact]
    public void Contains_BoundaryAddresses_AreInclusive()
    {
        var table = Ipv4RangeTable.Parse(["192.168.1.0/24"]);

        Assert.True(table.Contains(IPAddress.Parse("192.168.1.0")));
        Assert.True(table.Contains(IPAddress.Parse("192.168.1.255")));
        Assert.False(table.Contains(IPAddress.Parse("192.168.2.0")));
    }
}
