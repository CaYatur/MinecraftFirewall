using System.Net;
using MinecraftFirewall.Proxy.Identity;

namespace MinecraftFirewall.Tests;

public class IdentityEntryLearnIpTests
{
    [Fact]
    public void LearnIp_RecognizesTheLearnedAddress()
    {
        var entry = new IdentityEntry { Username = "Player1" };
        var ip = IPAddress.Parse("203.0.113.1");

        entry.LearnIp(ip, TimeSpan.FromDays(30), maxLearnedIps: 5);

        Assert.True(entry.IsIpRecognized(ip));
    }

    [Fact]
    public void LearnIp_DoesNotRecognizeADifferentAddress()
    {
        var entry = new IdentityEntry { Username = "Player1" };
        entry.LearnIp(IPAddress.Parse("203.0.113.1"), TimeSpan.FromDays(30), maxLearnedIps: 5);

        Assert.False(entry.IsIpRecognized(IPAddress.Parse("203.0.113.2")));
    }

    [Fact]
    public void LearnIp_ExceedingCap_EvictsOldestExpiringFirst()
    {
        var entry = new IdentityEntry { Username = "Player1" };
        var ip1 = IPAddress.Parse("203.0.113.1");
        var ip2 = IPAddress.Parse("203.0.113.2");
        var ip3 = IPAddress.Parse("203.0.113.3");

        entry.LearnIp(ip1, TimeSpan.FromDays(1), maxLearnedIps: 2);  // expires soonest
        entry.LearnIp(ip2, TimeSpan.FromDays(30), maxLearnedIps: 2);
        entry.LearnIp(ip3, TimeSpan.FromDays(30), maxLearnedIps: 2); // pushes count to 3, over the cap of 2

        Assert.False(entry.IsIpRecognized(ip1)); // evicted (soonest-expiring)
        Assert.True(entry.IsIpRecognized(ip2));
        Assert.True(entry.IsIpRecognized(ip3));
        Assert.Equal(2, entry.LearnedIps.Count);
    }

    [Fact]
    public void LearnIp_ReLearningSameAddress_RefreshesTtlWithoutDuplicating()
    {
        var entry = new IdentityEntry { Username = "Player1" };
        var ip = IPAddress.Parse("203.0.113.1");

        entry.LearnIp(ip, TimeSpan.FromSeconds(-1), maxLearnedIps: 5); // already-expired
        entry.LearnIp(ip, TimeSpan.FromDays(30), maxLearnedIps: 5);    // re-learn, fresh TTL

        Assert.True(entry.IsIpRecognized(ip));
        Assert.Single(entry.LearnedIps);
    }

    [Fact]
    public void LearnIp_AlreadyExpiredEntries_AreCleanedUpOnNextLearn()
    {
        var entry = new IdentityEntry { Username = "Player1" };
        entry.LearnIp(IPAddress.Parse("203.0.113.1"), TimeSpan.FromSeconds(-1), maxLearnedIps: 5);

        entry.LearnIp(IPAddress.Parse("203.0.113.2"), TimeSpan.FromDays(30), maxLearnedIps: 5);

        Assert.Single(entry.LearnedIps);
        Assert.Equal(IPAddress.Parse("203.0.113.2"), entry.LearnedIps[0].Address);
    }
}
