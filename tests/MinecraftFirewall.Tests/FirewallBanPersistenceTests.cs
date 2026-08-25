using System.Net;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace MinecraftFirewall.Tests;

/// <summary>
/// A service restart is simulated by constructing a second FirewallBanService over the SAME gateway —
/// exactly what happens in production, where the Windows Firewall keeps its rules across a restart.
/// The firewall is the only source of truth for ban state (no separate file to drift from it), so
/// these tests are really about whether the rules round-trip faithfully.
/// </summary>
public class FirewallBanPersistenceTests
{
    private static FirewallBanService CreateService(IWindowsFirewallGateway gateway, FirewallBanOptions? options = null, NeverBanOptions? neverBanOptions = null) =>
        new(Options.Create(options ?? new FirewallBanOptions()),
            new NeverBanList(Options.Create(neverBanOptions ?? new NeverBanOptions())),
            gateway,
            NullLogger<FirewallBanService>.Instance);

    [Fact]
    public void Restart_ReadoptsAnUnexpiredBan_SoItIsStillEnforcedAndStillCleanedUpLater()
    {
        // The original bug: a restart left the OS rule blocking but the service forgot its expiry, so
        // CleanupExpired could never lift it and the IP stayed blocked forever.
        var gateway = new FakeWindowsFirewallGateway();
        var ip = IPAddress.Parse("203.0.113.9");

        using (var before = CreateService(gateway))
            before.Ban(ip, "test reason", TimeSpan.FromHours(1));

        using var after = CreateService(gateway);

        Assert.True(after.IsBanned(ip));
        var adopted = Assert.Single(after.ListActiveBans());
        Assert.Equal(ip, adopted.Address);
        Assert.True(adopted.ExpiresAt > DateTimeOffset.UtcNow); // a real expiry, not "forever"
    }

    [Fact]
    public void Restart_PreservesTheOriginalExpiry_RatherThanRestartingTheClock()
    {
        var gateway = new FakeWindowsFirewallGateway();
        var ip = IPAddress.Parse("203.0.113.9");

        DateTimeOffset originalExpiry;
        using (var before = CreateService(gateway))
        {
            before.Ban(ip, "test reason", TimeSpan.FromHours(1));
            originalExpiry = before.ListActiveBans().Single().ExpiresAt;
        }

        using var after = CreateService(gateway);

        Assert.Equal(originalExpiry, after.ListActiveBans().Single().ExpiresAt);
    }

    [Fact]
    public void Restart_AnAlreadyExpiredRule_IsLiftedByTheNextCleanupRatherThanBlockingForever()
    {
        var gateway = new FakeWindowsFirewallGateway();
        var ip = IPAddress.Parse("203.0.113.9");

        using (var before = CreateService(gateway))
            before.Ban(ip, "test reason", TimeSpan.FromMilliseconds(-1)); // already expired

        using var after = CreateService(gateway);
        Assert.True(after.IsBanned(ip)); // adopted with its (past) expiry intact...

        after.CleanupExpiredNow();

        Assert.False(after.IsBanned(ip)); // ...and therefore actually cleaned up
        Assert.Empty(gateway.RuledAddresses);
    }

    [Fact]
    public void Restart_ARuleWithNoRecordedExpiry_GetsAFreshTtlSoItCannotBlockForever()
    {
        // Written by a build that predates expiries being stored in the rule description. Its real
        // lifetime is unknowable, so a bounded fresh TTL is the safe compromise: it briefly
        // over-blocks an IP something already judged hostile, but it definitely gets cleaned up.
        var gateway = new FakeWindowsFirewallGateway();
        var ip = IPAddress.Parse("203.0.113.9");
        gateway.SeedRuleWithoutExpiry(ip);

        var options = new FirewallBanOptions { DefaultBanDuration = TimeSpan.FromHours(2) };
        using var service = CreateService(gateway, options);

        Assert.True(service.IsBanned(ip));
        var adopted = service.ListActiveBans().Single();
        Assert.True(adopted.ExpiresAt > DateTimeOffset.UtcNow);
        Assert.True(adopted.ExpiresAt <= DateTimeOffset.UtcNow.AddHours(2).AddSeconds(5));
    }

    [Fact]
    public void Restart_DropsARuleForAnIpThatIsNowOnTheNeverBanList()
    {
        // The never-ban list can grow between runs — an admin adding their own IP after being locked
        // out is the obvious case. The current list must win over a rule written under the old one.
        var gateway = new FakeWindowsFirewallGateway();
        var ip = IPAddress.Parse("203.0.113.9");

        using (var before = CreateService(gateway))
            before.Ban(ip, "test reason", TimeSpan.FromHours(1));

        var neverBan = new NeverBanOptions { ExtraAllowlist = { "203.0.113.9/32" } };
        using var after = CreateService(gateway, neverBanOptions: neverBan);

        Assert.False(after.IsBanned(ip));
        Assert.Empty(gateway.RuledAddresses); // and the stale rule is actually removed
    }

    [Fact]
    public void ExtendingABan_UpdatesTheStoredExpiry_SoTheExtensionSurvivesARestart()
    {
        // Before this, extending only bumped the in-memory expiry; the rule still carried the old one,
        // so a restart silently reverted the extension and lifted the ban early.
        var gateway = new FakeWindowsFirewallGateway();
        var ip = IPAddress.Parse("203.0.113.9");

        using var service = CreateService(gateway);
        service.Ban(ip, "first", TimeSpan.FromMinutes(1));
        DateTimeOffset? shortExpiry = gateway.ExpiryFor(ip);

        var result = service.Ban(ip, "again", TimeSpan.FromHours(5));

        Assert.Equal(BanResult.AlreadyBanned, result);
        Assert.True(gateway.ExpiryFor(ip) > shortExpiry);

        using var afterRestart = CreateService(gateway);
        Assert.True(afterRestart.ListActiveBans().Single().ExpiresAt > DateTimeOffset.UtcNow.AddHours(4));
    }

    [Fact]
    public void Restart_WhenTheFirewallIsUnreachable_AdoptsNothingRatherThanThrowing()
    {
        // An unelevated service can't enumerate rules. Startup must still succeed — it already warns
        // about the missing elevation separately.
        var gateway = new UnreachableFirewallGateway();

        using var service = CreateService(gateway);

        Assert.Empty(service.ListActiveBans());
    }

    private sealed class UnreachableFirewallGateway : IWindowsFirewallGateway
    {
        public void AddOrUpdateBlockRule(IPAddress address, string reason, DateTimeOffset expiresAt) =>
            throw new InvalidOperationException("not elevated");

        public void RemoveBlockRule(IPAddress address) => throw new InvalidOperationException("not elevated");

        public IReadOnlyList<ManagedBlockRule> ListManagedBlockRules() => [];

        public bool CanAccessFirewall(out string? errorMessage)
        {
            errorMessage = "not elevated";
            return false;
        }
    }
}
