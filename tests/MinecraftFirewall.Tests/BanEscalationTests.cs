using System.Net;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Repeat offenders serve longer each time.
///
/// A flat ban is not a deterrent to anything automated — it is a schedule. A bot that comes back every
/// evening pays the same price every evening and never runs out of evenings. Doubling turns "keep
/// trying" into a strategy that costs more each time, while leaving the case that actually matters
/// untouched: a player who trips a limit once, and again months later, never reaches the interesting
/// part of the curve.
/// </summary>
public class BanEscalationTests
{
    private static readonly IPAddress Offender = IPAddress.Parse("203.0.113.200");

    private sealed record Fixture(FirewallBanService Service, FakeWindowsFirewallGateway Gateway) : IDisposable
    {
        public void Dispose() => Service.Dispose();
    }

    private static Fixture Create(Action<FirewallBanOptions>? tweak = null)
    {
        var options = new FirewallBanOptions
        {
            DefaultBanDuration = TimeSpan.FromHours(6),
            MaxBanDuration = TimeSpan.FromDays(30),
            RepeatOffenceMemory = TimeSpan.FromDays(14),
        };
        tweak?.Invoke(options);

        var gateway = new FakeWindowsFirewallGateway();
        var service = new FirewallBanService(Options.Create(options),
            new NeverBanList(Options.Create(new NeverBanOptions())),
            gateway, new RecordingAlertSender(), NullLogger<FirewallBanService>.Instance);

        return new Fixture(service, gateway);
    }

    /// <summary>The remaining time on the address's rule, which is what the escalation actually
    /// controls.</summary>
    private static TimeSpan RemainingBan(Fixture fixture, IPAddress address) =>
        fixture.Gateway.ExpiryFor(address)!.Value - DateTimeOffset.UtcNow;

    [Fact]
    public void AFirstBanIsExactlyTheConfiguredDefault()
    {
        // A server that never sees a repeat offender should behave as though this feature did not
        // exist.
        using Fixture fixture = Create();

        fixture.Service.Ban(Offender, "first");

        Assert.InRange(RemainingBan(fixture, Offender), TimeSpan.FromHours(5.9), TimeSpan.FromHours(6.1));
    }

    [Fact]
    public void EachLaterBanLastsTwiceAsLong()
    {
        using Fixture fixture = Create();

        double[] expectedHours = [6, 12, 24, 48, 96];
        foreach (double hours in expectedHours)
        {
            fixture.Service.Ban(Offender, "again");
            // Expiry has to be re-read each time: the ban is re-issued rather than accumulated.
            Assert.InRange(RemainingBan(fixture, Offender),
                TimeSpan.FromHours(hours * 0.98), TimeSpan.FromHours(hours * 1.02));

            // Expiring on its own must not forgive — remembering is the whole point.
            fixture.Service.Unban(Offender, forgetHistory: false);
        }
    }

    [Fact]
    public void EscalationStopsAtTheCap()
    {
        // Addresses get reassigned. Today's persistent attacker is somebody's home connection next
        // year, and a ban measured in decades would outlive any connection between the two.
        using Fixture fixture = Create(o => o.MaxBanDuration = TimeSpan.FromDays(2));

        for (int i = 0; i < 30; i++)
        {
            fixture.Service.Ban(Offender, "persistent");
            fixture.Service.Unban(Offender, forgetHistory: false);
        }

        fixture.Service.Ban(Offender, "persistent");
        Assert.InRange(RemainingBan(fixture, Offender), TimeSpan.FromDays(1.9), TimeSpan.FromDays(2.1));
    }

    [Fact]
    public void AnAdminUnbanningByHand_ClearsTheHistory()
    {
        // An admin lifting a ban is saying it was wrong. Carrying the offence forward would start the
        // next one halfway up a curve it should never have been on.
        using Fixture fixture = Create();

        fixture.Service.Ban(Offender, "mistake");
        fixture.Service.Unban(Offender);

        fixture.Service.Ban(Offender, "unrelated, later");
        Assert.InRange(RemainingBan(fixture, Offender), TimeSpan.FromHours(5.9), TimeSpan.FromHours(6.1));
    }

    [Fact]
    public void AnExplicitDurationIsRespectedRatherThanEscalated()
    {
        // The crawler ban asks for a month deliberately. A caller that chose a duration has already
        // made the judgement this would otherwise be making for them.
        using Fixture fixture = Create();

        fixture.Service.Ban(Offender, "first");
        fixture.Service.Unban(Offender, forgetHistory: false);
        fixture.Service.Ban(Offender, "crawler", TimeSpan.FromDays(30));

        Assert.InRange(RemainingBan(fixture, Offender), TimeSpan.FromDays(29.9), TimeSpan.FromDays(30.1));
    }

    [Fact]
    public void AnExplicitDurationStillCountsTowardsTheNextEscalation()
    {
        // It happened, so it counts — a crawler banned explicitly and later banned for something else
        // should carry that history.
        using Fixture fixture = Create();

        fixture.Service.Ban(Offender, "crawler", TimeSpan.FromMinutes(1));
        fixture.Service.Unban(Offender, forgetHistory: false);

        fixture.Service.Ban(Offender, "something else");
        Assert.InRange(RemainingBan(fixture, Offender), TimeSpan.FromHours(11.8), TimeSpan.FromHours(12.2));
    }

    [Fact]
    public void WithEscalationOff_EveryBanIsTheDefault()
    {
        using Fixture fixture = Create(o => o.EscalateRepeatOffenders = false);

        for (int i = 0; i < 5; i++)
        {
            fixture.Service.Ban(Offender, "again");
            Assert.InRange(RemainingBan(fixture, Offender), TimeSpan.FromHours(5.9), TimeSpan.FromHours(6.1));
            fixture.Service.Unban(Offender, forgetHistory: false);
        }
    }

    [Fact]
    public void AddressesEscalateIndependently()
    {
        using Fixture fixture = Create();
        var other = IPAddress.Parse("203.0.113.201");

        for (int i = 0; i < 3; i++)
        {
            fixture.Service.Ban(Offender, "again");
            fixture.Service.Unban(Offender, forgetHistory: false);
        }

        fixture.Service.Ban(other, "first time for this one");
        Assert.InRange(RemainingBan(fixture, other), TimeSpan.FromHours(5.9), TimeSpan.FromHours(6.1));
    }

    [Fact]
    public void TheAllowlistStillWinsOverEverything()
    {
        // Escalation must not become a way around the guarantee the whole project rests on: loopback
        // and the local network are never banned, however many times something trips a limit.
        using Fixture fixture = Create();

        for (int i = 0; i < 10; i++)
            Assert.Equal(BanResult.RefusedNeverBan, fixture.Service.Ban(IPAddress.Loopback, "repeatedly"));

        Assert.Empty(fixture.Gateway.RuledAddresses);
    }
}
