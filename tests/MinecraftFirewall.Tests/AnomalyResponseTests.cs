using System.Net;
using MinecraftFirewall.Proxy.Anomaly;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;

namespace MinecraftFirewall.Tests;

/// <summary>
/// What a repeated anomaly is allowed to cause.
///
/// This is the half of the model that can be unfair. Deciding whether a session resembles the others
/// is arithmetic; deciding that something should therefore happen to a player is a judgement, and it
/// is the one somebody notices when it is wrong. Everything here is about keeping that judgement
/// proportionate: nothing on a single odd session, nothing at all while the baseline is new, and
/// nothing beyond what the admin actually asked for.
/// </summary>
public class AnomalyResponseTests
{
    private static readonly IPAddress Player = IPAddress.Parse("203.0.113.120");

    private static AnomalyResponder Create(AnomalyAction action, Action<AnomalyOptions>? tweak = null)
    {
        var options = new AnomalyOptions
        {
            Enabled = true,
            Action = action,
            RepeatedAnomaliesBeforeAction = 3,
            SettlingPeriod = TimeSpan.FromHours(1),
            AnomalyMemory = TimeSpan.FromHours(6),
            ActionDuration = TimeSpan.FromHours(6),
        };
        tweak?.Invoke(options);

        return new AnomalyResponder(options, NullLogger.Instance);
    }

    /// <summary>A responder whose model has been ready long enough to act.</summary>
    private static (AnomalyResponder Responder, DateTimeOffset Now) Settled(AnomalyAction action, Action<AnomalyOptions>? tweak = null)
    {
        AnomalyResponder responder = Create(action, tweak);
        DateTimeOffset start = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        responder.NoteModelReady(start);

        return (responder, start.AddHours(2));
    }

    [Fact]
    public void WithTheDefaultAction_NothingEverHappens()
    {
        // The shipped setting. However often an address is flagged, the answer stays "write it down".
        (AnomalyResponder responder, DateTimeOffset now) = Settled(AnomalyAction.Report);

        for (int i = 0; i < 20; i++)
            Assert.Equal(AnomalyAction.Report, responder.Decide(Player, 0.9, now.AddMinutes(i)));
    }

    [Fact]
    public void OneOddSessionIsNeverEnough()
    {
        // Sessions are odd for innocent reasons constantly — a short visit, a bad connection, someone
        // idling in a menu. Acting on one would make a firewall that punishes unusual play.
        (AnomalyResponder responder, DateTimeOffset now) = Settled(AnomalyAction.Ban);

        Assert.Equal(AnomalyAction.Report, responder.Decide(Player, 0.9, now));
        Assert.Equal(AnomalyAction.Report, responder.Decide(Player, 0.9, now.AddMinutes(1)));
    }

    [Fact]
    public void ThePatternIsWhatActs()
    {
        (AnomalyResponder responder, DateTimeOffset now) = Settled(AnomalyAction.Ban);

        responder.Decide(Player, 0.9, now);
        responder.Decide(Player, 0.9, now.AddMinutes(1));

        Assert.Equal(AnomalyAction.Ban, responder.Decide(Player, 0.9, now.AddMinutes(2)));
    }

    [Fact]
    public void NothingHappensWhileTheModelIsStillSettling()
    {
        // A freshly trained baseline has seen whoever happened to be online while it was learning and
        // nobody else. It is least reliable exactly when it is newest, which is also when it is most
        // tempting to trust.
        AnomalyResponder responder = Create(AnomalyAction.Ban);
        DateTimeOffset start = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        responder.NoteModelReady(start);

        for (int i = 0; i < 10; i++)
            Assert.Equal(AnomalyAction.Report, responder.Decide(Player, 0.95, start.AddMinutes(i)));

        // Past the settling period, the same pattern does act.
        DateTimeOffset later = start.AddHours(2);
        responder.Decide(Player, 0.95, later);
        responder.Decide(Player, 0.95, later.AddMinutes(1));
        Assert.Equal(AnomalyAction.Ban, responder.Decide(Player, 0.95, later.AddMinutes(2)));
    }

    [Fact]
    public void NothingHappensIfTheModelWasNeverReady()
    {
        // Belt and braces: a responder that has never been told the model trained must not act on the
        // strength of anomalies it could not have computed.
        AnomalyResponder responder = Create(AnomalyAction.Ban);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        for (int i = 0; i < 10; i++)
            Assert.Equal(AnomalyAction.Report, responder.Decide(Player, 0.95, now.AddMinutes(i)));
    }

    [Fact]
    public void AnomaliesSpacedFurtherApartThanTheMemory_DoNotAccumulate()
    {
        (AnomalyResponder responder, DateTimeOffset now) = Settled(AnomalyAction.Ban, o => o.AnomalyMemory = TimeSpan.FromMinutes(30));

        responder.Decide(Player, 0.9, now);
        responder.Decide(Player, 0.9, now.AddHours(3));

        Assert.Equal(AnomalyAction.Report, responder.Decide(Player, 0.9, now.AddHours(6)));
    }

    [Fact]
    public void AddressesAreJudgedIndependently()
    {
        (AnomalyResponder responder, DateTimeOffset now) = Settled(AnomalyAction.Ban);
        var other = IPAddress.Parse("203.0.113.121");

        responder.Decide(Player, 0.9, now);
        responder.Decide(Player, 0.9, now.AddMinutes(1));

        Assert.Equal(AnomalyAction.Report, responder.Decide(other, 0.9, now.AddMinutes(2)));
    }

    [Fact]
    public void AReauthenticationRequirementIsSingleUse()
    {
        // The point is to make the *next* connection prove itself, not to put an address into a state
        // somebody has to be rescued from. If it is still behaving oddly, it gets asked again.
        (AnomalyResponder responder, DateTimeOffset now) = Settled(AnomalyAction.RequireReauthentication);

        responder.RequireReauthentication(Player, now);

        Assert.True(responder.ConsumeReauthenticationRequirement(Player, now.AddMinutes(1)));
        Assert.False(responder.ConsumeReauthenticationRequirement(Player, now.AddMinutes(2)));
    }

    [Fact]
    public void AnExpiredReauthenticationRequirementDoesNotFire()
    {
        (AnomalyResponder responder, DateTimeOffset now) = Settled(AnomalyAction.RequireReauthentication,
            o => o.ActionDuration = TimeSpan.FromMinutes(5));

        responder.RequireReauthentication(Player, now);

        Assert.False(responder.ConsumeReauthenticationRequirement(Player, now.AddHours(1)));
    }

    [Fact]
    public void AThrottleExpiresOnItsOwn()
    {
        (AnomalyResponder responder, DateTimeOffset now) = Settled(AnomalyAction.Throttle,
            o => o.ActionDuration = TimeSpan.FromMinutes(30));

        responder.Throttle(Player, now);

        Assert.True(responder.IsThrottled(Player, now.AddMinutes(10)));
        Assert.False(responder.IsThrottled(Player, now.AddHours(2)));
    }

    [Fact]
    public void AThrottledAddressGetsLessRoomFromTheGovernor()
    {
        // The action means nothing unless something honours it. This is the wiring, end to end.
        using ConnectionGovernor governor = DefenseTestFactory.CreateGovernor(new DdosOptions
        {
            MaxConcurrentPerIp = 8,
            UnderAttackTightening = 0.25,
        });

        (AnomalyResponder responder, DateTimeOffset now) = Settled(AnomalyAction.Throttle);
        governor.IsAddressThrottled = address => responder.IsThrottled(address, now);

        // Untouched, the address gets its full allowance.
        var ordinary = IPAddress.Parse("203.0.113.130");
        for (int i = 0; i < 8; i++)
            Assert.True(governor.TryAdmit(ordinary).Admitted);

        responder.Throttle(Player, now);

        // Flagged, it gets a quarter of it.
        for (int i = 0; i < 2; i++)
            Assert.True(governor.TryAdmit(Player).Admitted);

        Assert.False(governor.TryAdmit(Player).Admitted);
    }

    [Fact]
    public void PruningDropsWhatHasAgedOut()
    {
        (AnomalyResponder responder, DateTimeOffset now) = Settled(AnomalyAction.Throttle,
            o => o.ActionDuration = TimeSpan.FromMinutes(5));

        responder.Throttle(Player, now);
        responder.RequireReauthentication(Player, now);
        responder.Decide(Player, 0.9, now);

        Assert.Equal(1, responder.ThrottledCount);
        Assert.Equal(1, responder.AwaitingReauthentication);

        responder.Prune(now.AddDays(1));

        Assert.Equal(0, responder.ThrottledCount);
        Assert.Equal(0, responder.AwaitingReauthentication);
        Assert.Empty(responder.Snapshot());
    }

    [Fact]
    public void TheSnapshotKeepsTheWorstScoreSeen()
    {
        // A number somebody has to interpret, so the history keeps the strongest evidence rather than
        // the most recent.
        (AnomalyResponder responder, DateTimeOffset now) = Settled(AnomalyAction.Report);

        responder.Decide(Player, 0.72, now);
        responder.Decide(Player, 0.95, now.AddMinutes(1));
        responder.Decide(Player, 0.66, now.AddMinutes(2));

        (IPAddress address, AnomalyRecord record) = responder.Snapshot()[0];

        Assert.Equal(Player, address);
        Assert.Equal(3, record.Count);
        Assert.Equal(0.95, record.WorstScore, 3);
    }
}
