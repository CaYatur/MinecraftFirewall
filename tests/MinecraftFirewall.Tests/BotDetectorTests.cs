using System.Net;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Tests.TestDoubles;

namespace MinecraftFirewall.Tests;

public class BotDetectorTests
{
    private static readonly IPAddress Player = IPAddress.Parse("203.0.113.50");

    /// <summary>The shape of a real join: the client asks for the server list, then logs in.</summary>
    private static BotAssessment AssessNormalJoin(BotDetector detector, string username = "Steve", IPAddress? from = null)
    {
        IPAddress address = from ?? Player;
        DateTimeOffset now = DateTimeOffset.UtcNow;

        detector.RecordStatusPing(address, now);
        return detector.Assess(address, username, protocolVersion: 774, protocolKnown: true, now);
    }

    [Fact]
    public void AnOrdinaryPlayerJoining_ScoresNothingAtAll()
    {
        // The test that matters most. Everything else here is about catching bots; this one is about
        // not catching players, and it is the failure that would actually cost someone their server.
        using BotDetector detector = DefenseTestFactory.CreateBotDetector();

        BotAssessment assessment = AssessNormalJoin(detector);

        Assert.Equal(0, assessment.Score);
        Assert.False(assessment.ShouldDeny);
        Assert.False(assessment.ShouldReport);
        Assert.Empty(assessment.Signals);
    }

    [Fact]
    public void LoggingInWithoutEverAskingForTheServerList_IsNoticed()
    {
        using BotDetector detector = DefenseTestFactory.CreateBotDetector();

        BotAssessment assessment = detector.Assess(Player, "Steve", 774, true, DateTimeOffset.UtcNow);

        Assert.Contains(assessment.Signals, s => s.Name == "no-recent-ping");
    }

    [Fact]
    public void APingLongEnoughAgo_NoLongerCounts()
    {
        using BotDetector detector = DefenseTestFactory.CreateBotDetector(new BotDefenseOptions
        {
            PingMemory = TimeSpan.FromMinutes(10),
        });

        DateTimeOffset now = DateTimeOffset.UtcNow;
        detector.RecordStatusPing(Player, now - TimeSpan.FromMinutes(30));

        BotAssessment assessment = detector.Assess(Player, "Steve", 774, true, now);

        Assert.Contains(assessment.Signals, s => s.Name == "no-recent-ping");
    }

    [Fact]
    public void WorkingThroughAListOfUsernames_IsTheStrongestSignalThereIs()
    {
        using BotDetector detector = DefenseTestFactory.CreateBotDetector(new BotDefenseOptions
        {
            DistinctUsernamesBeforeSuspicion = 4,
        });

        BotAssessment last = BotAssessment.Clean;
        foreach (string name in new[] { "Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot" })
            last = AssessNormalJoin(detector, name);

        Assert.Contains(last.Signals, s => s.Name == "many-usernames");
    }

    [Fact]
    public void AFewNamesFromOneHousehold_IsNotSuspicious()
    {
        // Siblings behind one router. This must not fire, or the feature is unusable on a home
        // connection — which is most of the servers this is for.
        using BotDetector detector = DefenseTestFactory.CreateBotDetector();

        BotAssessment last = BotAssessment.Clean;
        foreach (string name in new[] { "Ayse", "Mehmet", "Zeynep" })
            last = AssessNormalJoin(detector, name);

        Assert.DoesNotContain(last.Signals, s => s.Name == "many-usernames");
    }

    [Fact]
    public void PerfectlyEvenReconnects_AreRecognisedAsALoop()
    {
        using BotDetector detector = DefenseTestFactory.CreateBotDetector(new BotDefenseOptions
        {
            CadenceSamples = 5,
            MechanicalCadenceThreshold = 0.12,
        });

        DateTimeOffset start = DateTimeOffset.UtcNow;
        detector.RecordStatusPing(Player, start);

        BotAssessment last = BotAssessment.Clean;
        for (int i = 0; i < 8; i++)
            last = detector.Assess(Player, "Steve", 774, true, start.AddSeconds(i * 5));

        Assert.Contains(last.Signals, s => s.Name == "mechanical-cadence");
    }

    [Fact]
    public void HumanReconnectTiming_IsNotMistakenForALoop()
    {
        using BotDetector detector = DefenseTestFactory.CreateBotDetector();

        DateTimeOffset start = DateTimeOffset.UtcNow;
        detector.RecordStatusPing(Player, start);

        // Gaps a person produces: they notice, they retry, they get distracted, they retry again.
        double[] gaps = [0, 4, 19, 23, 61, 70, 140];
        BotAssessment last = BotAssessment.Clean;
        foreach (double gap in gaps)
            last = detector.Assess(Player, "Steve", 774, true, start.AddSeconds(gap));

        Assert.DoesNotContain(last.Signals, s => s.Name == "mechanical-cadence");
    }

    [Fact]
    public void RepeatedHostnameMismatches_FollowTheAddressToItsNextConnection()
    {
        // The point of recording it: the refusal already happened on those earlier connections. What
        // survives is the pattern, which is what separates "someone shared the raw IP" from
        // "something is enumerating".
        using BotDetector detector = DefenseTestFactory.CreateBotDetector();

        detector.RecordHostnameMismatch(Player, HostnameMismatchKind.ForeignDomain);
        detector.RecordHostnameMismatch(Player, HostnameMismatchKind.ForeignDomain);

        BotAssessment assessment = AssessNormalJoin(detector);

        Assert.Contains(assessment.Signals, s => s.Name == "hostname-mismatch");
    }

    [Fact]
    public void WhatThePanelIsToldMatchesWhatTheLogPrints()
    {
        // Explain and Assess score the same address from the same history, and they are two pieces of
        // code. That is a drift waiting to happen — and it very nearly happened on the day Explain
        // was written, which reached for two option names that do not exist and had to have the real
        // threshold and weight copied across by hand.
        //
        // The invariant is containment, not equality: Explain reports what is *remembered* about an
        // address, while Assess adds what this particular connection looks like. So everything Explain
        // says must appear in Assess, with the same name and the same weight. If a threshold or a
        // weight is ever tuned in one and not the other, the Players page starts showing a different
        // number than the log prints and nobody finds out.
        using BotDetector detector = DefenseTestFactory.CreateBotDetector();

        for (int i = 0; i < 3; i++)
        {
            detector.RecordHostnameMismatch(Player, HostnameMismatchKind.ForeignDomain);
            detector.RecordHandshakeWithoutLogin(Player);
        }

        // Explained first: Assess deliberately records the connection it is scoring, and asking the
        // question must not change the answer.
        IReadOnlyList<BotSignal> explained = detector.Explain(Player);
        BotAssessment assessed = AssessNormalJoin(detector);

        Assert.NotEmpty(explained);

        foreach (BotSignal signal in explained)
        {
            BotSignal[] matches = [.. assessed.Signals.Where(s => s.Name == signal.Name)];
            Assert.True(matches.Length == 1,
                $"the Players page reports '{signal.Name}' but a real assessment produces {matches.Length} of them");

            Assert.True(matches[0].Weight == signal.Weight,
                $"'{signal.Name}' is worth {signal.Weight} on the Players page and {matches[0].Weight} in the log");
        }
    }

    [Fact]
    public void ConnectingByRawIpIsNotAHostnameMismatchAtAll()
    {
        // Found by reading a live server's log, not by testing. Somebody given the address instead of
        // the name sends that address in the hostname field — and the person that most often describes
        // is the administrator, testing their own server. Counting it meant the owner's every
        // connection carried a bot signal for something they had done to themselves.
        using BotDetector detector = DefenseTestFactory.CreateBotDetector();

        for (int i = 0; i < 5; i++)
            detector.RecordHostnameMismatch(Player, HostnameMismatchKind.DirectIpConnect);

        BotAssessment assessment = AssessNormalJoin(detector);

        Assert.DoesNotContain(assessment.Signals, s => s.Name == "hostname-mismatch");
    }

    [Fact]
    public void AnAddressStopsBeingSuspiciousByStopping()
    {
        // The other half of the same bug. The count only ever went up, so once an address had been
        // refused a few times, every later connection from it scored the full weight forever — with no
        // way back short of restarting the service.
        using BotDetector detector = DefenseTestFactory.CreateBotDetector(new BotDefenseOptions { HostnameMismatchMemory = TimeSpan.Zero });

        detector.RecordHostnameMismatch(Player, HostnameMismatchKind.ForeignDomain);
        detector.RecordHostnameMismatch(Player, HostnameMismatchKind.ForeignDomain);

        BotAssessment assessment = AssessNormalJoin(detector);

        Assert.DoesNotContain(assessment.Signals, s => s.Name == "hostname-mismatch");
    }

    [Fact]
    public void RepeatedAbandonedHandshakes_LookLikeAScan()
    {
        using BotDetector detector = DefenseTestFactory.CreateBotDetector();

        for (int i = 0; i < 3; i++)
            detector.RecordHandshakeWithoutLogin(Player);

        BotAssessment assessment = AssessNormalJoin(detector);

        Assert.Contains(assessment.Signals, s => s.Name == "scanner-behaviour");
    }

    [Fact]
    public void AnUnknownButPlausibleProtocolVersion_IsNotHeldAgainstAnyone()
    {
        // A client one release newer than this proxy. Refusing it would age this software badly, and
        // the packet-ID registry already handles not-knowing by declining to inspect.
        using BotDetector detector = DefenseTestFactory.CreateBotDetector();

        BotAssessment assessment = AssessNormalJoin(detector);
        detector.RecordStatusPing(Player, DateTimeOffset.UtcNow);
        BotAssessment newer = detector.Assess(Player, "Steve", protocolVersion: 999, protocolKnown: false, DateTimeOffset.UtcNow);

        Assert.DoesNotContain(newer.Signals, s => s.Name == "implausible-protocol");
        Assert.Equal(0, assessment.Score);
    }

    [Fact]
    public void ANonsenseProtocolVersion_IsNoticed()
    {
        using BotDetector detector = DefenseTestFactory.CreateBotDetector();
        detector.RecordStatusPing(Player, DateTimeOffset.UtcNow);

        BotAssessment assessment = detector.Assess(Player, "Steve", protocolVersion: 999_999, protocolKnown: false, DateTimeOffset.UtcNow);

        Assert.Contains(assessment.Signals, s => s.Name == "implausible-protocol");
    }

    [Fact]
    public void InLogOnlyMode_EvenAMaximumScoreLetsTheConnectionThrough()
    {
        // The shipped default. Nobody should discover what their own traffic scores by having players
        // refused.
        using BotDetector detector = DefenseTestFactory.CreateBotDetector(new BotDefenseOptions
        {
            Action = BotAction.LogOnly,
            DenyScore = 1,
        });

        BotAssessment assessment = detector.Assess(Player, "aaaaaaa", 999_999, false, DateTimeOffset.UtcNow);

        Assert.True(assessment.Score >= 1);
        Assert.False(assessment.ShouldDeny);
        Assert.True(assessment.ShouldReport);
    }

    [Fact]
    public void InDenyMode_ScoreAtTheThreshold_Denies()
    {
        using BotDetector detector = DefenseTestFactory.CreateBotDetector(new BotDefenseOptions
        {
            Action = BotAction.Deny,
            DenyScore = 30,
            WeightNoRecentPing = 30,
        });

        BotAssessment assessment = detector.Assess(Player, "Steve", 774, true, DateTimeOffset.UtcNow);

        Assert.True(assessment.ShouldDeny);
    }

    [Fact]
    public void LoopbackIsNeverScored()
    {
        using BotDetector detector = DefenseTestFactory.CreateBotDetector(new BotDefenseOptions { Action = BotAction.Deny, DenyScore = 1 });

        BotAssessment assessment = detector.Assess(IPAddress.Loopback, "zzzzzzz", 999_999, false, DateTimeOffset.UtcNow);

        Assert.Equal(0, assessment.Score);
        Assert.False(assessment.ShouldDeny);
    }

    [Fact]
    public void WhenDisabled_NothingIsAssessed()
    {
        using BotDetector detector = DefenseTestFactory.CreateBotDetector(new BotDefenseOptions { Enabled = false, Action = BotAction.Deny, DenyScore = 1 });

        Assert.Equal(0, detector.Assess(Player, "aaaaaa", 999_999, false, DateTimeOffset.UtcNow).Score);
    }

    [Fact]
    public void ExplainNamesEverySignalAndItsWeight()
    {
        // A refusal nobody can explain is a refusal nobody can argue with, which is how a false
        // positive becomes permanent.
        using BotDetector detector = DefenseTestFactory.CreateBotDetector();

        BotAssessment assessment = detector.Assess(Player, "aaaaaaa", 999_999, false, DateTimeOffset.UtcNow);
        string explanation = assessment.Explain();

        Assert.Contains("no-recent-ping", explanation, StringComparison.Ordinal);
        Assert.Contains("+", explanation, StringComparison.Ordinal);
    }
}
