using System.Net;
using MinecraftFirewall.Proxy.Anomaly;
using MinecraftFirewall.Tests.TestDoubles;

namespace MinecraftFirewall.Tests;

public class IsolationForestTests
{
    /// <summary>A tight cluster with one point far outside it — the simplest case where the answer is
    /// not in dispute.</summary>
    private static List<double[]> Cluster(int count, double centre = 10.0)
    {
        var random = new Random(1);
        var samples = new List<double[]>(count);
        for (int i = 0; i < count; i++)
            samples.Add([centre + (random.NextDouble() * 0.5), centre + (random.NextDouble() * 0.5)]);

        return samples;
    }

    [Fact]
    public void APointFarOutsideTheCluster_ScoresHigherThanOneInsideIt()
    {
        IsolationForest forest = IsolationForest.Train(Cluster(400));

        double inside = forest.Score([10.2, 10.2]);
        double outside = forest.Score([90.0, 90.0]);

        Assert.True(outside > inside, $"outlier scored {outside:0.000}, ordinary point scored {inside:0.000}");
        Assert.True(outside > 0.6, $"an obvious outlier should score well above the ordinary range, got {outside:0.000}");
    }

    [Fact]
    public void OrdinaryPointsSitNearTheMiddleOfTheRange()
    {
        // The property the threshold depends on: if ordinary traffic scored 0.7, every connection would
        // be reported and the feature would be noise.
        IsolationForest forest = IsolationForest.Train(Cluster(400));

        // The absolute band is wide on purpose: what "ordinary" scores depends on how tightly the
        // data clusters, which is exactly why the detector calibrates a cut-off from its own baseline
        // rather than trusting a fixed number. What must hold is that ordinary points are well below
        // an obvious outlier, which the test above asserts directly.
        foreach (double[] point in Cluster(20))
            Assert.InRange(forest.Score(point), 0.20, 0.75);
    }

    [Fact]
    public void ScoresAreDeterministicForTheSameSeed()
    {
        // Two servers with the same traffic should reach the same conclusion, and a restart should not
        // silently change what counts as unusual.
        List<double[]> samples = Cluster(200);

        double first = IsolationForest.Train(samples, seed: 7).Score([50, 50]);
        double second = IsolationForest.Train(samples, seed: 7).Score([50, 50]);

        Assert.Equal(first, second, 10);
    }

    [Fact]
    public void TrainingOnNothingIsRejectedRatherThanProducingAModelWithNoOpinion() =>
        Assert.Throws<ArgumentException>(() => IsolationForest.Train([]));

    [Fact]
    public void AFeatureEveryoneAgreesOn_DoesNotBreakTraining()
    {
        // A constant column has no split point that separates anything. It must be skipped, not
        // divided by zero.
        var samples = new List<double[]>();
        for (int i = 0; i < 100; i++)
            samples.Add([i, 5.0]);

        IsolationForest forest = IsolationForest.Train(samples);

        Assert.InRange(forest.Score([50, 5.0]), 0.0, 1.0);
    }
}

public class AnomalyDetectorTests
{
    private static readonly IPAddress Player = IPAddress.Parse("203.0.113.90");

    private static ConnectionFeatures TypicalSession(double durationSeconds = 600, int packets = 12000) => new(
        DurationSeconds: durationSeconds,
        PacketsFromClient: packets,
        BytesFromClient: packets * 30L,
        PeakPacketsPerSecond: 22,
        DistinctPacketKinds: 9,
        SecondsToFirstPacket: 0.2,
        ChatMessages: 4,
        MovementPackets: (int)(packets * 0.8));

    [Fact]
    public void WhileDisabled_NothingIsLearnedAndNothingIsScored()
    {
        // The shipped default.
        using var detector = DefenseTestFactory.CreateAnomalyDetector();

        for (int i = 0; i < 500; i++)
            detector.Observe(TypicalSession(), wasClean: true);

        detector.Retrain();

        Assert.Equal(0, detector.BaselineSize);
        Assert.False(detector.IsTrained);
        Assert.Null(detector.Score(Player, TypicalSession()));
    }

    [Fact]
    public void BeforeEnoughSamples_ItSaysNothingRatherThanGuessing()
    {
        // Returning null rather than a neutral score matters: a caller handed 0.5 could not tell "this
        // looks ordinary" from "no opinion", and that difference decides whether a person is told.
        using var detector = DefenseTestFactory.CreateAnomalyDetector(new AnomalyOptions
        {
            Enabled = true,
            MinimumSamplesBeforeScoring = 300,
        });

        for (int i = 0; i < 50; i++)
            detector.Observe(TypicalSession(), wasClean: true);

        detector.Retrain();

        Assert.False(detector.IsTrained);
        Assert.Null(detector.Score(Player, TypicalSession()));
    }

    [Fact]
    public void ConnectionsThatEarnedAStrike_AreNeverLearnedFrom()
    {
        // The poisoning defence. A flood being actively refused must never become the definition of
        // normal, or the model would go on to report the first real player.
        using var detector = DefenseTestFactory.CreateAnomalyDetector(new AnomalyOptions { Enabled = true });

        for (int i = 0; i < 500; i++)
            detector.Observe(TypicalSession(durationSeconds: 0.4, packets: 5), wasClean: false);

        Assert.Equal(0, detector.BaselineSize);
    }

    [Fact]
    public void ASessionUnlikeEveryOtherOne_IsReported()
    {
        using var detector = DefenseTestFactory.CreateAnomalyDetector(new AnomalyOptions
        {
            Enabled = true,
            MinimumSamplesBeforeScoring = 200,
        });

        var random = new Random(3);
        for (int i = 0; i < 400; i++)
        {
            detector.Observe(TypicalSession(
                durationSeconds: 500 + (random.NextDouble() * 400),
                packets: 10000 + random.Next(4000)), wasClean: true);
        }

        detector.Retrain();
        Assert.True(detector.IsTrained);

        // A session that connected, blasted packets for a fraction of a second, and left.
        AnomalyVerdict? verdict = detector.Score(Player, new ConnectionFeatures(
            DurationSeconds: 0.3,
            PacketsFromClient: 900,
            BytesFromClient: 4_000_000,
            PeakPacketsPerSecond: 3000,
            DistinctPacketKinds: 1,
            SecondsToFirstPacket: 0.001,
            ChatMessages: 0,
            MovementPackets: 0));

        Assert.NotNull(verdict);
        Assert.True(verdict!.Value.Unusual, $"scored {verdict.Value.Score:0.000}, expected it to be flagged");
    }

    [Fact]
    public void AnOrdinarySession_IsNotReported()
    {
        // The half that decides whether anyone keeps the feature switched on.
        using var detector = DefenseTestFactory.CreateAnomalyDetector(new AnomalyOptions
        {
            Enabled = true,
            MinimumSamplesBeforeScoring = 200,
        });

        var random = new Random(4);
        for (int i = 0; i < 400; i++)
        {
            detector.Observe(TypicalSession(
                durationSeconds: 500 + (random.NextDouble() * 400),
                packets: 10000 + random.Next(4000)), wasClean: true);
        }

        detector.Retrain();

        AnomalyVerdict? verdict = detector.Score(Player, TypicalSession(durationSeconds: 700, packets: 12500));

        Assert.NotNull(verdict);
        Assert.False(verdict!.Value.Unusual, $"an ordinary session scored {verdict.Value.Score:0.000}");
    }

    [Fact]
    public void TheBaselineIsARollingWindow()
    {
        // A server's traffic changes as it grows, and a baseline that still remembered last year would
        // call this month unusual.
        using var detector = DefenseTestFactory.CreateAnomalyDetector(new AnomalyOptions
        {
            Enabled = true,
            BaselineWindow = 100,
        });

        for (int i = 0; i < 500; i++)
            detector.Observe(TypicalSession(), wasClean: true);

        Assert.Equal(100, detector.BaselineSize);
    }

    [Fact]
    public void TheVerdictExplainsItselfRatherThanJustScoring()
    {
        // A number with no explanation attached gets ignored, and this one is only ever read by a
        // person deciding whether it means anything.
        using var detector = DefenseTestFactory.CreateAnomalyDetector(new AnomalyOptions
        {
            Enabled = true,
            MinimumSamplesBeforeScoring = 50,
        });

        for (int i = 0; i < 100; i++)
            detector.Observe(TypicalSession(), wasClean: true);

        detector.Retrain();

        AnomalyVerdict verdict = detector.Score(Player, TypicalSession())!.Value;

        Assert.Contains("packets", verdict.Description, StringComparison.Ordinal);
        Assert.Contains("pkt/s", verdict.Description, StringComparison.Ordinal);
    }
}
