using System.Buffers.Binary;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Inspection;

namespace MinecraftFirewall.Tests;

public class MovementAnalyzerTests
{
    /// <summary>Protocol 774's move_player_pos: three big-endian doubles then a flags byte.</summary>
    private static byte[] Position(double x, double y, double z)
    {
        var fields = new byte[25];
        BinaryPrimitives.WriteDoubleBigEndian(fields.AsSpan(0, 8), x);
        BinaryPrimitives.WriteDoubleBigEndian(fields.AsSpan(8, 8), y);
        BinaryPrimitives.WriteDoubleBigEndian(fields.AsSpan(16, 8), z);
        return fields;
    }

    private static InspectionOptions Options(Action<InspectionOptions>? tweak = null)
    {
        var options = new InspectionOptions();
        tweak?.Invoke(options);
        return options;
    }

    [Theory]
    [InlineData(double.NaN, 64, 0)]
    [InlineData(0, double.NaN, 0)]
    [InlineData(0, 64, double.NaN)]
    [InlineData(double.PositiveInfinity, 64, 0)]
    [InlineData(0, double.NegativeInfinity, 0)]
    public void CoordinatesThatAreNotNumbers_AreRefusedOutright(double x, double y, double z)
    {
        // Not a cheat and not a judgement call — a long-standing way to upset a server's physics and
        // chunk maths, and something no client produces by playing. This is the one movement check
        // that enforces by default.
        var analyzer = new MovementAnalyzer(Options());

        MovementFinding finding = analyzer.Inspect(Position(x, y, z), DateTimeOffset.UtcNow);

        Assert.Equal(MovementSeverity.Invalid, finding.Severity);
    }

    [Fact]
    public void CoordinatesBeyondTheWorldLimit_AreRefused()
    {
        var analyzer = new MovementAnalyzer(Options());

        MovementFinding finding = analyzer.Inspect(Position(4e7, 64, 0), DateTimeOffset.UtcNow);

        Assert.Equal(MovementSeverity.Invalid, finding.Severity);
    }

    [Fact]
    public void APlayerWalkingAround_IsNeverFlagged()
    {
        var analyzer = new MovementAnalyzer(Options());
        DateTimeOffset now = DateTimeOffset.UtcNow;

        // Twenty updates a second at sprinting speed, which is what a real client sends.
        for (int tick = 0; tick < 60; tick++)
        {
            MovementFinding finding = analyzer.Inspect(
                Position(tick * 0.28, 64, 0),
                now.AddMilliseconds(tick * 50));

            Assert.Equal(MovementSeverity.None, finding.Severity);
        }
    }

    [Fact]
    public void SustainedImpossibleSpeed_IsReportedButOnlyAfterARunOfIt()
    {
        var analyzer = new MovementAnalyzer(Options(o => o.MovementAnomaliesBeforeReport = 4));
        DateTimeOffset now = DateTimeOffset.UtcNow;

        int firstReportedAtTick = -1;
        for (int tick = 0; tick < 8; tick++)
        {
            MovementSeverity severity = analyzer.Inspect(Position(tick * 20.0, 64, 0), now.AddMilliseconds(tick * 50)).Severity;

            if (severity == MovementSeverity.Suspicious && firstReportedAtTick < 0)
                firstReportedAtTick = tick;
        }

        // Tick 0 only establishes a starting position — there is nothing to measure against yet — so
        // the fourth consecutive anomalous *measurement* is the one at tick 4. Nothing may be reported
        // before then: a single reading is a teleport or a lag spike far more often than it is a cheat.
        Assert.Equal(4, firstReportedAtTick);
        Assert.Equal(1, analyzer.TotalAnomalies);
    }

    [Fact]
    public void OneIsolatedJump_DoesNotAccumulateTowardsAReport()
    {
        // A plugin teleport, or a boat, between ordinary steps. The counter has to reset, or a long
        // session would eventually report any player at all.
        var analyzer = new MovementAnalyzer(Options(o => o.MovementAnomaliesBeforeReport = 3));
        DateTimeOffset now = DateTimeOffset.UtcNow;

        double x = 0;
        for (int tick = 0; tick < 30; tick++)
        {
            x += tick % 6 == 0 ? 40.0 : 0.2;
            MovementFinding finding = analyzer.Inspect(Position(x, 64, 0), now.AddMilliseconds(tick * 50));
            Assert.Equal(MovementSeverity.None, finding.Severity);
        }
    }

    [Fact]
    public void ALagSpike_IsNotReadAsASpeedMeasurement()
    {
        // Two seconds of silence then a normal-sized step would look like teleportation if the gap
        // were divided into it. It is skipped instead.
        var analyzer = new MovementAnalyzer(Options(o => o.MovementAnomaliesBeforeReport = 1));
        DateTimeOffset now = DateTimeOffset.UtcNow;

        analyzer.Inspect(Position(0, 64, 0), now);
        MovementFinding finding = analyzer.Inspect(Position(200, 64, 0), now.AddSeconds(10));

        Assert.Equal(MovementSeverity.None, finding.Severity);
    }

    [Fact]
    public void APacketWhoseLayoutDoesNotMatch_IsLeftAloneRatherThanGuessedAt()
    {
        // Reading a field at the wrong offset would mean interpreting someone's rotation as their
        // position. The cost of that guess would be paid by every legitimate player at once.
        var analyzer = new MovementAnalyzer(Options());

        for (int i = 0; i < 10; i++)
            Assert.Equal(MovementSeverity.None, analyzer.Inspect(new byte[9], DateTimeOffset.UtcNow).Severity);

        Assert.True(analyzer.LayoutUnrecognised);
    }

    [Fact]
    public void WhenAnalysisIsOff_ImpossibleCoordinatesAreStillRefused()
    {
        // The two settings are independent on purpose: someone who turns off the speed heuristic
        // because of false positives must not lose crash-input blocking with it.
        var analyzer = new MovementAnalyzer(Options(o =>
        {
            o.AnalyseMovement = false;
            o.BlockImpossibleCoordinates = true;
        }));

        Assert.Equal(MovementSeverity.Invalid, analyzer.Inspect(Position(double.NaN, 64, 0), DateTimeOffset.UtcNow).Severity);
    }
}

public class PacketBudgetTests
{
    [Fact]
    public void TrafficWithinBudget_IsNeverCharged()
    {
        var budget = new PacketBudget(maxPacketsPerSecond: 100, maxBytesPerSecond: 100_000);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        for (int i = 0; i < 100; i++)
            Assert.Null(budget.Charge(200, now));
    }

    [Fact]
    public void TooManyPacketsInOneSecond_IsRefused()
    {
        var budget = new PacketBudget(maxPacketsPerSecond: 10, maxBytesPerSecond: 1_000_000);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        for (int i = 0; i < 10; i++)
            Assert.Null(budget.Charge(10, now));

        Assert.NotNull(budget.Charge(10, now));
    }

    [Fact]
    public void TooManyBytesInOneSecond_IsRefusedEvenAtALowPacketRate()
    {
        var budget = new PacketBudget(maxPacketsPerSecond: 1000, maxBytesPerSecond: 5_000);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        Assert.Null(budget.Charge(4_000, now));
        Assert.NotNull(budget.Charge(4_000, now));
    }

    [Fact]
    public void TheAllowanceRefillsWithTheNextSecond()
    {
        var budget = new PacketBudget(maxPacketsPerSecond: 5, maxBytesPerSecond: 1_000_000);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        for (int i = 0; i < 5; i++)
            budget.Charge(10, now);

        Assert.NotNull(budget.Charge(10, now));
        Assert.Null(budget.Charge(10, now.AddSeconds(1.1)));
    }
}

public class SlidingCounterTests
{
    [Fact]
    public void EventsInsideTheWindowAreCounted_AndOnesOutsideAreNot()
    {
        var counter = new SlidingCounter(TimeSpan.FromSeconds(10), capacity: 32);
        DateTimeOffset start = DateTimeOffset.UtcNow;

        for (int i = 0; i < 5; i++)
            counter.Record("a", start.AddSeconds(i));

        Assert.Equal(5, counter.Count("a", start.AddSeconds(5)));
        Assert.Equal(0, counter.Count("a", start.AddSeconds(60)));
    }

    [Fact]
    public void KeysAreIndependent()
    {
        var counter = new SlidingCounter(TimeSpan.FromSeconds(10), capacity: 8);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        counter.Record("a", now);
        counter.Record("a", now);
        counter.Record("b", now);

        Assert.Equal(2, counter.Count("a", now));
        Assert.Equal(1, counter.Count("b", now));
    }

    [Fact]
    public void MemoryPerKeyIsBounded_SoAFloodCannotGrowTheCounterItself()
    {
        // The property that matters under attack: recording ten thousand events for one key must not
        // allocate ten thousand anything. The ring saturates at its capacity instead.
        var counter = new SlidingCounter(TimeSpan.FromMinutes(1), capacity: 16);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        int last = 0;
        for (int i = 0; i < 10_000; i++)
            last = counter.Record("flood", now);

        Assert.Equal(16, last);
    }

    [Fact]
    public void PruneRemovesKeysWithNothingLeftInTheWindow()
    {
        var counter = new SlidingCounter(TimeSpan.FromSeconds(5), capacity: 8);
        DateTimeOffset start = DateTimeOffset.UtcNow;

        counter.Record("gone", start);
        counter.Record("here", start.AddMinutes(10));

        Assert.Equal(2, counter.TrackedKeys);
        Assert.Equal(1, counter.Prune(start.AddMinutes(10)));
        Assert.Equal(1, counter.TrackedKeys);
    }
}
