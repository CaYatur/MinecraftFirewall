using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Anomaly;

/// <summary>
/// Learns what ordinary connections to *this* server look like, and reports the ones that do not fit.
///
/// Every other check in this firewall encodes a rule somebody wrote down: this many connections, that
/// packet size, this scheme in a chat message. Rules only catch what their author thought of. The
/// value of learning a baseline instead is that it needs no such foresight — a technique nobody has
/// seen before still has to produce network behaviour, and behaviour unlike everything else on the
/// server is what gets reported, whatever the technique was.
///
/// The honest limits, which are why this ships off and reports rather than blocks:
///
/// It learns from whatever traffic arrives. An attacker present throughout the learning window
/// becomes part of the baseline — the classic poisoning problem, and unavoidable for anything that
/// trains on live data. Three things narrow it: only connections that ended cleanly and never earned a
/// strike are learned from, a minimum sample count is required before any score is produced, and the
/// model is rebuilt from a rolling window rather than accumulating forever.
///
/// It says "unlike the others", not "malicious". A server whose players are all in one country will
/// score a visitor from elsewhere as unusual, correctly and uselessly. Only a person looking at the
/// report can supply that judgement, which is exactly why it produces a report.
/// </summary>
public sealed class AnomalyDetector : IDisposable
{
    private readonly AnomalyOptions _options;
    private readonly ILogger<AnomalyDetector> _logger;
    private readonly ConcurrentQueue<double[]> _baseline = new();
    private readonly Timer _retrainTimer;

    private volatile IsolationForest? _forest;
    private double _cutoff = 1.0;
    private long _scored;
    private long _flagged;

    public AnomalyDetector(IOptions<AnomalyOptions> options, ILogger<AnomalyDetector> logger)
    {
        _options = options.Value;
        _logger = logger;
        _retrainTimer = new Timer(_ => Retrain(), null, _options.RetrainInterval, _options.RetrainInterval);
    }

    public bool Enabled => _options.Enabled;

    public bool IsTrained => _forest is not null;

    public int BaselineSize => _baseline.Count;

    public long TotalScored => Interlocked.Read(ref _scored);

    public long TotalFlagged => Interlocked.Read(ref _flagged);

    /// <summary>The score above which a connection is reported, calibrated from this server's own
    /// baseline at the last retrain.</summary>
    public double Cutoff => Volatile.Read(ref _cutoff);

    /// <summary>
    /// Adds a finished connection to the baseline.
    ///
    /// <paramref name="wasClean"/> is the poisoning defence, such as it is: only connections that
    /// completed without earning a strike are learned from. It does not make the baseline safe — an
    /// attacker whose connections look clean still teaches the model — but it does stop the obvious
    /// case where a flood being actively refused becomes the definition of normal.
    /// </summary>
    public void Observe(ConnectionFeatures features, bool wasClean)
    {
        if (!_options.Enabled || !wasClean)
            return;

        _baseline.Enqueue(features.ToVector());

        // A rolling window rather than an ever-growing history: a server's traffic changes as it grows,
        // and a baseline that still remembers last year would call this month unusual.
        while (_baseline.Count > _options.BaselineWindow)
            _baseline.TryDequeue(out _);
    }

    /// <summary>
    /// Scores a connection, or returns null when there is nothing to compare it against yet.
    ///
    /// Returning null rather than a neutral score is deliberate. A caller that received 0.5 while the
    /// model was untrained would have no way to tell "this looks ordinary" from "no opinion", and the
    /// difference matters when the answer is going in front of a person.
    /// </summary>
    public AnomalyVerdict? Score(IPAddress address, ConnectionFeatures features)
    {
        IsolationForest? forest = _forest;
        if (!_options.Enabled || forest is null)
            return null;

        double score = forest.Score(features.ToVector());
        Interlocked.Increment(ref _scored);

        bool unusual = score >= Volatile.Read(ref _cutoff);
        if (unusual)
            Interlocked.Increment(ref _flagged);

        return new AnomalyVerdict(score, unusual, features.Describe());
    }

    /// <summary>Rebuilds the model from the current window. Runs on a timer rather than per
    /// connection: training is the expensive half, and a baseline that shifts between two consecutive
    /// connections would make scores incomparable.</summary>
    public void Retrain()
    {
        if (!_options.Enabled)
            return;

        try
        {
            double[][] samples = [.. _baseline];
            if (samples.Length < _options.MinimumSamplesBeforeScoring)
            {
                _logger.LogDebug("Anomaly detection is still learning: {Count} of {Needed} connections observed.",
                    samples.Length, _options.MinimumSamplesBeforeScoring);
                return;
            }

            bool first = _forest is null;
            IsolationForest forest = IsolationForest.Train(samples, _options.Trees, _options.SubsampleSize);

            // Calibrate against the baseline the model was just built from: score every sample, sort,
            // and take the requested percentile. This is what makes the threshold mean the same thing
            // on every server instead of depending on how tightly that server's traffic happens to
            // cluster.
            double[] baselineScores = [.. samples.Select(forest.Score).Order()];
            int index = Math.Clamp((int)(baselineScores.Length * _options.AnomalyPercentile), 0, baselineScores.Length - 1);

            Volatile.Write(ref _cutoff, baselineScores[index]);
            _forest = forest;

            if (first)
            {
                _logger.LogInformation(
                    "Anomaly detection has learned a baseline from {Count} connections and is now scoring " +
                    "(reporting above {Cutoff:0.000}). It reports only — it never refuses anyone.",
                    samples.Length, baselineScores[index]);
            }
        }
        catch (Exception ex)
        {
            // An optional, report-only extra must never be a reason the firewall stops working.
            _logger.LogWarning(ex, "Could not rebuild the anomaly model. Scoring continues with the previous one.");
        }
    }

    public void Dispose() => _retrainTimer.Dispose();
}

public readonly record struct AnomalyVerdict(double Score, bool Unusual, string Description);
