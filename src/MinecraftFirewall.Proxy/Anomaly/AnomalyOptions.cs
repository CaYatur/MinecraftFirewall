namespace MinecraftFirewall.Proxy.Anomaly;

/// <summary>
/// Statistical anomaly detection over finished connections.
///
/// Off by default, and reporting-only with no setting to change that. Both are deliberate.
///
/// Off, because it learns from live traffic and therefore learns from whoever is connecting — an
/// attacker present during the learning window becomes part of the baseline. That is inherent to
/// training on production data and cannot be engineered away, only narrowed: only connections that
/// ended cleanly and never earned a strike are learned from, a minimum sample count is required before
/// any score is produced, and the model is rebuilt from a rolling window. Someone switching this on
/// should know that is the trade.
///
/// Reporting-only, because what it detects is "unlike the other connections to this server", which is
/// not the same claim as "malicious" and cannot be made into it. A server whose players are all in one
/// timezone will score an unusual-hours visitor as anomalous, correctly and unhelpfully. Only a person
/// can supply the missing judgement, so the output goes where a person will see it.
/// </summary>
public sealed class AnomalyOptions
{
    public const string SectionName = "AnomalyDetection";

    public bool Enabled { get; set; }

    /// <summary>
    /// What a repeated anomaly is allowed to cause, in increasing order of consequence:
    ///
    ///   Report                  write it down, and nothing else
    ///   Score                   count it towards the bot score, alongside the behavioural signals
    ///   RequireReauthentication ask the address to log in again next time, even from a known address
    ///   Throttle                tighten that address's connection limits for a while
    ///   Ban                     a real firewall ban for ActionDuration
    ///
    /// Report is the default and the only one that cannot be wrong. Everything above it acts on a
    /// statistical claim — "unlike this server's other connections" — which is not the same as
    /// "malicious" and never becomes it. Score is the natural second step: it lets an oddity tip a
    /// connection that was already behaving strangely without ever deciding anything on its own.
    /// </summary>
    public AnomalyAction Action { get; set; } = AnomalyAction.Report;

    /// <summary>
    /// Anomalous sessions from one address before anything happens.
    ///
    /// Sessions are odd for innocent reasons constantly — a short visit, a bad connection, someone
    /// idling in a menu. Acting on one would produce a firewall that punishes unusual play. A pattern
    /// is a different claim, and this is what makes it one.
    /// </summary>
    public int RepeatedAnomaliesBeforeAction { get; set; } = 3;

    /// <summary>How long anomalies keep counting towards that total, measured from the most recent.</summary>
    public TimeSpan AnomalyMemory { get; set; } = TimeSpan.FromHours(6);

    /// <summary>
    /// How long the model must have been trained before it is allowed to affect anyone.
    ///
    /// A freshly-built baseline is at its least reliable exactly when it is newest — it has seen
    /// whoever happened to be online while it was learning and nobody else. Waiting lets the picture of
    /// "normal" fill out before anything it says costs a player anything.
    /// </summary>
    public TimeSpan SettlingPeriod { get; set; } = TimeSpan.FromHours(1);

    /// <summary>How long a throttle, a re-authentication requirement or a ban lasts.</summary>
    public TimeSpan ActionDuration { get; set; } = TimeSpan.FromHours(6);

    /// <summary>Bot-score contribution when <see cref="Action"/> is Score. Deliberately below the
    /// refusal threshold on its own — it is meant to tip a decision, not make one.</summary>
    public int ScoreWeight { get; set; } = 40;

    /// <summary>
    /// Connections that must be observed before anything is scored.
    ///
    /// Not a performance figure — a poisoning defence. A model built from twenty connections during a
    /// flood would define the flood as normal and then report the first real player. A few hundred
    /// clean connections is enough for the baseline to be dominated by ordinary traffic on any server
    /// worth protecting.
    /// </summary>
    public int MinimumSamplesBeforeScoring { get; set; } = 300;

    /// <summary>How many recent clean connections the baseline holds. A rolling window rather than a
    /// growing history, because a server's traffic changes as it grows and a baseline that still
    /// remembers last year would call this month unusual.</summary>
    public int BaselineWindow { get; set; } = 5000;

    /// <summary>
    /// Which fraction of the server's own connections are treated as ordinary. At 0.99, only
    /// connections scoring above the most unusual 1% of the baseline are reported.
    ///
    /// A percentile rather than a raw score, because raw isolation-forest scores are not comparable
    /// between datasets. The textbook figure of "around 0.5 is normal" is only true for data shaped
    /// like the paper's examples; on a tight cluster of very similar sessions, every point — including
    /// perfectly ordinary ones — lands near 0.62. A fixed cut-off there would report every connection
    /// on one server and nothing at all on another. Measuring against the server's own distribution
    /// removes the guesswork entirely: the question becomes "unusual compared to what this server
    /// normally sees", which is the question worth asking anyway.
    /// </summary>
    public double AnomalyPercentile { get; set; } = 0.99;

    public int Trees { get; set; } = 64;

    /// <summary>Samples each tree is built from. Small on purpose, and counter-intuitively so: a large
    /// subsample lets clusters of near-duplicates conceal the anomalies among them. 256 is the figure
    /// the original paper settles on.</summary>
    public int SubsampleSize { get; set; } = 256;

    /// <summary>How often the model is rebuilt. Training is the expensive half, and a baseline that
    /// shifted between two consecutive connections would make their scores incomparable.</summary>
    public TimeSpan RetrainInterval { get; set; } = TimeSpan.FromMinutes(10);
}
