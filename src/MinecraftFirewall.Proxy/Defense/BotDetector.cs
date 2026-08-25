using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Defense;

/// <summary>One signal that fired, with what it contributed and why — kept together so a refusal can
/// always be explained rather than just asserted.</summary>
public readonly record struct BotSignal(string Name, int Weight, string Detail);

public sealed record BotAssessment(int Score, IReadOnlyList<BotSignal> Signals, bool ShouldDeny, bool ShouldReport)
{
    public static readonly BotAssessment Clean = new(0, [], false, false);

    public string Explain() => Signals.Count == 0
        ? "no bot signals"
        : string.Join("; ", Signals.Select(s => $"{s.Name} (+{s.Weight}): {s.Detail}"));
}

/// <summary>
/// Scores how much a connection behaves like software rather than a person.
///
/// The signals are deliberately about *behaviour over time from an address*, not about the contents of
/// a single packet. Anything visible in one packet can be copied from a real client in an afternoon;
/// what is much harder to fake is the shape of a real player's session — pinging the server list
/// before joining, using one name, and reconnecting at irregular human intervals. A bot author can
/// defeat any one of these, but each countermeasure costs them something, and the point of scoring
/// rather than gating is that they have to defeat all of them at once.
///
/// State is per address and bounded: a fixed number of remembered usernames and connection times each,
/// pruned on a timer. A detector whose memory grows with the size of the attack would be a liability.
/// </summary>
public sealed class BotDetector : IDisposable
{
    private const int MaxRememberedUsernames = 24;
    private const int MaxRememberedConnections = 16;

    private readonly BotDefenseOptions _options;
    private readonly ThreatIntelligence _threatIntelligence;
    private readonly ConcurrentDictionary<IPAddress, ClientHistory> _histories = new();
    private readonly Timer _pruneTimer;

    public BotDetector(IOptions<BotDefenseOptions> options, ThreatIntelligence threatIntelligence)
    {
        _options = options.Value;
        _threatIntelligence = threatIntelligence;
        _pruneTimer = new Timer(_ => Prune(), null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
    }

    /// <summary>Records that this address asked for the server list. Called for every status ping,
    /// including ones the rate limiter goes on to refuse — the fact that a ping was attempted is what
    /// matters here, not whether it was served.</summary>
    public void RecordStatusPing(IPAddress address, DateTimeOffset now) =>
        History(address).LastStatusPing = now;

    /// <summary>Records a handshake that ended without a login — the shape of a scanner sweeping
    /// ports, as distinct from a player whose client pings and then joins.</summary>
    public void RecordHandshakeWithoutLogin(IPAddress address) =>
        History(address).AbandonedHandshakes++;

    /// <summary>
    /// Records that this address connected claiming a hostname the profile does not serve.
    ///
    /// The connection itself was already refused where that happened — this is about what the
    /// refusal leaves behind. An address that keeps announcing domains this server does not serve is
    /// enumerating, and only a record that outlives the connection can show that.
    ///
    /// Two things this deliberately does not count, both found by reading a real server's log rather
    /// than by testing.
    ///
    /// Connecting by raw IP is not announcing a foreign domain. It is what happens when somebody is
    /// given the address instead of the name — most often the administrator, testing their own
    /// server. Counting it meant the owner's every connection carried a bot signal for something they
    /// had done to themselves.
    ///
    /// And the count is now a window rather than a tally. It only ever went up, so once an address had
    /// been refused a few times, every later connection from it — including every successful,
    /// entirely legitimate one — scored the full weight forever, with no way back short of a
    /// service restart.
    /// </summary>
    public void RecordHostnameMismatch(IPAddress address, HostnameMismatchKind kind)
    {
        if (kind != HostnameMismatchKind.ForeignDomain)
            return;

        History(address).RecordHostnameMismatch(DateTimeOffset.UtcNow, _options.HostnameMismatchMemory);
    }

    /// <summary>
    /// Records that the anomaly model has repeatedly flagged this address, so it counts towards the
    /// bot score on later connections.
    ///
    /// This is the mildest way for a statistical judgement to have any effect at all, and the one most
    /// likely to be right: "unlike the other connections" is weak evidence on its own, but combined
    /// with a metronomic reconnect pattern or a run of usernames it is a much stronger claim than
    /// either part. It never refuses anyone by itself — the weight is deliberately below the threshold.
    /// </summary>
    public void RecordAnomaly(IPAddress address, int weight) =>
        History(address).AnomalyWeight = weight;

    /// <summary>
    /// What is currently held against an address, without treating the question as a connection.
    ///
    /// Assess both scores and records — it notes the connection, the username and the cadence,
    /// because that is what it is for. The control panel asks this several times a minute on a poll
    /// timer, and asking through Assess would mean the panel being open was itself evidence of a bot.
    ///
    /// Returns only the signals that survive without a connection to hang them on: what is remembered
    /// about the address, rather than what this particular moment looks like.
    /// </summary>
    public IReadOnlyList<BotSignal> Explain(IPAddress address)
    {
        if (!_options.Enabled || IPAddress.IsLoopback(address) || !_histories.TryGetValue(address, out ClientHistory? history))
            return [];

        DateTimeOffset now = DateTimeOffset.UtcNow;
        var signals = new List<BotSignal>(4);

        int mismatches = history.RecentHostnameMismatches(now, _options.HostnameMismatchMemory);
        if (mismatches > 0)
        {
            signals.Add(new BotSignal("hostname-mismatch", _options.WeightHostnameMismatch,
                $"{mismatches} connection(s) in the last {Describe(_options.HostnameMismatchMemory)} announced a domain this server does not serve"));
        }

        if (history.AbandonedHandshakes >= 3)
        {
            signals.Add(new BotSignal("scanner-behaviour", _options.WeightScannerBehaviour,
                $"{history.AbandonedHandshakes} handshakes from this address ended without a login"));
        }

        if (history.CadenceCoefficientOfVariation(_options.CadenceSamples) is { } cv && cv < _options.MechanicalCadenceThreshold)
        {
            signals.Add(new BotSignal("mechanical-cadence", _options.WeightMechanicalCadence,
                $"reconnect intervals vary by only {cv:P0} — too even for a person"));
        }

        if (history.AnomalyWeight > 0)
        {
            signals.Add(new BotSignal("anomaly-history", history.AnomalyWeight,
                "the anomaly model has repeatedly flagged connections from this address"));
        }

        if (_threatIntelligence.Action == ThreatListAction.Score && _threatIntelligence.IsOnImportedList(address))
        {
            signals.Add(new BotSignal("on-threat-list", _threatIntelligence.ScoreWeight,
                "this address appears on an imported public threat list"));
        }

        return signals;
    }

    public BotAssessment Assess(IPAddress address, string username, int protocolVersion, bool protocolKnown, DateTimeOffset now)
    {
        if (!_options.Enabled || IPAddress.IsLoopback(address))
            return BotAssessment.Clean;

        ClientHistory history = History(address);
        var signals = new List<BotSignal>(4);

        history.RecordConnection(now);
        int distinctNames = history.RecordUsername(username);

        if (history.LastStatusPing is not { } ping || now - ping > _options.PingMemory)
        {
            signals.Add(new BotSignal("no-recent-ping", _options.WeightNoRecentPing,
                "logged in without asking for the server list first"));
        }

        if (distinctNames > _options.DistinctUsernamesBeforeSuspicion)
        {
            signals.Add(new BotSignal("many-usernames", _options.WeightManyUsernames,
                $"{distinctNames} different usernames from this address in {Describe(_options.UsernameMemory)}"));
        }

        if (history.CadenceCoefficientOfVariation(_options.CadenceSamples) is { } cv && cv < _options.MechanicalCadenceThreshold)
        {
            signals.Add(new BotSignal("mechanical-cadence", _options.WeightMechanicalCadence,
                $"reconnect intervals vary by only {cv:P0} — too even for a person"));
        }

        if (UsernameShape.LooksGenerated(username))
        {
            signals.Add(new BotSignal("generated-username", _options.WeightGeneratedUsername,
                $"'{Trim(username)}' has the shape of a generated name"));
        }

        int mismatches = history.RecentHostnameMismatches(now, _options.HostnameMismatchMemory);
        if (mismatches > 0)
        {
            signals.Add(new BotSignal("hostname-mismatch", _options.WeightHostnameMismatch,
                $"{mismatches} connection(s) from this address in the last {Describe(_options.HostnameMismatchMemory)} " +
                "announced a domain this server does not serve"));
        }

        // Second-hand evidence, so it is only allowed to contribute to a score — never to be the
        // whole reason. See ThreatIntelOptions for why the default stops short of blocking.
        if (_threatIntelligence.Action == ThreatListAction.Score && _threatIntelligence.IsOnImportedList(address))
        {
            signals.Add(new BotSignal("on-threat-list", _threatIntelligence.ScoreWeight,
                "this address appears on an imported public threat list"));
        }

        if (history.AnomalyWeight > 0)
        {
            signals.Add(new BotSignal("anomalous-sessions", history.AnomalyWeight,
                "earlier sessions from this address did not resemble this server's usual traffic"));
        }

        if (history.AbandonedHandshakes >= 3)
        {
            signals.Add(new BotSignal("scanner-behaviour", _options.WeightScannerBehaviour,
                $"{history.AbandonedHandshakes} handshakes from this address ended without a login"));
        }

        if (!protocolKnown && !IsPlausibleProtocol(protocolVersion))
        {
            signals.Add(new BotSignal("implausible-protocol", _options.WeightImplausibleProtocol,
                $"claimed protocol version {protocolVersion}"));
        }

        int score = signals.Sum(s => s.Weight);

        return new BotAssessment(
            score,
            signals,
            ShouldDeny: _options.Action == BotAction.Deny && score >= _options.DenyScore,
            ShouldReport: score >= _options.ReportScore);
    }

    /// <summary>
    /// Whether a protocol version is one a real Minecraft client could plausibly be sending.
    ///
    /// Version numbers are checked as a range rather than a list because the list would be wrong
    /// within weeks: every Minecraft release adds one, and a firewall that rejects clients newer than
    /// itself is worse than one that lets an odd number through. The lower bound is 1.7's netty
    /// rewrite, the first version this proxy could speak to at all; the upper bound is far enough
    /// ahead to outlast this software.
    /// </summary>
    private static bool IsPlausibleProtocol(int version) => version is >= 4 and <= 2000;

    private ClientHistory History(IPAddress address) => _histories.GetOrAdd(address, static _ => new ClientHistory());

    private static string Describe(TimeSpan span) =>
        span.TotalMinutes >= 1 ? $"{span.TotalMinutes:0} minutes" : $"{span.TotalSeconds:0} seconds";

    private static string Trim(string value) => value.Length <= 32 ? value : value[..32] + "…";

    private void Prune()
    {
        DateTimeOffset cutoff = DateTimeOffset.UtcNow - _options.UsernameMemory - TimeSpan.FromMinutes(5);
        foreach ((IPAddress address, ClientHistory history) in _histories)
        {
            if (history.LastActivity < cutoff)
                _histories.TryRemove(address, out _);
        }
    }

    public void Dispose() => _pruneTimer.Dispose();

    /// <summary>Per-address memory. Every collection here has a hard cap, so the cost of tracking an
    /// attacker never scales with how hard they try.</summary>
    private sealed class ClientHistory
    {
        private readonly Lock _gate = new();
        private readonly Dictionary<string, DateTimeOffset> _usernames = new(StringComparer.OrdinalIgnoreCase);
        private readonly Queue<DateTimeOffset> _connections = new();

        public DateTimeOffset? LastStatusPing { get; set; }
        public int AbandonedHandshakes { get; set; }
        private readonly Queue<DateTimeOffset> _hostnameMismatches = new();
        public int AnomalyWeight { get; set; }
        public DateTimeOffset LastActivity { get; private set; } = DateTimeOffset.UtcNow;

        public void RecordConnection(DateTimeOffset now)
        {
            lock (_gate)
            {
                LastActivity = now;
                _connections.Enqueue(now);
                while (_connections.Count > MaxRememberedConnections)
                    _connections.Dequeue();
            }
        }

        public void RecordHostnameMismatch(DateTimeOffset now, TimeSpan memory)
        {
            lock (_gate)
            {
                LastActivity = now;
                _hostnameMismatches.Enqueue(now);
                Trim(now, memory);
            }
        }

        /// <summary>How many mismatches are still inside the memory window. A window rather than a
        /// tally so an address can stop being suspicious by stopping.</summary>
        public int RecentHostnameMismatches(DateTimeOffset now, TimeSpan memory)
        {
            lock (_gate)
            {
                Trim(now, memory);
                return _hostnameMismatches.Count;
            }
        }

        private void Trim(DateTimeOffset now, TimeSpan memory)
        {
            while (_hostnameMismatches.Count > 0 && now - _hostnameMismatches.Peek() > memory)
                _hostnameMismatches.Dequeue();

            while (_hostnameMismatches.Count > MaxRememberedConnections)
                _hostnameMismatches.Dequeue();
        }

        /// <summary>Adds a username and returns how many distinct ones are still inside the memory
        /// window. Returns the live count rather than the total ever seen, so an address that used
        /// several names last week is not held against it forever.</summary>
        public int RecordUsername(string username)
        {
            lock (_gate)
            {
                DateTimeOffset now = DateTimeOffset.UtcNow;
                _usernames[username] = now;

                if (_usernames.Count > MaxRememberedUsernames)
                {
                    string oldest = _usernames.MinBy(pair => pair.Value).Key;
                    _usernames.Remove(oldest);
                }

                return _usernames.Count;
            }
        }

        /// <summary>
        /// How evenly spaced this address's reconnects are, as a coefficient of variation (standard
        /// deviation over mean). Null until there are enough samples to mean anything.
        ///
        /// Coefficient of variation rather than raw variance because it is scale-free: a bot looping
        /// every 2 seconds and one looping every 5 minutes are equally mechanical, and only a
        /// scale-free measure says so.
        /// </summary>
        public double? CadenceCoefficientOfVariation(int minimumSamples)
        {
            lock (_gate)
            {
                if (_connections.Count < minimumSamples)
                    return null;

                DateTimeOffset[] times = [.. _connections];
                double[] gaps = new double[times.Length - 1];
                for (int i = 1; i < times.Length; i++)
                    gaps[i - 1] = (times[i] - times[i - 1]).TotalSeconds;

                double mean = gaps.Average();
                if (mean <= 0.001)
                    return null; // simultaneous connections are a flood, which the governor handles

                double variance = gaps.Sum(g => (g - mean) * (g - mean)) / gaps.Length;
                return Math.Sqrt(variance) / mean;
            }
        }
    }
}
