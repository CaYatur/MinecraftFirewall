using System.Collections.Concurrent;
using System.Net;

namespace MinecraftFirewall.Proxy.Anomaly;

/// <summary>What the model is allowed to do about a connection that did not fit the baseline.</summary>
public enum AnomalyAction
{
    /// <summary>Write it down. The default, and the only one that cannot be wrong.</summary>
    Report,

    /// <summary>Feed it into the bot score, so it counts alongside the behavioural signals rather than
    /// deciding anything by itself. The mildest thing that is more than a log line, and the one most
    /// likely to be right: a statistical oddity plus a metronomic reconnect pattern is a much stronger
    /// claim than either alone.</summary>
    Score,

    /// <summary>Ask the address to prove itself again on its next connection, even from an address it
    /// has used before. Costs a returning player one password; costs an intruder the password they do
    /// not have.</summary>
    RequireReauthentication,

    /// <summary>Tighten the connection limits for that address, so whatever it was doing gets less
    /// room without anyone being refused outright.</summary>
    Throttle,

    /// <summary>A real firewall ban, for the configured duration.</summary>
    Ban,
}

/// <summary>One address's recent anomaly history and what has been decided about it.</summary>
public sealed record AnomalyRecord(int Count, DateTimeOffset FirstSeen, DateTimeOffset LastSeen, double WorstScore);

/// <summary>
/// Decides what, if anything, to do about an address whose sessions keep not fitting.
///
/// Kept separate from the detector because they answer different questions and one of them is far
/// harder. Whether a session resembles the others is arithmetic. Whether that means something should
/// happen to the player is a judgement involving how often it has happened, how long the model has
/// been running, and how much the admin trusts it — and it is the half where a mistake is visible to
/// somebody trying to play.
///
/// Three things keep it proportionate. Nothing happens on a single odd session, because sessions are
/// odd for innocent reasons all the time. Nothing happens at all until the model has been settled for
/// a while, because a freshly-trained baseline is at its least reliable exactly when it is newest.
/// And the actions are ordered so the admin picks how far they are willing to go, with the default
/// being no further than a log line.
/// </summary>
public sealed class AnomalyResponder(AnomalyOptions options, ILogger logger)
{
    private readonly ConcurrentDictionary<IPAddress, AnomalyRecord> _history = new();
    private readonly ConcurrentDictionary<IPAddress, DateTimeOffset> _reauthRequired = new();
    private readonly ConcurrentDictionary<IPAddress, DateTimeOffset> _throttled = new();

    private DateTimeOffset? _modelReadyAt;

    /// <summary>Called when the model first produces a usable baseline. Starts the settling clock.</summary>
    public void NoteModelReady(DateTimeOffset now) => _modelReadyAt ??= now;

    /// <summary>
    /// Records an anomalous session and returns the action to take, or <see cref="AnomalyAction.Report"/>
    /// when nothing more is warranted yet.
    /// </summary>
    public AnomalyAction Decide(IPAddress address, double score, DateTimeOffset now)
    {
        AnomalyRecord record = _history.AddOrUpdate(
            address,
            _ => new AnomalyRecord(1, now, now, score),
            (_, previous) => now - previous.LastSeen > options.AnomalyMemory
                ? new AnomalyRecord(1, now, now, score)
                : new AnomalyRecord(previous.Count + 1, previous.FirstSeen, now, Math.Max(previous.WorstScore, score)));

        if (options.Action == AnomalyAction.Report)
            return AnomalyAction.Report;

        // A baseline is at its least trustworthy the moment it is first built, which is also the moment
        // it is most tempting to act on. Waiting lets the picture of "normal" fill out before anything
        // it says costs a player anything.
        if (_modelReadyAt is not { } readyAt || now - readyAt < options.SettlingPeriod)
        {
            logger.LogDebug("Anomaly from {Ip} noted but not acted on — the model is still settling.", address);
            return AnomalyAction.Report;
        }

        if (record.Count < options.RepeatedAnomaliesBeforeAction)
            return AnomalyAction.Report;

        return options.Action;
    }

    /// <summary>Marks an address as needing to authenticate again on its next connection.</summary>
    public void RequireReauthentication(IPAddress address, DateTimeOffset now) =>
        _reauthRequired[address] = now + options.ActionDuration;

    /// <summary>
    /// True when this address owes a fresh authentication, clearing the requirement as it answers.
    ///
    /// Single-use on purpose: the point is to make the *next* connection prove itself, not to put the
    /// address into a state it has to be rescued from. If it is still behaving oddly, it will be asked
    /// again.
    /// </summary>
    public bool ConsumeReauthenticationRequirement(IPAddress address, DateTimeOffset now)
    {
        if (!_reauthRequired.TryRemove(address, out DateTimeOffset until))
            return false;

        return until > now;
    }

    public void Throttle(IPAddress address, DateTimeOffset now) =>
        _throttled[address] = now + options.ActionDuration;

    /// <summary>True while this address is under tightened connection limits.</summary>
    public bool IsThrottled(IPAddress address, DateTimeOffset now)
    {
        if (!_throttled.TryGetValue(address, out DateTimeOffset until))
            return false;

        if (until > now)
            return true;

        _throttled.TryRemove(address, out _);
        return false;
    }

    public IReadOnlyList<(IPAddress Address, AnomalyRecord Record)> Snapshot() =>
        [.. _history.Select(pair => (pair.Key, pair.Value)).OrderByDescending(x => x.Value.LastSeen)];

    public int ThrottledCount => _throttled.Count;

    public int AwaitingReauthentication => _reauthRequired.Count;

    /// <summary>Drops addresses whose anomalies have aged out. Called on the same timer as the retrain,
    /// so nothing accumulates on a server that has been running for months.</summary>
    public void Prune(DateTimeOffset now)
    {
        foreach ((IPAddress address, AnomalyRecord record) in _history)
        {
            if (now - record.LastSeen > options.AnomalyMemory)
                _history.TryRemove(address, out _);
        }

        foreach ((IPAddress address, DateTimeOffset until) in _throttled)
        {
            if (until <= now)
                _throttled.TryRemove(address, out _);
        }

        foreach ((IPAddress address, DateTimeOffset until) in _reauthRequired)
        {
            if (until <= now)
                _reauthRequired.TryRemove(address, out _);
        }
    }
}
