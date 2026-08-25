using System.Collections.Concurrent;
using System.Net;
using MinecraftFirewall.Proxy.Alerts;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Enforcement;

public enum BanResult
{
    Banned,
    AlreadyBanned,
    RefusedNeverBan,
    Failed,
}

/// <summary>
/// Ban state, TTL, and never-ban policy — the part of firewall enforcement worth unit testing.
/// Actual rule mutation is delegated to IWindowsFirewallGateway (see WindowsFirewallGateway for the
/// real, COM-backed implementation) so tests can inject a fake and never touch the real firewall.
/// A ban applies to every server profile at once, since it blocks the IP from the machine, not from
/// one port.
/// </summary>
public sealed class FirewallBanService : IDisposable
{
    /// <summary>How many times each address has been banned, and when it last was. Bounded by pruning
    /// alongside the expiry sweep — an attacker must not be able to grow this by attacking.</summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<IPAddress, OffenceRecord> _offences = new();

    private sealed record OffenceRecord(int Count, DateTimeOffset LastBannedAt);

    private static readonly TimeSpan NeverBanWarningInterval = TimeSpan.FromMinutes(1);

    private readonly System.Collections.Concurrent.ConcurrentDictionary<IPAddress, DateTimeOffset> _lastNeverBanWarning = new();

    private readonly FirewallBanOptions _options;
    private readonly NeverBanList _neverBanList;
    private readonly IWindowsFirewallGateway _gateway;
    private readonly ILogger<FirewallBanService> _logger;
    private readonly ConcurrentDictionary<IPAddress, DateTimeOffset> _activeBans = new();
    private readonly Timer _cleanupTimer;

    private readonly IAlertSender _alerts;

    public FirewallBanService(
        IOptions<FirewallBanOptions> options,
        NeverBanList neverBanList,
        IWindowsFirewallGateway gateway,
        IAlertSender alerts,
        ILogger<FirewallBanService> logger)
    {
        _options = options.Value;
        _neverBanList = neverBanList;
        _gateway = gateway;
        _alerts = alerts;
        _logger = logger;
        _cleanupTimer = new Timer(_ => CleanupExpired(), null, _options.CleanupInterval, _options.CleanupInterval);

        if (!_gateway.CanAccessFirewall(out string? probeError))
        {
            _logger.LogWarning(
                "Cannot access the Windows Firewall ({Error}). The service is probably not running with " +
                "Administrator rights. Bans will still be tracked and enforced in-process, but the OS-level " +
                "firewall rule that should block the IP machine-wide will not be created until this is fixed.",
                probeError);
        }

        AdoptExistingBans();
    }

    /// <summary>
    /// Rebuilds ban state from the firewall rules this app already owns, so a restart doesn't orphan
    /// them. Without this, a restart left the OS rule in place and blocking (no security regression)
    /// while the service forgot its expiry entirely — so CleanupExpired could never lift it, and the
    /// IP stayed blocked forever.
    ///
    /// The firewall is used as the source of truth rather than a separate state file on purpose:
    /// there is then only one place a ban can exist, so the two can't drift. An admin who deletes a
    /// rule by hand in wf.msc gets a service that agrees with them on the next start, and an admin
    /// reading the rules sees the expiry written in the description rather than needing this app to
    /// interpret it for them.
    /// </summary>
    private void AdoptExistingBans()
    {
        int adopted = 0, undated = 0;

        foreach (var rule in _gateway.ListManagedBlockRules())
        {
            if (_neverBanList.IsProtected(rule.Address))
            {
                // The never-ban list may have grown since the rule was created — honour the current
                // list, not the one that was in effect back then.
                _logger.LogWarning("Removing leftover firewall rule for {Ip}: it is now protected by the never-ban list.", rule.Address);
                Unban(rule.Address);
                continue;
            }

            if (rule.ExpiresAt is { } expiresAt)
            {
                _activeBans[rule.Address] = expiresAt;
                adopted++;
                continue;
            }

            // A rule from a build that didn't record expiries. Its intended lifetime is unknowable,
            // so give it a fresh default TTL: that errs toward briefly over-blocking an IP something
            // already judged hostile, and — unlike leaving it untracked — guarantees it eventually
            // gets cleaned up instead of blocking forever.
            _activeBans[rule.Address] = DateTimeOffset.UtcNow + _options.DefaultBanDuration;
            undated++;
        }

        if (adopted > 0 || undated > 0)
        {
            _logger.LogInformation(
                "Adopted {Adopted} existing firewall ban(s) from previous runs. {Undated} had no recorded expiry and were given a fresh {Ttl} TTL so they don't block forever.",
                adopted, undated, _options.DefaultBanDuration);
        }
    }

    public bool IsBanned(IPAddress address) => _activeBans.ContainsKey(address);

    /// <summary>One warning per address per minute. The dictionary is bounded by the never-ban list
    /// being small by construction — it holds loopback, the private ranges and whatever the admin
    /// added, so it cannot be grown by an attacker.</summary>
    private bool ShouldLogNeverBanRefusal(IPAddress address)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        if (_lastNeverBanWarning.TryGetValue(address, out DateTimeOffset last) && now - last < NeverBanWarningInterval)
            return false;

        _lastNeverBanWarning[address] = now;
        return true;
    }

    public BanResult Ban(IPAddress address, string reason, TimeSpan? duration = null)
    {
        if (_neverBanList.IsProtected(address))
        {
            // Throttled per address, because this is reached once per refused connection and the
            // connections being refused are, by definition, arriving unusually fast. An unthrottled
            // warning here turns a flood from one allowlisted address — a LAN machine gone haywire,
            // or an admin load-testing their own server — into thousands of log lines a second, and
            // then the disk is what fails rather than the thing being defended against.
            if (ShouldLogNeverBanRefusal(address))
            {
                _logger.LogWarning("Refused to ban {Ip} — protected by the never-ban list. Reason was: {Reason} " +
                                   "(further refusals for this address will be logged at most once a minute)", address, reason);
            }

            return BanResult.RefusedNeverBan;
        }

        // Recorded whether or not the duration was chosen by the caller: a crawler banned explicitly and
        // then later banned again for something else should carry that history. Only the *duration* is
        // left alone when a caller specified one, since that was already a deliberate judgement.
        int offence = RecordOffence(address, DateTimeOffset.UtcNow);
        var ttl = duration ?? EscalatedDuration(offence);
        var expiresAt = DateTimeOffset.UtcNow + ttl;
        bool alreadyBanned = _activeBans.ContainsKey(address);

        try
        {
            // Called for an extension too, not just a fresh ban: the rule's own description is what a
            // restart reads the expiry back from, so skipping this would quietly lose every extension
            // across a restart and lift the ban early.
            _gateway.AddOrUpdateBlockRule(address, reason, expiresAt);
        }
        catch (Exception ex)
        {
            // OS-level enforcement failed (commonly: not running elevated) — still record the ban
            // in-process so IsBanned() keeps denying this IP at the proxy layer. A silent no-op here
            // would mean a "banned" IP sails straight through every subsequent connection attempt.
            _activeBans[address] = expiresAt;
            _logger.LogError(ex, "Failed to create a Windows Firewall rule blocking {Ip}; falling back to in-process blocking only " +
                "(the service may not be running with Administrator rights).", address);
            return BanResult.Failed;
        }

        _activeBans[address] = expiresAt;

        if (alreadyBanned)
        {
            _logger.LogInformation("Extended ban for {Ip} to {ExpiresAt}. Reason: {Reason}", address, expiresAt, reason);
            return BanResult.AlreadyBanned;
        }

        _logger.LogWarning("Banned {Ip} until {ExpiresAt} ({Ttl}, offence {Offence}). Reason: {Reason}",
            address, expiresAt, Describe(ttl), offence, reason);
        _alerts.Send(AlertKind.Ban, $"🚫 **Banned `{AlertText.Field(address.ToString())}`** until `{expiresAt:u}`\n{AlertText.Field(reason)}");
        return BanResult.Banned;
    }

    /// <summary>
    /// Lifts a ban.
    ///
    /// <paramref name="forgetHistory"/> separates the two callers, which want opposite things. An
    /// admin unbanning by hand is saying the ban was wrong, so the offence count goes with it —
    /// otherwise the next ban would start halfway up the escalation curve for something that should
    /// never have counted. A ban expiring on its own is saying nothing of the kind: remembering that
    /// it happened is the entire point of escalation.
    /// </summary>
    public void Unban(IPAddress address, bool forgetHistory = true)
    {
        try
        {
            _gateway.RemoveBlockRule(address);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove the Windows Firewall rule blocking {Ip}.", address);
        }

        if (forgetHistory)
            _offences.TryRemove(address, out _);

        if (_activeBans.TryRemove(address, out _))
            _logger.LogInformation("Unbanned {Ip}.", address);
    }

    /// <summary>
    /// Records this ban against the address and returns which offence it is, counting only those
    /// inside the memory window.
    ///
    /// Held in memory, which means a service restart forgives everyone. That is a real limitation and
    /// a deliberate trade: the alternative is another file on disk holding a list of addresses and
    /// their sentences, and the escalation is a deterrent rather than a security boundary — nothing
    /// depends on it surviving. A server that restarts often enough for this to matter has a different
    /// problem.
    /// </summary>
    private int RecordOffence(IPAddress address, DateTimeOffset now)
    {
        return _offences.AddOrUpdate(
            address,
            _ => new OffenceRecord(1, now),
            (_, previous) => now - previous.LastBannedAt > _options.RepeatOffenceMemory
                ? new OffenceRecord(1, now)
                : new OffenceRecord(previous.Count + 1, now)).Count;
    }

    /// <summary>Doubles per offence, capped. The first ban is exactly the configured default, so a
    /// server that never sees a repeat offender behaves as if this feature did not exist.</summary>
    private TimeSpan EscalatedDuration(int offence)
    {
        if (!_options.EscalateRepeatOffenders || offence <= 1)
            return _options.DefaultBanDuration;

        // Shifted rather than raised to a power, and clamped first: 2^63 ticks overflows long before
        // an address could realistically get there, and an overflowed TimeSpan is a negative one.
        int doublings = Math.Min(offence - 1, 20);
        double ticks = _options.DefaultBanDuration.Ticks * Math.Pow(2, doublings);

        return ticks >= _options.MaxBanDuration.Ticks
            ? _options.MaxBanDuration
            : TimeSpan.FromTicks((long)ticks);
    }

    private static string Describe(TimeSpan span) =>
        span.TotalDays >= 1 ? $"{span.TotalDays:0.#} days" : $"{span.TotalHours:0.#} hours";

    public IReadOnlyCollection<(IPAddress Address, DateTimeOffset ExpiresAt)> ListActiveBans() =>
        _activeBans.Select(kv => (kv.Key, kv.Value)).ToArray();

    /// <summary>Runs the expiry sweep immediately instead of waiting for the timer — lets tests assert
    /// that an adopted ban really is cleaned up, rather than only that it was recorded.</summary>
    internal void CleanupExpiredNow() => CleanupExpired();

    private void CleanupExpired()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var (address, expiresAt) in _activeBans.ToArray())
        {
            if (expiresAt <= now)
                Unban(address, forgetHistory: false);
        }

        // Offence history outlives the ban it caused — that is what escalation is — but not forever.
        foreach (var (address, record) in _offences.ToArray())
        {
            if (now - record.LastBannedAt > _options.RepeatOffenceMemory)
                _offences.TryRemove(address, out _);
        }
    }

    public void Dispose() => _cleanupTimer.Dispose();
}
