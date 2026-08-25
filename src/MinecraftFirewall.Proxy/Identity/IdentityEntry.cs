using System.Net;

namespace MinecraftFirewall.Proxy.Identity;

/// <summary>What happened to one player, for the per-player history an administrator reads.</summary>
public enum PlayerEventKind
{
    Registered,
    LoggedIn,
    LoginFailed,
    PasswordChanged,
    PasswordReset,
    PremiumClaimRequested,
    PremiumVerified,
    PremiumVerificationFailed,
    Denied,
    Kicked,
}

/// <summary>One line of a player's history. Deliberately a fixed set of kinds with a short free-text
/// detail, rather than free-form log lines: an administrator needs to be able to see at a glance that
/// a name has six failed logins from four addresses, and prose does not answer that.</summary>
public sealed record PlayerEvent(DateTimeOffset When, PlayerEventKind Kind, string? Address, string Detail);

/// <summary>
/// One username's identity record. Fields are grouped by the stage that populates them; all of
/// them live on this single record type (not parallel per-feature stores) so the gate has exactly
/// one precedence rule to apply, described in IdentityGate. Multiple connections for the same
/// username can race on LearnedIps concurrently, so mutation and iteration both go through _lock.
/// </summary>
public sealed class IdentityEntry
{
    /// <summary>How much of a player's history is kept. Bounded for the same reason the learned-IP
    /// list is: an attacker hammering one name must not be able to make this grow without limit, and
    /// nobody reads past the last few dozen entries anyway.</summary>
    private const int MaxEvents = 40;

    private readonly Lock _lock = new();
    private readonly List<LearnedIp> _learnedIps = [];
    private readonly List<PlayerEvent> _events = [];

    public required string Username { get; init; }

    // Stage 1
    public List<CidrRange> StaticAllowlist { get; init; } = [];

    // Stage 3
    public string? PasswordHash { get; set; }

    // Stage 4 — admin-declared only, never auto-set by observing traffic (see docs/plan.md's
    // "explicitly rejected" note on auto-probing).
    public bool PremiumRequired { get; set; }

    /// <summary>
    /// Set when the player holding this name has asked, and confirmed, that it be locked to their
    /// Microsoft account. The next connection using the name is challenged once, whether or not
    /// auto-claim is switched on for the server.
    ///
    /// Deliberately not persisted across restarts. It is a short-lived intent rather than a setting,
    /// and losing it costs one repeated command — whereas an armed request surviving a restart could
    /// be waiting days later for a connection the player never made.
    /// </summary>
    public PremiumClaimRequest? PremiumClaimRequested { get; set; }

    /// <summary>The Mojang UUID this username is permanently locked to, recorded on the first
    /// successful premium verification. Mutated only via <see cref="TryClaimOrMatchPinnedUuid"/> —
    /// see there for why an ordinary setter would be a real vulnerability.</summary>
    public Guid? PinnedUuid { get; private set; }

    public IReadOnlyList<LearnedIp> LearnedIps
    {
        get { lock (_lock) return _learnedIps.ToArray(); }
    }

    // ---- what an administrator sees ---------------------------------------------------------------
    // Written from every connection path and read by the control panel on a poll timer, so all of it
    // goes through the same lock as the learned-IP list, and for the same reason.

    /// <summary>When this name first set a password. Null for a name that has only ever been declared
    /// in configuration, or that is locked to a Minecraft account instead.</summary>
    public DateTimeOffset? RegisteredAt
    {
        get { lock (_lock) return _registeredAt; }
        set { lock (_lock) _registeredAt = value; }
    }

    public DateTimeOffset? LastSeenAt
    {
        get { lock (_lock) return _lastSeenAt; }
        set { lock (_lock) _lastSeenAt = value; }
    }

    /// <summary>The address this name last connected from. Kept as text: it is only ever displayed,
    /// and an address that failed to parse is still worth showing an administrator.</summary>
    public string? LastAddress
    {
        get { lock (_lock) return _lastAddress; }
        set { lock (_lock) _lastAddress = value; }
    }

    private DateTimeOffset? _registeredAt;
    private DateTimeOffset? _lastSeenAt;
    private string? _lastAddress;

    /// <summary>This name's history, oldest first.</summary>
    public IReadOnlyList<PlayerEvent> Events
    {
        get { lock (_lock) return _events.ToArray(); }
    }

    /// <summary>Adds one line to this name's history, and moves the last-seen marker with it.</summary>
    public void Record(PlayerEventKind kind, IPAddress? address, string detail, DateTimeOffset now)
    {
        lock (_lock)
        {
            _events.Add(new PlayerEvent(now, kind, address?.ToString(), detail));
            while (_events.Count > MaxEvents)
                _events.RemoveAt(0);

            _lastSeenAt = now;
            if (address is not null)
                _lastAddress = address.ToString();
        }
    }

    /// <summary>Restores a history line loaded from disk, without touching the last-seen marker —
    /// that is restored separately, from what was saved, rather than being reset to now by the act of
    /// loading it.</summary>
    public void RestoreEvent(PlayerEvent restored)
    {
        lock (_lock)
        {
            _events.Add(restored);
            while (_events.Count > MaxEvents)
                _events.RemoveAt(0);
        }
    }

    /// <summary>Forgets every address this name is trusted from, so the next connection has to prove
    /// the password again. The static allowlist is untouched: that one comes from appsettings.json,
    /// and this process does not get to overrule the file an administrator edits.</summary>
    public void ForgetLearnedIps()
    {
        lock (_lock) _learnedIps.Clear();
    }

    public bool IsIpRecognized(IPAddress address)
    {
        foreach (var range in StaticAllowlist)
        {
            if (range.Contains(address))
                return true;
        }

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        lock (_lock)
        {
            foreach (var learned in _learnedIps)
            {
                if (learned.ExpiresAtUnixSeconds > now && learned.Address.Equals(address))
                    return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Claims the permanent UUID pin for this username on the first successful premium verification,
    /// or confirms that a later verification is the same account. Returns false only when a pin is
    /// already recorded and <paramref name="verifiedUuid"/> belongs to someone else.
    ///
    /// The check-and-claim must be one atomic step, which is why this is a method rather than a
    /// public setter over a public getter. Two genuine connections for the same username can arrive
    /// concurrently (a reconnect racing a stale session is routine); with a read-then-write from
    /// caller code, both could observe a null pin and both write, letting the second connection's
    /// UUID silently replace the first. That is precisely the "somebody else takes the name" outcome
    /// this whole feature exists to prevent, so it is closed here rather than left to call sites.
    /// </summary>
    public bool TryClaimOrMatchPinnedUuid(Guid verifiedUuid)
    {
        lock (_lock)
        {
            if (PinnedUuid is null)
            {
                PinnedUuid = verifiedUuid;
                return true;
            }

            return PinnedUuid.Value == verifiedUuid;
        }
    }

    /// <summary>
    /// Restores a learned IP with its ORIGINAL absolute expiry, for loading a persisted store at
    /// startup. Distinct from <see cref="LearnIp"/> on purpose: that one computes expiry from "now",
    /// so reusing it here would silently renew every learned IP's TTL on every service restart —
    /// turning a 30-day trust window into an unbounded one for anyone who restarts regularly.
    /// Already-expired entries are dropped rather than restored.
    /// </summary>
    public void RestoreLearnedIp(IPAddress address, long expiresAtUnixSeconds)
    {
        if (expiresAtUnixSeconds <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            return;

        lock (_lock)
        {
            _learnedIps.RemoveAll(ip => ip.Address.Equals(address));
            _learnedIps.Add(new LearnedIp(address, expiresAtUnixSeconds));
        }
    }

    /// <summary>
    /// Records a successful CaYaDev-Check authentication's IP as trusted for future connections.
    /// TTL-capped and count-capped (oldest-expiring evicted first) so a single account can't
    /// accumulate an unbounded, permanent list of trusted IPs — every entry ages out eventually.
    /// </summary>
    public void LearnIp(IPAddress address, TimeSpan ttl, int maxLearnedIps)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        lock (_lock)
        {
            _learnedIps.RemoveAll(ip => ip.ExpiresAtUnixSeconds <= now || ip.Address.Equals(address));
            _learnedIps.Add(new LearnedIp(address, now + (long)ttl.TotalSeconds));

            while (_learnedIps.Count > maxLearnedIps)
            {
                var oldest = _learnedIps.OrderBy(ip => ip.ExpiresAtUnixSeconds).First();
                _learnedIps.Remove(oldest);
            }
        }
    }
}

public sealed record LearnedIp(IPAddress Address, long ExpiresAtUnixSeconds);
