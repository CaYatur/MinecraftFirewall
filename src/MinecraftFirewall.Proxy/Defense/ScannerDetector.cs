using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Defense;

/// <summary>What kind of mismatch a refused hostname was.</summary>
public enum HostnameMismatchKind
{
    /// <summary>The client sent this server's raw IP address. Somebody typed the address in, or shared
    /// it — including, very often, the admin testing their own server.</summary>
    DirectIpConnect,

    /// <summary>The client sent a domain this server does not serve. Nobody arrives at a Minecraft
    /// server by accident under someone else's domain name.</summary>
    ForeignDomain,
}

/// <summary>
/// Recognises the server-indexing crawlers that sweep the internet looking for Minecraft servers, and
/// escalates them to a long ban once they have identified themselves often enough.
///
/// The signal is unusually clean, and it comes from the crawlers themselves. A Minecraft client puts
/// the address the player typed into the Handshake packet, so a player who was given a raw IP sends
/// that IP. A crawler sweeping address ranges has no address to send, so it sends *its own* domain —
/// its brand, in the field meant for the server's name. Watching a real server for an afternoon shows
/// exactly this: the owner's own connections carry the server's IP, and the crawlers carry names like
/// their own site's.
///
/// That distinction is the whole design here. A raw IP in the hostname field is ambiguous — it is what
/// the admin's own test connection looks like — so it earns an ordinary strike and nothing more. A
/// foreign domain is not ambiguous, and after a few of them the address is banned for far longer than
/// the usual ban, because a crawler will otherwise be back next week.
///
/// Only meaningful when a profile actually declares AllowedHostnames: with no list, nothing is a
/// mismatch and this never sees anything.
/// </summary>
public sealed class ScannerDetector(IOptions<BotDefenseOptions> options, ILogger<ScannerDetector> logger)
{
    private readonly BotDefenseOptions _options = options.Value;
    private readonly ConcurrentDictionary<IPAddress, Sightings> _sightings = new();

    /// <summary>
    /// Classifies a refused hostname. An empty or unparseable value counts as a foreign domain: a
    /// real client always sends something, and something unreadable is not a player either.
    /// </summary>
    public static HostnameMismatchKind Classify(string claimedHostname) =>
        IPAddress.TryParse(claimedHostname.Trim(), out _)
            ? HostnameMismatchKind.DirectIpConnect
            : HostnameMismatchKind.ForeignDomain;

    /// <summary>
    /// Records one refused connection and returns the ban duration if this address has now earned one,
    /// or null if it has not.
    ///
    /// The names it announced are kept with the count, because a ban that cannot say what it was for
    /// is one nobody can check. They are the strongest evidence available for this particular
    /// judgement — a list of domains that are demonstrably not this server's.
    /// </summary>
    public TimeSpan? RecordMismatch(IPAddress address, string claimedHostname, HostnameMismatchKind kind, DateTimeOffset now)
    {
        if (!_options.Enabled || kind != HostnameMismatchKind.ForeignDomain)
            return null;

        Sightings sightings = _sightings.GetOrAdd(address, static _ => new Sightings());
        int count = sightings.Record(claimedHostname, now, _options.ScannerMemory);

        if (count < _options.ScannerMismatchesBeforeBan)
            return null;

        logger.LogWarning(
            "SCANNER: {Ip} has announced {Count} hostname(s) this server does not serve ({Names}) — " +
            "banning it for {Duration}. This is the shape of a server-indexing crawler, not a player.",
            address, count, sightings.Describe(), _options.ScannerBanDuration);

        // Cleared so a re-offence after the ban expires starts its own count rather than banning on
        // the first sighting — the ban is the response to a pattern, and the pattern has to be
        // re-established.
        _sightings.TryRemove(address, out _);

        return _options.ScannerBanDuration;
    }

    /// <summary>Drops addresses with nothing left inside the memory window. Called by the owner on a
    /// timer rather than during a record, so the cleanup never lands on a connection's path.</summary>
    public int Prune(DateTimeOffset now)
    {
        int removed = 0;
        foreach ((IPAddress address, Sightings sightings) in _sightings)
        {
            if (sightings.IsEmpty(now, _options.ScannerMemory) && _sightings.TryRemove(address, out _))
                removed++;
        }

        return removed;
    }

    public int TrackedAddresses => _sightings.Count;

    /// <summary>Per-address memory, bounded in both directions: a fixed number of remembered names,
    /// and a window they fall out of.</summary>
    private sealed class Sightings
    {
        private const int MaxRememberedNames = 8;

        private readonly Lock _gate = new();
        private readonly Dictionary<string, DateTimeOffset> _names = new(StringComparer.OrdinalIgnoreCase);

        public int Record(string hostname, DateTimeOffset now, TimeSpan window)
        {
            // Bounded before it is stored: the hostname is attacker-controlled text, and a dictionary
            // keyed on it must not be a way to make this process allocate.
            string key = hostname.Length <= 64 ? hostname : hostname[..64];

            lock (_gate)
            {
                DateTimeOffset cutoff = now - window;
                foreach (string stale in _names.Where(pair => pair.Value < cutoff).Select(pair => pair.Key).ToArray())
                    _names.Remove(stale);

                _names[key] = now;

                if (_names.Count > MaxRememberedNames)
                    _names.Remove(_names.MinBy(pair => pair.Value).Key);

                return _names.Count;
            }
        }

        public bool IsEmpty(DateTimeOffset now, TimeSpan window)
        {
            lock (_gate)
                return _names.Values.All(seen => seen < now - window);
        }

        public string Describe()
        {
            lock (_gate)
                return string.Join(", ", _names.Keys.Take(MaxRememberedNames));
        }
    }
}
