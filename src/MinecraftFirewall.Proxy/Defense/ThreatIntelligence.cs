using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using MinecraftFirewall.Proxy.IpIntel;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Defense;

/// <summary>One address this installation caught itself, and what it was doing.</summary>
public sealed record LocalThreatRecord(IPAddress Address, string Reason, DateTimeOffset FirstSeen, DateTimeOffset LastSeen, int Hits);

/// <summary>
/// Holds both halves of the threat picture: lists imported from elsewhere, and what this server has
/// watched happen on its own ports.
///
/// They are kept apart rather than merged into one table because they justify different actions. A
/// honeypot hit is this machine's own observation of a connection to a port no legitimate player has
/// any reason to touch — first-hand, and specific to a real event. An imported list is somebody
/// else's judgement about traffic that was never aimed here. Merging them would mean the weakest
/// evidence inherited the strongest response.
/// </summary>
public sealed class ThreatIntelligence
{
    private readonly ThreatIntelOptions _options;
    private readonly ILogger<ThreatIntelligence> _logger;
    private readonly ConcurrentDictionary<IPAddress, LocalThreatRecord> _local = new();

    private volatile Ipv4RangeTable _imported = Ipv4RangeTable.Empty;
    private int _dirty;

    public ThreatIntelligence(IOptions<ThreatIntelOptions> options, ILogger<ThreatIntelligence> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public bool Enabled => _options.Enabled;

    public ThreatListAction Action => _options.Action;

    public int ScoreWeight => _options.ScoreWeight;

    public int ImportedRangeCount => _imported.RangeCount;

    public int LocalRecordCount => _local.Count;

    public void UpdateImported(Ipv4RangeTable table) => _imported = table;

    /// <summary>True when an imported list names this address. Second-hand evidence — see
    /// <see cref="ThreatIntelOptions.Action"/> for what the caller is allowed to do about it.</summary>
    public bool IsOnImportedList(IPAddress address) => _options.Enabled && _imported.Contains(address);

    /// <summary>True when this installation caught the address itself.</summary>
    public bool IsLocallyObserved(IPAddress address) => _local.ContainsKey(address);

    /// <summary>Records a first-hand observation. Repeat hits from the same address update the
    /// existing record rather than adding another, so the file stays a list of addresses rather than
    /// a list of events.</summary>
    public void RecordLocalHit(IPAddress address, string reason, DateTimeOffset now)
    {
        _local.AddOrUpdate(
            address,
            _ => new LocalThreatRecord(address, reason, now, now, 1),
            (_, existing) => existing with { LastSeen = now, Hits = existing.Hits + 1, Reason = reason });

        Interlocked.Exchange(ref _dirty, 1);
        TrimIfOversized();
    }

    public IReadOnlyList<LocalThreatRecord> LocalSnapshot() =>
        [.. _local.Values.OrderByDescending(r => r.LastSeen)];

    // ---- persistence ---------------------------------------------------------------------------
    // Deliberately the same one-address-per-line format the feeds are read in, with the details as a
    // trailing comment. That means this file can be published as a feed for another installation with
    // no conversion step, and it stays readable in Notepad.

    public void Load()
    {
        try
        {
            if (!File.Exists(_options.LocalThreatLogPath))
                return;

            DateTimeOffset cutoff = DateTimeOffset.UtcNow - _options.LocalRetention;
            int loaded = 0, expired = 0;

            foreach (string line in File.ReadLines(_options.LocalThreatLogPath))
            {
                if (!TryParseRecord(line, out LocalThreatRecord? record))
                    continue;

                if (record!.LastSeen < cutoff)
                {
                    expired++;
                    continue;
                }

                _local[record.Address] = record;
                loaded++;
            }

            _logger.LogInformation("Loaded {Loaded} locally-observed threat address(es) ({Expired} expired).", loaded, expired);
        }
        catch (Exception ex)
        {
            // A damaged file must not stop the service starting. Losing this history costs nothing a
            // fresh honeypot hit will not re-establish.
            _logger.LogWarning(ex, "Could not read {Path} — starting with an empty local threat list.", _options.LocalThreatLogPath);
        }
    }

    /// <summary>Writes the local list if anything has changed since the last write. Returns false
    /// when there was nothing to do, so the caller's timer stays quiet on an idle server.</summary>
    public bool SaveIfChanged()
    {
        if (Interlocked.Exchange(ref _dirty, 0) == 0)
            return false;

        try
        {
            string? directory = Path.GetDirectoryName(_options.LocalThreatLogPath);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);

            DateTimeOffset cutoff = DateTimeOffset.UtcNow - _options.LocalRetention;
            var lines = new List<string>
            {
                "# Addresses this MinecraftFirewall installation caught on its own honeypot ports.",
                "# One address per line — the same format the imported feeds use, so this file can be",
                "# published as a feed for other installations as-is.",
                $"# Written {DateTimeOffset.UtcNow:u}",
            };

            foreach (LocalThreatRecord record in _local.Values.OrderByDescending(r => r.LastSeen))
            {
                if (record.LastSeen < cutoff)
                {
                    _local.TryRemove(record.Address, out _);
                    continue;
                }

                lines.Add($"{record.Address}\t# {record.Hits}x {record.Reason}, last {record.LastSeen:u}, first {record.FirstSeen:u}");
            }

            string temporary = _options.LocalThreatLogPath + ".tmp";
            File.WriteAllLines(temporary, lines);
            File.Move(temporary, _options.LocalThreatLogPath, overwrite: true);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not write {Path}.", _options.LocalThreatLogPath);
            // Put the flag back so the next tick tries again rather than silently dropping the change.
            Interlocked.Exchange(ref _dirty, 1);
            return false;
        }
    }

    private void TrimIfOversized()
    {
        if (_local.Count <= _options.MaxLocalRecords)
            return;

        foreach (LocalThreatRecord record in _local.Values
                     .OrderBy(r => r.LastSeen)
                     .Take(_local.Count - _options.MaxLocalRecords))
        {
            _local.TryRemove(record.Address, out _);
        }
    }

    private static bool TryParseRecord(string line, out LocalThreatRecord? record)
    {
        record = null;
        string trimmed = line.Trim();
        if (trimmed.Length == 0 || trimmed.StartsWith('#'))
            return false;

        string[] parts = trimmed.Split('\t', 2);
        if (!IPAddress.TryParse(parts[0].Trim(), out IPAddress? address))
            return false;

        // The comment column is a convenience for whoever opens the file, not a contract. If it is
        // missing or unreadable the address itself is still worth keeping.
        string reason = "previously observed";
        DateTimeOffset lastSeen = DateTimeOffset.UtcNow;
        DateTimeOffset firstSeen = lastSeen;
        int hits = 1;

        if (parts.Length == 2)
        {
            string comment = parts[1].TrimStart('#', ' ');
            string[] fields = comment.Split(',', StringSplitOptions.TrimEntries);

            if (fields.Length > 0)
            {
                string head = fields[0];
                int space = head.IndexOf(' ');
                if (space > 1 && int.TryParse(head[..space].TrimEnd('x'), out int parsedHits))
                {
                    hits = parsedHits;
                    reason = head[(space + 1)..];
                }
                else
                {
                    reason = head;
                }
            }

            lastSeen = ParseStamp(fields, "last ") ?? lastSeen;
            firstSeen = ParseStamp(fields, "first ") ?? lastSeen;
        }

        record = new LocalThreatRecord(address, reason, firstSeen, lastSeen, hits);
        return true;
    }

    private static DateTimeOffset? ParseStamp(string[] fields, string prefix)
    {
        foreach (string field in fields)
        {
            if (field.StartsWith(prefix, StringComparison.Ordinal) &&
                DateTimeOffset.TryParse(field[prefix.Length..], CultureInfo.InvariantCulture, out DateTimeOffset value))
            {
                return value;
            }
        }

        return null;
    }
}
