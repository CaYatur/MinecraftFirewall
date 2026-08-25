using System.Collections.Concurrent;

namespace MinecraftFirewall.Proxy.Identity;

/// <summary>Per-profile identity records, keyed case-insensitively (Minecraft names aren't case-distinct in practice).</summary>
public sealed class IdentityStore
{
    private readonly ConcurrentDictionary<string, IdentityEntry> _entries = new(StringComparer.OrdinalIgnoreCase);

    public void AddOrReplace(IdentityEntry entry) => _entries[entry.Username] = entry;

    public IdentityEntry? Find(string username) =>
        _entries.TryGetValue(username, out var entry) ? entry : null;

    public IdentityEntry GetOrCreate(string username) =>
        _entries.GetOrAdd(username, name => new IdentityEntry { Username = name });

    /// <summary>Snapshot of every entry, for the persistence layer. A ConcurrentDictionary enumerates
    /// safely against concurrent writes, and the copy keeps callers from holding the live collection.</summary>
    public IReadOnlyList<IdentityEntry> All() => _entries.Values.ToArray();

    /// <summary>Forgets a name entirely. Only what was learned at runtime — a name declared in
    /// appsettings.json is rebuilt from there on the next start, which is deliberate: config is its
    /// own source of truth and this process does not edit it.</summary>
    public bool Remove(string username) => _entries.TryRemove(username, out _);
}
