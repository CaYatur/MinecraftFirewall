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
}
