using System.Collections.Concurrent;

namespace MinecraftFirewall.Proxy.Defense;

/// <summary>
/// Counts events per key within a rolling window, keeping only a timestamp ring per key rather than
/// one entry per event.
///
/// This exists instead of reusing ConnectionRateLimiter because the two answer different questions
/// under different pressure. That one is consulted a few times per login and keys on
/// (profile, address, kind); this one is consulted on every accepted socket during a flood, which is
/// precisely when allocating a queue node per event is least affordable. A fixed-size ring per key
/// bounds the memory a flood can cause this counter itself to consume — which matters, because a
/// defence that allocates in proportion to the attack is part of the attack.
/// </summary>
public sealed class SlidingCounter(TimeSpan window, int capacity)
{
    private readonly ConcurrentDictionary<string, Ring> _rings = new();

    /// <summary>Records one event and returns how many fall inside the window, including this one.
    /// A saturated ring reports its capacity, which is always at or above any threshold worth
    /// checking — the exact count past that point is not information anyone acts on.</summary>
    public int Record(string key, DateTimeOffset now)
    {
        Ring ring = _rings.GetOrAdd(key, _ => new Ring(capacity));
        return ring.Record(now, window);
    }

    public int Count(string key, DateTimeOffset now) =>
        _rings.TryGetValue(key, out Ring? ring) ? ring.Count(now, window) : 0;

    /// <summary>Drops keys with nothing left inside the window. Called on a timer by the owner rather
    /// than opportunistically during a record, so the cleanup cost never lands on the hot path.</summary>
    public int Prune(DateTimeOffset now)
    {
        int removed = 0;
        foreach ((string key, Ring ring) in _rings)
        {
            if (ring.Count(now, window) == 0 && _rings.TryRemove(key, out _))
                removed++;
        }

        return removed;
    }

    public int TrackedKeys => _rings.Count;

    private sealed class Ring(int capacity)
    {
        private readonly DateTimeOffset[] _stamps = new DateTimeOffset[capacity];
        private readonly Lock _gate = new();
        private int _next;
        private int _filled;

        public int Record(DateTimeOffset now, TimeSpan window)
        {
            lock (_gate)
            {
                _stamps[_next] = now;
                _next = (_next + 1) % capacity;
                if (_filled < capacity)
                    _filled++;

                return CountLocked(now, window);
            }
        }

        public int Count(DateTimeOffset now, TimeSpan window)
        {
            lock (_gate)
                return CountLocked(now, window);
        }

        private int CountLocked(DateTimeOffset now, TimeSpan window)
        {
            DateTimeOffset cutoff = now - window;
            int count = 0;
            for (int i = 0; i < _filled; i++)
            {
                if (_stamps[i] > cutoff)
                    count++;
            }

            return count;
        }
    }
}
