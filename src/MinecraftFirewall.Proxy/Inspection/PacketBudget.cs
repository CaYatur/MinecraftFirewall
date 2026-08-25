namespace MinecraftFirewall.Proxy.Inspection;

/// <summary>
/// Per-connection packet and byte allowance, measured over one-second buckets.
///
/// This is the limit that matters once a connection is past every identity check. The admission
/// control at the accept loop bounds how many connections an address may have; nothing there bounds
/// what a single accepted connection may then send, and a packet flood down one authorised socket is
/// both easier to mount and cheaper for the attacker than opening a thousand.
///
/// Owned by one connection and touched only from that connection's read loop, so it needs no locking
/// — which is the point of keeping it per-connection rather than sharing a rate limiter across all of
/// them. The counters reset rather than sliding: a rolling window would need a timestamp per packet,
/// and at two hundred packets a second per connection the bookkeeping would cost more than the check.
/// </summary>
public sealed class PacketBudget(int maxPacketsPerSecond, int maxBytesPerSecond)
{
    private long _windowStartTicks = DateTimeOffset.UtcNow.Ticks;
    private int _packets;
    private long _bytes;

    public int PeakPacketsPerSecond { get; private set; }

    /// <summary>Records one packet. Returns null when it is within budget, or the reason it is not.
    /// The caller disconnects on a refusal rather than dropping the packet: a client over this limit
    /// is either broken or hostile, and silently discarding its packets would leave it in a state the
    /// backend disagrees with.</summary>
    public string? Charge(int frameBytes, DateTimeOffset now)
    {
        long elapsed = now.Ticks - Interlocked.Read(ref _windowStartTicks);
        if (elapsed >= TimeSpan.TicksPerSecond)
        {
            if (_packets > PeakPacketsPerSecond)
                PeakPacketsPerSecond = _packets;

            _windowStartTicks = now.Ticks;
            _packets = 0;
            _bytes = 0;
        }

        _packets++;
        _bytes += frameBytes;

        if (_packets > maxPacketsPerSecond)
            return $"{_packets} packets in one second (limit {maxPacketsPerSecond})";

        if (_bytes > maxBytesPerSecond)
            return $"{_bytes / 1024} KB in one second (limit {maxBytesPerSecond / 1024} KB)";

        return null;
    }
}
