using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.RateLimiting;

public enum RateLimitKind
{
    StatusPing,
    LoginAttempt,
}

/// <summary>
/// Sliding-window connection rate limiting, keyed per (server profile, IP, kind) so heavy load on
/// one server never throttles another, and status pings are tracked separately from login attempts
/// since they have very different legitimate-traffic shapes.
/// </summary>
public sealed class ConnectionRateLimiter : IDisposable
{
    private readonly RateLimitOptions _options;
    private readonly ConcurrentDictionary<(string Profile, IPAddress Ip, RateLimitKind Kind), ConcurrentQueue<DateTimeOffset>> _windows = new();
    private readonly Timer _cleanupTimer;

    public ConnectionRateLimiter(IOptions<RateLimitOptions> options)
    {
        _options = options.Value;
        _cleanupTimer = new Timer(_ => CleanupStaleEntries(), null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
    }

    /// <summary>Registers one attempt and returns false if it exceeds the configured threshold for its window.</summary>
    public bool TryRegisterAttempt(string profileName, IPAddress ip, RateLimitKind kind)
    {
        var (max, window) = kind == RateLimitKind.StatusPing
            ? (_options.StatusPingMaxPerWindow, _options.StatusPingWindow)
            : (_options.LoginMaxPerWindow, _options.LoginWindow);

        var key = (profileName, ip, kind);
        var queue = _windows.GetOrAdd(key, _ => new ConcurrentQueue<DateTimeOffset>());

        var now = DateTimeOffset.UtcNow;
        queue.Enqueue(now);
        TrimOld(queue, now, window);

        return queue.Count <= max;
    }

    private static void TrimOld(ConcurrentQueue<DateTimeOffset> queue, DateTimeOffset now, TimeSpan window)
    {
        while (queue.TryPeek(out var oldest) && now - oldest > window)
            queue.TryDequeue(out _);
    }

    private void CleanupStaleEntries()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var (key, queue) in _windows)
        {
            var window = key.Kind == RateLimitKind.StatusPing ? _options.StatusPingWindow : _options.LoginWindow;
            TrimOld(queue, now, window);
            if (queue.IsEmpty)
                _windows.TryRemove(key, out _);
        }
    }

    public void Dispose() => _cleanupTimer.Dispose();
}
