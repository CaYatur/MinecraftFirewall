using System.Net;
using MinecraftFirewall.Proxy.RateLimiting;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Tests;

public class ConnectionRateLimiterTests
{
    private static ConnectionRateLimiter CreateLimiter(int max, TimeSpan window)
    {
        var options = new RateLimitOptions
        {
            LoginMaxPerWindow = max,
            LoginWindow = window,
            StatusPingMaxPerWindow = max,
            StatusPingWindow = window,
        };
        return new ConnectionRateLimiter(Options.Create(options));
    }

    [Fact]
    public void TryRegisterAttempt_UnderThreshold_ReturnsTrue()
    {
        using var limiter = CreateLimiter(max: 3, window: TimeSpan.FromSeconds(10));
        var ip = IPAddress.Parse("203.0.113.1");

        Assert.True(limiter.TryRegisterAttempt("profileA", ip, RateLimitKind.LoginAttempt));
        Assert.True(limiter.TryRegisterAttempt("profileA", ip, RateLimitKind.LoginAttempt));
        Assert.True(limiter.TryRegisterAttempt("profileA", ip, RateLimitKind.LoginAttempt));
    }

    [Fact]
    public void TryRegisterAttempt_ExceedsThreshold_ReturnsFalse()
    {
        using var limiter = CreateLimiter(max: 2, window: TimeSpan.FromSeconds(10));
        var ip = IPAddress.Parse("203.0.113.1");

        Assert.True(limiter.TryRegisterAttempt("profileA", ip, RateLimitKind.LoginAttempt));
        Assert.True(limiter.TryRegisterAttempt("profileA", ip, RateLimitKind.LoginAttempt));
        Assert.False(limiter.TryRegisterAttempt("profileA", ip, RateLimitKind.LoginAttempt));
    }

    [Fact]
    public void TryRegisterAttempt_DifferentProfiles_AreIndependent()
    {
        using var limiter = CreateLimiter(max: 1, window: TimeSpan.FromSeconds(10));
        var ip = IPAddress.Parse("203.0.113.1");

        Assert.True(limiter.TryRegisterAttempt("profileA", ip, RateLimitKind.LoginAttempt));
        Assert.False(limiter.TryRegisterAttempt("profileA", ip, RateLimitKind.LoginAttempt));

        // Same IP, different profile — must not be throttled by profileA's usage.
        Assert.True(limiter.TryRegisterAttempt("profileB", ip, RateLimitKind.LoginAttempt));
    }

    [Fact]
    public void TryRegisterAttempt_DifferentKinds_AreIndependent()
    {
        using var limiter = CreateLimiter(max: 1, window: TimeSpan.FromSeconds(10));
        var ip = IPAddress.Parse("203.0.113.1");

        Assert.True(limiter.TryRegisterAttempt("profileA", ip, RateLimitKind.LoginAttempt));
        Assert.False(limiter.TryRegisterAttempt("profileA", ip, RateLimitKind.LoginAttempt));

        Assert.True(limiter.TryRegisterAttempt("profileA", ip, RateLimitKind.StatusPing));
    }

    [Fact]
    public async Task TryRegisterAttempt_AfterWindowExpires_ResetsAsync()
    {
        using var limiter = CreateLimiter(max: 1, window: TimeSpan.FromMilliseconds(50));
        var ip = IPAddress.Parse("203.0.113.1");

        Assert.True(limiter.TryRegisterAttempt("profileA", ip, RateLimitKind.LoginAttempt));
        Assert.False(limiter.TryRegisterAttempt("profileA", ip, RateLimitKind.LoginAttempt));

        await Task.Delay(100);

        Assert.True(limiter.TryRegisterAttempt("profileA", ip, RateLimitKind.LoginAttempt));
    }
}
