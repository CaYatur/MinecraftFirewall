namespace MinecraftFirewall.Proxy.RateLimiting;

public sealed class RateLimitOptions
{
    public const string SectionName = "RateLimits";

    // Status pings (server-list refresh) are cheap for a legitimate client to send repeatedly,
    // so this window is looser than login attempts.
    public int StatusPingMaxPerWindow { get; set; } = 20;
    public TimeSpan StatusPingWindow { get; set; } = TimeSpan.FromSeconds(10);

    public int LoginMaxPerWindow { get; set; } = 5;
    public TimeSpan LoginWindow { get; set; } = TimeSpan.FromSeconds(30);
}
