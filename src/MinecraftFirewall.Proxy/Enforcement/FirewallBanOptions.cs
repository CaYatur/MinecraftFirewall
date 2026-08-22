namespace MinecraftFirewall.Proxy.Enforcement;

public sealed class FirewallBanOptions
{
    public const string SectionName = "FirewallBan";

    public TimeSpan DefaultBanDuration { get; set; } = TimeSpan.FromHours(6);

    /// <summary>Consecutive rate-limit violations from one IP before a firewall-level ban is issued.</summary>
    public int StrikesBeforeBan { get; set; } = 5;

    public TimeSpan CleanupInterval { get; set; } = TimeSpan.FromMinutes(1);
}
