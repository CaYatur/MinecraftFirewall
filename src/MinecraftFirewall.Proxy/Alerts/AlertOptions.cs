namespace MinecraftFirewall.Proxy.Alerts;

public sealed class AlertOptions
{
    public const string SectionName = "Alerts";

    /// <summary>Discord webhook URL. Empty (the default) disables alerting entirely — no queue, no
    /// outbound requests. This is a secret: anyone holding it can post to the channel.</summary>
    public string DiscordWebhookUrl { get; set; } = "";

    /// <summary>Smallest gap between webhook posts. Discord rate-limits webhooks (roughly 5 requests
    /// per 2 seconds); a bot flood could otherwise generate alerts far faster than that.</summary>
    public TimeSpan MinimumInterval { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>How many alerts may wait in the queue before new ones are dropped. Bounded on purpose:
    /// an unbounded queue under a sustained attack is a memory leak in the exact situation where the
    /// proxy most needs to stay up. Drops are counted and reported rather than hidden.</summary>
    public int MaxQueuedAlerts { get; set; } = 200;

    public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Alert whenever an IP is banned.</summary>
    public bool OnBan { get; set; } = true;

    /// <summary>Alert when a registered player authenticates from a new IP. Low volume, and the point
    /// of it is that a stolen password shows up as a visible event rather than silently working.</summary>
    public bool OnNewTrustedIp { get; set; } = true;

    /// <summary>Alert when a PremiumRequired username fails Mojang verification.</summary>
    public bool OnPremiumVerificationFailure { get; set; } = true;

    /// <summary>Alert when a non-trusted connection issues a command on the dangerous list.</summary>
    public bool OnDangerousCommand { get; set; } = true;
}
