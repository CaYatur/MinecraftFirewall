namespace MinecraftFirewall.Proxy.Identity;

public sealed class IdentityOptions
{
    public const string SectionName = "Identity";

    /// <summary>How long a CaYaDev-Check-learned IP stays trusted before it must be re-earned.</summary>
    public TimeSpan LearnedIpTtl { get; set; } = TimeSpan.FromDays(30);

    /// <summary>Cap per username; oldest-expiring is evicted first once exceeded.</summary>
    public int MaxLearnedIpsPerUsername { get; set; } = 5;

    public int PasswordMinLength { get; set; } = 6;
}
