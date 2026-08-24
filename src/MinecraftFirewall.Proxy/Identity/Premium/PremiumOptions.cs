namespace MinecraftFirewall.Proxy.Identity.Premium;

public sealed class PremiumOptions
{
    public const string SectionName = "Premium";

    /// <summary>Timeout for the Mojang hasJoined HTTP call. Unlike IpInfoOptions.HttpTimeout, a
    /// timeout here always means DENY (fail-closed) — see IPremiumSessionClient's doc comment.</summary>
    public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(5);
}
