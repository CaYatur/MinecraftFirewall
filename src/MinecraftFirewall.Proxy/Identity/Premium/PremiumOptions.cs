namespace MinecraftFirewall.Proxy.Identity.Premium;

public sealed class PremiumOptions
{
    public const string SectionName = "Premium";

    /// <summary>
    /// Master switch for the whole premium-verification path, so it can be turned off if Mojang's
    /// session API changes or misbehaves, without touching Stages 1–3.
    ///
    /// Turning it off does NOT downgrade a <c>PremiumRequired</c> username to the password/IP checks —
    /// it denies that name outright, for everyone. Falling back to a weaker gate would hand the name
    /// to exactly the attacker the admin declared it premium to keep out, so "disabled" fails closed
    /// and the only way to relax protection on a name is to remove its <c>RequirePremium</c> flag.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Timeout for the Mojang hasJoined HTTP call. Unlike IpInfoOptions.HttpTimeout, a
    /// timeout here always means DENY (fail-closed) — see IPremiumSessionClient's doc comment.</summary>
    public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(5);
}
