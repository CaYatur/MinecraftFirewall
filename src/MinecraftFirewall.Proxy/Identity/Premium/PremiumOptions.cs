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

    /// <summary>
    /// Challenge every unrecognised username, and permanently claim the name for whoever proves they
    /// own a genuine Mojang account. Off by default — see the warning below.
    ///
    /// **This is deliberately not the design that was rejected during planning.** That one probed new
    /// names and recorded the *result*, marking a name "not premium, offline-eligible" when the check
    /// failed — which handed every valuable username to whoever connected with a cracked client first,
    /// the exact attack the feature exists to stop. This only ever writes a *positive*: a failed check
    /// records nothing at all, the player joins as an ordinary offline player, and the real owner can
    /// still claim the name later simply by connecting once. Nothing an attacker does can mark a name
    /// as un-protectable.
    ///
    /// The real cost, and why it ships off: turning this on means the proxy sends an Encryption
    /// Request to every new player. Genuine clients answer silently, and clients that answer but fail
    /// Mojang's check are still let through — but a launcher that mishandles the request outright will
    /// fail to connect at all. On a server whose whole audience is offline players, that is a
    /// self-inflicted outage, so the operator has to turn it on knowingly and test it.
    /// </summary>
    public bool AutoClaimOnVerifiedLogin { get; set; }

    /// <summary>Timeout for the Mojang hasJoined HTTP call. Unlike IpInfoOptions.HttpTimeout, a
    /// timeout here always means DENY (fail-closed) — see IPremiumSessionClient's doc comment.</summary>
    public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(5);
}
