namespace MinecraftFirewall.Proxy.Identity;

public sealed class IdentityOptions
{
    public const string SectionName = "Identity";

    /// <summary>How long a CaYaDev-Check-learned IP stays trusted before it must be re-earned.</summary>
    public TimeSpan LearnedIpTtl { get; set; } = TimeSpan.FromDays(30);

    /// <summary>Cap per username; oldest-expiring is evicted first once exceeded.</summary>
    public int MaxLearnedIpsPerUsername { get; set; } = 5;

    public int PasswordMinLength { get; set; } = 6;

    /// <summary>
    /// Require every player to register a password and log in, the way AuthMe and its relatives do on
    /// an offline-mode server.
    ///
    /// Off by default, because switching it on changes what joining the server means for everyone at
    /// once. With it off, the password system is opt-in: a player who types /register gets their name
    /// protected, and everybody else plays as they always did. With it on, nobody reaches the world
    /// until they have authenticated.
    ///
    /// Premium-locked names skip it entirely, and that is not an oversight. A name proven to belong to
    /// a real Microsoft account has already been authenticated by something far stronger than a
    /// password this server stores, and asking for one on top would be asking the genuine owner to
    /// prove themselves twice — the exact thing this project promises never to do.
    /// </summary>
    public bool RequireRegistrationForEveryone { get; set; }

    /// <summary>
    /// How long a player has to authenticate before the connection is closed.
    ///
    /// Generous, because the alternative to waiting is kicking somebody who was reading the message.
    /// A player who is genuinely stuck is better served by a kick that explains itself than by an
    /// indefinite freeze they cannot interpret.
    /// </summary>
    public TimeSpan AuthenticationTimeout { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>How often the prompt is repeated while a player is waiting to authenticate. Minecraft
    /// chat scrolls, and a single message sent at join time is gone by the time somebody looks.</summary>
    public TimeSpan AuthenticationReminderInterval { get; set; } = TimeSpan.FromSeconds(10);
}
