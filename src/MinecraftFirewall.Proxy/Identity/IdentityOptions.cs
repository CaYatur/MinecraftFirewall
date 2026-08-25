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

    /// <summary>
    /// Whether a player waiting to authenticate has their client pinned in place.
    ///
    /// Their packets are refused either way, so the server never sees them move. What this adds is
    /// telling the *client* so. Minecraft predicts movement locally and only corrects it when the
    /// server disagrees, so without this the held player watches themselves walk around and then snap
    /// back — which reads as a broken server, not as a login prompt. This was reported from live play,
    /// not caught by a test.
    /// </summary>
    public bool LockPositionWhileAuthenticating { get; set; } = true;

    /// <summary>
    /// Where a held player's client is told it is. The origin by default, and deliberately not their
    /// real position: coordinates are on screen for anyone watching a stream or looking over a
    /// shoulder, and somebody who has not yet proved who they are should not be leaking a base
    /// location to whoever is currently wearing their name.
    /// </summary>
    public double LockPositionX { get; set; }

    public double LockPositionY { get; set; }

    public double LockPositionZ { get; set; }

    /// <summary>
    /// How often the pin is re-applied while the player waits.
    ///
    /// It has to repeat, because gravity is a client-side prediction too: pinned once, the player
    /// simply starts falling from the origin. Frequently enough that they never visibly drift, rarely
    /// enough to stay a rounding error next to the twenty movement packets a second the client is
    /// already sending.
    /// </summary>
    public TimeSpan PositionLockInterval { get; set; } = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// Whether a held player who starts taking damage is disconnected rather than left to die.
    ///
    /// A firewall in front of a server cannot stop a creeper. The player is genuinely standing in the
    /// world while they read the prompt, and the only thing that decides their health is the server
    /// itself — nothing this proxy refuses or rewrites changes that. What it can do is notice, and end
    /// the connection before the death happens: a kick costs them a reconnect, a death costs them
    /// their inventory.
    /// </summary>
    public bool DisconnectIfDamagedWhileAuthenticating { get; set; } = true;

    /// <summary>
    /// How much health a held player has to lose before they are pulled out, out of the usual twenty.
    /// Half a heart by default: the point is to act on the first hit, not to referee a fair fight.
    ///
    /// A drop rather than a level, and that distinction is the whole of it. Measured against a fixed
    /// level, somebody who simply logged off wounded would be kicked the instant they joined — told
    /// that something had attacked them, when nothing had. The server announces their health on join,
    /// and that first announcement is the baseline; damage is a decrease from it.
    /// </summary>
    public float DamageDisconnectMinimumDrop { get; set; } = 0.5f;
}
