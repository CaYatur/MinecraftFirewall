namespace MinecraftFirewall.Proxy.Messages;

/// <summary>
/// Every player-facing kick/disconnect string the proxy can send, in one place, bound from the
/// "Messages" section of appsettings.json (IOptions, same pattern as every other options type here).
/// Defaults are English; override any subset of these per-deployment — e.g. to Turkish — without
/// touching code. A field left out of config keeps its English default.
/// </summary>
public sealed class MessagesOptions
{
    public const string SectionName = "Messages";

    /// <summary>Sent on a generic policy denial (rate limit, protected-username mismatch, VPN block, ban).</summary>
    public string GenericDenied { get; set; } = "This connection was blocked by MinecraftFirewall.";

    /// <summary>
    /// Only ever shown to a connection using a *protected* username — one locked to a Microsoft
    /// account, or registered with a password and arriving from a new address — on a client version
    /// this build has no verified packet table for. Ordinary players on any version are unaffected and
    /// never see it, which the wording says so nobody concludes the server is version-locked.
    /// </summary>
    public string UnsupportedClientVersion { get; set; } =
        "This username is protected, and protecting it needs a client version this server's firewall knows. " +
        "Yours is not one of them yet. Other players are unaffected — ask the administrator to update MinecraftFirewall, " +
        "or join with a supported version.";

    /// <summary>Sent when AllowedHostnames is configured for the profile and the connection's
    /// Handshake Server Address doesn't match any entry.</summary>
    public string HostnameNotAllowed { get; set; } = "This server can only be reached through its allowed address(es).";

    /// <summary>Sent when a non-trusted connection issues a dangerous command.</summary>
    public string DangerousCommandBlocked { get; set; } =
        "You are not authorized to use that command. Your connection was closed for security reasons.";

    /// <summary>Sent when the mandatory first-message grace-authentication check fails (wrong
    /// password, or the first message wasn't a /login command at all).</summary>
    public string GraceAuthenticationFailed { get; set; } =
        "Authentication failed. This IP is not recognized and the correct password was not provided.";

    /// <summary>Sent when a username marked PremiumRequired fails Mojang session verification — a
    /// cracked/offline client, a failed hasJoined check, or a UUID that doesn't match the one this
    /// name is pinned to. Worded for the case that actually reaches a human: the genuine owner
    /// hitting a Mojang outage, since anyone else has no legitimate reason to be here.</summary>
    public string PremiumVerificationFailed { get; set; } =
        "This username is reserved for its verified Minecraft account owner. Sign in with the genuine account and try again.";

    /// <summary>Shown when a player types /premium — the explanation, and what confirming will do.
    /// Deliberately spells out that it is permanent, because it is.</summary>
    public string PremiumLockExplain { get; set; } =
        "Locking your name means only your real Minecraft account can ever use it on this server, from any address, " +
        "and you will never be asked for a password. This cannot be undone by you afterwards. " +
        "To go ahead, type /premium confirm — you will be disconnected, and must rejoin using the genuine account.";

    /// <summary>Shown as the disconnect reason after /premium confirm.</summary>
    public string PremiumLockArmed { get; set; } =
        "Ready. Rejoin now with the real Minecraft account that owns this name, and it will be locked to it. " +
        "If you rejoin with anything else, nothing is recorded and you simply play as usual.";

    /// <summary>Shown once the claim has succeeded, on the connection that proved it.</summary>
    public string PremiumLockSucceeded { get; set; } =
        "Your name is now locked to this Minecraft account. Nobody else can use it on this server.";

    // ---- server-wide registration (Identity.RequireRegistrationForEveryone) -----------------------
    // Sent into the player's chat while they are held still, so they are longer and more instructional
    // than the kick messages above: somebody reading these is stuck and needs to be told what to do,
    // not merely told what happened.

    public string RegistrationPrompt { get; set; } =
        "This server requires an account. Type  /register <password>  to create one. " +
        "You cannot move or interact until you do. Choose something you have not used elsewhere.";

    public string LoginPrompt { get; set; } =
        "Welcome back. Type  /login <password>  to continue. You cannot move or interact until you do.";

    public string AuthenticationAccepted { get; set; } =
        "Authenticated. Have fun.";

    /// <summary>Takes the configured minimum length as {0}.</summary>
    public string PasswordTooShort { get; set; } =
        "That password is too short — it needs at least {0} characters. Try again with  /register <password>";

    public string AuthenticationTimedOut { get; set; } =
        "You did not register or log in within the time allowed. Reconnect and try again.";
}
