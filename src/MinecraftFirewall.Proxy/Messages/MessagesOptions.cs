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

    /// <summary>Sent when a registered username's protocol version has no verified Play-state packet
    /// table, so the grace-authentication check that username requires can't be safely performed.</summary>
    public string UnsupportedClientVersion { get; set; } =
        "This client version is not supported by the server's protection layer. Contact the server administrator.";

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
}
