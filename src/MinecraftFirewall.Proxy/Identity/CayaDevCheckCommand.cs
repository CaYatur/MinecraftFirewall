namespace MinecraftFirewall.Proxy.Identity;

public enum CayaDevCheckCommandKind
{
    None,
    Register,
    Login,

    /// <summary>The player asked what locking their name to their Microsoft account would do. Answered
    /// with an explanation and a request to confirm — never acted on directly, because the answer is
    /// permanent and they are about to be asked to reconnect.</summary>
    PremiumLockAsk,

    /// <summary>The player confirmed. Arms a claim; the next connection using this name is challenged.</summary>
    PremiumLockConfirm,

    /// <summary>A player changing their own password, in game, by proving the old one first.</summary>
    ChangePassword,
}

/// <summary>A parsed command. <paramref name="Password"/> is the new password for a change, and
/// <paramref name="CurrentPassword"/> the one being proved — empty for every other kind.</summary>
public sealed record CayaDevCheckCommand(CayaDevCheckCommandKind Kind, string Password, string CurrentPassword = "");

/// <summary>
/// Parses the CaYaDev-Check self-service commands. These only ever arrive via Minecraft's
/// chat_command packet (never plain chat), which already strips the leading slash — so `/register x`
/// and `/cayadevcheck register x` show up here as "register x" and "cayadevcheck register x".
/// Recognized forms: "register &lt;password&gt;", "login &lt;password&gt;", the same two prefixed with
/// "cayadevcheck" or its short alias "cdc", and "premium" / "premium confirm" for a player locking
/// their own name to their Microsoft account. The password itself is never logged — see
/// PlayStateInspector for where the raw command text gets redacted before it reaches any log sink.
/// </summary>
public static class CayaDevCheckCommandParser
{
    public static CayaDevCheckCommand Parse(string commandText)
    {
        string[] parts = commandText.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        // The premium commands carry no password, so they are matched before the two-token forms —
        // "premium confirm" would otherwise be read as a command with "confirm" as its password, and
        // that word would then be redacted from the log as though it were a secret.
        if (parts.Length >= 1 && parts[0].Equals("premium", StringComparison.OrdinalIgnoreCase))
        {
            return parts.Length == 2 && parts[1].Equals("confirm", StringComparison.OrdinalIgnoreCase)
                ? new CayaDevCheckCommand(CayaDevCheckCommandKind.PremiumLockConfirm, "")
                : new CayaDevCheckCommand(CayaDevCheckCommandKind.PremiumLockAsk, "");
        }

        // Three tokens and a change-password verb: old password, then new. Matched before the
        // "cayadevcheck register x" form below, which is also three tokens.
        if (parts.Length == 3 && IsChangePasswordVerb(parts[0]))
            return new CayaDevCheckCommand(CayaDevCheckCommandKind.ChangePassword, parts[2], parts[1]);

        if (parts.Length == 2)
        {
            if (parts[0].Equals("register", StringComparison.OrdinalIgnoreCase))
                return new CayaDevCheckCommand(CayaDevCheckCommandKind.Register, parts[1]);
            if (parts[0].Equals("login", StringComparison.OrdinalIgnoreCase))
                return new CayaDevCheckCommand(CayaDevCheckCommandKind.Login, parts[1]);
        }

        if (parts.Length == 3 &&
            (parts[0].Equals("cayadevcheck", StringComparison.OrdinalIgnoreCase) ||
             parts[0].Equals("cdc", StringComparison.OrdinalIgnoreCase)))
        {
            if (parts[1].Equals("register", StringComparison.OrdinalIgnoreCase))
                return new CayaDevCheckCommand(CayaDevCheckCommandKind.Register, parts[2]);
            if (parts[1].Equals("login", StringComparison.OrdinalIgnoreCase))
                return new CayaDevCheckCommand(CayaDevCheckCommandKind.Login, parts[2]);
        }

        return new CayaDevCheckCommand(CayaDevCheckCommandKind.None, "");
    }

    private static bool IsChangePasswordVerb(string token) =>
        token.Equals("changepassword", StringComparison.OrdinalIgnoreCase) ||
        token.Equals("changepass", StringComparison.OrdinalIgnoreCase) ||
        token.Equals("passwd", StringComparison.OrdinalIgnoreCase);

    /// <summary>True for any recognized CaYaDev-Check command form, used to redact chat text before
    /// logging even when parsing didn't fully succeed (e.g. wrong argument count) — a near-miss typo
    /// of a password command must never end up in a log file either.</summary>
    public static bool LooksLikeCayaDevCheckCommand(string commandText)
    {
        string first = commandText.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
        return first.Equals("register", StringComparison.OrdinalIgnoreCase) ||
               first.Equals("login", StringComparison.OrdinalIgnoreCase) ||
               IsChangePasswordVerb(first) ||
               first.Equals("premium", StringComparison.OrdinalIgnoreCase) ||
               first.Equals("cayadevcheck", StringComparison.OrdinalIgnoreCase) ||
               first.Equals("cdc", StringComparison.OrdinalIgnoreCase);
    }
}
