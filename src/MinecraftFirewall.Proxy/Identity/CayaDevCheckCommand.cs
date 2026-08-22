namespace MinecraftFirewall.Proxy.Identity;

public enum CayaDevCheckCommandKind
{
    None,
    Register,
    Login,
}

public sealed record CayaDevCheckCommand(CayaDevCheckCommandKind Kind, string Password);

/// <summary>
/// Parses the CaYaDev-Check self-service commands. These only ever arrive via Minecraft's
/// chat_command packet (never plain chat), which already strips the leading slash — so `/register x`
/// and `/cayadevcheck register x` show up here as "register x" and "cayadevcheck register x".
/// Recognized forms: "register &lt;password&gt;", "login &lt;password&gt;", and the same two prefixed
/// with "cayadevcheck" or its short alias "cdc". The password itself is never logged — see
/// PlayStateInspector for where the raw command text gets redacted before it reaches any log sink.
/// </summary>
public static class CayaDevCheckCommandParser
{
    public static CayaDevCheckCommand Parse(string commandText)
    {
        string[] parts = commandText.Split(' ', StringSplitOptions.RemoveEmptyEntries);

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

    /// <summary>True for any recognized CaYaDev-Check command form, used to redact chat text before
    /// logging even when parsing didn't fully succeed (e.g. wrong argument count) — a near-miss typo
    /// of a password command must never end up in a log file either.</summary>
    public static bool LooksLikeCayaDevCheckCommand(string commandText)
    {
        string first = commandText.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
        return first.Equals("register", StringComparison.OrdinalIgnoreCase) ||
               first.Equals("login", StringComparison.OrdinalIgnoreCase) ||
               first.Equals("cayadevcheck", StringComparison.OrdinalIgnoreCase) ||
               first.Equals("cdc", StringComparison.OrdinalIgnoreCase);
    }
}
