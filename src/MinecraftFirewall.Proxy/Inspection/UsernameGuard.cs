namespace MinecraftFirewall.Proxy.Inspection;

/// <summary>
/// Checks the username from Login Start before anything else touches it.
///
/// This is the earliest attacker-controlled string in the whole connection, and — importantly — it is
/// a string that gets logged. That combination is precisely how Log4Shell reached Minecraft servers:
/// not through a clever protocol attack, but through a name that the server dutifully wrote to its
/// log, where a formatter interpreted it. Anything downstream that formats a username is a candidate
/// for the same class of bug, including plugins nobody here knows are installed.
///
/// The length check is the part with no judgement in it. The protocol's own limit is 16 characters,
/// so a longer name is not a strict client, a modded client or a Bedrock player — it is not a
/// Minecraft client at all. That makes it safe to refuse outright, and it also bounds every log line,
/// database column and scoreboard entry the name later reaches.
///
/// The character set is deliberately *not* enforced. Vanilla only permits letters, digits and
/// underscores, but Geyser and Floodgate prefix Bedrock players with a dot, and other bridges use
/// their own conventions. Refusing those would break real setups to catch nothing the injection scan
/// does not already catch.
/// </summary>
public static class UsernameGuard
{
    /// <summary>Minecraft's own limit for the Login Start username field.</summary>
    public const int ProtocolMaxLength = 16;

    /// <summary>Returns why the username should be refused, or null if it is acceptable.</summary>
    public static string? Check(string username, InspectionOptions options)
    {
        if (username.Length == 0)
            return "empty username";

        if (username.Length > ProtocolMaxLength)
        {
            return $"username of {username.Length} characters, over the protocol limit of {ProtocolMaxLength}";
        }

        if (!options.ScanForInjectionPayloads)
            return null;

        PayloadFinding? finding = PayloadScanner.Scan(username, ProtocolMaxLength);
        return finding is null ? null : $"{finding.Rule}: {finding.Detail}";
    }

    /// <summary>
    /// A form of the username that is safe to put in a log line, whatever the client sent.
    ///
    /// Used on the refusal path, where by definition the name failed its checks and must still be
    /// reported. Writing the raw value there would hand the payload straight to the log formatter —
    /// which is the exact thing being defended against.
    /// </summary>
    public static string ForLogging(string username)
    {
        Span<char> safe = stackalloc char[Math.Min(username.Length, 32)];
        for (int i = 0; i < safe.Length; i++)
        {
            char c = username[i];
            safe[i] = char.IsLetterOrDigit(c) || c is '_' or '-' or '.' ? c : '?';
        }

        return username.Length > safe.Length
            ? string.Concat(safe, $"… ({username.Length} chars)")
            : new string(safe);
    }
}
