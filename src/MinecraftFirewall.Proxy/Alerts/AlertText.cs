using System.Text.RegularExpressions;

namespace MinecraftFirewall.Proxy.Alerts;

/// <summary>
/// Makes attacker-influenced text safe to post into a chat channel.
///
/// Alert bodies embed values that came off the wire — usernames, handshake hostnames, command names.
/// Two things follow from that. First, a mass mention (<c>@everyone</c>/<c>@here</c>) chosen as a
/// hostname would let anyone who can reach the public port ping an entire Discord server at will, so
/// mentions are defanged rather than escaped (escaping is renderer-dependent; a zero-width break is
/// not). Second, arbitrary text can carry markdown, newlines that fake extra alert lines, or enough
/// length to blow Discord's 2000-character limit and get the whole post rejected — so control
/// characters go, and everything is length-capped.
/// </summary>
public static partial class AlertText
{
    public const int MaxMessageLength = 1800; // Discord's limit is 2000; leave headroom for prefixes.
    private const int MaxFieldLength = 200;

    [GeneratedRegex(@"@(everyone|here)", RegexOptions.IgnoreCase)]
    private static partial Regex MassMentionRegex();

    [GeneratedRegex(@"[\p{C}]")]
    private static partial Regex ControlCharacterRegex();

    /// <summary>Sanitizes one untrusted value for embedding in an alert.</summary>
    public static string Field(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return "(empty)";

        string cleaned = ControlCharacterRegex().Replace(value, " ");
        cleaned = MassMentionRegex().Replace(cleaned, m => "@​" + m.Groups[1].Value);
        cleaned = cleaned.Replace("`", "'", StringComparison.Ordinal);

        return cleaned.Length > MaxFieldLength ? cleaned[..MaxFieldLength] + "…" : cleaned;
    }

    /// <summary>Final guard on a fully-composed message, in case several sanitized fields still add
    /// up past the limit — an over-long post is rejected by Discord outright, i.e. a silently lost alert.</summary>
    public static string Truncate(string message) =>
        message.Length > MaxMessageLength ? message[..MaxMessageLength] + "…" : message;
}
