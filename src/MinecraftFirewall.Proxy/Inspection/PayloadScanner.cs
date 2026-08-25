using System.Text;

namespace MinecraftFirewall.Proxy.Inspection;

/// <summary>What a scan found, or null when the text was unremarkable.</summary>
public sealed record PayloadFinding(string Rule, string Detail);

/// <summary>
/// Looks at free-form player text for the shapes that attack whatever reads it next.
///
/// The case that motivates this is Log4Shell. A Minecraft server logs chat messages and usernames,
/// and for a while logging one containing <c>${jndi:ldap://…}</c> made the server fetch and execute
/// remote code. That specific hole is patched, but the general shape is not going away: player text
/// reaches log formatters, plugin config parsers, database queries and web panels, and each of those
/// is a different interpreter with a different injection syntax. A proxy that can drop the packet
/// before the backend ever sees it protects software it does not know is installed — including a
/// plugin that has not been updated, which is the realistic failure.
///
/// Obfuscation is the hard part, and it is handled by normalising rather than by pattern-matching.
/// The Log4j lookup syntax lets an attacker write <c>${${lower:j}${lower:n}di:…}</c> or
/// <c>${${::-j}${::-n}${::-d}${::-i}:…}</c>, which no literal search for "jndi" will ever find. So the
/// text is first stripped of the syntax that does the obfuscating — the braces, the dollar signs, the
/// default-value markers, the case-conversion lookup names — and the search runs on what is left.
/// That inverts the problem: instead of enumerating obfuscations, it removes the tools used to build
/// them.
///
/// It scans, it does not sanitise. Nothing here rewrites a packet — a match means the packet is
/// dropped and the player is disconnected, because a partially-cleaned payload passed downstream is
/// how filters get bypassed.
/// </summary>
public static class PayloadScanner
{
    /// <summary>
    /// Lookup schemes that carry a remote fetch. These are the ones that turn a log line into a
    /// network request; the harmless lookups (date, sys, java) are deliberately not listed, because
    /// the point is to catch retrieval, not to ban a syntax.
    /// </summary>
    private static readonly string[] DangerousSchemes =
    [
        "jndi:", "ldap:", "ldaps:", "rmi:", "dns:", "nis:", "iiop:", "corba:", "nds:",
    ];

    /// <summary>
    /// Sequences whose only purpose in an exploit string is to hide the scheme name from a literal
    /// search.
    ///
    /// <c>::</c> earns its place here: it is what is left of <c>${::-x}</c> — a lookup with no name
    /// and no default, which resolves to nothing but breaks up the letters around it — once the
    /// braces and hyphen have been stripped. Without removing it, <c>${::-j}${::-n}${::-d}${::-i}</c>
    /// normalises to <c>::j::n::d::i</c> and the scheme never reassembles.
    /// </summary>
    private static readonly string[] ObfuscationWrappers =
    [
        "::", "lower:", "upper:", "env:", "sys:", "main:", "base64:",
    ];

    public static PayloadFinding? Scan(string text, int maxLength)
    {
        if (text.Length > maxLength)
        {
            return new PayloadFinding("oversized-text",
                $"{text.Length} characters, over the protocol limit of {maxLength}");
        }

        if (ContainsControlCharacters(text, out char offending))
        {
            return new PayloadFinding("control-characters",
                $"contains U+{(int)offending:X4}, which a Minecraft client cannot type");
        }

        string normalized = NormalizeForLookupSearch(text);
        foreach (string scheme in DangerousSchemes)
        {
            if (normalized.Contains(scheme, StringComparison.Ordinal))
            {
                return new PayloadFinding("injection-lookup",
                    $"contains a '{scheme.TrimEnd(':')}' lookup after de-obfuscation");
            }
        }

        return null;
    }

    /// <summary>
    /// Strips the characters and lookup names an attacker uses to break a scheme name into pieces,
    /// then lowercases what remains.
    ///
    /// Worth being precise about the trade-off: this deliberately over-strips. Removing every dollar
    /// sign, brace, hyphen and colon-hyphen pair means an innocent message could in principle be
    /// mangled into something that matches — but for that to happen it would have to already contain
    /// the letters of a scheme name in order, separated only by exactly the punctuation the exploit
    /// syntax uses. The cost of a false positive is one blocked chat message; the cost of a false
    /// negative is remote code execution on the server.
    /// </summary>
    public static string NormalizeForLookupSearch(string text)
    {
        var builder = new StringBuilder(text.Length);

        foreach (char c in text)
        {
            // ${, }, and the :- default-value marker are the whole obfuscation toolkit. Dropping them
            // rejoins a scheme name that was split across nested lookups.
            if (c is '$' or '{' or '}' or '-' or ' ' or '\t')
                continue;

            builder.Append(char.ToLowerInvariant(c));
        }

        string collapsed = builder.ToString();

        // Remove the wrapper names themselves, repeatedly: ${${lower:${lower:j}}ndi:…} nests them, so
        // one pass is not enough. Bounded so a pathological input cannot spin here.
        for (int pass = 0; pass < 4; pass++)
        {
            string before = collapsed;
            foreach (string wrapper in ObfuscationWrappers)
                collapsed = collapsed.Replace(wrapper, "", StringComparison.Ordinal);

            if (collapsed == before)
                break;
        }

        return collapsed;
    }

    /// <summary>
    /// True when the text holds a character a Minecraft client cannot produce.
    ///
    /// The section sign is included on purpose even though it is printable: it is the colour and
    /// formatting escape, and the client strips it from what a player types. One arriving from a
    /// client means something other than the client wrote the message — and it is the standard way to
    /// forge chat that appears to come from the server.
    /// </summary>
    private static bool ContainsControlCharacters(string text, out char offending)
    {
        foreach (char c in text)
        {
            if (c == '§' || (char.IsControl(c) && c is not ('\n' or '\r' or '\t')))
            {
                offending = c;
                return true;
            }
        }

        offending = '\0';
        return false;
    }

    /// <summary>
    /// Whether a plugin-message channel is a well-formed namespaced identifier, as the protocol
    /// requires: <c>namespace:path</c> using only lowercase letters, digits and a short set of
    /// punctuation.
    ///
    /// Checked because the channel name is a string the backend routes on, and a malformed one is
    /// either a broken client or an attempt to reach a handler by a name the server did not intend to
    /// expose. Valid-but-unknown channels are left alone — servers legitimately invent their own, and
    /// an allowlist here would break every modded setup.
    /// </summary>
    public static bool IsValidChannelName(string channel)
    {
        if (channel.Length is 0 or > 256)
            return false;

        int colon = channel.IndexOf(':');
        if (colon <= 0 || colon == channel.Length - 1)
            return false;

        // A dot-dot segment is technically legal in a namespaced identifier — the character set
        // permits it — but nothing legitimate has ever contained one, and a channel name reaching a
        // handler that treats it as a path is exactly where that would matter. Cheap to refuse.
        if (channel.Contains("..", StringComparison.Ordinal))
            return false;

        for (int i = 0; i < channel.Length; i++)
        {
            char c = channel[i];
            bool ok = i < colon
                ? char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '_' or '-' or '.'
                : char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '_' or '-' or '.' or '/' or ':';

            if (!ok)
                return false;
        }

        return true;
    }
}
