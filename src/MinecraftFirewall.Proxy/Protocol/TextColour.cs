using System.Text;

namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>One run of text that shares a single appearance.</summary>
public readonly record struct TextRun(string Text, string? Colour, bool Bold, bool Italic, bool Underlined, bool Strikethrough, bool Obfuscated)
{
    public bool IsPlain => Colour is null && !Bold && !Italic && !Underlined && !Strikethrough && !Obfuscated;
}

/// <summary>
/// Turns Minecraft's familiar formatting codes into runs of styled text.
///
/// The codes are the ones every server owner already knows — <c>§c</c> for red, <c>§l</c> for bold —
/// and they are accepted with <c>&amp;</c> as well, because typing a section sign into a JSON file is
/// awkward and nobody does it. That is the whole reason this exists rather than a set of colour
/// fields in configuration: an admin writing a prompt should be able to colour a word of it the same
/// way they would anywhere else in Minecraft, without learning a new syntax.
///
/// <c>&amp;</c> is only treated as a code when the character after it is a lowercase code or a digit,
/// so ordinary text like "Q&amp;A" survives untouched.
/// </summary>
public static class TextColour
{
    private static readonly Dictionary<char, string> Colours = new()
    {
        ['0'] = "black",
        ['1'] = "dark_blue",
        ['2'] = "dark_green",
        ['3'] = "dark_aqua",
        ['4'] = "dark_red",
        ['5'] = "dark_purple",
        ['6'] = "gold",
        ['7'] = "gray",
        ['8'] = "dark_gray",
        ['9'] = "blue",
        ['a'] = "green",
        ['b'] = "aqua",
        ['c'] = "red",
        ['d'] = "light_purple",
        ['e'] = "yellow",
        ['f'] = "white",
    };

    private const string Decorations = "klmno";
    private const char Reset = 'r';

    /// <summary>True when this text carries any formatting at all. Used to keep the common case on the
    /// cheaper encoding: a message with no codes in it stays a single flat component.</summary>
    public static bool HasCodes(string text)
    {
        for (int i = 0; i + 1 < text.Length; i++)
        {
            if (IsCodeStart(text, i))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Splits text into runs, each carrying the appearance in force where it appears.
    ///
    /// Every run states its appearance in full rather than relying on what came before. Minecraft's
    /// components inherit from their parent, so a run that simply left out a colour would quietly pick
    /// up whatever the surrounding message happened to be — which is how a message ends up half red
    /// because something earlier in the chat was.
    /// </summary>
    public static List<TextRun> Split(string text)
    {
        var runs = new List<TextRun>();
        var current = new StringBuilder();

        string? colour = null;
        bool bold = false, italic = false, underlined = false, strikethrough = false, obfuscated = false;

        void Flush()
        {
            if (current.Length == 0)
                return;

            runs.Add(new TextRun(current.ToString(), colour, bold, italic, underlined, strikethrough, obfuscated));
            current.Clear();
        }

        for (int i = 0; i < text.Length; i++)
        {
            if (!IsCodeStart(text, i))
            {
                current.Append(text[i]);
                continue;
            }

            char code = char.ToLowerInvariant(text[i + 1]);
            Flush();
            i++;

            if (code == Reset)
            {
                colour = null;
                bold = italic = underlined = strikethrough = obfuscated = false;
            }
            else if (Colours.TryGetValue(code, out string? named))
            {
                // A colour resets decorations, exactly as it does in the game. Without this, a bold
                // word would silently make the rest of the line bold too.
                colour = named;
                bold = italic = underlined = strikethrough = obfuscated = false;
            }
            else
            {
                switch (code)
                {
                    case 'k': obfuscated = true; break;
                    case 'l': bold = true; break;
                    case 'm': strikethrough = true; break;
                    case 'n': underlined = true; break;
                    case 'o': italic = true; break;
                }
            }
        }

        Flush();
        return runs;
    }

    /// <summary>Removes the codes without applying them — for anything that has to hold plain text,
    /// such as a log line.</summary>
    public static string Strip(string text)
    {
        var plain = new StringBuilder(text.Length);

        for (int i = 0; i < text.Length; i++)
        {
            if (IsCodeStart(text, i))
            {
                i++;
                continue;
            }

            plain.Append(text[i]);
        }

        return plain.ToString();
    }

    private static bool IsCodeStart(string text, int index)
    {
        if (index + 1 >= text.Length)
            return false;

        char marker = text[index];
        if (marker is not ('§' or '&'))
            return false;

        char code = text[index + 1];

        // The section sign is never typed by accident, so it takes any case. An ampersand is, so it
        // only counts when what follows could not plausibly be ordinary prose.
        if (marker == '§')
            code = char.ToLowerInvariant(code);
        else if (char.IsUpper(code))
            return false;

        return Colours.ContainsKey(code) || Decorations.Contains(code) || code == Reset;
    }
}
