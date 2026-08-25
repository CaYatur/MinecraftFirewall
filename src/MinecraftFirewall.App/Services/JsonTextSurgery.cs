using System.Text;

namespace MinecraftFirewall.App.Services;

/// <summary>
/// Replaces one value inside a JSON document by editing the text, leaving every other byte exactly
/// as it was.
///
/// This exists because the obvious approach does not work. Parsing with
/// <c>JsonCommentHandling.Skip</c> and writing the document back out through <c>JsonNode</c> silently
/// discards every comment in the file — <c>System.Text.Json</c> has no comment-preserving DOM, and
/// "Skip" means "drop", not "keep aside". The shipped appsettings.json is more explanatory comment
/// than configuration: roughly a hundred lines saying why the honeypot ships switched off, why
/// movement analysis only reports, why disabling premium verification denies rather than falls back.
/// Someone renaming their server from the control panel would have deleted all of it, and would never
/// have known.
///
/// So the editor finds the exact character span of the value it needs to change and splices new text
/// over it. Everything outside that span — comments, formatting, sections this app knows nothing
/// about, trailing commas — is preserved because it is never touched.
///
/// The scanner is string-aware and comment-aware, which is the part that has to be right: a brace
/// inside a string literal or a comment must not be counted as structure, or the span ends in the
/// wrong place and the splice corrupts the file.
/// </summary>
public static class JsonTextSurgery
{
    /// <summary>
    /// Replaces the value at <paramref name="path"/> with <paramref name="newValueText"/>, which must
    /// already be valid JSON. Returns null when the path is not present, so the caller can decide
    /// what to do rather than having a decision made for it.
    /// </summary>
    public static string? ReplaceValue(string json, IReadOnlyList<string> path, string newValueText)
    {
        if (!TryFindValueSpan(json, path, out int start, out int end))
            return null;

        // Continuation lines are re-indented to sit under the property they belong to. Purely
        // cosmetic, but a config file people are expected to read by hand should not come back from
        // an edit looking like it was machine-mangled.
        string indented = Indent(newValueText, IndentationOf(json, start));

        return string.Concat(json.AsSpan(0, start), indented, json.AsSpan(end));
    }

    /// <summary>
    /// Copies whole top-level sections from one document into another, inserting them just before the
    /// root object closes.
    ///
    /// This exists for upgrades. A release that adds settings ships them in its own appsettings.json,
    /// but an existing installation keeps the file it already has — which is the right default, since
    /// that file holds the user's servers and protected usernames. The consequence is a configuration
    /// with no section for the new features at all, and every switch for them failing with "could not
    /// find that setting". Copying the section across, comments and all, is what closes that gap
    /// without touching anything the user wrote.
    ///
    /// Returns null if any requested section is missing from the source, since a half-applied repair
    /// would be worse than none.
    /// </summary>
    public static string? CopySections(string target, string source, IReadOnlyList<string> sectionNames)
    {
        if (sectionNames.Count == 0)
            return target;

        var blocks = new List<string>();
        foreach (string name in sectionNames)
        {
            if (!TryFindValueSpan(source, [name], out int start, out int end))
                return null;

            // The comment block immediately above a section is part of it as far as a reader is
            // concerned — it is where the explanation of what the setting does actually lives, and
            // copying the value without it would deliver settings nobody can interpret.
            int commentStart = StartOfLeadingComments(source, start, name);

            blocks.Add(source[commentStart..end].TrimEnd());
        }

        int insertAt = EndOfRootObject(target);
        if (insertAt < 0)
            return null;

        // The property this is being inserted after has no comma of its own — it was the last one. So
        // one has to be added here, unless the root object is empty or already ends in a comma. Getting
        // this wrong produces a file that looks right and does not parse, which is the worst outcome
        // available for a repair whose entire purpose is not to damage anyone's configuration.
        string separator = Environment.NewLine + Environment.NewLine + "  ";
        string lead = NeedsSeparatingComma(target, insertAt) ? "," : "";
        string added = lead + separator + string.Join("," + separator, blocks);

        return string.Concat(target.AsSpan(0, insertAt), added, Environment.NewLine, target.AsSpan(insertAt));
    }

    /// <summary>True when the character before the root object's closing brace is the end of a value
    /// rather than an opening brace or an existing comma. Comments and whitespace are stepped over —
    /// a trailing explanation before the final brace is common in this project's own config.</summary>
    private static bool NeedsSeparatingComma(string json, int closingBrace)
    {
        int i = closingBrace - 1;

        while (i >= 0)
        {
            if (char.IsWhiteSpace(json[i]))
            {
                i--;
                continue;
            }

            // A line comment is only recognisable by scanning forward from its start, so step back to
            // the beginning of the line and check whether it is one.
            int lineStart = json.LastIndexOf('\n', i) + 1;
            string line = json[lineStart..(i + 1)].TrimStart();
            if (line.StartsWith("//", StringComparison.Ordinal))
            {
                i = lineStart - 1;
                continue;
            }

            return json[i] is not ('{' or ',');
        }

        return false;
    }

    /// <summary>Walks backwards from a property's value to the start of the comment block introducing
    /// it, including the property name itself.</summary>
    private static int StartOfLeadingComments(string json, int valueStart, string name)
    {
        int nameIndex = json.LastIndexOf('"' + name + '"', valueStart, StringComparison.Ordinal);
        if (nameIndex < 0)
            return valueStart;

        int lineStart = json.LastIndexOf('\n', nameIndex) + 1;

        // Step back over contiguous comment lines. A blank line ends the block: comments separated
        // from a property by an empty line belong to whatever came before it.
        while (lineStart > 0)
        {
            int previousStart = json.LastIndexOf('\n', lineStart - 2) + 1;
            if (previousStart < 0 || previousStart >= lineStart)
                break;

            string previous = json[previousStart..(lineStart - 1)].Trim();
            if (!previous.StartsWith("//", StringComparison.Ordinal))
                break;

            lineStart = previousStart;
        }

        return lineStart;
    }

    /// <summary>Index of the root object's closing brace, so new properties can be inserted before it.
    /// Found by matching rather than by searching for the last brace, which would land inside a
    /// trailing comment.</summary>
    private static int EndOfRootObject(string json)
    {
        int start = SkipTrivia(json, 0);
        if (start >= json.Length || json[start] != '{')
            return -1;

        int end = SkipBalanced(json, start, '{', '}');
        return end <= start ? -1 : end - 1;
    }

    /// <summary>Finds the character span of the value at a property path, exclusive of surrounding
    /// whitespace. <paramref name="path"/> walks nested objects: ["Premium", "AutoClaim"].</summary>
    public static bool TryFindValueSpan(string json, IReadOnlyList<string> path, out int start, out int end)
    {
        start = end = 0;

        int i = SkipTrivia(json, 0);
        if (i >= json.Length || json[i] != '{')
            return false;

        int objectStart = i;

        for (int segment = 0; segment < path.Count; segment++)
        {
            if (!TryFindProperty(json, objectStart, path[segment], out int valueStart, out int valueEnd))
                return false;

            if (segment == path.Count - 1)
            {
                start = valueStart;
                end = valueEnd;
                return true;
            }

            // Every non-final segment has to be an object, or the path does not describe this document.
            if (json[valueStart] != '{')
                return false;

            objectStart = valueStart;
        }

        return false;
    }

    private static bool TryFindProperty(string json, int objectStart, string name, out int valueStart, out int valueEnd)
    {
        valueStart = valueEnd = 0;

        int i = SkipTrivia(json, objectStart + 1);

        while (i < json.Length)
        {
            if (json[i] == '}')
                return false;

            if (json[i] == ',')
            {
                i = SkipTrivia(json, i + 1);
                continue;
            }

            if (json[i] != '"')
                return false; // not a well-formed object at this point

            int keyEnd = SkipString(json, i);
            string key = json[(i + 1)..(keyEnd - 1)];

            i = SkipTrivia(json, keyEnd);
            if (i >= json.Length || json[i] != ':')
                return false;

            i = SkipTrivia(json, i + 1);
            int start = i;
            int end = SkipValue(json, i);

            if (key == name)
            {
                valueStart = start;
                valueEnd = end;
                return true;
            }

            i = SkipTrivia(json, end);
        }

        return false;
    }

    /// <summary>Returns the index just past a complete JSON value starting at <paramref name="i"/>.</summary>
    private static int SkipValue(string json, int i)
    {
        if (i >= json.Length)
            return i;

        return json[i] switch
        {
            '{' => SkipBalanced(json, i, '{', '}'),
            '[' => SkipBalanced(json, i, '[', ']'),
            '"' => SkipString(json, i),
            _ => SkipScalar(json, i),
        };
    }

    /// <summary>
    /// Walks from an opening bracket to its match.
    ///
    /// Strings and comments are skipped wholesale rather than scanned character by character, which is
    /// the entire correctness argument: a <c>}</c> inside a comment explaining the option above it, or
    /// inside a message string, is not structure, and counting it would end the span early and corrupt
    /// the file on write.
    /// </summary>
    private static int SkipBalanced(string json, int i, char open, char close)
    {
        int depth = 0;

        while (i < json.Length)
        {
            char c = json[i];

            if (c == '"')
            {
                i = SkipString(json, i);
                continue;
            }

            if (c == '/' && i + 1 < json.Length && (json[i + 1] == '/' || json[i + 1] == '*'))
            {
                i = SkipComment(json, i);
                continue;
            }

            if (c == open)
                depth++;
            else if (c == close && --depth == 0)
                return i + 1;

            i++;
        }

        return i;
    }

    private static int SkipString(string json, int i)
    {
        i++; // opening quote
        while (i < json.Length)
        {
            if (json[i] == '\\')
            {
                i += 2;
                continue;
            }

            if (json[i] == '"')
                return i + 1;

            i++;
        }

        return i;
    }

    private static int SkipScalar(string json, int i)
    {
        while (i < json.Length && json[i] is not (',' or '}' or ']') && !char.IsWhiteSpace(json[i]))
            i++;

        return i;
    }

    private static int SkipComment(string json, int i)
    {
        if (json[i + 1] == '/')
        {
            while (i < json.Length && json[i] != '\n')
                i++;

            return i;
        }

        i += 2;
        while (i + 1 < json.Length && !(json[i] == '*' && json[i + 1] == '/'))
            i++;

        return Math.Min(i + 2, json.Length);
    }

    private static int SkipTrivia(string json, int i)
    {
        while (i < json.Length)
        {
            if (char.IsWhiteSpace(json[i]))
            {
                i++;
            }
            else if (json[i] == '/' && i + 1 < json.Length && (json[i + 1] == '/' || json[i + 1] == '*'))
            {
                i = SkipComment(json, i);
            }
            else
            {
                return i;
            }
        }

        return i;
    }

    /// <summary>How far the line containing <paramref name="index"/> is indented, so replacement text
    /// can be lined up with what it is replacing.</summary>
    private static int IndentationOf(string json, int index)
    {
        int lineStart = json.LastIndexOf('\n', Math.Max(0, index - 1)) + 1;
        int spaces = 0;
        while (lineStart + spaces < index && json[lineStart + spaces] == ' ')
            spaces++;

        return spaces;
    }

    private static string Indent(string valueText, int spaces)
    {
        if (spaces == 0)
            return valueText;

        string pad = new(' ', spaces);
        var builder = new StringBuilder(valueText.Length + 32);

        // The first line is left alone: it starts where the old value started, which is already
        // indented by whatever precedes it on that line.
        string[] lines = valueText.Replace("\r\n", "\n").Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            if (i > 0)
                builder.Append(Environment.NewLine).Append(pad);

            builder.Append(lines[i]);
        }

        return builder.ToString();
    }
}
