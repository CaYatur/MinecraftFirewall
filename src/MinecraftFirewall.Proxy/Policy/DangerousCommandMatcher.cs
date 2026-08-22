namespace MinecraftFirewall.Proxy.Policy;

/// <summary>
/// Normalizes a serverbound command string (leading-slash-stripped, as Minecraft's chat_command
/// packet delivers it) and checks its base command name against the configured dangerous list.
/// Heuristic defense-in-depth, not a guarantee: this only catches the base command name, not every
/// alias a datapack/plugin might register, and can't see commands a mod adds after the fact.
/// </summary>
public static class DangerousCommandMatcher
{
    public static bool IsMatch(string commandText, IReadOnlyCollection<string> dangerousCommands)
    {
        string baseCommand = ExtractBaseCommand(commandText);
        return dangerousCommands.Contains(baseCommand, StringComparer.OrdinalIgnoreCase);
    }

    public static string ExtractBaseCommand(string commandText)
    {
        string text = commandText.TrimStart('/').Trim();
        int spaceIndex = text.IndexOf(' ');
        string first = spaceIndex >= 0 ? text[..spaceIndex] : text;

        // Strip a "minecraft:" (or any other) namespace prefix, e.g. "minecraft:op" -> "op".
        int colonIndex = first.IndexOf(':');
        if (colonIndex >= 0)
            first = first[(colonIndex + 1)..];

        return first.ToLowerInvariant();
    }
}
