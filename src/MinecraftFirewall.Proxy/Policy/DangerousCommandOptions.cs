namespace MinecraftFirewall.Proxy.Policy;

public sealed class DangerousCommandOptions
{
    public const string SectionName = "DangerousCommands";

    /// <summary>Base command names (no leading slash, no namespace prefix, no arguments) that are
    /// treated as OP-only/destructive. Matching is heuristic defense-in-depth, not a guarantee — see
    /// DangerousCommandMatcher's normalization for exactly what it accounts for.</summary>
    public List<string> Commands { get; set; } =
    [
        "op", "deop", "stop", "ban", "ban-ip", "pardon", "pardon-ip", "whitelist",
        "gamerule", "gamemode", "difficulty", "save-off", "save-on", "kick", "kill",
        "give", "clear", "tp", "teleport", "setblock", "fill", "summon", "execute",
        "reload", "datapack", "worldborder", "defaultgamemode", "forceload",
    ];
}
