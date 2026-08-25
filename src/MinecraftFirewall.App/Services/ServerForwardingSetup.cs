using System.IO;

namespace MinecraftFirewall.App.Services;

/// <summary>What would have to change in a server's own configuration for IP forwarding to work.</summary>
public sealed record ForwardingSetupPlan(
    bool Possible,
    string? FilePath,
    string? Key,
    string? RecommendedMode,
    bool AlreadyEnabled,
    string? CurrentLine,
    string? ProposedLine,
    string Explanation);

/// <summary>
/// Turns on the server's own half of IP forwarding.
///
/// Forwarding takes two settings that have to agree, on opposite sides of a boundary, and when they
/// do not agree the failure is total: the server reads the forwarding data as the first Minecraft
/// packet, cannot decode it, and drops every connection. That is why this exists — rather than a line
/// in the documentation. Setting one side from the control panel and leaving somebody to find the
/// other is how the mismatch happens.
///
/// <para>
/// Which setting depends on what the server is, and that is decided by which file exists rather than
/// by asking: Paper keeps <c>proxies.proxy-protocol</c> in <c>config/paper-global.yml</c>, Spigot
/// keeps <c>settings.bungeecord</c> in <c>spigot.yml</c>. A folder with neither is a vanilla server,
/// and vanilla has no mechanism for this at all — which is worth saying as a finding rather than as
/// a failure, because no amount of configuring will change it.
/// </para>
///
/// <para>
/// The edit is line-oriented and touches exactly one line. A YAML round-trip would reformat the file
/// and eat the comments Paper ships to explain its own settings — the same mistake this project has
/// already made once, with a JSON round-trip, on the user's own configuration.
/// </para>
/// </summary>
public sealed class ServerForwardingSetup
{
    private const string PaperFile = "config/paper-global.yml";
    private const string PaperParent = "proxies";
    private const string PaperKey = "proxy-protocol";

    private const string SpigotFile = "spigot.yml";
    private const string SpigotParent = "settings";
    private const string SpigotKey = "bungeecord";

    /// <summary>
    /// Works out which setting this server needs, and what the line would become.
    ///
    /// Nothing is written. The result is what the confirmation shows, and what it shows is the exact
    /// file and the exact line, because approving "enable forwarding" is not the same as approving a
    /// change to a file somebody else's software owns.
    /// </summary>
    public ForwardingSetupPlan Plan(BackendServerInfo server, bool enable)
    {
        if (server.Directory is not { } directory)
        {
            return Impossible(
                "The Minecraft server's folder could not be found. It is located by matching the port in a " +
                "server.properties against this profile's backend port, which needs the server to be running " +
                "and readable by this account.");
        }

        string paper = Path.Combine(directory, PaperFile.Replace('/', Path.DirectorySeparatorChar));
        string spigot = Path.Combine(directory, SpigotFile);

        // Paper first: a Paper server has both files, and proxy protocol is the better of the two — it
        // knows nothing about Minecraft's protocol, so it does not move when the game does, and it
        // covers the server-list ping as well as joining.
        if (File.Exists(paper))
            return Read(paper, PaperParent, PaperKey, "ProxyProtocol", enable);

        if (File.Exists(spigot))
            return Read(spigot, SpigotParent, SpigotKey, "BungeeCord", enable);

        return Impossible(
            $"Neither {PaperFile} nor {SpigotFile} is in {directory}, which means this is a vanilla server. " +
            "Vanilla has no way to be told a player's real address — it only ever sees the socket it is " +
            "talking to, and there is no setting for it. Paper and Spigot both have one. Until then, leave " +
            "IP forwarding off, or your server will refuse every connection.");
    }

    /// <summary>Applies the one-line change. Only ever called after a person has approved the exact
    /// line in <see cref="ForwardingSetupPlan.ProposedLine"/>.</summary>
    public (bool Success, string Message) Apply(ForwardingSetupPlan plan)
    {
        if (!plan.Possible || plan.FilePath is not { } path || plan.ProposedLine is not { } proposed)
            return (false, plan.Explanation);

        try
        {
            string[] lines = File.ReadAllLines(path);
            int index = FindKeyLine(lines, ParentOf(path), KeyOf(path));

            if (index < 0)
                return (false, $"Could not find where to put {KeyOf(path)} in {path}. Set it by hand.");

            // One backup, beside the file, so a person who does not like the result can put it back
            // without needing this application to do it for them.
            File.Copy(path, path + ".mcfirewall-backup", overwrite: true);

            lines[index] = proposed;
            File.WriteAllLines(path, lines);

            return (true,
                $"Set in {path}. Restart your Minecraft server for it to take effect — until then it keeps " +
                "the old setting, so leave IP forwarding off here until you have. The previous file is beside " +
                "it as .mcfirewall-backup.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (false,
                $"Could not write {path}: {ex.Message}. If the server runs as another user, set " +
                $"{KeyOf(path)} there by hand.");
        }
    }

    private static ForwardingSetupPlan Read(string path, string parent, string key, string mode, bool enable)
    {
        string[] lines;
        try
        {
            lines = File.ReadAllLines(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Impossible($"Could not read {path}: {ex.Message}");
        }

        int index = FindKeyLine(lines, parent, key);

        if (index < 0)
        {
            return new ForwardingSetupPlan(false, path, key, mode, false, null, null,
                $"{path} has no {key} under {parent}. That is unusual enough to be worth looking at by hand " +
                "rather than having this application guess where to add it.");
        }

        string current = lines[index];
        bool alreadyEnabled = current.TrimEnd().EndsWith("true", StringComparison.OrdinalIgnoreCase);

        string indent = current[..(current.Length - current.TrimStart().Length)];
        string proposed = $"{indent}{key}: {(enable ? "true" : "false")}";

        return new ForwardingSetupPlan(true, path, key, mode, alreadyEnabled, current, proposed,
            alreadyEnabled == enable
                ? $"{key} in {path} is already {(enable ? "true" : "false")}. Nothing needs changing."
                : $"One line in {path} changes:{Environment.NewLine}{current.Trim()}  ->  {proposed.Trim()}");
    }

    /// <summary>
    /// Finds the key's line inside its parent block, and only inside it.
    ///
    /// Scoped to the block on purpose. Both of these key names are short and ordinary, and a search of
    /// the whole file would happily find one in a comment or under a different parent — then rewrite
    /// it, in a file the server owns and this application does not.
    /// </summary>
    private static int FindKeyLine(string[] lines, string parent, string key)
    {
        int start = Array.FindIndex(lines, line => line.TrimEnd() == parent + ":");
        if (start < 0)
            return -1;

        for (int i = start + 1; i < lines.Length; i++)
        {
            string line = lines[i];

            if (line.Trim().Length == 0)
                continue;

            // Back at the outer level: the block is over, and the key was not in it.
            if (!char.IsWhiteSpace(line[0]))
                return -1;

            string trimmed = line.TrimStart();
            if (trimmed.StartsWith('#'))
                continue;

            if (trimmed.StartsWith(key + ":", StringComparison.Ordinal))
                return i;
        }

        return -1;
    }

    private static string ParentOf(string path) =>
        path.EndsWith(SpigotFile, StringComparison.OrdinalIgnoreCase) ? SpigotParent : PaperParent;

    private static string KeyOf(string path) =>
        path.EndsWith(SpigotFile, StringComparison.OrdinalIgnoreCase) ? SpigotKey : PaperKey;

    private static ForwardingSetupPlan Impossible(string explanation) =>
        new(false, null, null, null, false, null, null, explanation);
}
