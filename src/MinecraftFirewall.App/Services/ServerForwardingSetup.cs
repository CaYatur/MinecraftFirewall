using System.IO;

namespace MinecraftFirewall.App.Services;

/// <summary>
/// One line of one file that would change.
///
/// Identified by its index as well as its text. Searching for the text again at write time finds the
/// FIRST line matching it, which is not necessarily the one that was planned — these key names are
/// short and ordinary, and a file can easily hold the same line under a different parent. Planning
/// inside the right block and then writing outside it is exactly the bug the block scoping exists to
/// prevent, and it is how this was written the first time.
/// </summary>
public sealed record YamlEdit(string FilePath, string Key, int LineIndex, string CurrentLine, string ProposedLine)
{
    public string Describe() => $"{FilePath}{Environment.NewLine}    {CurrentLine.Trim()}  ->  {ProposedLine.Trim()}";
}

/// <summary>What would have to change in a server's own configuration for IP forwarding to work.</summary>
public sealed record ForwardingSetupPlan(
    bool Possible,
    string? RecommendedMode,
    bool AlreadyCorrect,
    IReadOnlyList<YamlEdit> Edits,
    string Explanation);

/// <summary>
/// Turns on the server's own half of IP forwarding, and turns off the half that would conflict.
///
/// Forwarding takes two settings that have to agree, on opposite sides of a boundary, and when they
/// do not agree the failure is total: the server reads the forwarding data as the first Minecraft
/// packet, cannot decode it, and drops every connection. That is why this exists rather than a line
/// in the documentation. Setting one side from the control panel and leaving somebody to find the
/// other is how the mismatch happens.
///
/// <para>
/// There are two settings a server can have, and only one may be on. Paper keeps
/// <c>proxies.proxy-protocol</c> in <c>config/paper-global.yml</c>; Spigot keeps
/// <c>settings.bungeecord</c> in <c>spigot.yml</c>, and Paper honours that one too. Leaving both on
/// does not double anything — it makes the server announce to its plugins that it sits behind a
/// BungeeCord network when it does not, and they believe it. SkinsRestorer switches into proxy mode
/// and stops working; anything else asking the same question does the same. So enabling one always
/// disables the other, inside the same approval.
/// </para>
///
/// <para>
/// A folder with neither file is a vanilla server, and vanilla has no mechanism for this at all — a
/// finding worth stating rather than a failure to apologise for, because no amount of configuring
/// changes it.
/// </para>
///
/// <para>
/// Edits are line-oriented and leave the file byte for byte identical apart from the values changed,
/// line endings included. A YAML round-trip would reformat it and eat the comments it ships with —
/// the same mistake this project already made once, with a JSON round-trip, on the user's own
/// settings.
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
    /// Works out what this server needs, and exactly which lines would change.
    ///
    /// Nothing is written. The result is what the confirmation shows, and it shows every line, because
    /// approving "set my server up" is not the same as approving edits to files somebody else's
    /// software owns.
    /// </summary>
    /// <param name="mode">"ProxyProtocol", "BungeeCord", or anything else meaning off.</param>
    public ForwardingSetupPlan Plan(BackendServerInfo server, string mode)
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

        if (!File.Exists(paper) && !File.Exists(spigot))
        {
            return Impossible(
                $"Neither {PaperFile} nor {SpigotFile} is in {directory}, which means this is a vanilla server. " +
                "Vanilla has no way to be told a player's real address — it only ever sees the socket it is " +
                "talking to, and there is no setting for it. Paper and Spigot both have one. Leave IP " +
                "forwarding off here, or your server will refuse every connection.");
        }

        bool wantProxyProtocol = mode == "ProxyProtocol";
        bool wantBungee = mode == "BungeeCord";

        if (wantProxyProtocol && !File.Exists(paper))
        {
            return Impossible(
                $"PROXY protocol needs Paper, and there is no {PaperFile} in {directory}. On Spigot, choose " +
                "BungeeCord style instead.");
        }

        var edits = new List<YamlEdit>();
        var problems = new List<string>();

        // Both files every time, because only one of these may be on. Leaving the other set is what
        // makes a server tell its plugins it is behind a BungeeCord network when it is not.
        Consider(paper, PaperParent, PaperKey, wantProxyProtocol, edits, problems);
        Consider(spigot, SpigotParent, SpigotKey, wantBungee, edits, problems);

        if (problems.Count > 0 && edits.Count == 0)
            return Impossible(string.Join(" ", problems));

        string recommended = wantProxyProtocol ? "ProxyProtocol" : wantBungee ? "BungeeCord" : "None";

        if (edits.Count == 0)
        {
            return new ForwardingSetupPlan(true, recommended, true, [],
                "Your server is already set up correctly for this. Nothing needs changing.");
        }

        string detail = string.Join(Environment.NewLine, edits.Select(e => e.Describe()));
        int files = edits.Select(e => e.FilePath).Distinct().Count();

        return new ForwardingSetupPlan(true, recommended, false, edits,
            edits.Count == 1
                ? $"One line changes:{Environment.NewLine}{detail}"
                : $"{edits.Count} lines change, in {files} file(s):{Environment.NewLine}{detail}");
    }

    /// <summary>Applies every approved line. Only ever called after a person has seen them all.</summary>
    public (bool Success, string Message) Apply(ForwardingSetupPlan plan)
    {
        if (!plan.Possible)
            return (false, plan.Explanation);

        if (plan.AlreadyCorrect)
            return (true, plan.Explanation);

        var done = new List<string>();

        foreach (YamlEdit edit in plan.Edits)
        {
            (bool ok, string message) = ApplyOne(edit);
            if (!ok)
                return (false, message);

            done.Add($"{Path.GetFileName(edit.FilePath)}: {edit.Key}");
        }

        return (true,
            $"Set {string.Join(", ", done)}. Restart your Minecraft server for it to take effect — until then " +
            "it keeps the old settings, so leave IP forwarding off here until you have. Each file's previous " +
            "version is beside it as .mcfirewall-backup.");
    }

    private static (bool Success, string Message) ApplyOne(YamlEdit edit)
    {
        try
        {
            // Read and written as raw text, split on newlines only. ReadAllLines/WriteAllLines would
            // rewrite every line ending in the file to this machine's — Paper writes LF, Windows writes
            // CRLF — so changing one value would show up as a change to every line. The file parses
            // either way, but "one line changes" has to be true, and a diff full of noise is a diff
            // nobody reads.
            string[] lines = File.ReadAllText(edit.FilePath).Split('\n');

            // The planned line, at the planned place, still saying what it said. Anything else
            // means the file moved between showing somebody the change and making it, and writing
            // then would be writing something nobody agreed to.
            if (edit.LineIndex >= lines.Length || lines[edit.LineIndex].TrimEnd('\r') != edit.CurrentLine)
                return (false, $"{edit.FilePath} changed since this was worked out. Nothing was written — try again.");

            int index = edit.LineIndex;

            File.Copy(edit.FilePath, edit.FilePath + ".mcfirewall-backup", overwrite: true);

            // Whatever this particular line ended with, it still ends with.
            lines[index] = lines[index].EndsWith('\r') ? edit.ProposedLine + "\r" : edit.ProposedLine;
            File.WriteAllText(edit.FilePath, string.Join('\n', lines));

            return (true, "");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (false,
                $"Could not write {edit.FilePath}: {ex.Message}. If the server runs as another user, set " +
                $"{edit.Key} there by hand.");
        }
    }

    /// <summary>Adds an edit for one file's key, if the file has it and it is not already right.</summary>
    private static void Consider(string path, string parent, string key, bool enable,
        List<YamlEdit> edits, List<string> problems)
    {
        if (!File.Exists(path))
            return;

        string[] lines;
        try
        {
            lines = File.ReadAllText(path).Split('\n');
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            problems.Add($"Could not read {path}: {ex.Message}");
            return;
        }

        int index = FindKeyLine(lines, parent, key);
        if (index < 0)
        {
            // Only worth complaining about for the key being turned ON. A file that never had the
            // other one cannot have it set wrongly.
            if (enable)
            {
                problems.Add($"{path} has no {key} under {parent}, which is unusual enough to be worth looking " +
                             "at by hand rather than having this application guess where to add it.");
            }

            return;
        }

        string current = lines[index].TrimEnd('\r');
        bool currentlyOn = current.TrimEnd().EndsWith("true", StringComparison.OrdinalIgnoreCase);

        if (currentlyOn == enable)
            return;

        string indent = current[..(current.Length - current.TrimStart().Length)];
        edits.Add(new YamlEdit(path, key, index, current, $"{indent}{key}: {(enable ? "true" : "false")}"));
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
        int start = Array.FindIndex(lines, line => line.TrimEnd('\r').TrimEnd() == parent + ":");
        if (start < 0)
            return -1;

        for (int i = start + 1; i < lines.Length; i++)
        {
            string line = lines[i].TrimEnd('\r');

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

    private static ForwardingSetupPlan Impossible(string explanation) =>
        new(false, null, false, [], explanation);
}
