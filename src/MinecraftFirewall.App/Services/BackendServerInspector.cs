using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace MinecraftFirewall.App.Services;

/// <summary>What could be learned about the Minecraft server sitting behind the proxy.</summary>
public sealed record BackendServerInfo(
    string? Directory,
    string? ServerVersion,
    int? ProtocolVersion,
    bool HasViaVersion,
    bool HasViaBackwards,
    IReadOnlyList<string> Plugins);

/// <summary>
/// Works out what the server behind the proxy actually is, by finding the process listening on its
/// port and reading its own files.
///
/// The alternative — asking the admin to tell the control panel their server version — gets answered
/// wrongly or not at all, and the answer that matters most (whether ViaVersion is installed) is one
/// most people would not think to mention. The process is right there holding the port, its working
/// directory is knowable, and everything worth knowing is a file in it.
///
/// Read-only, and every step is allowed to fail. A server started from an unusual launcher, running as
/// another user, or living somewhere the control panel cannot read leaves this returning nulls, which
/// the caller renders as "could not tell" rather than as a finding. Nothing here changes a decision the
/// firewall makes; it exists to tell a person what their own setup implies.
/// </summary>
public sealed class BackendServerInspector
{
    /// <summary>Matches the version out of a server jar's name, which is where Paper, Purpur and
    /// Spigot all put it, and out of version_history.json where Paper also records it.</summary>
    private static readonly Regex VersionPattern = new(@"1\.\d{1,2}(\.\d{1,2})?", RegexOptions.Compiled);

    public BackendServerInfo Inspect(int backendPort)
    {
        string? directory = FindWorkingDirectory(backendPort);
        if (directory is null || !Directory.Exists(directory))
            return new BackendServerInfo(null, null, null, false, false, []);

        (string? version, int? protocol) = ReadVersion(directory);
        IReadOnlyList<string> plugins = ReadPlugins(directory);

        return new BackendServerInfo(
            directory,
            version,
            protocol,
            plugins.Any(p => p.Contains("viaversion", StringComparison.OrdinalIgnoreCase)),
            plugins.Any(p => p.Contains("viabackwards", StringComparison.OrdinalIgnoreCase)),
            plugins);
    }

    /// <summary>
    /// Where the Minecraft server behind the proxy actually lives.
    ///
    /// Two attempts, because the obvious one is not enough. Reading the listening process's command
    /// line works when somebody launched it with a full path, but the ordinary way to start a
    /// Minecraft server is `java -jar paper.jar` from inside its own folder — a relative path that
    /// names no directory at all, and a Java process's own image path points at the JVM.
    ///
    /// So the fallback uses the thing that identifies a server uniquely and is already known: its
    /// port. Every server has a server.properties saying which port it listens on, so a folder whose
    /// server.properties matches the backend port is that server, wherever it happens to be. The
    /// search is bounded in both breadth and depth — this runs when somebody presses a button, not on
    /// a timer, and a scan of an entire disk would be a poor way to answer a question about one port.
    /// </summary>
    private static string? FindWorkingDirectory(int backendPort) =>
        FromCommandLine(backendPort) ?? FromServerProperties(backendPort);

    private static string? FromCommandLine(int backendPort)
    {
        try
        {
            int? pid = FindListeningProcess(backendPort);
            if (pid is null)
                return null;

            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");

            foreach (System.Management.ManagementBaseObject item in searcher.Get())
            {
                if (item["CommandLine"] is not string commandLine)
                    continue;

                Match jar = Regex.Match(commandLine, @"([A-Za-z]:\\[^""]*?\.jar)", RegexOptions.IgnoreCase);
                if (jar.Success)
                    return Path.GetDirectoryName(jar.Groups[1].Value);
            }
        }
        catch
        {
            // WMI unavailable, access denied, or the process gone since — all of which mean the same
            // thing here: try the other way.
        }

        return null;
    }

    /// <summary>Roots worth looking under. Where people actually keep a Minecraft server, plus the
    /// root of every fixed drive for the ones who keep it at C:\MinecraftServer.</summary>
    private static IEnumerable<string> SearchRoots()
    {
        yield return Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        foreach (DriveInfo drive in DriveInfo.GetDrives())
        {
            if (drive.DriveType == DriveType.Fixed && drive.IsReady)
                yield return drive.RootDirectory.FullName;
        }
    }

    private static string? FromServerProperties(int backendPort)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (string root in SearchRoots())
        {
            if (string.IsNullOrEmpty(root) || !seen.Add(root) || !Directory.Exists(root))
                continue;

            string? found = SearchForServerProperties(root, backendPort, depth: 0);
            if (found is not null)
                return found;
        }

        return null;
    }

    /// <summary>
    /// Walks a limited way down looking for a server.properties on the right port.
    ///
    /// Recursion is written by hand rather than using SearchOption.AllDirectories so the depth can be
    /// capped and unreadable folders skipped individually — one access-denied directory must not end
    /// the search, and on a user profile there are always several.
    /// </summary>
    private static string? SearchForServerProperties(string directory, int backendPort, int depth)
    {
        const int maxDepth = 3;

        try
        {
            string properties = Path.Combine(directory, "server.properties");
            if (File.Exists(properties) && PortIn(properties) == backendPort)
                return directory;

            if (depth >= maxDepth)
                return null;

            foreach (string child in Directory.EnumerateDirectories(directory))
            {
                string name = Path.GetFileName(child);

                // Skipping the places a Minecraft server is never kept is what makes this fast enough
                // to run from a button press rather than a background job.
                if (name.StartsWith('.') || name is "Windows" or "$Recycle.Bin" or "System Volume Information"
                    or "node_modules" or "AppData" or "ProgramData")
                {
                    continue;
                }

                string? found = SearchForServerProperties(child, backendPort, depth + 1);
                if (found is not null)
                    return found;
            }
        }
        catch
        {
            // Unreadable directory — skip it and keep looking elsewhere.
        }

        return null;
    }

    private static int? PortIn(string serverProperties)
    {
        try
        {
            foreach (string line in File.ReadLines(serverProperties))
            {
                if (line.StartsWith("server-port=", StringComparison.OrdinalIgnoreCase)
                    && int.TryParse(line["server-port=".Length..].Trim(), out int port))
                {
                    return port;
                }
            }
        }
        catch
        {
            // Locked or unreadable while the server writes it.
        }

        return null;
    }

    private static int? FindListeningProcess(int port)
    {
        try
        {
            var startInfo = new ProcessStartInfo("netstat.exe")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            startInfo.ArgumentList.Add("-ano");

            using Process? process = Process.Start(startInfo);
            if (process is null)
                return null;

            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            foreach (string line in output.Split('\n'))
            {
                if (!line.Contains("LISTENING", StringComparison.Ordinal) || !line.Contains($":{port} ", StringComparison.Ordinal))
                    continue;

                string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 0 && int.TryParse(parts[^1], out int pid))
                    return pid;
            }
        }
        catch
        {
            // Same as above.
        }

        return null;
    }

    /// <summary>Reads the server version from whichever of the usual places exists. Paper keeps a
    /// version_history.json; everything else has it in the jar's filename.</summary>
    private static (string? Version, int? Protocol) ReadVersion(string directory)
    {
        try
        {
            string history = Path.Combine(directory, "version_history.json");
            if (File.Exists(history))
            {
                Match match = VersionPattern.Match(File.ReadAllText(history));
                if (match.Success)
                    return (match.Value, ProtocolFor(match.Value));
            }

            foreach (string jar in Directory.EnumerateFiles(directory, "*.jar", SearchOption.TopDirectoryOnly))
            {
                Match match = VersionPattern.Match(Path.GetFileName(jar));
                if (match.Success)
                    return (match.Value, ProtocolFor(match.Value));
            }
        }
        catch
        {
            // Unreadable directory — reported as "could not tell".
        }

        return (null, null);
    }

    /// <summary>
    /// Protocol number for a release, for the handful the control panel wants to talk about.
    ///
    /// Deliberately small and only used for display. The proxy's own registry is the authority on what
    /// can be inspected, and it is generated rather than typed — this is here so the panel can say
    /// "your server is 1.21.6" without a second generated table for something nobody's security
    /// depends on.
    /// </summary>
    private static int? ProtocolFor(string version) => version switch
    {
        "1.20.2" => 764,
        "1.20.3" or "1.20.4" => 765,
        "1.20.5" or "1.20.6" => 766,
        "1.21" or "1.21.1" => 767,
        "1.21.2" or "1.21.3" => 768,
        "1.21.4" => 769,
        "1.21.5" => 770,
        "1.21.6" => 771,
        "1.21.7" or "1.21.8" => 772,
        "1.21.9" or "1.21.10" => 773,
        "1.21.11" => 774,
        _ => null,
    };

    private static IReadOnlyList<string> ReadPlugins(string directory)
    {
        try
        {
            string plugins = Path.Combine(directory, "plugins");
            if (!Directory.Exists(plugins))
                return [];

            return [.. Directory.EnumerateFiles(plugins, "*.jar", SearchOption.TopDirectoryOnly)
                .Select(Path.GetFileNameWithoutExtension)
                .OfType<string>()
                .Order()];
        }
        catch
        {
            return [];
        }
    }
}
