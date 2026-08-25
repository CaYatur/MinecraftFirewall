using System.IO;

namespace MinecraftFirewall.App.Services;

/// <summary>What installing the plugin would mean for this particular server, worked out before
/// anybody is asked to approve it.</summary>
public sealed record PluginInstallPlan(
    bool Possible,
    string? PluginsDirectory,
    string? TargetPath,
    bool AlreadyInstalled,
    string Explanation);

/// <summary>
/// Copies the optional server plugin into a Minecraft server's plugins folder.
///
/// This is the only place this application writes into somebody else's software, so it is the place
/// that has to be most careful. The server directory is found by a heuristic — matching the port in
/// a server.properties against the backend port — and a heuristic that is wrong here does not fail
/// politely, it writes a jar into a directory that is not what anybody meant.
///
/// So: nothing is written until the exact absolute path has been shown to a person and they have
/// approved that path. A missing plugins folder is treated as evidence that the wrong directory was
/// found, not as something to create — a Minecraft server that takes plugins already has one, and a
/// server that does not is not a server this plugin can help. And only this project's own filename is
/// ever written or replaced, so nothing anybody else installed can be overwritten by a mistake here.
/// </summary>
public sealed class PluginInstaller
{
    /// <summary>The jar's name, and the only filename this class will ever create or replace.</summary>
    public const string JarName = "MinecraftFirewallBridge.jar";

    /// <summary>
    /// Works out whether installing is possible, and where it would go.
    ///
    /// Returns an explanation in every case, including the ones where it cannot proceed, because
    /// "unavailable" with no reason is the least useful thing a panel can say.
    /// </summary>
    public PluginInstallPlan Plan(BackendServerInfo server)
    {
        // Where it would go is worked out first, and the jar's own presence is checked last. The
        // order matters: a panel still needs to show whether the plugin is installed, and still needs
        // to be able to remove it, on an installation whose jar is missing. Bailing out early would
        // make a missing jar look like a missing server.
        if (server.Directory is not { } directory)
        {
            return new PluginInstallPlan(false, null, null, false,
                "The Minecraft server's folder could not be found. It is located by matching the port in a " +
                "server.properties against this profile's backend port, which needs the server to be running " +
                "and readable by this account.");
        }

        string plugins = Path.Combine(directory, "plugins");

        if (!Directory.Exists(plugins))
        {
            // Not created. Its absence is the strongest evidence available that the directory found is
            // not a plugin-capable Minecraft server, and creating it would turn a wrong guess into a
            // stray folder in somebody's file system, with a jar in it.
            return new PluginInstallPlan(false, null, null, false,
                $"No plugins folder in {directory}. Either that is not the server's folder, or the server " +
                "does not support plugins — vanilla servers do not. Paper and Spigot do.");
        }

        string target = Path.Combine(plugins, JarName);
        bool installed = File.Exists(target);

        if (!File.Exists(SourceJarPath()))
        {
            return new PluginInstallPlan(false, plugins, target, installed,
                "The plugin jar is missing from this installation, so it cannot be installed from here. " +
                "Reinstall MinecraftFirewall, or build it with plugin/build.ps1 from the source repository." +
                (installed ? $" A copy is already at {target} and can still be removed." : string.Empty));
        }

        return new PluginInstallPlan(true, plugins, target, installed,
            installed
                ? $"Already installed at {target}. Installing again replaces it with this version."
                : $"Will be copied to {target}. The server must be restarted before it loads.");
    }

    /// <summary>
    /// Performs the copy. Only ever called after a person has approved the exact path in
    /// <see cref="PluginInstallPlan.TargetPath"/>.
    /// </summary>
    public (bool Success, string Message) Install(PluginInstallPlan plan)
    {
        if (!plan.Possible || plan.TargetPath is not { } target)
            return (false, plan.Explanation);

        try
        {
            File.Copy(SourceJarPath(), target, overwrite: true);

            return (true,
                $"Copied to {target}. Restart your Minecraft server to load it — until then nothing changes, " +
                "which is normal and not a failure.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (false,
                $"Could not write {target}: {ex.Message}. If the server is running as another user, copy the " +
                "jar there yourself — it is at " + SourceJarPath() + ".");
        }
    }

    /// <summary>Removes it again. Uninstalling has to be as easy as installing, or people are stuck
    /// with something they were persuaded to try.</summary>
    public (bool Success, string Message) Uninstall(PluginInstallPlan plan)
    {
        if (plan.TargetPath is not { } target || !File.Exists(target))
            return (false, "It is not installed there.");

        try
        {
            File.Delete(target);
            return (true, $"Removed {target}. Restart your Minecraft server to unload it.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (false, $"Could not remove {target}: {ex.Message}");
        }
    }

    /// <summary>Beside this application, where the installer puts it.</summary>
    private static string SourceJarPath() =>
        Path.Combine(AppContext.BaseDirectory, JarName);
}
