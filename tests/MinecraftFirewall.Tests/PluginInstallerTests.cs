using MinecraftFirewall.App.Services;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Copying the optional plugin into somebody's Minecraft server.
///
/// This is the only place this project writes into software it does not own, and the directory it
/// writes to is found by a heuristic — matching a port in a server.properties. A heuristic that is
/// wrong here does not fail politely; it puts a file somewhere nobody meant. So most of what follows
/// is about refusing, and about refusing for a reason a person can read.
/// </summary>
public class PluginInstallerTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"mcfw-plugin-{Guid.NewGuid():N}");

    public PluginInstallerTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, recursive: true);

        GC.SuppressFinalize(this);
    }

    private static BackendServerInfo Server(string? directory) =>
        new(directory, "1.21.11", 774, false, false, []);

    private string ServerWithPlugins()
    {
        string plugins = Path.Combine(_root, "plugins");
        Directory.CreateDirectory(plugins);
        return _root;
    }

    /// <summary>True when the jar is beside the test binary — it is not, in a plain test run, so the
    /// tests that need it say why they are checking what they check.</summary>
    private static bool JarIsPresent() =>
        File.Exists(Path.Combine(AppContext.BaseDirectory, PluginInstaller.JarName));

    [Fact]
    public void AServerFolderThatCouldNotBeFoundIsRefusedWithAReason()
    {
        // "Unavailable" with no reason is the least useful thing a panel can say, and this is the case
        // a person is most likely to hit: a server running as another user, or started from somewhere
        // unusual.
        PluginInstallPlan plan = new PluginInstaller().Plan(Server(null));

        Assert.False(plan.Possible);
        Assert.Null(plan.TargetPath);
        Assert.NotEmpty(plan.Explanation);
    }

    [Fact]
    public void AFolderWithNoPluginsDirectoryIsRefusedRatherThanHavingOneCreated()
    {
        // The most important refusal here. A missing plugins folder is the strongest evidence
        // available that the directory found is not a plugin-capable Minecraft server — and creating
        // it would turn a wrong guess into a stray folder in somebody's file system, with a jar in it.
        PluginInstallPlan plan = new PluginInstaller().Plan(Server(_root));

        Assert.False(plan.Possible);
        Assert.False(Directory.Exists(Path.Combine(_root, "plugins")));
        Assert.Contains("plugins", plan.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TheExactPathIsWorkedOutBeforeAnybodyIsAsked()
    {
        // What the confirmation dialog shows is this path, not the idea of installing. Approving a
        // heuristic is not the same as approving where it landed.
        string directory = ServerWithPlugins();

        PluginInstallPlan plan = new PluginInstaller().Plan(Server(directory));

        if (!JarIsPresent())
        {
            // Without the jar the plan cannot proceed, and says so — which is itself the behaviour a
            // fresh source checkout should have before anybody has run the plugin build.
            Assert.False(plan.Possible);
            Assert.Contains("plugin", plan.Explanation, StringComparison.OrdinalIgnoreCase);
            return;
        }

        Assert.True(plan.Possible);
        Assert.Equal(Path.Combine(directory, "plugins", PluginInstaller.JarName), plan.TargetPath);
        Assert.True(Path.IsPathRooted(plan.TargetPath), "the path shown to a person has to be absolute");
    }

    [Fact]
    public void OnlyThisProjectsOwnFilenameIsEverTargeted()
    {
        // Nothing anybody else installed can be overwritten by a mistake in here, because the only
        // name this class will ever write is its own.
        string directory = ServerWithPlugins();
        string somebodyElses = Path.Combine(directory, "plugins", "EssentialsX.jar");
        File.WriteAllText(somebodyElses, "not ours");

        PluginInstallPlan plan = new PluginInstaller().Plan(Server(directory));

        Assert.True(plan.TargetPath is null || Path.GetFileName(plan.TargetPath) == PluginInstaller.JarName);
        Assert.Equal("not ours", File.ReadAllText(somebodyElses));
    }

    [Fact]
    public void AnAlreadyInstalledJarIsReportedRatherThanSilentlyReplaced()
    {
        // So the dialog can say "replaces it" instead of "installs it". A person who has already done
        // this once should be told what the second time does.
        string directory = ServerWithPlugins();
        File.WriteAllText(Path.Combine(directory, "plugins", PluginInstaller.JarName), "an older build");

        PluginInstallPlan plan = new PluginInstaller().Plan(Server(directory));

        Assert.True(plan.AlreadyInstalled);
        Assert.Contains(PluginInstaller.JarName, plan.Explanation, StringComparison.Ordinal);

        // The "replaces it" wording only belongs on a plan that can actually install. Where it cannot
        // — no jar shipped alongside, as in a plain test run — the explanation says that instead, and
        // still says the copy already there can be removed.
        Assert.Contains(
            JarIsPresent() ? "replac" : "remov",
            plan.Explanation,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RemovingWhatIsNotThereIsSaidRatherThanReportedAsSuccess()
    {
        string directory = ServerWithPlugins();
        var installer = new PluginInstaller();

        (bool success, _) = installer.Uninstall(installer.Plan(Server(directory)));

        Assert.False(success);
    }

    [Fact]
    public void RemovingDeletesOnlyOurOwnJar()
    {
        string directory = ServerWithPlugins();
        string ours = Path.Combine(directory, "plugins", PluginInstaller.JarName);
        string theirs = Path.Combine(directory, "plugins", "EssentialsX.jar");
        File.WriteAllText(ours, "ours");
        File.WriteAllText(theirs, "theirs");

        var installer = new PluginInstaller();
        (bool success, string message) = installer.Uninstall(installer.Plan(Server(directory)));

        Assert.True(success, message);
        Assert.False(File.Exists(ours));
        Assert.True(File.Exists(theirs), "nothing else in the plugins folder may be touched");
    }

    [Fact]
    public void EveryRefusalCarriesSomethingAPersonCanActOn()
    {
        // A panel shows this text verbatim. An empty explanation would be a dead end.
        var installer = new PluginInstaller();

        foreach (PluginInstallPlan plan in new[] { installer.Plan(Server(null)), installer.Plan(Server(_root)) })
        {
            Assert.False(plan.Possible);
            Assert.True(plan.Explanation.Length > 40, $"too terse to act on: '{plan.Explanation}'");
        }
    }
}
