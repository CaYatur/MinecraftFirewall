using MinecraftFirewall.App.Services;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Setting the server's own half of IP forwarding.
///
/// Forwarding takes two settings that have to agree, and when they do not the failure is total: the
/// server reads the forwarding data as a Minecraft packet, cannot decode it, and drops every
/// connection. That is why this exists rather than a line in the documentation — and why most of what
/// follows is about touching exactly one line of a file this project does not own, and refusing
/// clearly when it is not sure which line.
/// </summary>
public class ServerForwardingSetupTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"mcfw-yml-{Guid.NewGuid():N}");

    public ServerForwardingSetupTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, recursive: true);

        GC.SuppressFinalize(this);
    }

    private static BackendServerInfo Server(string? directory) =>
        new(directory, "1.21.11", 774, false, false, []);

    private string WritePaper(string body)
    {
        string dir = Path.Combine(_root, "config");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "paper-global.yml"), body);
        return _root;
    }

    private string WriteSpigot(string body)
    {
        File.WriteAllText(Path.Combine(_root, "spigot.yml"), body);
        return _root;
    }

    private const string PaperConfig = """
        _version: 31
        proxies:
          bungee-cord:
            online-mode: true
          proxy-protocol: false
          velocity:
            enabled: false
            online-mode: false
            secret: ''
        console:
          enable-brigadier-completions: true
        """;

    private const string SpigotConfig = """
        config-version: 12
        settings:
          bungeecord: false
          save-user-cache-on-stop-only: false
        world-settings:
          default:
            verbose: false
        """;

    // ---- what it decides ---------------------------------------------------------------------------

    [Fact]
    public void APaperServerIsPointedAtProxyProtocol()
    {
        // Both files exist on a Paper server, and proxy protocol is the better of the two: it knows
        // nothing about Minecraft's protocol, so it does not move when the game does.
        string directory = WritePaper(PaperConfig);
        WriteSpigot(SpigotConfig);

        ForwardingSetupPlan plan = new ServerForwardingSetup().Plan(Server(directory), enable: true);

        Assert.True(plan.Possible);
        Assert.Equal("ProxyProtocol", plan.RecommendedMode);
        Assert.Equal("proxy-protocol", plan.Key);
        Assert.EndsWith("paper-global.yml", plan.FilePath);
    }

    [Fact]
    public void ASpigotServerIsPointedAtBungeeCord()
    {
        string directory = WriteSpigot(SpigotConfig);

        ForwardingSetupPlan plan = new ServerForwardingSetup().Plan(Server(directory), enable: true);

        Assert.True(plan.Possible);
        Assert.Equal("BungeeCord", plan.RecommendedMode);
        Assert.Equal("bungeecord", plan.Key);
    }

    [Fact]
    public void AVanillaServerIsToldPlainlyThatThereIsNoSuchSetting()
    {
        // Not a failure to report as one. Vanilla only ever sees the socket it is talking to, and no
        // amount of configuring changes that — so the answer has to say so, or somebody will keep
        // trying and keep breaking their server.
        ForwardingSetupPlan plan = new ServerForwardingSetup().Plan(Server(_root), enable: true);

        Assert.False(plan.Possible);
        Assert.Contains("vanilla", plan.Explanation, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("no way", plan.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TheExactLineIsWorkedOutBeforeAnybodyIsAsked()
    {
        // Approving "enable forwarding" is not the same as approving a change to somebody else's file,
        // so what the confirmation shows is the line itself.
        string directory = WritePaper(PaperConfig);

        ForwardingSetupPlan plan = new ServerForwardingSetup().Plan(Server(directory), enable: true);

        Assert.Equal("  proxy-protocol: false", plan.CurrentLine);
        Assert.Equal("  proxy-protocol: true", plan.ProposedLine);
    }

    [Fact]
    public void AnAlreadyCorrectSettingIsReportedRatherThanRewritten()
    {
        string directory = WritePaper(PaperConfig.Replace("proxy-protocol: false", "proxy-protocol: true"));

        ForwardingSetupPlan plan = new ServerForwardingSetup().Plan(Server(directory), enable: true);

        Assert.True(plan.AlreadyEnabled);
        Assert.Contains("already", plan.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    // ---- what it writes ------------------------------------------------------------------------------

    [Fact]
    public void ExactlyOneLineChanges()
    {
        // The whole discipline. A YAML round-trip would reformat the file and eat the comments Paper
        // ships to explain its own settings — which is the mistake this project already made once, with
        // a JSON round-trip, on the user's own configuration.
        string directory = WritePaper(PaperConfig);
        string path = Path.Combine(directory, "config", "paper-global.yml");
        string[] before = File.ReadAllLines(path);

        var setup = new ServerForwardingSetup();
        (bool success, string message) = setup.Apply(setup.Plan(Server(directory), enable: true));

        Assert.True(success, message);

        string[] after = File.ReadAllLines(path);
        Assert.Equal(before.Length, after.Length);

        string[] changed = [.. before.Zip(after).Where(p => p.First != p.Second).Select(p => p.Second)];
        Assert.Equal(["  proxy-protocol: true"], changed);
    }

    [Fact]
    public void TheOriginalIsKeptBesideIt()
    {
        // Somebody who does not like the result should not need this application to undo it.
        string directory = WritePaper(PaperConfig);
        var setup = new ServerForwardingSetup();

        setup.Apply(setup.Plan(Server(directory), enable: true));

        string backup = Path.Combine(directory, "config", "paper-global.yml.mcfirewall-backup");
        Assert.True(File.Exists(backup));
        Assert.Contains("proxy-protocol: false", File.ReadAllText(backup), StringComparison.Ordinal);
    }

    [Fact]
    public void ItCanBeTurnedBackOffAgain()
    {
        string directory = WritePaper(PaperConfig);
        var setup = new ServerForwardingSetup();

        setup.Apply(setup.Plan(Server(directory), enable: true));
        setup.Apply(setup.Plan(Server(directory), enable: false));

        Assert.Contains("  proxy-protocol: false",
            File.ReadAllLines(Path.Combine(directory, "config", "paper-global.yml")));
    }

    // ---- what it refuses to touch --------------------------------------------------------------------

    [Fact]
    public void AKeyOfTheSameNameUnderAnotherParentIsLeftAlone()
    {
        // These names are short and ordinary. A search of the whole file would find one somewhere else
        // and rewrite it — in a file the server owns and this application does not.
        string directory = WritePaper("""
            some-other-section:
              proxy-protocol: false
            proxies:
              proxy-protocol: false
            """);

        var setup = new ServerForwardingSetup();
        setup.Apply(setup.Plan(Server(directory), enable: true));

        string[] lines = File.ReadAllLines(Path.Combine(directory, "config", "paper-global.yml"));

        Assert.Equal("  proxy-protocol: false", lines[1]); // the other section, untouched
        Assert.Equal("  proxy-protocol: true", lines[3]);  // ours
    }

    [Fact]
    public void ACommentedOutSettingIsNotMistakenForTheRealOne()
    {
        string directory = WritePaper("""
            proxies:
              # proxy-protocol: true
              proxy-protocol: false
            """);

        ForwardingSetupPlan plan = new ServerForwardingSetup().Plan(Server(directory), enable: true);

        Assert.Equal("  proxy-protocol: false", plan.CurrentLine);
    }

    [Fact]
    public void AFileWithoutTheKeyIsRefusedRatherThanGuessedAt()
    {
        // Adding a key means choosing where it goes, and a wrong guess in a YAML file is a server that
        // will not start. Worth a person's attention rather than this application's confidence.
        string directory = WritePaper("""
            proxies:
              velocity:
                enabled: false
            """);

        ForwardingSetupPlan plan = new ServerForwardingSetup().Plan(Server(directory), enable: true);

        Assert.False(plan.Possible);
        Assert.Contains("by hand", plan.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NothingIsWrittenForAPlanThatWasRefused()
    {
        string directory = WritePaper("""
            proxies:
              velocity:
                enabled: false
            """);
        string path = Path.Combine(directory, "config", "paper-global.yml");
        string before = File.ReadAllText(path);

        var setup = new ServerForwardingSetup();
        (bool success, _) = setup.Apply(setup.Plan(Server(directory), enable: true));

        Assert.False(success);
        Assert.Equal(before, File.ReadAllText(path));
    }
}
