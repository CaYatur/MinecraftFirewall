using MinecraftFirewall.App.Services;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Setting the server's own half of IP forwarding.
///
/// Forwarding takes two settings that have to agree, and when they do not the failure is total: the
/// server reads the forwarding data as a Minecraft packet, cannot decode it, and drops every
/// connection. That is why this exists rather than a line in the documentation.
///
/// The other half is that only ONE of the two available settings may be on. Leaving both set does not
/// double anything — it makes the server announce to its plugins that it sits behind a BungeeCord
/// network when it does not, and they believe it. That came back from a live server: SkinsRestorer
/// switched into proxy mode and stopped working, because a `bungeecord: true` left over from an
/// earlier attempt was still sitting beside the setting actually in use.
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

    /// <summary>Writes the bytes exactly as given, so a test about line endings is not undone by the
    /// helper that set it up.</summary>
    private string WritePaper(string body)
    {
        string dir = Path.Combine(_root, "config");
        Directory.CreateDirectory(dir);
        File.WriteAllBytes(Path.Combine(dir, "paper-global.yml"), System.Text.Encoding.UTF8.GetBytes(body));
        return _root;
    }

    private string WriteSpigot(string body)
    {
        File.WriteAllBytes(Path.Combine(_root, "spigot.yml"), System.Text.Encoding.UTF8.GetBytes(body));
        return _root;
    }

    private static string PaperConfig(bool proxyProtocol = false) =>
        "_version: 31\n" +
        "proxies:\n" +
        "  bungee-cord:\n" +
        "    online-mode: true\n" +
        $"  proxy-protocol: {(proxyProtocol ? "true" : "false")}\n" +
        "  velocity:\n" +
        "    enabled: false\n" +
        "console:\n" +
        "  enable-brigadier-completions: true\n";

    private static string SpigotConfig(bool bungee = false) =>
        "config-version: 12\n" +
        "settings:\n" +
        $"  bungeecord: {(bungee ? "true" : "false")}\n" +
        "  save-user-cache-on-stop-only: false\n";

    private string PaperPath => Path.Combine(_root, "config", "paper-global.yml");
    private string SpigotPath => Path.Combine(_root, "spigot.yml");

    // ---- what it decides ---------------------------------------------------------------------------

    [Fact]
    public void APaperServerCanUseProxyProtocol()
    {
        WritePaper(PaperConfig());
        WriteSpigot(SpigotConfig());

        ForwardingSetupPlan plan = new ServerForwardingSetup().Plan(Server(_root), "ProxyProtocol");

        Assert.True(plan.Possible);
        Assert.Equal("ProxyProtocol", plan.RecommendedMode);
        Assert.Contains(plan.Edits, e => e.Key == "proxy-protocol" && e.ProposedLine.EndsWith("true"));
    }

    [Fact]
    public void ASpigotOnlyServerIsRefusedProxyProtocolAndToldWhy()
    {
        // Proxy protocol is Paper's. Silently doing nothing, or setting the wrong key, would leave a
        // server that refuses every connection.
        WriteSpigot(SpigotConfig());

        ForwardingSetupPlan plan = new ServerForwardingSetup().Plan(Server(_root), "ProxyProtocol");

        Assert.False(plan.Possible);
        Assert.Contains("Paper", plan.Explanation, StringComparison.Ordinal);
        Assert.Contains("BungeeCord", plan.Explanation, StringComparison.Ordinal);
    }

    [Fact]
    public void AVanillaServerIsToldPlainlyThatThereIsNoSuchSetting()
    {
        // Not a failure to report as one. Vanilla only ever sees the socket it is talking to, and no
        // amount of configuring changes that — so the answer has to say so, or somebody will keep
        // trying and keep breaking their server.
        ForwardingSetupPlan plan = new ServerForwardingSetup().Plan(Server(_root), "ProxyProtocol");

        Assert.False(plan.Possible);
        Assert.Contains("vanilla", plan.Explanation, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("no way", plan.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TheExactLinesAreWorkedOutBeforeAnybodyIsAsked()
    {
        // Approving "set my server up" is not the same as approving edits to somebody else's files, so
        // what the confirmation shows is the lines themselves.
        WritePaper(PaperConfig());

        ForwardingSetupPlan plan = new ServerForwardingSetup().Plan(Server(_root), "ProxyProtocol");

        YamlEdit edit = Assert.Single(plan.Edits);
        Assert.Equal("  proxy-protocol: false", edit.CurrentLine);
        Assert.Equal("  proxy-protocol: true", edit.ProposedLine);
        Assert.Contains("proxy-protocol: false  ->  proxy-protocol: true", plan.Explanation, StringComparison.Ordinal);
    }

    [Fact]
    public void AServerAlreadySetUpCorrectlyIsLeftAlone()
    {
        WritePaper(PaperConfig(proxyProtocol: true));
        WriteSpigot(SpigotConfig(bungee: false));

        ForwardingSetupPlan plan = new ServerForwardingSetup().Plan(Server(_root), "ProxyProtocol");

        Assert.True(plan.AlreadyCorrect);
        Assert.Empty(plan.Edits);
    }

    // ---- only one of the two may be on ---------------------------------------------------------------

    [Fact]
    public void TurningOnProxyProtocolTurnsOffBungeeCord()
    {
        // The SkinsRestorer failure, from a live server. A leftover `bungeecord: true` makes the server
        // tell every plugin it is behind a BungeeCord network — SkinsRestorer switches into proxy mode
        // and stops working, and it is not the only plugin that asks.
        WritePaper(PaperConfig());
        WriteSpigot(SpigotConfig(bungee: true));

        var setup = new ServerForwardingSetup();
        ForwardingSetupPlan plan = setup.Plan(Server(_root), "ProxyProtocol");

        Assert.Equal(2, plan.Edits.Count);
        Assert.Contains(plan.Edits, e => e.Key == "proxy-protocol" && e.ProposedLine.EndsWith("true"));
        Assert.Contains(plan.Edits, e => e.Key == "bungeecord" && e.ProposedLine.EndsWith("false"));

        Assert.True(setup.Apply(plan).Success);

        Assert.Contains("  proxy-protocol: true", File.ReadAllText(PaperPath), StringComparison.Ordinal);
        Assert.Contains("  bungeecord: false", File.ReadAllText(SpigotPath), StringComparison.Ordinal);
    }

    [Fact]
    public void TurningOnBungeeCordTurnsOffProxyProtocol()
    {
        WritePaper(PaperConfig(proxyProtocol: true));
        WriteSpigot(SpigotConfig());

        var setup = new ServerForwardingSetup();

        Assert.True(setup.Apply(setup.Plan(Server(_root), "BungeeCord")).Success);

        Assert.Contains("  proxy-protocol: false", File.ReadAllText(PaperPath), StringComparison.Ordinal);
        Assert.Contains("  bungeecord: true", File.ReadAllText(SpigotPath), StringComparison.Ordinal);
    }

    [Fact]
    public void TurningForwardingOffTurnsBothOff()
    {
        WritePaper(PaperConfig(proxyProtocol: true));
        WriteSpigot(SpigotConfig(bungee: true));

        var setup = new ServerForwardingSetup();
        Assert.True(setup.Apply(setup.Plan(Server(_root), "None")).Success);

        Assert.Contains("  proxy-protocol: false", File.ReadAllText(PaperPath), StringComparison.Ordinal);
        Assert.Contains("  bungeecord: false", File.ReadAllText(SpigotPath), StringComparison.Ordinal);
    }

    // ---- what it writes ------------------------------------------------------------------------------

    [Fact]
    public void EveryOtherByteInTheFileIsIdentical()
    {
        // Stronger than counting lines, and it had to be: the first version of this compared line
        // arrays and passed, while actually rewriting all 144 line endings in a real Paper config.
        // Paper writes LF, Windows writes CRLF, and ReadAllLines/WriteAllLines quietly converts.
        WritePaper(PaperConfig());
        string before = File.ReadAllText(PaperPath);

        var setup = new ServerForwardingSetup();
        Assert.True(setup.Apply(setup.Plan(Server(_root), "ProxyProtocol")).Success);

        Assert.Equal(
            before.Replace("proxy-protocol: false", "proxy-protocol: true"),
            File.ReadAllText(PaperPath));
    }

    [Fact]
    public void ACarriageReturnOnTheChangedLineIsKeptToo()
    {
        WritePaper("proxies:\r\n  proxy-protocol: false\r\n");

        var setup = new ServerForwardingSetup();
        Assert.True(setup.Apply(setup.Plan(Server(_root), "ProxyProtocol")).Success);

        Assert.Equal("proxies:\r\n  proxy-protocol: true\r\n", File.ReadAllText(PaperPath));
    }

    [Fact]
    public void TheOriginalIsKeptBesideIt()
    {
        // Somebody who does not like the result should not need this application to undo it.
        WritePaper(PaperConfig());
        var setup = new ServerForwardingSetup();

        setup.Apply(setup.Plan(Server(_root), "ProxyProtocol"));

        Assert.Contains("proxy-protocol: false",
            File.ReadAllText(PaperPath + ".mcfirewall-backup"), StringComparison.Ordinal);
    }

    // ---- what it refuses to touch --------------------------------------------------------------------

    [Fact]
    public void AKeyOfTheSameNameUnderAnotherParentIsLeftAlone()
    {
        // These names are short and ordinary. A search of the whole file would find one somewhere else
        // and rewrite it — in a file the server owns and this application does not.
        WritePaper("some-other-section:\n  proxy-protocol: false\nproxies:\n  proxy-protocol: false\n");

        var setup = new ServerForwardingSetup();
        setup.Apply(setup.Plan(Server(_root), "ProxyProtocol"));

        string[] lines = File.ReadAllText(PaperPath).Split('\n');
        Assert.Equal("  proxy-protocol: false", lines[1]); // the other section, untouched
        Assert.Equal("  proxy-protocol: true", lines[3]);  // ours
    }

    [Fact]
    public void ACommentedOutSettingIsNotMistakenForTheRealOne()
    {
        WritePaper("proxies:\n  # proxy-protocol: true\n  proxy-protocol: false\n");

        ForwardingSetupPlan plan = new ServerForwardingSetup().Plan(Server(_root), "ProxyProtocol");

        Assert.Equal("  proxy-protocol: false", Assert.Single(plan.Edits).CurrentLine);
    }

    [Fact]
    public void AFileWithoutTheKeyIsRefusedRatherThanGuessedAt()
    {
        // Adding a key means choosing where it goes, and a wrong guess in a YAML file is a server that
        // will not start. Worth a person's attention rather than this application's confidence.
        WritePaper("proxies:\n  velocity:\n    enabled: false\n");

        ForwardingSetupPlan plan = new ServerForwardingSetup().Plan(Server(_root), "ProxyProtocol");

        Assert.False(plan.Possible);
        Assert.Contains("by hand", plan.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NothingIsWrittenForAPlanThatWasRefused()
    {
        WritePaper("proxies:\n  velocity:\n    enabled: false\n");
        string before = File.ReadAllText(PaperPath);

        var setup = new ServerForwardingSetup();
        (bool success, _) = setup.Apply(setup.Plan(Server(_root), "ProxyProtocol"));

        Assert.False(success);
        Assert.Equal(before, File.ReadAllText(PaperPath));
    }

    [Fact]
    public void AFileThatChangedSinceThePlanIsNotOverwritten()
    {
        // The gap between showing somebody a line and writing it. Rewriting a line that is no longer
        // the one they approved would be writing something nobody agreed to.
        WritePaper(PaperConfig());
        var setup = new ServerForwardingSetup();
        ForwardingSetupPlan plan = setup.Plan(Server(_root), "ProxyProtocol");

        WritePaper(PaperConfig().Replace("proxy-protocol: false", "proxy-protocol: maybe"));

        (bool success, string message) = setup.Apply(plan);

        Assert.False(success);
        Assert.Contains("changed since", message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("proxy-protocol: maybe", File.ReadAllText(PaperPath), StringComparison.Ordinal);
    }
}
