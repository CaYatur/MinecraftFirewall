using Microsoft.Extensions.Configuration;
using MinecraftFirewall.App.Localization;
using MinecraftFirewall.App.Services;
using MinecraftFirewall.Proxy;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Exercises every path the control panel writes to, against the real shipped configuration file, and
/// the upgrade case that made all of them fail.
///
/// The upgrade case is the reason this file exists. The installer never overwrites appsettings.json —
/// correctly, since it holds the user's servers and protected usernames — so an installation upgraded
/// from a release that predates a feature keeps a file with no section for it, and every switch for
/// that feature fails. Nothing about it is visible from a fresh install, which is the only kind the
/// other tests exercise.
/// </summary>
public class ConfigUpgradeTests
{
    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "MinecraftFirewall.slnx")))
            dir = dir.Parent;

        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static string ShippedConfig() =>
        Path.Combine(RepositoryRoot(), "src", "MinecraftFirewall.Proxy", "appsettings.json");

    /// <summary>Copies the shipped file into a disposable directory, optionally alongside a different
    /// live file — which is how an upgraded installation is simulated.</summary>
    private static (ServerConfigStore Store, string Directory) Sandbox(string? liveConfigContent = null)
    {
        string directory = Path.Combine(Path.GetTempPath(), $"mcfw-upgrade-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);

        string shipped = File.ReadAllText(ShippedConfig());
        File.WriteAllText(Path.Combine(directory, "appsettings.default.json"), shipped);
        File.WriteAllText(Path.Combine(directory, "appsettings.json"), liveConfigContent ?? shipped);

        return (new ServerConfigStore(Path.Combine(directory, "appsettings.json")), directory);
    }

    private static int CountCommentLines(string path) =>
        File.ReadLines(path).Count(line => line.TrimStart().StartsWith("//", StringComparison.Ordinal));

    /// <summary>Every path the Protection and Settings pages write. Each is a real Tag value from the
    /// XAML, so a rename that broke one would fail here rather than in front of a user.</summary>
    public static TheoryData<string[]> WritablePaths() =>
    [
        ["DdosProtection", "Enabled"],
        ["DeepInspection", "Enabled"],
        ["DeepInspection", "ScanForInjectionPayloads"],
        ["DeepInspection", "AnalyseMovement"],
        ["DeepInspection", "KickOnMovementAnomaly"],
        ["Honeypot", "Enabled"],
        ["AnomalyDetection", "Enabled"],
        ["Premium", "AutoClaimOnVerifiedLogin"],
    ];

    [Theory]
    [MemberData(nameof(WritablePaths))]
    public void EveryToggleTheUiOffers_WritesWithoutLosingAnything(string[] path)
    {
        (ServerConfigStore store, string directory) = Sandbox();
        try
        {
            int commentsBefore = CountCommentLines(store.ConfigPath);
            bool original = store.GetBool(path, false);

            (bool success, string message) = store.SetBool(path, !original);

            Assert.True(success, $"{string.Join(" > ", path)}: {message}");
            Assert.Equal(!original, store.GetBool(path, original));
            Assert.Equal(commentsBefore, CountCommentLines(store.ConfigPath));

            // Still loadable, so the splice produced valid JSON rather than something that merely
            // looks right.
            (List<ServerProfileEdit> profiles, string? error) = store.Load();
            Assert.Null(error);
            Assert.NotEmpty(profiles);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void TheBotActionChoice_RoundTrips()
    {
        (ServerConfigStore store, string directory) = Sandbox();
        try
        {
            Assert.Equal("LogOnly", store.GetString(["BotDefense", "Action"], "LogOnly"));

            Assert.True(store.SetString(["BotDefense", "Action"], "Deny").Success);
            Assert.Equal("Deny", store.GetString(["BotDefense", "Action"], "LogOnly"));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void AFreshInstall_IsMissingNothing()
    {
        (ServerConfigStore store, string directory) = Sandbox();
        try
        {
            Assert.Empty(store.MissingSections());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>The shape of a configuration written before the defence sections existed: the earlier
    /// release's file, with servers and messages but nothing else.</summary>
    private const string OldConfig = """
        {
          // A comment the user must keep.
          "ServerProfiles": [
            {
              "Name": "MyRealServer",
              "PublicPort": 25565,
              "BackendHost": "127.0.0.1",
              "BackendPort": 25566,
              "ProtectedUsernames": [ { "Username": "Admin", "AllowedIps": [], "RequirePremium": true } ],
              "AllowedHostnames": []
            }
          ],

          "Premium": {
            "Enabled": true,
            "AutoClaimOnVerifiedLogin": false
          }
        }
        """;

    [Fact]
    public void AnUpgradedConfiguration_IsRecognisedAsMissingTheNewSections()
    {
        (ServerConfigStore store, string directory) = Sandbox(OldConfig);
        try
        {
            IReadOnlyList<string> missing = store.MissingSections();

            Assert.Contains("DdosProtection", missing);
            Assert.Contains("BotDefense", missing);
            Assert.Contains("Honeypot", missing);
            Assert.Contains("ThreatIntel", missing);
            Assert.Contains("DeepInspection", missing);
            Assert.Contains("AnomalyDetection", missing);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void WithoutTheRepair_EverySwitchOnAnUpgradedConfigurationFails()
    {
        // The behaviour that made this necessary. Reporting a missing path rather than inventing one
        // is the right call — but it means the whole page is inert until the sections exist, which is
        // why the page says so instead of leaving the user to guess.
        (ServerConfigStore store, string directory) = Sandbox(OldConfig);
        try
        {
            (bool success, string message) = store.SetBool(["DdosProtection", "Enabled"], true);

            Assert.False(success);
            Assert.Contains("DdosProtection", message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void TheRepairAddsTheSections_KeepsTheUsersOwnSettings_AndBringsTheExplanationsWithIt()
    {
        (ServerConfigStore store, string directory) = Sandbox(OldConfig);
        try
        {
            (bool success, string message) = store.AddMissingSections();
            Assert.True(success, message);

            Assert.Empty(store.MissingSections());

            // Everything the user had is still there, untouched.
            (List<ServerProfileEdit> profiles, string? error) = store.Load();
            Assert.Null(error);
            Assert.Equal("MyRealServer", profiles[0].Name);
            Assert.Contains(profiles[0].ProtectedUsernames, n => n is { Username: "Admin", RequirePremium: true });

            string text = File.ReadAllText(store.ConfigPath);
            Assert.Contains("A comment the user must keep", text, StringComparison.Ordinal);

            // And the copied sections arrived with the explanations that make them interpretable — the
            // reason for copying text rather than serialising values.
            Assert.Contains("KickOnMovementAnomaly", text, StringComparison.Ordinal);
            Assert.Contains("//", text, StringComparison.Ordinal);
            Assert.True(CountCommentLines(store.ConfigPath) > 20,
                "the copied sections should bring their explanations with them");

            // The definitive check: the repaired file has to be readable by the *service*, through the
            // real .NET configuration pipeline, not merely by the app's own JsonNode reader. A splice
            // that produced almost-valid JSON would pass everything above and then stop the firewall
            // starting — the one outcome a repair must never cause.
            var config = new ConfigurationBuilder()
                .AddJsonFile(store.ConfigPath, optional: false)
                .Build();

            var ddos = config.GetSection(MinecraftFirewall.Proxy.Defense.DdosOptions.SectionName)
                .Get<MinecraftFirewall.Proxy.Defense.DdosOptions>();
            var inspection = config.GetSection(MinecraftFirewall.Proxy.Inspection.InspectionOptions.SectionName)
                .Get<MinecraftFirewall.Proxy.Inspection.InspectionOptions>();
            var threats = config.GetSection(MinecraftFirewall.Proxy.Defense.ThreatIntelOptions.SectionName)
                .Get<MinecraftFirewall.Proxy.Defense.ThreatIntelOptions>();

            Assert.NotNull(ddos);
            Assert.Equal(16, ddos!.MaxConcurrentPerIp);
            Assert.NotNull(inspection);
            Assert.False(inspection!.KickOnMovementAnomaly);

            // And the feed URL arrives with it, which is the other half of the upgrade break: without
            // the section, ThreatIntel is enabled with an empty URL list and imports nothing, silently.
            Assert.NotNull(threats);
            Assert.NotEmpty(threats!.FeedUrls);

            // The user's own server survived the round trip through the real pipeline too.
            var boundProfiles = config.GetSection("ServerProfiles").Get<List<ServerProfileConfig>>();
            Assert.NotNull(boundProfiles);
            Assert.Equal("MyRealServer", boundProfiles![0].Name);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void AfterTheRepair_TheSwitchesWork()
    {
        (ServerConfigStore store, string directory) = Sandbox(OldConfig);
        try
        {
            Assert.True(store.AddMissingSections().Success);

            foreach (string[] path in new[]
                     {
                         new[] { "DdosProtection", "Enabled" },
                         ["Honeypot", "Enabled"],
                         ["AnomalyDetection", "Enabled"],
                         ["DeepInspection", "KickOnMovementAnomaly"],
                     })
            {
                bool before = store.GetBool(path, false);
                Assert.True(store.SetBool(path, !before).Success, string.Join(" > ", path));
                Assert.Equal(!before, store.GetBool(path, before));
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void RepairingATwiceRepairedFile_IsANoOp()
    {
        (ServerConfigStore store, string directory) = Sandbox(OldConfig);
        try
        {
            Assert.True(store.AddMissingSections().Success);
            string afterFirst = File.ReadAllText(store.ConfigPath);

            Assert.True(store.AddMissingSections().Success);

            Assert.Equal(afterFirst, File.ReadAllText(store.ConfigPath));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}

/// <summary>
/// The two languages have to stay in step.
///
/// A key present in one dictionary and not the other produces no build error and no exception — just a
/// blank or a raw key on screen for whichever language was forgotten. With every new page adding
/// twenty or thirty strings at a time, that is a matter of when rather than whether.
/// </summary>
public class LocalizationParityTests
{
    [Fact]
    public void EnglishAndTurkishDefineExactlyTheSameKeys()
    {
        IReadOnlyCollection<string> english = Strings.KeysFor("en");
        IReadOnlyCollection<string> turkish = Strings.KeysFor("tr");

        Assert.Empty(english.Except(turkish));
        Assert.Empty(turkish.Except(english));
    }

    [Theory]
    [InlineData("en")]
    [InlineData("tr")]
    public void NoTranslationIsBlank(string language)
    {
        var strings = new Strings();
        strings.SetLanguage(language);

        foreach (string key in Strings.KeysFor(language))
            Assert.False(string.IsNullOrWhiteSpace(strings[key]), $"{language}: '{key}' is blank");
    }

    [Fact]
    public void AnUnknownKeyIsVisibleRatherThanSilent()
    {
        // If a key is ever missed, showing it is far better than showing nothing: a blank label looks
        // like a rendering bug, and the key itself points straight at the fix.
        var strings = new Strings();
        strings.SetLanguage("en");

        Assert.Contains("NoSuchKeyExists", strings["NoSuchKeyExists"], StringComparison.Ordinal);
    }
}
