using MinecraftFirewall.App.Services;

namespace MinecraftFirewall.Tests;

public class JsonTextSurgeryTests
{
    private const string Document = """
        {
          // A comment above the first section.
          "Alpha": {
            "One": 1,      // trailing comment
            "Two": false
          },

          /* A block comment
             spanning lines. */
          "Beta": [
            { "Name": "first" }
          ],

          "Gamma": "a string with a } brace and a // slash in it"
        }
        """;

    [Fact]
    public void ReplacingAnArray_LeavesEveryOtherByteAlone()
    {
        string? updated = JsonTextSurgery.ReplaceValue(Document, ["Beta"], """[ { "Name": "second" } ]""");

        Assert.NotNull(updated);
        Assert.Contains("A comment above the first section", updated!, StringComparison.Ordinal);
        Assert.Contains("trailing comment", updated, StringComparison.Ordinal);
        Assert.Contains("A block comment", updated, StringComparison.Ordinal);
        Assert.Contains("\"Name\": \"second\"", updated, StringComparison.Ordinal);
        Assert.DoesNotContain("\"Name\": \"first\"", updated, StringComparison.Ordinal);
    }

    [Fact]
    public void ABraceInsideAStringDoesNotEndTheSpan()
    {
        // The correctness argument for the whole scanner. If a brace in a string counted as structure,
        // the span would end in the wrong place and the splice would corrupt the file.
        string? updated = JsonTextSurgery.ReplaceValue(Document, ["Gamma"], "\"replaced\"");

        Assert.NotNull(updated);
        Assert.Contains("\"Gamma\": \"replaced\"", updated!, StringComparison.Ordinal);
        Assert.Contains("A comment above the first section", updated, StringComparison.Ordinal);
    }

    [Fact]
    public void ANestedPathIsFound()
    {
        string? updated = JsonTextSurgery.ReplaceValue(Document, ["Alpha", "Two"], "true");

        Assert.NotNull(updated);
        Assert.Contains("\"Two\": true", updated!, StringComparison.Ordinal);
        Assert.Contains("\"One\": 1", updated, StringComparison.Ordinal);
        Assert.Contains("trailing comment", updated, StringComparison.Ordinal);
    }

    [Fact]
    public void AMissingPathIsReportedRatherThanInvented()
    {
        Assert.Null(JsonTextSurgery.ReplaceValue(Document, ["Nope"], "1"));
        Assert.Null(JsonTextSurgery.ReplaceValue(Document, ["Alpha", "Nope"], "1"));
        // A non-final segment that is not an object cannot be walked into.
        Assert.Null(JsonTextSurgery.ReplaceValue(Document, ["Gamma", "Nope"], "1"));
    }

    [Fact]
    public void ACommentContainingABrace_DoesNotConfuseTheScanner()
    {
        const string tricky = """
            {
              // this comment has a } and a { in it
              "Value": 1,
              "After": 2
            }
            """;

        string? updated = JsonTextSurgery.ReplaceValue(tricky, ["After"], "99");

        Assert.NotNull(updated);
        Assert.Contains("\"After\": 99", updated!, StringComparison.Ordinal);
        Assert.Contains("\"Value\": 1", updated, StringComparison.Ordinal);
    }
}

/// <summary>
/// Round-trips the actual shipped appsettings.json through the control panel's editor.
///
/// The failure this exists for is silent and permanent: the first version of the editor parsed with
/// <c>JsonCommentHandling.Skip</c> and wrote back through <c>JsonNode</c>, which deletes every comment
/// in the file. Nobody would have noticed until they went looking for the explanation of a setting and
/// found it gone — and by then every copy on disk would be the stripped one.
/// </summary>
public class ServerConfigStoreRoundTripTests
{
    private static string ShippedConfigPath()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "MinecraftFirewall.slnx")))
            dir = dir.Parent;

        Assert.NotNull(dir);
        return Path.Combine(dir!.FullName, "src", "MinecraftFirewall.Proxy", "appsettings.json");
    }

    /// <summary>Copies the shipped file somewhere disposable, so a test can exercise the real writer
    /// against the real content without editing the repository.</summary>
    private static (ServerConfigStore Store, string Directory) CopyShippedConfig()
    {
        string directory = Path.Combine(Path.GetTempPath(), $"mcfw-config-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        File.Copy(ShippedConfigPath(), Path.Combine(directory, "appsettings.json"));

        return (new ServerConfigStore(Path.Combine(directory, "appsettings.json")), directory);
    }

    private static int CountCommentLines(string path) =>
        File.ReadLines(path).Count(line => line.TrimStart().StartsWith("//", StringComparison.Ordinal));

    [Fact]
    public void SavingAServerRename_KeepsEveryCommentInTheFile()
    {
        (ServerConfigStore store, string directory) = CopyShippedConfig();
        try
        {
            int before = CountCommentLines(store.ConfigPath);
            Assert.True(before > 50, "the shipped file should be full of explanation, or this test proves nothing");

            (List<ServerProfileEdit> profiles, string? error) = store.Load();
            Assert.Null(error);
            Assert.NotEmpty(profiles);

            profiles[0].Name = "MyRenamedServer";
            (bool success, string message) = store.Save(profiles);

            Assert.True(success, message);
            Assert.Equal(before, CountCommentLines(store.ConfigPath));
            Assert.Contains("MyRenamedServer", File.ReadAllText(store.ConfigPath), StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void FlippingASwitch_KeepsEveryCommentInTheFile()
    {
        (ServerConfigStore store, string directory) = CopyShippedConfig();
        try
        {
            int before = CountCommentLines(store.ConfigPath);

            Assert.False(store.GetAutoPremium());
            (bool success, string message) = store.SetAutoPremium(true);

            Assert.True(success, message);
            Assert.True(store.GetAutoPremium());
            Assert.Equal(before, CountCommentLines(store.ConfigPath));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void TheSavedFileIsStillValidConfigurationTheServiceCanRead()
    {
        // Preserving comments is worth nothing if the result no longer parses. This re-reads the
        // written file through the same loader the editor uses, and checks a section the editor never
        // touches came through intact.
        (ServerConfigStore store, string directory) = CopyShippedConfig();
        try
        {
            (List<ServerProfileEdit> profiles, _) = store.Load();
            profiles[0].PublicPort = 25599;
            profiles[0].ProtectedUsernames.Add(new ProtectedNameEdit { Username = "NewName", RequirePremium = true });
            Assert.True(store.Save(profiles).Success);

            (List<ServerProfileEdit> reloaded, string? error) = store.Load();

            Assert.Null(error);
            Assert.Equal(25599, reloaded[0].PublicPort);
            Assert.Contains(reloaded[0].ProtectedUsernames, n => n is { Username: "NewName", RequirePremium: true });

            // A section the editor knows nothing about, still there and still readable.
            string text = File.ReadAllText(store.ConfigPath);
            Assert.Contains("\"Serilog\"", text, StringComparison.Ordinal);
            Assert.Contains("\"DeepInspection\"", text, StringComparison.Ordinal);
            Assert.Contains("KickOnMovementAnomaly", text, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void APreviousCopyIsKeptAlongside()
    {
        (ServerConfigStore store, string directory) = CopyShippedConfig();
        try
        {
            (List<ServerProfileEdit> profiles, _) = store.Load();
            store.Save(profiles);

            Assert.True(File.Exists(store.ConfigPath + ".backup"));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
