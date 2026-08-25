using MinecraftFirewall.App.Services;
using MinecraftFirewall.Proxy.Messages;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Bringing player-facing messages up to the current defaults without trampling anybody's own words.
///
/// Configuration wins over the compiled defaults, which is right — it is their file. But it means an
/// improved default never reaches somebody who installed an older release: their prompts stay exactly
/// as they were, with nothing to say why. That is how a set of newly coloured login messages arrived
/// for new installations and for nobody else, which is what prompted this.
///
/// The safety rule is the whole design, and everything here is about it: a message is replaced only
/// when its text is one this project itself shipped, which is proof no person chose it.
/// </summary>
public class MessageRefreshTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"mcfw-msg-{Guid.NewGuid():N}");

    public MessageRefreshTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);

        GC.SuppressFinalize(this);
    }

    /// <summary>A key whose default has changed, taken from the generated history rather than named
    /// here — a test that hardcodes one breaks every time the wording moves on.</summary>
    private static (string Key, string OldValue) AChangedMessage()
    {
        var current = new MessagesOptions();

        foreach ((string key, string[] previous) in MessageDefaultHistory.PreviousDefaults)
        {
            if (current.GetType().GetProperty(key)?.GetValue(current) is string latest && latest != previous[0])
                return (key, previous[0]);
        }

        throw new InvalidOperationException("no message has an earlier default; the history is empty");
    }

    private ServerConfigStore StoreWith(string messagesJson)
    {
        string path = Path.Combine(_directory, "appsettings.json");
        File.WriteAllText(path,
            "{\n" +
            "  // A comment that has to survive.\n" +
            "  \"Identity\": { \"PasswordMinLength\": 6 },\n" +
            "  \"Messages\": {\n" + messagesJson + "\n  }\n" +
            "}\n");

        return new ServerConfigStore(path);
    }

    [Fact]
    public void AMessageStillAtAnOldDefaultIsBroughtUpToDate()
    {
        // The reported case: the login messages gained colour and an existing installation never saw
        // it, because its own file kept saying the old thing.
        (string key, string oldValue) = AChangedMessage();
        ServerConfigStore store = StoreWith($"    \"{key}\": {System.Text.Json.JsonSerializer.Serialize(oldValue)}");

        (bool success, string message) = store.RefreshDefaultMessages();

        Assert.True(success, message);
        Assert.Contains(key, message, StringComparison.Ordinal);

        string latest = (string)new MessagesOptions().GetType().GetProperty(key)!.GetValue(new MessagesOptions())!;
        Assert.Contains(System.Text.Json.JsonSerializer.Serialize(latest),
            File.ReadAllText(store.ConfigPath), StringComparison.Ordinal);
    }

    [Fact]
    public void AMessageSomebodyWroteThemselvesIsNeverTouched()
    {
        // The rule that matters most. Being unhelpful is recoverable; replacing somebody's own words
        // is not — and a server that has translated its prompts has every one of them "out of date".
        (string key, _) = AChangedMessage();
        const string theirs = "Sunucumuza hos geldiniz! Lutfen giris yapin.";

        ServerConfigStore store = StoreWith($"    \"{key}\": {System.Text.Json.JsonSerializer.Serialize(theirs)}");

        (bool success, _) = store.RefreshDefaultMessages();

        Assert.True(success);
        Assert.Contains(System.Text.Json.JsonSerializer.Serialize(theirs),
            File.ReadAllText(store.ConfigPath), StringComparison.Ordinal);
    }

    [Fact]
    public void TheReplySaysHowManyOfTheirOwnWereLeftAlone()
    {
        // So that "nothing happened" is never mistaken for "it did not work".
        (string key, _) = AChangedMessage();
        ServerConfigStore store = StoreWith($"    \"{key}\": \"something they wrote\"");

        (bool success, string message) = store.RefreshDefaultMessages();

        Assert.True(success);
        Assert.Contains("yourself", message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AMessageAlreadyAtTheLatestIsLeftAlone()
    {
        (string key, _) = AChangedMessage();
        string latest = (string)new MessagesOptions().GetType().GetProperty(key)!.GetValue(new MessagesOptions())!;

        ServerConfigStore store = StoreWith($"    \"{key}\": {System.Text.Json.JsonSerializer.Serialize(latest)}");
        string before = File.ReadAllText(store.ConfigPath);

        (bool success, string message) = store.RefreshDefaultMessages();

        Assert.True(success);
        Assert.Contains("up to date", message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(before, File.ReadAllText(store.ConfigPath));
    }

    [Fact]
    public void TheCommentsInTheFileSurvive()
    {
        // Spliced over the exact span of the old value rather than round-tripped. A JSON round-trip
        // eating every comment is a mistake this project has already made once, on this very file.
        (string key, string oldValue) = AChangedMessage();
        ServerConfigStore store = StoreWith($"    \"{key}\": {System.Text.Json.JsonSerializer.Serialize(oldValue)}");

        store.RefreshDefaultMessages();

        Assert.Contains("// A comment that has to survive.",
            File.ReadAllText(store.ConfigPath), StringComparison.Ordinal);
    }

    [Fact]
    public void AFileWithNoMessagesSectionIsSaidSoRatherThanCrashing()
    {
        string path = Path.Combine(_directory, "appsettings.json");
        File.WriteAllText(path, "{ \"Identity\": { } }");

        (bool success, string message) = new ServerConfigStore(path).RefreshDefaultMessages();

        Assert.False(success);
        Assert.Contains("Messages", message, StringComparison.Ordinal);
    }

    // ---- the history itself --------------------------------------------------------------------------

    [Fact]
    public void TheHistoryNeverContainsACurrentDefault()
    {
        // If it did, the check would call an up-to-date message "unedited and old" and rewrite it with
        // itself — harmless here, but it would mean the generator had stopped telling old from new.
        var current = new MessagesOptions();

        foreach ((string key, string[] previous) in MessageDefaultHistory.PreviousDefaults)
        {
            if (current.GetType().GetProperty(key)?.GetValue(current) is not string latest)
                continue;

            Assert.DoesNotContain(latest, previous);
        }
    }

    [Fact]
    public void EveryKeyInTheHistoryIsStillARealMessage()
    {
        // A key that has been removed or renamed would sit in the table forever, matching nothing.
        var current = new MessagesOptions();

        foreach (string key in MessageDefaultHistory.PreviousDefaults.Keys)
            Assert.NotNull(current.GetType().GetProperty(key));
    }

    [Fact]
    public void TheColouredLoginMessagesAreInTheHistory()
    {
        // The specific thing that prompted all of this: these gained colour in a release, and an
        // existing installation kept showing them plain. If they are not in the history, the refresh
        // cannot help the people who reported it.
        foreach (string key in new[] { "PremiumLockExplain", "PremiumLockArmed", "PremiumLockSucceeded" })
            Assert.True(MessageDefaultHistory.PreviousDefaults.ContainsKey(key), $"{key} has no recorded history");
    }
}
