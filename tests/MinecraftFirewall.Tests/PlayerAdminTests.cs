using System.Net;
using System.Text.Json;
using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Admin;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Tests.TestDoubles;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Managing the people a server knows, from the control panel.
///
/// The care here is mostly about what these commands must NOT quietly do. Two of them change who can
/// use a name; one of them only appears to persist. An administrator clicking a button gets no room
/// for a paragraph of warning, so the warning has to be in the reply, and the reply has to be true.
/// </summary>
public class PlayerAdminTests
{
    private static readonly IPAddress Player = IPAddress.Parse("159.146.99.204");

    private static (PlayerAdmin Admin, ServerProfile Profile) Create()
    {
        var profile = new ServerProfile { Name = "EkipSurvival", PublicPort = 25565, BackendHost = "127.0.0.1", BackendPort = 25566 };
        return (new PlayerAdmin([profile], DefenseTestFactory.CreateBotDetector()), profile);
    }

    private static JsonElement Parse(AdminResponse response)
    {
        Assert.True(response.Success, response.Message);
        return JsonDocument.Parse(response.Message).RootElement;
    }

    // ---- reading ---------------------------------------------------------------------------------

    [Fact]
    public void AnUnknownProfileIsSaidSoRatherThanReturningAnEmptyList()
    {
        // An empty list and a typo look identical in a panel, and only one of them means "nobody has
        // registered yet".
        (PlayerAdmin admin, _) = Create();

        AdminResponse response = admin.List(["NoSuchServer"]);

        Assert.False(response.Success);
        Assert.Contains("EkipSurvival", response.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheListSaysWhoEachNameIsAndWhenTheyRegistered()
    {
        (PlayerAdmin admin, ServerProfile profile) = Create();

        IdentityEntry entry = profile.IdentityStore.GetOrCreate("CaYatur");
        entry.PasswordHash = PasswordHasher.Hash("correcthorse");
        entry.RegisteredAt = new DateTimeOffset(2026, 8, 25, 16, 31, 43, TimeSpan.FromHours(3));
        entry.Record(PlayerEventKind.Registered, Player, "chose a password", entry.RegisteredAt.Value);

        JsonElement listed = Parse(admin.List(["EkipSurvival"]));
        JsonElement row = listed.EnumerateArray().Single();

        Assert.Equal("CaYatur", row.GetProperty("username").GetString());
        Assert.Equal("registered", row.GetProperty("status").GetString());
        Assert.Equal("159.146.99.204", row.GetProperty("lastIp").GetString());
        Assert.NotNull(row.GetProperty("registeredAt").GetString());
    }

    [Fact]
    public void APremiumLockedNameIsShownAsLockedRatherThanRegistered()
    {
        // The distinction matters more than it looks: a locked name has no password, and an
        // administrator seeing "no password" against a name they locked would reasonably conclude
        // something had gone wrong.
        (PlayerAdmin admin, ServerProfile profile) = Create();
        IdentityEntry entry = profile.IdentityStore.GetOrCreate("Owner");
        entry.PremiumRequired = true;

        JsonElement row = Parse(admin.List(["EkipSurvival"])).EnumerateArray().Single();

        Assert.Contains("premium-locked", row.GetProperty("status").GetString()!, StringComparison.Ordinal);
    }

    [Fact]
    public void OpeningAPlayerShowsTheirHistoryNewestFirst()
    {
        (PlayerAdmin admin, ServerProfile profile) = Create();
        IdentityEntry entry = profile.IdentityStore.GetOrCreate("CaYatur");

        var start = new DateTimeOffset(2026, 8, 25, 16, 0, 0, TimeSpan.Zero);
        entry.Record(PlayerEventKind.Registered, Player, "chose a password", start);
        entry.Record(PlayerEventKind.LoginFailed, Player, "wrong password", start.AddMinutes(5));
        entry.Record(PlayerEventKind.LoggedIn, Player, "password accepted", start.AddMinutes(6));

        JsonElement detail = Parse(admin.Info(["EkipSurvival", "CaYatur"]));
        string[] kinds = [.. detail.GetProperty("events").EnumerateArray().Select(e => e.GetProperty("kind").GetString()!)];

        Assert.Equal(["LoggedIn", "LoginFailed", "Registered"], kinds);
    }

    [Fact]
    public void TheRiskFiguresAreLabelledAsBelongingToAnAddress()
    {
        // The scorer keys on an address, and one address can carry several names — this project's own
        // test server saw two. Presenting an address's score as a person's would quietly imply an
        // alt-account correlation that has not been built, so the scope says what it is.
        (PlayerAdmin admin, ServerProfile profile) = Create();
        IdentityEntry entry = profile.IdentityStore.GetOrCreate("CaYatur");
        entry.Record(PlayerEventKind.LoggedIn, Player, "joined", DateTimeOffset.UtcNow);

        JsonElement detail = Parse(admin.Info(["EkipSurvival", "CaYatur"]));

        Assert.Contains("address", detail.GetProperty("riskScope").GetString()!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not for the person", detail.GetProperty("riskScope").GetString()!, StringComparison.Ordinal);
    }

    [Fact]
    public void RiskIsSurfacedFromTheRealScorerRatherThanInvented()
    {
        // Same signals the login path scores, so the weights the panel shows add up to the number the
        // log prints. A second scorer would drift from the first and nobody would know which was right.
        (PlayerAdmin admin, ServerProfile profile) = Create();
        var detector = DefenseTestFactory.CreateBotDetector();
        var withDetector = new PlayerAdmin([profile], detector);

        IdentityEntry entry = profile.IdentityStore.GetOrCreate("CaYatur");
        entry.Record(PlayerEventKind.LoggedIn, Player, "joined", DateTimeOffset.UtcNow);

        for (int i = 0; i < 3; i++)
            detector.RecordHostnameMismatch(Player, HostnameMismatchKind.ForeignDomain);

        JsonElement detail = Parse(withDetector.Info(["EkipSurvival", "CaYatur"]));
        JsonElement[] risks = [.. detail.GetProperty("risks").EnumerateArray()];

        Assert.Contains(risks, r => r.GetProperty("name").GetString() == "hostname-mismatch");
        Assert.Equal(risks.Sum(r => r.GetProperty("weight").GetInt32()), detail.GetProperty("riskTotal").GetInt32());

        _ = admin; // the shared-detector instance is not the one under test here
    }

    [Fact]
    public void AskingAboutSomebodyTheServerHasNeverSeenIsAnError()
    {
        (PlayerAdmin admin, _) = Create();

        Assert.False(admin.Info(["EkipSurvival", "Nobody"]).Success);
    }

    // ---- changing things --------------------------------------------------------------------------

    [Fact]
    public void ResettingAPasswordAlsoForgetsTheAddressesItWasTrustedFrom()
    {
        // Otherwise a reset hands the name to whoever is nearest: the password is gone, but the
        // address is still trusted, so the next connection from it walks straight in and registers.
        (PlayerAdmin admin, ServerProfile profile) = Create();
        IdentityEntry entry = profile.IdentityStore.GetOrCreate("CaYatur");
        entry.PasswordHash = PasswordHasher.Hash("correcthorse");
        entry.LearnIp(Player, TimeSpan.FromDays(30), 5);

        AdminResponse response = admin.ResetPassword(["EkipSurvival", "CaYatur"]);

        Assert.True(response.Success);
        Assert.Null(entry.PasswordHash);
        Assert.False(entry.IsIpRecognized(Player));
    }

    [Fact]
    public void AResetIsRecordedInThePlayersOwnHistory()
    {
        // So that "why am I being asked to register again?" has an answer somebody can look up.
        (PlayerAdmin admin, ServerProfile profile) = Create();
        IdentityEntry entry = profile.IdentityStore.GetOrCreate("CaYatur");
        entry.PasswordHash = PasswordHasher.Hash("correcthorse");

        admin.ResetPassword(["EkipSurvival", "CaYatur"]);

        Assert.Contains(entry.Events, e => e.Kind == PlayerEventKind.PasswordReset);
    }

    [Fact]
    public void ForgettingAddressesLeavesThePasswordAlone()
    {
        // The gentler half of a reset: make them prove the password again, without taking it away.
        (PlayerAdmin admin, ServerProfile profile) = Create();
        IdentityEntry entry = profile.IdentityStore.GetOrCreate("CaYatur");
        entry.PasswordHash = PasswordHasher.Hash("correcthorse");
        entry.LearnIp(Player, TimeSpan.FromDays(30), 5);

        Assert.True(admin.ForgetAddresses(["EkipSurvival", "CaYatur"]).Success);

        Assert.NotNull(entry.PasswordHash);
        Assert.False(entry.IsIpRecognized(Player));
    }

    [Fact]
    public void RemovingANameDeclaredInConfigurationSaysItWillComeBack()
    {
        // It genuinely will, on the next restart, because appsettings.json is that field's source of
        // truth. Letting somebody find that out for themselves a week later is the worst option.
        (PlayerAdmin admin, ServerProfile profile) = Create();
        IdentityEntry entry = profile.IdentityStore.GetOrCreate("Owner");
        entry.PremiumRequired = true;

        AdminResponse response = admin.Remove(["EkipSurvival", "Owner"]);

        Assert.True(response.Success);
        Assert.Contains("appsettings.json", response.Message, StringComparison.Ordinal);
        Assert.Null(profile.IdentityStore.Find("Owner"));
    }

    [Fact]
    public void RemovingAnOrdinaryRegisteredNameDoesNotClaimItWillComeBack()
    {
        (PlayerAdmin admin, ServerProfile profile) = Create();
        profile.IdentityStore.GetOrCreate("CaYatur").PasswordHash = PasswordHasher.Hash("correcthorse");

        AdminResponse response = admin.Remove(["EkipSurvival", "CaYatur"]);

        Assert.True(response.Success);
        Assert.DoesNotContain("come back", response.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void LockingANameToAnAccountWarnsThatItDoesNotSurviveARestart()
    {
        // The one setting whose loss fails OPEN rather than closed: the name becomes usable by anyone
        // again, rather than simply being denied. It has already bitten once, on the CLI.
        (PlayerAdmin admin, ServerProfile profile) = Create();

        AdminResponse response = admin.SetPremium(["EkipSurvival", "Owner", "true"]);

        Assert.True(response.Success);
        Assert.True(profile.IdentityStore.Find("Owner")!.PremiumRequired);
        Assert.Contains("does NOT", response.Message, StringComparison.Ordinal);
        Assert.Contains("RequirePremium", response.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UnlockingSaysToRemoveItFromConfigurationToo()
    {
        (PlayerAdmin admin, ServerProfile profile) = Create();
        profile.IdentityStore.GetOrCreate("Owner").PremiumRequired = true;

        AdminResponse response = admin.SetPremium(["EkipSurvival", "Owner", "false"]);

        Assert.True(response.Success);
        Assert.False(profile.IdentityStore.Find("Owner")!.PremiumRequired);
        Assert.Contains("appsettings.json", response.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryCommandRefusesTheWrongNumberOfArguments()
    {
        // These arrive from a pipe, and a malformed one must be a message rather than an exception
        // that takes the admin surface down with it.
        (PlayerAdmin admin, _) = Create();

        Assert.False(admin.List([]).Success);
        Assert.False(admin.Info(["EkipSurvival"]).Success);
        Assert.False(admin.ResetPassword(["EkipSurvival"]).Success);
        Assert.False(admin.ForgetAddresses([]).Success);
        Assert.False(admin.Remove(["EkipSurvival"]).Success);
        Assert.False(admin.SetPremium(["EkipSurvival", "Owner", "maybe"]).Success);
    }
}
