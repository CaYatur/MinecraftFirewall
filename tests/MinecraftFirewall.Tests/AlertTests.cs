using System.Net;
using MinecraftFirewall.Proxy.Alerts;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.IpIntel;
using MinecraftFirewall.Proxy.Policy;
using MinecraftFirewall.Proxy.RateLimiting;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace MinecraftFirewall.Tests;

public class AlertTextTests
{
    [Theory]
    [InlineData("@everyone")]
    [InlineData("@here")]
    [InlineData("@EveryOne")]
    public void Field_DefangsMassMentions(string input)
    {
        // Alert bodies embed values that came off the wire — a handshake hostname of "@everyone"
        // would otherwise let anyone who can reach the public port ping a whole Discord server.
        string result = AlertText.Field(input);

        Assert.DoesNotContain("@everyone", result, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("@here", result, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Field_StripsControlCharacters_SoInjectedNewlinesCannotFakeExtraAlertLines()
    {
        // Control characters become spaces rather than vanishing, so the text stays readable. The
        // point is only that an embedded value can never introduce a line of its own and so pass
        // itself off as a separate alert.
        string result = AlertText.Field("evil\nBanned 203.0.113.1\r\nname");

        Assert.DoesNotContain('\n', result);
        Assert.DoesNotContain('\r', result);
        Assert.Single(result.Split('\n'));
    }

    [Fact]
    public void Field_NeutralisesBackticks_SoTextCannotBreakOutOfACodeSpan()
    {
        Assert.DoesNotContain('`', AlertText.Field("na`me` **bold**"));
    }

    [Fact]
    public void Field_CapsLongValues()
    {
        string result = AlertText.Field(new string('x', 5000));

        Assert.True(result.Length < 300);
    }

    [Fact]
    public void Field_EmptyOrNull_ReturnsAPlaceholderRatherThanBlank()
    {
        Assert.Equal("(empty)", AlertText.Field(null));
        Assert.Equal("(empty)", AlertText.Field(""));
    }

    [Fact]
    public void Truncate_KeepsMessagesUnderDiscordsLimit()
    {
        // An over-long post is rejected outright by Discord, which means a silently lost alert.
        string result = AlertText.Truncate(new string('x', 10_000));

        Assert.True(result.Length <= AlertText.MaxMessageLength + 1);
    }
}

public class DiscordAlertSenderTests
{
    private static DiscordAlertSender CreateSender(AlertOptions options, FakeHttpMessageHandler handler) =>
        new(Options.Create(options), new FakeHttpClientFactory(handler), NullLogger<DiscordAlertSender>.Instance);

    [Fact]
    public void Send_WithNoWebhookConfigured_DoesNothingAndReportsDisabled()
    {
        var handler = new FakeHttpMessageHandler((_, _) => throw new InvalidOperationException("must not be called"));
        using var sender = CreateSender(new AlertOptions(), handler);

        Assert.False(sender.IsEnabled);
        sender.Send(AlertKind.Ban, "should be ignored"); // must not throw
    }

    [Fact]
    public async Task Send_PostsTheMessageToTheConfiguredWebhook()
    {
        var posted = new TaskCompletionSource<string>();
        var handler = new FakeHttpMessageHandler(async (request, ct) =>
        {
            posted.TrySetResult(await request.Content!.ReadAsStringAsync(ct));
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        });

        using var sender = CreateSender(
            new AlertOptions { DiscordWebhookUrl = "https://discord.test/webhook", MinimumInterval = TimeSpan.Zero },
            handler);

        sender.Send(AlertKind.Ban, "test alert body");

        string body = await posted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Contains("test alert body", body, StringComparison.Ordinal);
    }

    [Fact]
    public void Send_DisabledKind_IsNotPosted()
    {
        var handler = new FakeHttpMessageHandler((_, _) => throw new InvalidOperationException("must not be called"));
        using var sender = CreateSender(
            new AlertOptions { DiscordWebhookUrl = "https://discord.test/webhook", OnDangerousCommand = false, MinimumInterval = TimeSpan.Zero },
            handler);

        sender.Send(AlertKind.DangerousCommand, "should be filtered out");
    }

    [Fact]
    public void Send_WhenTheWebhookIsFailing_DoesNotThrowIntoTheCaller()
    {
        // Every call site is on a live connection's path — an alerting outage must never surface as a
        // failed or delayed player connection.
        var handler = new FakeHttpMessageHandler((_, _) => throw new HttpRequestException("network down"));
        using var sender = CreateSender(
            new AlertOptions { DiscordWebhookUrl = "https://discord.test/webhook", MinimumInterval = TimeSpan.Zero },
            handler);

        for (int i = 0; i < 20; i++)
            sender.Send(AlertKind.Ban, $"alert {i}");
    }

    [Fact]
    public void Send_FloodingBeyondTheQueueBound_StaysBoundedAndReturnsImmediately()
    {
        // The scenario that matters: a bot flood generating alerts far faster than Discord accepts
        // them. Send must never block the proxy, and the queue must not grow without limit.
        var handler = new FakeHttpMessageHandler(async (_, ct) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(30), ct);
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        });
        using var sender = CreateSender(
            new AlertOptions { DiscordWebhookUrl = "https://discord.test/webhook", MaxQueuedAlerts = 10 },
            handler);

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        for (int i = 0; i < 10_000; i++)
            sender.Send(AlertKind.Ban, $"alert {i}");
        stopwatch.Stop();

        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5), $"Send blocked the caller for {stopwatch.Elapsed}.");
    }
}

public class PolicyEngineAlertTests
{
    private static PolicyEngine CreateEngine(RecordingAlertSender alerts, int strikesBeforeBan = 100)
    {
        var banOptions = Options.Create(new FirewallBanOptions { StrikesBeforeBan = strikesBeforeBan });
        var banService = new FirewallBanService(
            banOptions,
            new NeverBanList(Options.Create(new NeverBanOptions())),
            new FakeWindowsFirewallGateway(),
            alerts,
            NullLogger<FirewallBanService>.Instance);

        return new PolicyEngine(
            new VpnIntelligence(),
            new ConnectionRateLimiter(Options.Create(new RateLimitOptions())),
            banService,
            new StrikeTracker(),
            new FakeIpInfoClient(),
            alerts,
            banOptions,
            Options.Create(new IpInfoOptions()),
            NullLogger<PolicyEngine>.Instance);
    }

    private static string SingleMessageOfKind(RecordingAlertSender alerts, AlertKind kind) =>
        Assert.Single(alerts.Sent, a => a.Kind == kind).Message;

    [Fact]
    public void RegisterDangerousCommand_AlertsWithTheBaseCommandAndAlsoFiresTheFastTrackBan()
    {
        // A dangerous command is fast-tracked straight to the ban threshold, so this deliberately
        // produces two alerts — the command itself and the resulting ban. Asserting both keeps the
        // fast-track behaviour visible rather than accidentally asserting it away.
        var alerts = new RecordingAlertSender();
        var engine = CreateEngine(alerts, strikesBeforeBan: 1);

        engine.RegisterDangerousCommand(IPAddress.Parse("203.0.113.9"), "profileA", "Mallory", "op");

        string message = SingleMessageOfKind(alerts, AlertKind.DangerousCommand);
        Assert.Contains("op", message, StringComparison.Ordinal);
        Assert.Contains("Mallory", message, StringComparison.Ordinal);
        Assert.Contains(alerts.Sent, a => a.Kind == AlertKind.Ban);
    }

    [Fact]
    public void RegisterGraceAuthSuccess_AlertsSoAStolenPasswordIsVisible()
    {
        var alerts = new RecordingAlertSender();
        var engine = CreateEngine(alerts);

        engine.RegisterGraceAuthSuccess(IPAddress.Parse("203.0.113.9"), "profileA", "Player1");

        string message = SingleMessageOfKind(alerts, AlertKind.NewTrustedIp);
        Assert.Contains("Player1", message, StringComparison.Ordinal);
    }

    [Fact]
    public void RegisterPremiumVerificationFailure_DistinguishesImpersonationFromAnOrdinaryFailure()
    {
        // The two cases read very differently to an admin: one may well be their own outage-hit
        // player, the other is someone with real credentials trying to take a claimed name.
        var alerts = new RecordingAlertSender();
        var engine = CreateEngine(alerts);
        var ip = IPAddress.Parse("203.0.113.9");

        engine.RegisterPremiumVerificationFailure(ip, "profileA", "Owner", "Mojang session check failed.", pinnedToDifferentAccount: false);
        engine.RegisterPremiumVerificationFailure(ip, "profileA", "Owner", "Username is pinned to a different Minecraft account.", pinnedToDifferentAccount: true);

        var premiumAlerts = alerts.Sent.Where(a => a.Kind == AlertKind.PremiumVerificationFailure).ToList();
        Assert.Equal(2, premiumAlerts.Count);
        Assert.Contains("outage", premiumAlerts[0].Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Impersonation", premiumAlerts[1].Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AUsernameContainingAMassMention_IsDefangedBeforeItReachesTheAlert()
    {
        // Minecraft usernames can't contain '@', but nothing guarantees every caller is a real
        // Minecraft client — the sanitisation has to hold at the alert boundary regardless.
        var alerts = new RecordingAlertSender();
        var engine = CreateEngine(alerts);

        engine.RegisterDangerousCommand(IPAddress.Parse("203.0.113.9"), "profileA", "@everyone", "op");

        Assert.All(alerts.Sent, a => Assert.DoesNotContain("@everyone", a.Message, StringComparison.OrdinalIgnoreCase));
    }
}
