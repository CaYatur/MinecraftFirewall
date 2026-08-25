using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Alerts;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.Inspection;
using MinecraftFirewall.Proxy.Identity.Persistence;
using MinecraftFirewall.Proxy.Identity.Premium;
using MinecraftFirewall.Proxy.IpIntel;
using MinecraftFirewall.Proxy.Messages;
using MinecraftFirewall.Proxy.RateLimiting;
using Microsoft.Extensions.Configuration;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Loads the actual shipped src/MinecraftFirewall.Proxy/appsettings.json through the real .NET JSON
/// configuration pipeline (not a hand-built in-memory fixture). This is the only test that would catch
/// a JSON syntax error in that file — e.g. the commented-out Turkish "Messages" example block breaking
/// the surrounding object — since no other test ever parses the shipped file itself.
/// </summary>
public class AppSettingsJsonBindingTests
{
    private static string FindAppSettingsPath()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "MinecraftFirewall.slnx")))
            dir = dir.Parent;

        if (dir is null)
            throw new InvalidOperationException("Could not locate the repository root from the test output directory.");

        return Path.Combine(dir.FullName, "src", "MinecraftFirewall.Proxy", "appsettings.json");
    }

    private static IConfigurationRoot LoadConfiguration() =>
        new ConfigurationBuilder().AddJsonFile(FindAppSettingsPath(), optional: false).Build();

    [Fact]
    public void AppSettingsJson_DefenceSections_BindToTheOptionTypesTheServiceActuallyReads()
    {
        // A typo in a section name does not fail — it binds nothing, and the option object silently
        // keeps its compiled defaults. For the defence layer that failure mode is worse than usual:
        // the settings that ship deliberately switched OFF (honeypot, bot denial, movement kicking)
        // would look identical to a misspelled section, so nobody would ever notice the file was
        // being ignored. Each assertion below is a value that differs from — or is deliberately
        // pinned to — the C# default, so a mis-bound section shows up as a failure.
        var config = LoadConfiguration();

        var ddos = config.GetSection(DdosOptions.SectionName).Get<DdosOptions>();
        Assert.NotNull(ddos);
        Assert.True(ddos!.Enabled);
        Assert.Equal(16, ddos.MaxConcurrentPerIp);
        Assert.Equal(TimeSpan.FromSeconds(45), ddos.UnderAttackCooldown);

        var bots = config.GetSection(BotDefenseOptions.SectionName).Get<BotDefenseOptions>();
        Assert.NotNull(bots);
        // Ships in log-only mode on purpose — see BotDefenseOptions.Action.
        Assert.Equal(BotAction.LogOnly, bots!.Action);

        var honeypot = config.GetSection(HoneypotOptions.SectionName).Get<HoneypotOptions>();
        Assert.NotNull(honeypot);
        Assert.False(honeypot!.Enabled);
        Assert.NotEmpty(honeypot.Ports);

        var threats = config.GetSection(ThreatIntelOptions.SectionName).Get<ThreatIntelOptions>();
        Assert.NotNull(threats);
        Assert.Equal(ThreatListAction.Score, threats!.Action);
        Assert.NotEmpty(threats.FeedUrls);

        var inspection = config.GetSection(InspectionOptions.SectionName).Get<InspectionOptions>();
        Assert.NotNull(inspection);
        Assert.True(inspection!.Enabled);
        Assert.True(inspection.BlockImpossibleCoordinates);
        // The one that must stay off: this proxy cannot see the ice, boat or plugin teleport that
        // would explain an unusual movement. See InspectionOptions.KickOnMovementAnomaly.
        Assert.False(inspection.KickOnMovementAnomaly);
    }

    [Fact]
    public void AppSettingsJson_HoneypotPorts_DoNotCollideWithAnyShippedServerProfile()
    {
        // A decoy bound on a real server port either fails or, depending on start order, wins — and
        // then bans players for connecting to their own server. The service drops colliding ports at
        // startup, but the shipped defaults should not rely on that rescue.
        var config = LoadConfiguration();

        var honeypot = config.GetSection(HoneypotOptions.SectionName).Get<HoneypotOptions>()!;
        var profiles = config.GetSection("ServerProfiles").Get<List<ServerProfileConfig>>()!;

        foreach (var profile in profiles)
        {
            Assert.DoesNotContain(profile.PublicPort, honeypot.Ports);
            Assert.DoesNotContain(profile.BackendPort, honeypot.Ports);
        }
    }

    [Fact]
    public void AppSettingsJson_ParsesWithoutError()
    {
        var config = LoadConfiguration();

        Assert.NotNull(config);
    }

    [Fact]
    public void AppSettingsJson_MessagesSection_BindsAndTheCommentedTurkishBlockDidNotSilentlyApply()
    {
        var config = LoadConfiguration();
        var messages = new MessagesOptions();
        config.GetSection(MessagesOptions.SectionName).Bind(messages);

        Assert.Equal(new MessagesOptions().GenericDenied, messages.GenericDenied);
        Assert.DoesNotContain("bağlantı", messages.GenericDenied, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AppSettingsJson_ServerProfiles_BindsAtLeastOneProfileWithNoHostnameRestrictionByDefault()
    {
        var config = LoadConfiguration();
        var profileConfigs = config.GetSection("ServerProfiles").Get<List<ServerProfileConfig>>();

        Assert.NotNull(profileConfigs);
        Assert.NotEmpty(profileConfigs!);
        Assert.Empty(profileConfigs![0].AllowedHostnames);
    }

    [Fact]
    public void AppSettingsJson_EveryKnownOptionsSection_BindsWithoutThrowing()
    {
        var config = LoadConfiguration();

        // DangerousCommands and Identity aren't in the shipped file at all — that's intentional, they
        // fall back to their code defaults — so they're not asserted NotNull here, only the sections
        // the shipped file actually declares.
        Assert.NotNull(config.GetSection(VpnIntelOptions.SectionName).Get<VpnIntelOptions>());
        Assert.NotNull(config.GetSection(RateLimitOptions.SectionName).Get<RateLimitOptions>());
        Assert.NotNull(config.GetSection(FirewallBanOptions.SectionName).Get<FirewallBanOptions>());
        Assert.NotNull(config.GetSection(NeverBanOptions.SectionName).Get<NeverBanOptions>());
        Assert.NotNull(config.GetSection(MessagesOptions.SectionName).Get<MessagesOptions>());
        Assert.NotNull(config.GetSection(IpInfoOptions.SectionName).Get<IpInfoOptions>());
        Assert.NotNull(config.GetSection(PremiumOptions.SectionName).Get<PremiumOptions>());
        Assert.NotNull(config.GetSection(IdentityPersistenceOptions.SectionName).Get<IdentityPersistenceOptions>());
        Assert.NotNull(config.GetSection(AlertOptions.SectionName).Get<AlertOptions>());
    }

    [Fact]
    public void AppSettingsJson_Alerts_ShipWithNoWebhookSoNothingIsSentByDefault()
    {
        // A webhook URL is a secret and a destination the operator must choose deliberately — this
        // must never ship pointing anywhere.
        var config = LoadConfiguration();
        var alerts = config.GetSection(AlertOptions.SectionName).Get<AlertOptions>();

        Assert.NotNull(alerts);
        Assert.True(string.IsNullOrWhiteSpace(alerts!.DiscordWebhookUrl));
        Assert.True(alerts.MaxQueuedAlerts > 0); // a zero bound would silently discard every alert
    }

    [Fact]
    public void AppSettingsJson_IdentityPersistence_ShipsEnabledWithAUsablePath()
    {
        // Shipping this disabled would silently un-claim every premium name on restart, so it's on by
        // default and the path has to actually be rooted somewhere writable, not left blank.
        var config = LoadConfiguration();
        var persistence = config.GetSection(IdentityPersistenceOptions.SectionName).Get<IdentityPersistenceOptions>();

        Assert.NotNull(persistence);
        Assert.True(persistence!.Enabled);
        Assert.False(string.IsNullOrWhiteSpace(persistence.FilePath));
        Assert.True(Path.IsPathRooted(persistence.FilePath));
        Assert.True(persistence.SaveInterval > TimeSpan.Zero);
    }

    [Fact]
    public void AppSettingsJson_PremiumSection_ShipsEnabled()
    {
        // Unlike IpInfo, premium verification needs no account or token of its own — Mojang's
        // hasJoined endpoint is public — so it ships on. It only ever does anything for a username
        // an admin explicitly marked RequirePremium, and there are none in the shipped profiles.
        var config = LoadConfiguration();
        var premium = config.GetSection(PremiumOptions.SectionName).Get<PremiumOptions>();

        Assert.NotNull(premium);
        Assert.True(premium!.Enabled);
    }

    [Fact]
    public void AppSettingsJson_MessagesSection_DeclaresEveryMessageTheCodeDefines()
    {
        // The shipped file spells out all messages rather than relying on code defaults, so a newly
        // added message that nobody remembered to add here would leave operators unable to find and
        // translate it. This catches that at build time instead.
        var config = LoadConfiguration();
        var declaredKeys = config.GetSection(MessagesOptions.SectionName).GetChildren().Select(c => c.Key).ToHashSet();
        var codeProperties = typeof(MessagesOptions).GetProperties().Select(p => p.Name);

        Assert.All(codeProperties, name => Assert.Contains(name, declaredKeys));
    }

    [Fact]
    public void AppSettingsJson_IpInfoSection_ShipsDisabledByDefault()
    {
        var config = LoadConfiguration();
        var ipInfo = config.GetSection(IpInfoOptions.SectionName).Get<IpInfoOptions>();

        Assert.NotNull(ipInfo);
        Assert.True(string.IsNullOrEmpty(ipInfo!.Token)); // no token shipped — feature is opt-in
        Assert.False(ipInfo.ApplyToAllConnections);
    }
}
