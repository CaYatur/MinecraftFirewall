using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Enforcement;
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
