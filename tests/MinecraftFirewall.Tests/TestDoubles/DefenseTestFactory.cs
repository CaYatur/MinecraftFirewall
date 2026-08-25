using MinecraftFirewall.Proxy.Alerts;
using MinecraftFirewall.Proxy.Anomaly;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.IpIntel;
using MinecraftFirewall.Proxy.Policy;
using MinecraftFirewall.Proxy.RateLimiting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Tests.TestDoubles;

/// <summary>
/// Builds the defence-layer services with settings that suit a test rather than a live server.
///
/// The important default here is that threat intelligence is constructed with no feeds and pointed at
/// a throwaway file path. A test that accidentally reached the network would be slow, would fail on a
/// build machine with no internet, and — worse — would produce different results depending on who was
/// on a public blocklist that day.
/// </summary>
public static class DefenseTestFactory
{
    public static ThreatIntelligence CreateThreatIntelligence(ThreatListAction action = ThreatListAction.LogOnly) =>
        new(Options.Create(new ThreatIntelOptions
        {
            FeedUrls = [],
            Action = action,
            LocalThreatLogPath = Path.Combine(Path.GetTempPath(), $"mcfw-test-threats-{Guid.NewGuid():N}.txt"),
        }), NullLogger<ThreatIntelligence>.Instance);

    public static ConnectionGovernor CreateGovernor(DdosOptions? options = null) =>
        new(Options.Create(options ?? new DdosOptions()), NullLogger<ConnectionGovernor>.Instance);

    /// <summary>Disabled by default, which is how it ships — a test that wanted it on would say so.</summary>
    public static AnomalyDetector CreateAnomalyDetector(AnomalyOptions? options = null) =>
        new(Options.Create(options ?? new AnomalyOptions()), NullLogger<AnomalyDetector>.Instance);

    public static ScannerDetector CreateScannerDetector(BotDefenseOptions? options = null) =>
        new(Options.Create(options ?? new BotDefenseOptions()), NullLogger<ScannerDetector>.Instance);

    /// <summary>
    /// Builds a PolicyEngine with test-friendly collaborators.
    ///
    /// It exists because the engine's constructor is where every new defence subsystem arrives, and
    /// each arrival used to break six test files that differed only in which two arguments they cared
    /// about. Everything optional here defaults to something inert, so a test names only what it is
    /// actually testing and adding a dependency touches one file.
    /// </summary>
    public static PolicyEngine CreatePolicyEngine(
        FirewallBanService? banService = null,
        IAlertSender? alerts = null,
        ConnectionRateLimiter? rateLimiter = null,
        VpnIntelligence? vpnIntelligence = null,
        IIpInfoClient? ipInfo = null,
        StrikeTracker? strikeTracker = null,
        FirewallBanOptions? banOptions = null,
        IpInfoOptions? ipInfoOptions = null,
        DdosOptions? ddosOptions = null,
        BotDefenseOptions? botOptions = null,
        IdentityOptions? identityOptions = null,
        AnomalyOptions? anomalyOptions = null,
        ThreatIntelligence? threats = null,
        BotDetector? botDetector = null,
        AnomalyResponder? anomalyResponder = null)
    {
        IOptions<FirewallBanOptions> ban = Options.Create(banOptions ?? new FirewallBanOptions());
        alerts ??= new RecordingAlertSender();
        threats ??= CreateThreatIntelligence();

        banService ??= new FirewallBanService(ban, new NeverBanList(Options.Create(new NeverBanOptions())),
            new FakeWindowsFirewallGateway(), alerts, NullLogger<FirewallBanService>.Instance);

        return new PolicyEngine(
            vpnIntelligence ?? new VpnIntelligence(),
            rateLimiter ?? new ConnectionRateLimiter(Options.Create(new RateLimitOptions())),
            banService,
            strikeTracker ?? new StrikeTracker(),
            ipInfo ?? new FakeIpInfoClient(),
            alerts,
            threats,
            CreateScannerDetector(botOptions),
            botDetector ?? CreateBotDetector(botOptions, threats),
            anomalyResponder ?? CreateAnomalyDetector(anomalyOptions).Responder,
            ban,
            Options.Create(ipInfoOptions ?? new IpInfoOptions()),
            Options.Create(ddosOptions ?? new DdosOptions()),
            Options.Create(botOptions ?? new BotDefenseOptions()),
            Options.Create(identityOptions ?? new IdentityOptions()),
            Options.Create(anomalyOptions ?? new AnomalyOptions()),
            NullLogger<PolicyEngine>.Instance);
    }

    public static BotDetector CreateBotDetector(BotDefenseOptions? options = null, ThreatIntelligence? threats = null) =>
        new(Options.Create(options ?? new BotDefenseOptions()), threats ?? CreateThreatIntelligence());
}
