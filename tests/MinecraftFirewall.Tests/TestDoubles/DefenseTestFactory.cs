using MinecraftFirewall.Proxy.Anomaly;
using MinecraftFirewall.Proxy.Defense;
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

    public static BotDetector CreateBotDetector(BotDefenseOptions? options = null, ThreatIntelligence? threats = null) =>
        new(Options.Create(options ?? new BotDefenseOptions()), threats ?? CreateThreatIntelligence());
}
