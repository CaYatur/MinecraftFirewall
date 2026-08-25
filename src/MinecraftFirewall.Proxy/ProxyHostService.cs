using MinecraftFirewall.Proxy.Anomaly;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Identity.Premium;
using MinecraftFirewall.Proxy.Inspection;
using MinecraftFirewall.Proxy.Messages;
using MinecraftFirewall.Proxy.Policy;
using MinecraftFirewall.Proxy.Protocol;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy;

/// <summary>Starts one ProxyListener per configured server profile and keeps them running for the service's lifetime.</summary>
public sealed class ProxyHostService(
    IReadOnlyList<ServerProfile> profiles,
    PolicyEngine policyEngine,
    IOptions<IdentityOptions> identityOptions,
    IOptions<Policy.DangerousCommandOptions> dangerousCommandOptions,
    IOptions<MessagesOptions> messagesOptions,
    IOptions<InspectionOptions> inspectionOptions,
    PremiumLoginHandshake premiumHandshake,
    ConnectionGovernor governor,
    BotDetector botDetector,
    AnomalyDetector anomalyDetector,
    ProtocolLearningService protocolLearning,
    ILoggerFactory loggerFactory) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (profiles.Count == 0)
        {
            loggerFactory.CreateLogger<ProxyHostService>()
                .LogWarning("No server profiles configured — nothing to listen on. Add entries under ServerProfiles in appsettings.json.");
            return;
        }

        IReadOnlyCollection<string> dangerousCommands = dangerousCommandOptions.Value.Commands;
        MessagesOptions messages = messagesOptions.Value;

        var tasks = profiles.Select(profile =>
        {
            var logger = loggerFactory.CreateLogger($"ProxyListener.{profile.Name}");
            var listener = new ProxyListener(profile, policyEngine, identityOptions.Value, dangerousCommands, messages,
                premiumHandshake, governor, botDetector, inspectionOptions.Value, anomalyDetector, protocolLearning, logger);
            return listener.RunAsync(stoppingToken);
        }).ToArray();

        await Task.WhenAll(tasks).ConfigureAwait(false);
    }
}
