using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Policy;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy;

/// <summary>Starts one ProxyListener per configured server profile and keeps them running for the service's lifetime.</summary>
public sealed class ProxyHostService(
    IReadOnlyList<ServerProfile> profiles,
    PolicyEngine policyEngine,
    IOptions<IdentityOptions> identityOptions,
    IOptions<Policy.DangerousCommandOptions> dangerousCommandOptions,
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

        var tasks = profiles.Select(profile =>
        {
            var logger = loggerFactory.CreateLogger($"ProxyListener.{profile.Name}");
            var listener = new ProxyListener(profile, policyEngine, identityOptions.Value, dangerousCommands, logger);
            return listener.RunAsync(stoppingToken);
        }).ToArray();

        await Task.WhenAll(tasks).ConfigureAwait(false);
    }
}
