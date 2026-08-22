using MinecraftFirewall.Proxy.Policy;

namespace MinecraftFirewall.Proxy;

/// <summary>Starts one ProxyListener per configured server profile and keeps them running for the service's lifetime.</summary>
public sealed class ProxyHostService(
    IReadOnlyList<ServerProfile> profiles,
    PolicyEngine policyEngine,
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

        var tasks = profiles.Select(profile =>
        {
            var logger = loggerFactory.CreateLogger($"ProxyListener.{profile.Name}");
            var listener = new ProxyListener(profile, policyEngine, logger);
            return listener.RunAsync(stoppingToken);
        }).ToArray();

        await Task.WhenAll(tasks).ConfigureAwait(false);
    }
}
