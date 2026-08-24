using System.Net;
using System.Net.Sockets;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Messages;
using MinecraftFirewall.Proxy.Policy;

namespace MinecraftFirewall.Proxy;

/// <summary>One accept loop bound to a single server profile's public port.</summary>
public sealed class ProxyListener(
    ServerProfile profile,
    PolicyEngine policyEngine,
    IdentityOptions identityOptions,
    IReadOnlyCollection<string> dangerousCommands,
    MessagesOptions messages,
    ILogger logger)
{
    public async Task RunAsync(CancellationToken ct)
    {
        var listener = new TcpListener(IPAddress.Any, profile.PublicPort);
        listener.Start();
        logger.LogInformation("[{Profile}] listening on port {Port}, forwarding to {Host}:{BackendPort}.",
            profile.Name, profile.PublicPort, profile.BackendHost, profile.BackendPort);

        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                _ = HandleClientSafelyAsync(client, ct);
            }
        }
        finally
        {
            listener.Stop();
        }
    }

    private async Task HandleClientSafelyAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            await ClientConnection.HandleAsync(client, profile, policyEngine, identityOptions, dangerousCommands, messages, logger, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "[{Profile}] unhandled error while handling a connection.", profile.Name);
        }
    }
}
