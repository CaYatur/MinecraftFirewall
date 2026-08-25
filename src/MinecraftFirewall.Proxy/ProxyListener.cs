using System.Net;
using System.Net.Sockets;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Identity.Premium;
using MinecraftFirewall.Proxy.Inspection;
using MinecraftFirewall.Proxy.Messages;
using MinecraftFirewall.Proxy.Policy;

namespace MinecraftFirewall.Proxy;

/// <summary>
/// One accept loop bound to a single server profile's public port.
///
/// The accept loop is where a flood is cheapest to survive, so admission control happens here rather
/// than inside the connection handler: an address over its limit is refused before a stream is opened,
/// before a task is queued, and before a single byte is read. Everything downstream — handshake
/// parsing, policy evaluation, the identity gate — costs real work, and a flood is precisely an
/// attempt to make the server do that work faster than it can afford to.
/// </summary>
public sealed class ProxyListener(
    ServerProfile profile,
    PolicyEngine policyEngine,
    IdentityOptions identityOptions,
    IReadOnlyCollection<string> dangerousCommands,
    MessagesOptions messages,
    PremiumLoginHandshake premiumHandshake,
    ConnectionGovernor governor,
    BotDetector botDetector,
    InspectionOptions inspection,
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

                if (!TryAdmit(client, out ConnectionLease? lease))
                    continue;

                _ = HandleClientSafelyAsync(client, lease!, ct);
            }
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>
    /// Applies admission control and closes the socket itself when the answer is no.
    ///
    /// Disposing on the refusal path is not tidiness: the sockets being turned away are, by
    /// definition, arriving faster than usual, so leaking one per refusal would exhaust handles
    /// fastest under exactly the conditions this check exists for.
    /// </summary>
    private bool TryAdmit(TcpClient client, out ConnectionLease? lease)
    {
        lease = null;

        if (client.Client.RemoteEndPoint is not IPEndPoint endpoint)
        {
            client.Dispose();
            return false;
        }

        AdmissionResult admission = governor.TryAdmit(endpoint.Address);
        if (admission.Admitted)
        {
            lease = admission.Lease;
            return true;
        }

        client.Dispose();

        // Debug, not warning. A refusal during a flood happens thousands of times a second, and a log
        // line each would make the disk the thing that fails. The governor logs the transition into
        // defensive mode once, which is the event actually worth seeing.
        logger.LogDebug("[{Profile}] refused {Ip}: {Verdict} — {Detail}",
            profile.Name, endpoint.Address, admission.Verdict, admission.Detail);

        policyEngine.RegisterFloodRefusal(endpoint.Address, profile.Name, admission.Verdict);
        return false;
    }

    private async Task HandleClientSafelyAsync(TcpClient client, ConnectionLease lease, CancellationToken ct)
    {
        try
        {
            await ClientConnection.HandleAsync(client, profile, policyEngine, identityOptions, dangerousCommands,
                messages, premiumHandshake, botDetector, inspection, logger, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "[{Profile}] unhandled error while handling a connection.", profile.Name);
        }
        finally
        {
            // Covers every path out of the handler, including the early returns for a malformed
            // handshake. A slot that is never given back is a slot lost for the process's lifetime.
            lease.Dispose();
        }
    }
}
