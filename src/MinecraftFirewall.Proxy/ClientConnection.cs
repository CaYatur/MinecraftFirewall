using System.Net;
using System.Net.Sockets;
using MinecraftFirewall.Proxy.Policy;
using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Proxy;

/// <summary>
/// Per-connection orchestration: read Handshake (+ Login Start if applicable) under a short
/// pre-login deadline, ask the PolicyEngine for a decision, then either deny (with a proper Login
/// Disconnect packet when possible) or forward the bytes already read verbatim and become a byte
/// pump for the rest of the connection. Stage 1 never inspects anything past this point — Play-state
/// inspection is Stage 3.
/// </summary>
public static class ClientConnection
{
    private static readonly TimeSpan PreLoginTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan BackendConnectTimeout = TimeSpan.FromSeconds(5);

    public static async Task HandleAsync(TcpClient client, ServerProfile profile, PolicyEngine policyEngine, ILogger logger, CancellationToken hostShutdown)
    {
        using var _ = client;
        client.NoDelay = true;

        if (client.Client.RemoteEndPoint is not IPEndPoint remoteEndPoint)
        {
            return;
        }

        IPAddress remoteAddress = remoteEndPoint.Address;

        using var preLoginCts = CancellationTokenSource.CreateLinkedTokenSource(hostShutdown);
        preLoginCts.CancelAfter(PreLoginTimeout);

        NetworkStream clientStream = client.GetStream();

        Frame handshakeFrame;
        HandshakeInfo handshake;
        try
        {
            handshakeFrame = await FrameReader.ReadFrameAsync(clientStream, FrameReader.MaxPreLoginFrameSize, preLoginCts.Token).ConfigureAwait(false);
            handshake = HandshakeReader.ParseHandshake(handshakeFrame.Payload);
        }
        catch (OperationCanceledException) when (!hostShutdown.IsCancellationRequested)
        {
            logger.LogDebug("[{Profile}] {Ip} timed out or was slow sending the Handshake packet.", profile.Name, remoteAddress);
            return;
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or EndOfStreamException or SocketException)
        {
            logger.LogDebug("[{Profile}] {Ip} sent a malformed Handshake: {Message}", profile.Name, remoteAddress, ex.Message);
            return;
        }

        if (handshake.NextState == HandshakeNextState.Status)
        {
            await HandleStatusAsync(client, clientStream, handshakeFrame, profile, remoteAddress, policyEngine, logger, hostShutdown).ConfigureAwait(false);
            return;
        }

        await HandleLoginAsync(client, clientStream, handshakeFrame, profile, remoteAddress, policyEngine, logger, preLoginCts, hostShutdown).ConfigureAwait(false);
    }

    private static async Task HandleStatusAsync(TcpClient client, NetworkStream clientStream, Frame handshakeFrame,
        ServerProfile profile, IPAddress remoteAddress, PolicyEngine policyEngine, ILogger logger, CancellationToken hostShutdown)
    {
        var decision = policyEngine.EvaluateStatusPing(profile, remoteAddress);
        if (!decision.Allow)
        {
            logger.LogDebug("[{Profile}] status ping from {Ip} denied: {Reason}", profile.Name, remoteAddress, decision.Reason);
            return;
        }

        var (backendClient, backendStream) = await TryConnectBackendAsync(profile, logger, hostShutdown).ConfigureAwait(false);
        if (backendClient is null || backendStream is null)
            return;

        using var _ = backendClient;
        await backendStream.WriteAsync(handshakeFrame.Raw, hostShutdown).ConfigureAwait(false);
        await PumpBothWaysAsync(clientStream, backendStream, hostShutdown).ConfigureAwait(false);
    }

    private static async Task HandleLoginAsync(TcpClient client, NetworkStream clientStream, Frame handshakeFrame,
        ServerProfile profile, IPAddress remoteAddress, PolicyEngine policyEngine, ILogger logger,
        CancellationTokenSource preLoginCts, CancellationToken hostShutdown)
    {
        Frame loginStartFrame;
        string username;
        try
        {
            loginStartFrame = await FrameReader.ReadFrameAsync(clientStream, FrameReader.MaxPreLoginFrameSize, preLoginCts.Token).ConfigureAwait(false);
            username = HandshakeReader.ParseLoginStartUsername(loginStartFrame.Payload);
        }
        catch (OperationCanceledException) when (!hostShutdown.IsCancellationRequested)
        {
            logger.LogDebug("[{Profile}] {Ip} timed out or was slow sending Login Start.", profile.Name, remoteAddress);
            return;
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or EndOfStreamException or SocketException)
        {
            logger.LogDebug("[{Profile}] {Ip} sent a malformed Login Start: {Message}", profile.Name, remoteAddress, ex.Message);
            return;
        }

        var decision = policyEngine.EvaluateLogin(profile, remoteAddress, username);
        if (!decision.Allow)
        {
            logger.LogInformation("[{Profile}] login denied for '{Username}' from {Ip}: {Reason}",
                profile.Name, username, remoteAddress, decision.Reason);
            await TrySendDisconnectAsync(clientStream, "This connection was blocked by MinecraftFirewall.", hostShutdown).ConfigureAwait(false);
            return;
        }

        var (backendClient, backendStream) = await TryConnectBackendAsync(profile, logger, hostShutdown).ConfigureAwait(false);
        if (backendClient is null || backendStream is null)
            return;

        using var _ = backendClient;
        logger.LogInformation("[{Profile}] login allowed for '{Username}' from {Ip}.", profile.Name, username, remoteAddress);

        await backendStream.WriteAsync(handshakeFrame.Raw, hostShutdown).ConfigureAwait(false);
        await backendStream.WriteAsync(loginStartFrame.Raw, hostShutdown).ConfigureAwait(false);
        await PumpBothWaysAsync(clientStream, backendStream, hostShutdown).ConfigureAwait(false);
    }

    private static async Task<(TcpClient? Client, NetworkStream? Stream)> TryConnectBackendAsync(
        ServerProfile profile, ILogger logger, CancellationToken hostShutdown)
    {
        var backendClient = new TcpClient { NoDelay = true };

        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(hostShutdown);
        connectCts.CancelAfter(BackendConnectTimeout);

        try
        {
            await backendClient.ConnectAsync(profile.BackendHost, profile.BackendPort, connectCts.Token).ConfigureAwait(false);
            return (backendClient, backendClient.GetStream());
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "[{Profile}] failed to connect to backend {Host}:{Port}.", profile.Name, profile.BackendHost, profile.BackendPort);
            backendClient.Dispose();
            return (null, null);
        }
    }

    private static async Task TrySendDisconnectAsync(NetworkStream clientStream, string reason, CancellationToken ct)
    {
        try
        {
            byte[] packet = LoginDisconnect.BuildPacket(reason);
            await clientStream.WriteAsync(packet, ct).ConfigureAwait(false);
        }
        catch
        {
            // Best-effort only — the connection is being closed either way.
        }
    }

    private static async Task PumpBothWaysAsync(NetworkStream clientStream, NetworkStream backendStream, CancellationToken hostShutdown)
    {
        using var pumpCts = CancellationTokenSource.CreateLinkedTokenSource(hostShutdown);

        Task clientToBackend = PumpAsync(clientStream, backendStream, pumpCts);
        Task backendToClient = PumpAsync(backendStream, clientStream, pumpCts);

        await Task.WhenAny(clientToBackend, backendToClient).ConfigureAwait(false);
        pumpCts.Cancel();

        try
        {
            await Task.WhenAll(clientToBackend, backendToClient).ConfigureAwait(false);
        }
        catch
        {
            // Expected once one side closes and the other's copy is cancelled/faults.
        }
    }

    private static async Task PumpAsync(NetworkStream source, NetworkStream destination, CancellationTokenSource pumpCts)
    {
        try
        {
            await source.CopyToAsync(destination, 81920, pumpCts.Token).ConfigureAwait(false);
        }
        catch
        {
            // Any failure here just means this half of the relay is done; the caller tears down both.
        }
        finally
        {
            pumpCts.Cancel();
        }
    }
}
