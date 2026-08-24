using System.Net;
using System.Net.Sockets;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Identity.Premium;
using MinecraftFirewall.Proxy.Messages;
using MinecraftFirewall.Proxy.Policy;
using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Proxy;

/// <summary>
/// Per-connection orchestration: read Handshake (+ Login Start if applicable) under a short
/// pre-login deadline, ask the PolicyEngine for a decision, then either deny (with a proper Login
/// Disconnect packet when possible) or forward the bytes already read verbatim. From there: if the
/// client's protocol version is one Stage 3 has verified packet IDs for (ProtocolVersionRegistry),
/// the client-to-backend direction runs through PlayStateInspector (command auditing, CaYaDev-Check);
/// otherwise it's a plain byte pump exactly like Stage 1, since inspecting an unverified version's
/// packets would mean guessing IDs — never done here.
///
/// A username the admin declared PremiumRequired takes one extra step first (Stage 4): before any
/// backend connection is opened, this runs a real Mojang encryption challenge against the client
/// (PremiumLoginHandshake) and, on success, wraps the client-side stream in an AesCfb8Stream.
/// Everything downstream then behaves identically to a normal connection — which is the whole point
/// of doing it that way. The proxy owns only the Encryption Request/Response exchange; the backend's
/// own Set Compression and Login Success are forwarded through the cipher verbatim, and they are
/// exactly what a client expects to receive after it sends an Encryption Response, so no packet ever
/// has to be re-framed and both sides land on the same compression threshold for free.
/// </summary>
public static class ClientConnection
{
    private static readonly TimeSpan PreLoginTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan BackendConnectTimeout = TimeSpan.FromSeconds(5);

    public static async Task HandleAsync(
        TcpClient client,
        ServerProfile profile,
        PolicyEngine policyEngine,
        IdentityOptions identityOptions,
        IReadOnlyCollection<string> dangerousCommands,
        MessagesOptions messages,
        PremiumLoginHandshake premiumHandshake,
        ILogger logger,
        CancellationToken hostShutdown)
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

        var hostnameDecision = policyEngine.EvaluateHostname(profile, remoteAddress, handshake.ServerAddress);
        if (!hostnameDecision.Allow)
        {
            logger.LogInformation("[{Profile}] connection from {Ip} denied: {Reason}", profile.Name, remoteAddress, hostnameDecision.Reason);
            if (handshake.NextState == HandshakeNextState.Login)
            {
                await TrySendDisconnectAsync(client, clientStream, messages.HostnameNotAllowed, hostShutdown).ConfigureAwait(false);
            }
            return;
        }

        if (handshake.NextState == HandshakeNextState.Status)
        {
            await HandleStatusAsync(client, clientStream, handshakeFrame, profile, remoteAddress, policyEngine, logger, hostShutdown).ConfigureAwait(false);
            return;
        }

        await HandleLoginAsync(client, clientStream, handshakeFrame, handshake, profile, remoteAddress,
            policyEngine, identityOptions, dangerousCommands, messages, premiumHandshake, logger, preLoginCts, hostShutdown).ConfigureAwait(false);
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

    private static async Task HandleLoginAsync(TcpClient client, NetworkStream clientStream, Frame handshakeFrame, HandshakeInfo handshake,
        ServerProfile profile, IPAddress remoteAddress, PolicyEngine policyEngine, IdentityOptions identityOptions,
        IReadOnlyCollection<string> dangerousCommands, MessagesOptions messages, PremiumLoginHandshake premiumHandshake,
        ILogger logger, CancellationTokenSource preLoginCts, CancellationToken hostShutdown)
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

        var decision = await policyEngine.EvaluateLogin(profile, remoteAddress, username, hostShutdown).ConfigureAwait(false);
        if (!decision.Allow)
        {
            logger.LogInformation("[{Profile}] login denied for '{Username}' from {Ip}: {Reason}",
                profile.Name, username, remoteAddress, decision.Reason);
            await TrySendDisconnectAsync(client, clientStream, messages.GenericDenied, hostShutdown).ConfigureAwait(false);
            return;
        }

        bool hasPacketIds = ProtocolVersionRegistry.TryGet(handshake.ProtocolVersion, out var packetIds);

        if (decision.GraceAuth is not null && !hasPacketIds)
        {
            // Can't safely fulfil "must /login as the first message" without decoding Play-state chat
            // packets for this protocol version — fail closed rather than let an unverified guess
            // stand in for a security check on a registered username.
            logger.LogWarning("[{Profile}] '{Username}' requires grace-authentication but protocol version {Version} has no verified packet table — denying.",
                profile.Name, username, handshake.ProtocolVersion);
            await TrySendDisconnectAsync(client, clientStream, messages.UnsupportedClientVersion, hostShutdown).ConfigureAwait(false);
            return;
        }

        // Everything below reads and writes the client through `clientIo`, which for a verified
        // premium connection is the cipher wrapper rather than the bare socket stream.
        Stream clientIo = clientStream;
        AesCfb8Stream? cipherStream = null;

        try
        {
            if (decision.Premium is not null)
            {
                cipherStream = await RunPremiumChallengeAsync(client, clientStream, decision.Premium, profile, remoteAddress,
                    username, handshake.ProtocolVersion, hasPacketIds, policyEngine, messages, premiumHandshake, logger, hostShutdown).ConfigureAwait(false);

                if (cipherStream is null)
                    return; // denied — RunPremiumChallengeAsync already logged, kicked, and struck

                clientIo = cipherStream;
            }

            var (backendClient, backendStream) = await TryConnectBackendAsync(profile, logger, hostShutdown).ConfigureAwait(false);
            if (backendClient is null || backendStream is null)
                return;

            using var _ = backendClient;
            logger.LogInformation("[{Profile}] login allowed for '{Username}' from {Ip}.", profile.Name, username, remoteAddress);

            await backendStream.WriteAsync(handshakeFrame.Raw, hostShutdown).ConfigureAwait(false);
            await backendStream.WriteAsync(loginStartFrame.Raw, hostShutdown).ConfigureAwait(false);

            if (hasPacketIds)
            {
                var inspector = new PlayStateInspector(
                    profile, username, remoteAddress, packetIds, decision.GraceAuth,
                    startsTrusted: decision.GraceAuth is null,
                    identityOptions, dangerousCommands, messages, policyEngine, logger);

                await PumpWithInspectionAsync(client, clientIo, backendStream, inspector, packetIds, hostShutdown).ConfigureAwait(false);
            }
            else
            {
                await PumpBothWaysAsync(clientIo, backendStream, hostShutdown).ConfigureAwait(false);
            }
        }
        finally
        {
            // leaveInnerOpen: true, so this releases the cipher state only — the socket's lifetime
            // still belongs to the caller's `using` on the TcpClient.
            cipherStream?.Dispose();
        }
    }

    /// <summary>
    /// Runs the Stage 4 Mojang encryption challenge for a PremiumRequired username. Returns the
    /// cipher-wrapped client stream on success, or null if the connection was denied (in which case
    /// it has already kicked the client where possible, logged, and registered a strike).
    /// </summary>
    private static async Task<AesCfb8Stream?> RunPremiumChallengeAsync(
        TcpClient client, NetworkStream clientStream, PremiumRequirement premium, ServerProfile profile,
        IPAddress remoteAddress, string username, int protocolVersion, bool hasPacketIds, PolicyEngine policyEngine,
        MessagesOptions messages, PremiumLoginHandshake premiumHandshake, ILogger logger, CancellationToken hostShutdown)
    {
        if (!premiumHandshake.Enabled)
        {
            // Fails closed on purpose — see PremiumOptions.Enabled. Disabling the feature must never
            // downgrade a premium-declared name to the weaker password/IP checks.
            logger.LogWarning("[{Profile}] '{Username}' is PremiumRequired but premium verification is disabled in config — denying.", profile.Name, username);
            await TrySendDisconnectAsync(client, clientStream, messages.PremiumVerificationFailed, hostShutdown).ConfigureAwait(false);
            return null;
        }

        if (!hasPacketIds)
        {
            // The Encryption Request layout was only verified against protocol versions in
            // ProtocolVersionRegistry (notably its trailing "Should Authenticate" boolean, which
            // older versions don't have). Sending a guessed layout to an unverified client version
            // would corrupt its login, so this fails closed exactly like the grace-auth gate above.
            logger.LogWarning("[{Profile}] '{Username}' is PremiumRequired but protocol version {Version} has no verified packet table — denying.",
                profile.Name, username, protocolVersion);
            await TrySendDisconnectAsync(client, clientStream, messages.UnsupportedClientVersion, hostShutdown).ConfigureAwait(false);
            return null;
        }

        PremiumLoginOutcome outcome;
        try
        {
            outcome = await premiumHandshake.RunAsync(clientStream, premium.Entry, username, hostShutdown).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException)
        {
            logger.LogDebug("[{Profile}] '{Username}' dropped during the premium encryption challenge: {Message}", profile.Name, username, ex.Message);
            return null;
        }

        if (outcome.Success)
        {
            logger.LogInformation("[{Profile}] premium verification passed for '{Username}' from {Ip}.", profile.Name, username, remoteAddress);
            policyEngine.RegisterPremiumVerificationSuccess(remoteAddress);
            return new AesCfb8Stream(clientStream, outcome.SharedSecret!, leaveInnerOpen: true);
        }

        logger.LogWarning("[{Profile}] premium verification FAILED for '{Username}' from {Ip}: {Reason}",
            profile.Name, username, remoteAddress, outcome.FailureReason);
        policyEngine.RegisterPremiumVerificationFailure(remoteAddress, profile.Name, username, outcome.FailureReason, outcome.PinnedToDifferentAccount);

        if (outcome.SharedSecret is not null)
        {
            // The client completed the crypto handshake, so it has already switched its own cipher
            // on — a plaintext kick would reach it as noise. Send the disconnect through the very
            // same cipher instead, uncompressed, since no Set Compression was ever exchanged.
            using var encrypted = new AesCfb8Stream(clientStream, outcome.SharedSecret, leaveInnerOpen: true);
            await TrySendDisconnectAsync(client, encrypted, messages.PremiumVerificationFailed, hostShutdown).ConfigureAwait(false);
        }
        // Otherwise the crypto never validated, so there is no key the client would accept a message
        // under — closing the socket is the only honest option.

        return null;
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

    private static async Task TrySendDisconnectAsync(TcpClient client, Stream clientStream, string reason, CancellationToken ct)
    {
        try
        {
            byte[] packet = LoginDisconnect.BuildPacket(reason);
            await clientStream.WriteAsync(packet, ct).ConfigureAwait(false);
            await clientStream.FlushAsync(ct).ConfigureAwait(false);

            // A hard Dispose() right after writing can RST the connection before the client reads
            // the kick message — especially if the client has unread bytes still queued. Half-close
            // our send side and give the client a brief grace period to read the packet before the
            // caller's `using` disposes the socket.
            client.Client.Shutdown(SocketShutdown.Send);
            await Task.Delay(TimeSpan.FromMilliseconds(250), CancellationToken.None).ConfigureAwait(false);
        }
        catch
        {
            // Best-effort only — the connection is being closed either way.
        }
    }

    private static async Task TrySendPlayDisconnectAsync(TcpClient client, Stream clientStream, int playDisconnectPacketId, string reason, CancellationToken ct)
    {
        try
        {
            byte[] packet = FrameWriter.WriteCompressedFrameUncompressedPayload(playDisconnectPacketId, NbtTextComponent.BuildLiteral(reason));
            await clientStream.WriteAsync(packet, ct).ConfigureAwait(false);
            await clientStream.FlushAsync(ct).ConfigureAwait(false);
            client.Client.Shutdown(SocketShutdown.Send);
            await Task.Delay(TimeSpan.FromMilliseconds(250), CancellationToken.None).ConfigureAwait(false);
        }
        catch
        {
            // Best-effort only — the connection is being closed either way.
        }
    }

    private static async Task PumpBothWaysAsync(Stream clientStream, Stream backendStream, CancellationToken hostShutdown)
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

    private static async Task PumpWithInspectionAsync(TcpClient client, Stream clientStream, Stream backendStream,
        PlayStateInspector inspector, PlayStatePacketIds packetIds, CancellationToken hostShutdown)
    {
        using var pumpCts = CancellationTokenSource.CreateLinkedTokenSource(hostShutdown);

        Task backendToClient = PumpAsync(backendStream, clientStream, pumpCts);
        Task clientToBackend = RunInspectorAsync(inspector, clientStream, backendStream, pumpCts);

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

        if (inspector.DisconnectReason is not null)
        {
            await TrySendPlayDisconnectAsync(client, clientStream, packetIds.PlayDisconnectClientbound, inspector.DisconnectReason, CancellationToken.None)
                .ConfigureAwait(false);
        }
    }

    private static async Task RunInspectorAsync(PlayStateInspector inspector, Stream clientStream, Stream backendStream, CancellationTokenSource pumpCts)
    {
        try
        {
            await inspector.RunAsync(clientStream, backendStream, pumpCts.Token).ConfigureAwait(false);
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

    private static async Task PumpAsync(Stream source, Stream destination, CancellationTokenSource pumpCts)
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
