using System.Net;
using System.Net.Sockets;
using MinecraftFirewall.Proxy.Anomaly;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Identity.Premium;
using MinecraftFirewall.Proxy.Inspection;
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
        BotDetector botDetector,
        InspectionOptions inspection,
        AnomalyDetector anomalyDetector,
        ProtocolLearningService protocolLearning,
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

            // The refusal already happened; this is what it leaves behind. A client that lies about
            // the hostname field defeats the check itself — nothing the client sends can be trusted to
            // describe how it connected — but repeating the attempt is behaviour, and behaviour is
            // what the bot score is made of. The boundary that actually enforces "only through my
            // domain" is the backend being unreachable, not this; see the README honesty notes.
            botDetector.RecordHostnameMismatch(remoteAddress);

            if (handshake.NextState == HandshakeNextState.Login)
            {
                await TrySendDisconnectAsync(client, clientStream, messages.HostnameNotAllowed, hostShutdown).ConfigureAwait(false);
            }
            return;
        }

        if (handshake.NextState == HandshakeNextState.Status)
        {
            // Recorded before the rate limiter gets a say: what matters to the bot score is that this
            // address asked for the server list at all, which is what a real client does before it
            // joins — not whether this particular ping was served.
            botDetector.RecordStatusPing(remoteAddress, DateTimeOffset.UtcNow);
            await HandleStatusAsync(client, clientStream, handshakeFrame, profile, remoteAddress, policyEngine, logger, hostShutdown).ConfigureAwait(false);
            return;
        }

        await HandleLoginAsync(client, clientStream, handshakeFrame, handshake, profile, remoteAddress,
            policyEngine, identityOptions, dangerousCommands, messages, premiumHandshake, botDetector, inspection,
            anomalyDetector, protocolLearning, logger, preLoginCts, hostShutdown).ConfigureAwait(false);
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
        BotDetector botDetector, InspectionOptions inspection, AnomalyDetector anomalyDetector,
        ProtocolLearningService protocolLearning, ILogger logger, CancellationTokenSource preLoginCts,
        CancellationToken hostShutdown)
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
            // Announced an intent to log in and then went quiet. One of these is nothing — a player
            // alt-tabbing away mid-join does it. Several from one address is a port sweep, which is
            // why it is counted rather than only logged.
            botDetector.RecordHandshakeWithoutLogin(remoteAddress);
            logger.LogDebug("[{Profile}] {Ip} timed out or was slow sending Login Start.", profile.Name, remoteAddress);
            return;
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or EndOfStreamException or SocketException)
        {
            botDetector.RecordHandshakeWithoutLogin(remoteAddress);
            logger.LogDebug("[{Profile}] {Ip} sent a malformed Login Start: {Message}", profile.Name, remoteAddress, ex.Message);
            return;
        }

        // Before the username is logged, evaluated, or forwarded anywhere. It is the first
        // attacker-controlled string in the connection and it is one that gets written to a log, which
        // is exactly the path Log4Shell took into Minecraft servers. Note the deliberate use of a
        // sanitised form in the log line below: reporting the refusal must not itself hand the payload
        // to the formatter being protected.
        if (inspection.Enabled && UsernameGuard.Check(username, inspection) is { } usernameProblem)
        {
            logger.LogWarning("[{Profile}] refused a login from {Ip}: {Problem} (name shown sanitised: '{Safe}')",
                profile.Name, remoteAddress, usernameProblem, UsernameGuard.ForLogging(username));
            policyEngine.RegisterProtocolViolation(remoteAddress, profile.Name, UsernameGuard.ForLogging(username), usernameProblem);
            await TrySendDisconnectAsync(client, clientStream, messages.GenericDenied, hostShutdown).ConfigureAwait(false);
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

        // A dictionary write and nothing else. The version this client is speaking is the only
        // evidence anyone has that a table for it is worth fetching, and the fetching happens on a
        // background loop rather than here — a player waiting at a connect screen must not be made to
        // wait for an HTTP request.
        if (!hasPacketIds)
            protocolLearning.NoteUnknownVersion(handshake.ProtocolVersion);

        // Deliberately after the policy engine, never before it. The identity checks are the ones with
        // a definite answer — an allowlisted address, a correct password, a verified Mojang account —
        // and a heuristic must never get to overrule one of those. What the score judges is the
        // connections about which nothing definite was known.
        BotAssessment bots = botDetector.Assess(remoteAddress, username, handshake.ProtocolVersion, hasPacketIds, DateTimeOffset.UtcNow);
        if (bots.ShouldDeny)
        {
            logger.LogWarning("[{Profile}] refused '{Username}' from {Ip} as automated (score {Score}): {Signals}",
                profile.Name, username, remoteAddress, bots.Score, bots.Explain());
            policyEngine.RegisterBotDenial(remoteAddress, profile.Name, username, bots);
            await TrySendDisconnectAsync(client, clientStream, messages.GenericDenied, hostShutdown).ConfigureAwait(false);
            return;
        }

        if (bots.ShouldReport)
            policyEngine.ReportBotSuspicion(remoteAddress, profile.Name, username, bots);

        if (decision.GraceAuth is not null && !hasPacketIds)
        {
            // Two very different situations reach this line, and treating them the same was wrong.
            //
            // A *specific* account is being protected — someone registered this name with a password,
            // and the connection is from an address that name has never used. Enforcing that needs the
            // Play-state chat packet IDs for this client's protocol version, and guessing them would
            // mean an unverified guess standing in for a security check on somebody's account. Fails
            // closed, as it always has.
            //
            // Server-wide registration applied to a name nobody has claimed is not that. It is a
            // blanket policy, no particular identity is at stake, and refusing every player whose
            // client is a point release away from one this build knows would make the whole feature
            // unusable — which is exactly what it did. Those connections go through, and the log says
            // plainly what could not be enforced and how to fix it.
            if (decision.GraceAuth.NeedsRegistration)
            {
                logger.LogWarning(
                    "[{Profile}] '{Username}' joined on protocol version {Version}, which this build has no verified " +
                    "packet table for — registration could NOT be enforced for this connection and they were let in. " +
                    "Supported versions: {Supported}. Update MinecraftFirewall to cover newer clients.",
                    profile.Name, username, handshake.ProtocolVersion, ProtocolVersionRegistry.SupportedVersionsDescription);
            }
            else
            {
                logger.LogWarning("[{Profile}] '{Username}' is a registered name connecting from a new address, but protocol " +
                                  "version {Version} has no verified packet table — denying rather than skipping the password check.",
                    profile.Name, username, handshake.ProtocolVersion);
                await TrySendDisconnectAsync(client, clientStream, messages.UnsupportedClientVersion, hostShutdown).ConfigureAwait(false);
                return;
            }
        }

        // Everything below reads and writes the client through `clientIo`, which for a verified
        // premium connection is the cipher wrapper rather than the bare socket stream.
        Stream clientIo = clientStream;
        AesCfb8Stream? cipherStream = null;
        bool claimRequestedByPlayer = false;

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
            else if (hasPacketIds && HasLivePremiumClaimRequest(profile, username))
            {
                claimRequestedByPlayer = true;
                // The player asked for this themselves, so it runs whether or not the server has
                // auto-claim switched on — that setting decides whether *everyone* is offered the
                // challenge, which is a different question from whether this one person asked for it.
                cipherStream = await TryAutoClaimAsync(clientStream, profile, remoteAddress, username, premiumHandshake, logger, hostShutdown)
                    .ConfigureAwait(false);

                if (cipherStream is not null)
                    clientIo = cipherStream;
            }
            else if (premiumHandshake.AutoClaimEnabled && hasPacketIds)
            {
                // Opportunistic: nobody declared this name premium, so nothing is being enforced here.
                // If a genuine account answers, the name is claimed for them permanently; if anything
                // at all goes wrong the connection simply carries on as an ordinary offline login and
                // no record is made either way. See PremiumOptions.AutoClaimOnVerifiedLogin.
                cipherStream = await TryAutoClaimAsync(clientStream, profile, remoteAddress, username, premiumHandshake, logger, hostShutdown)
                    .ConfigureAwait(false);

                if (cipherStream is not null)
                    clientIo = cipherStream;
            }

            var (backendClient, backendStream) = await TryConnectBackendAsync(profile, logger, hostShutdown).ConfigureAwait(false);
            if (backendClient is null || backendStream is null)
                return;

            using var _ = backendClient;
            logger.LogInformation("[{Profile}] login allowed for '{Username}' from {Ip}.", profile.Name, username, remoteAddress);

            // From here the client socket has two writers: the pump carrying the backend's replies, and
            // the inspector when the premium self-lock flow speaks to the player. Minecraft's wire
            // format is length-prefixed frames, so an interleaved write produces a frame whose declared
            // length does not match its contents and the client disconnects with a decode error nobody
            // can explain. Both go through the same serializing wrapper.
            clientIo = new SynchronizedWriteStream(clientIo);

            await backendStream.WriteAsync(handshakeFrame.Raw, hostShutdown).ConfigureAwait(false);
            await backendStream.WriteAsync(loginStartFrame.Raw, hostShutdown).ConfigureAwait(false);

            if (hasPacketIds)
            {
                var inspector = new PlayStateInspector(
                    profile, username, remoteAddress, packetIds, decision.GraceAuth,
                    startsTrusted: decision.GraceAuth is null,
                    identityOptions, dangerousCommands, messages, policyEngine, inspection, logger)
                {
                    // Only when the player asked for it and the challenge actually pinned the name.
                    // Announcing it for an ordinary auto-claim would be confusing: nobody asked.
                    AnnouncePremiumLockSucceeded = claimRequestedByPlayer && profile.IdentityStore.Find(username)?.PremiumRequired == true,
                };

                await PumpWithInspectionAsync(client, clientIo, backendStream, inspector, packetIds, hostShutdown).ConfigureAwait(false);

                // After the session, not during it. What the model learns from is the shape of a whole
                // conversation — how long it lasted, how it was paced, what mix of packets it carried —
                // and none of that exists until the connection is over.
                ScoreFinishedSession(inspector, anomalyDetector, policyEngine, profile, username, remoteAddress, logger);
            }
            else
            {
                await PumpBothWaysAsync(clientIo, backendStream, hostShutdown).ConfigureAwait(false);
            }
        }
        finally
        {
            // Both leave their inner stream open, so this releases the cipher state and the write lock
            // only — the socket's lifetime still belongs to the caller's `using` on the TcpClient.
            (clientIo as SynchronizedWriteStream)?.Dispose();
            cipherStream?.Dispose();
        }
    }

    /// <summary>
    /// Feeds a finished connection to the anomaly baseline and hands any finding to the responder.
    ///
    /// What the model detects is "unlike the other connections to this server", which is a weaker
    /// claim than "malicious" and never becomes it — a server whose players are all in one timezone
    /// will flag an unusual-hours visitor, correctly and unhelpfully. What the responder adds is the
    /// judgement the model cannot make: how often it has happened, how settled the baseline is, and
    /// how far the admin has said they are willing to go.
    /// </summary>
    private static void ScoreFinishedSession(PlayStateInspector inspector, AnomalyDetector anomalyDetector,
        PolicyEngine policyEngine, ServerProfile profile, string username, IPAddress remoteAddress, ILogger logger)
    {
        if (!anomalyDetector.Enabled)
            return;

        try
        {
            ConnectionFeatures features = inspector.BuildFeatures(DateTimeOffset.UtcNow);

            // Scored against the model as it stands, then added to the baseline — in that order, so a
            // connection is never compared against a baseline it is already part of.
            AnomalyVerdict? verdict = anomalyDetector.Score(remoteAddress, features);
            anomalyDetector.Observe(features, wasClean: !inspector.HadViolation);

            if (verdict is { Unusual: true } unusual)
            {
                AnomalyAction action = anomalyDetector.Responder.Decide(remoteAddress, unusual.Score, DateTimeOffset.UtcNow);
                policyEngine.ApplyAnomalyAction(remoteAddress, profile.Name, username, unusual, action);
            }
        }
        catch (Exception ex)
        {
            // An optional, report-only extra must never affect a connection that has already finished.
            logger.LogDebug(ex, "[{Profile}] anomaly scoring failed for '{Username}'.", profile.Name, username);
        }
    }

    /// <summary>
    /// Offers an undeclared username the chance to prove it belongs to a genuine Mojang account, and
    /// claims it permanently if so.
    ///
    /// Returns the cipher-wrapped stream when the crypto handshake completed — which happens whether
    /// or not Mojang confirmed the session, because by then the client has switched its own cipher on
    /// and every later byte must go through it. Returns null only when the handshake never produced a
    /// shared key, in which case the caller keeps using the plaintext stream. A failed claim is never
    /// a denial: the player continues as an ordinary offline login.
    /// </summary>
    private static async Task<AesCfb8Stream?> TryAutoClaimAsync(
        NetworkStream clientStream, ServerProfile profile, IPAddress remoteAddress, string username,
        PremiumLoginHandshake premiumHandshake, ILogger logger, CancellationToken hostShutdown)
    {
        try
        {
            IdentityEntry entry = profile.IdentityStore.GetOrCreate(username);
            PremiumLoginOutcome outcome = await premiumHandshake
                .TryAutoClaimAsync(clientStream, entry, username, hostShutdown)
                .ConfigureAwait(false);

            if (outcome.Success)
                logger.LogInformation("[{Profile}] '{Username}' auto-claimed by a verified account from {Ip}.", profile.Name, username, remoteAddress);
            else
                logger.LogDebug("[{Profile}] '{Username}' did not verify ({Reason}) — continuing as a normal offline login, nothing recorded.",
                    profile.Name, username, outcome.FailureReason);

            return outcome.SharedSecret is not null
                ? new AesCfb8Stream(clientStream, outcome.SharedSecret, leaveInnerOpen: true)
                : null;
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException)
        {
            logger.LogDebug("[{Profile}] '{Username}' dropped during the optional premium challenge: {Message}", profile.Name, username, ex.Message);
            return null;
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

    /// <summary>
    /// Whether this username has a live, player-initiated request to be locked to a Microsoft account.
    ///
    /// Reading it clears it, whatever happens next. The request is a single-use intent: if the person
    /// who armed it connects with a cracked client, the challenge fails, nothing is recorded, and the
    /// request must not sit there waiting to fire again on somebody else's connection.
    /// </summary>
    private static bool HasLivePremiumClaimRequest(ServerProfile profile, string username)
    {
        IdentityEntry? entry = profile.IdentityStore.Find(username);
        if (entry?.PremiumClaimRequested is not { } request)
            return false;

        entry.PremiumClaimRequested = null;
        return request.IsLive(DateTimeOffset.UtcNow);
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
