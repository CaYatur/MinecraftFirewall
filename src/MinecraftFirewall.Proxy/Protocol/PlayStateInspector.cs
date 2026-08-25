using System.Net;
using MinecraftFirewall.Proxy.Anomaly;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Inspection;
using MinecraftFirewall.Proxy.Messages;
using MinecraftFirewall.Proxy.Policy;

namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>
/// Inspects the client-to-backend half of a Play-state connection, starting from the very first
/// packet after Login Start. Tracks phase as Login (always exactly one packet, Login Acknowledged,
/// blindly forwarded — see the constructor's initial _awaitingLoginAcknowledged field and the comment
/// at its use site for why this step exists and isn't optional) -> Configuration (forwarded
/// byte-for-byte until Finish Configuration is seen) -> Play (chat/chat_command/chat_command_signed
/// decoded; everything else forwarded byte-for-byte from DecodedPacket.RawFrame, never
/// re-serialized). The backend-to-client direction is NOT handled here — ClientConnection still uses
/// a plain byte pump for that side, since Stage 3 has no reason to inspect anything the server sends.
/// </summary>
public sealed class PlayStateInspector(
    ServerProfile profile,
    string username,
    IPAddress remoteAddress,
    PlayStatePacketIds packetIds,
    GraceAuthRequirement? graceAuth,
    bool startsTrusted,
    IdentityOptions identityOptions,
    IReadOnlyCollection<string> dangerousCommands,
    MessagesOptions messages,
    PolicyEngine policyEngine,
    InspectionOptions inspection,
    ILogger logger,
    AuthHold? authHold = null,
    Func<DateTimeOffset>? clock = null)
{
    /// <summary>
    /// The state shared with the pump carrying the backend's side of this connection.
    ///
    /// Holding a player in place takes both halves: only the pump ever learns where the backend has
    /// put them, and only this class knows when they have authenticated. Optional so the older
    /// constructor and the tests built on it still work -- without one, the hold refuses movement
    /// without correcting the client, which is exactly what it did before.
    /// </summary>
    private readonly AuthHold _hold = authHold ?? new AuthHold();

    /// <summary>
    /// Where "now" comes from. Overridable because every rate and speed judgement here is a division
    /// by elapsed time, and a test feeding packets from a MemoryStream delivers them all in the same
    /// instant — so against the wall clock the interesting paths are skipped by the very guards that
    /// stop a lag spike being read as a speed measurement, and the tests pass without ever reaching
    /// the code they claim to cover.
    /// </summary>
    private readonly Func<DateTimeOffset> _now = clock ?? (static () => DateTimeOffset.UtcNow);

    /// <summary>Ceiling for one sign line or book page. Vanilla allows far less, but the point here
    /// is to bound the scan rather than to police length — the packet size cap does that.</summary>
    private const int MaxWrittenTextLength = 8192;

    private readonly PacketBudget _budget = new(inspection.MaxPacketsPerSecond, inspection.MaxBytesPerSecond);
    private readonly MovementAnalyzer _movement = new(inspection);
    private readonly SecondCounter _attacks = new(clock?.Invoke() ?? DateTimeOffset.UtcNow);

    private bool _awaitingLoginAcknowledged = true;
    private bool _inPlayState;
    private bool _graceAuthResolved;
    private bool _isTrusted = startsTrusted;
    private bool _reportedLayoutProblem;
    private bool _reportedAttackRate;

    /// <summary>
    /// Set when this connection is the one that just proved ownership of a name the player asked to
    /// lock. Delivered once they reach Play state, because that is the first moment there is a chat box
    /// to deliver it to — the challenge itself happens during login, where nothing can be said.
    /// </summary>
    public bool AnnouncePremiumLockSucceeded { get; set; }

    /// <summary>Where the proxy writes when it speaks to the player without ending the connection.
    /// Set for the duration of RunAsync; the stream it points at serializes writes, because the pump
    /// carrying the backend's replies is writing to the same socket at the same time.</summary>
    private Stream? _clientWriter;

    /// <summary>When the player entered Play state still needing to authenticate. The timeout is
    /// measured from here rather than from the connection opening, because loading the world can take
    /// a while and none of that time is the player ignoring a prompt they have not seen yet.</summary>
    private DateTimeOffset? _authPromptedAt;
    private DateTimeOffset _lastAuthReminder;
    private DateTimeOffset _lastPositionLock;

    /// <summary>
    /// The teleport that puts a player back where the backend has them, while it is still unanswered.
    ///
    /// Movement stays swallowed until this is confirmed, which closes a race that would otherwise send
    /// the backend a position of nowhere. The client cannot know it has been released until the
    /// restoring teleport reaches it, so any movement packet already on its way was composed while it
    /// still believed it was standing at the origin. Forwarding one of those is a player apparently
    /// crossing the world in a single tick — which a server quite reasonably rejects.
    /// </summary>
    private int? _pendingRestoreTeleport;

    /// <summary>
    /// When to stop waiting for that confirmation and let the player move regardless.
    ///
    /// Every real client answers a teleport, but "every real client" is a claim about software this
    /// project does not control and cannot test all of. The failure mode without a deadline is a
    /// player who authenticated successfully and then cannot move at all, which is worse than the
    /// single rejected movement packet the wait exists to prevent.
    /// </summary>
    private DateTimeOffset _restoreDeadline;

    /// <summary>How long that wait may last. Generous next to a round trip, brief next to a person's
    /// patience.</summary>
    private static readonly TimeSpan RestoreConfirmationTimeout = TimeSpan.FromSeconds(5);
    private volatile bool _damageSeenWhileHeld;

    /// <summary>The last health the backend announced, against which the next one is compared. Only
    /// ever read and written on the pump's thread, so it needs no synchronisation of its own.</summary>
    private float? _healthBaseline;

    // Session tallies, kept for the anomaly baseline. Deliberately counted here rather than in the
    // analyser: this is the one place every serverbound packet passes through exactly once.
    private readonly HashSet<int> _packetKinds = [];
    private DateTimeOffset _startedAt;
    private DateTimeOffset? _firstPacketAt;
    private int _packetsSeen;
    private long _bytesSeen;
    private int _chatMessages;
    private int _movementPackets;

    public PlayStateInspector(
        ServerProfile profile,
        string username,
        IPAddress remoteAddress,
        PlayStatePacketIds packetIds,
        GraceAuthRequirement? graceAuth,
        bool startsTrusted,
        IdentityOptions identityOptions,
        IReadOnlyCollection<string> dangerousCommands,
        MessagesOptions messages,
        PolicyEngine policyEngine,
        InspectionOptions inspection,
        ILogger logger)
        : this(profile, username, remoteAddress, packetIds, graceAuth, startsTrusted, identityOptions,
               dangerousCommands, messages, policyEngine, inspection, logger, null, null)
    {
    }

    /// <summary>Set when a dangerous command or a failed grace-authentication means this connection
    /// must be cut off — the caller (ClientConnection) checks this after the loop ends to decide
    /// whether to send a Play-state Disconnect before closing.</summary>
    public string? DisconnectReason { get; private set; }

    /// <summary>True once anything at all was refused on this connection. The anomaly baseline learns
    /// only from connections where this stayed false — a flood being actively refused must never
    /// become the definition of normal.</summary>
    public bool HadViolation { get; private set; }

    /// <summary>The finished session as the anomaly model sees it. Only the shape of the conversation
    /// goes in: declared values like the protocol version or the username are free for an attacker to
    /// set to anything, so learning from them would teach the model whatever they chose.</summary>
    public ConnectionFeatures BuildFeatures(DateTimeOffset endedAt) => new(
        DurationSeconds: (endedAt - _startedAt).TotalSeconds,
        PacketsFromClient: _packetsSeen,
        BytesFromClient: _bytesSeen,
        PeakPacketsPerSecond: _budget.PeakPacketsPerSecond,
        DistinctPacketKinds: _packetKinds.Count,
        SecondsToFirstPacket: ((_firstPacketAt ?? endedAt) - _startedAt).TotalSeconds,
        ChatMessages: _chatMessages,
        MovementPackets: _movementPackets);

    public async Task RunAsync(Stream clientStream, Stream backendStream, CancellationToken ct)
    {
        _startedAt = _now();
        _clientWriter = clientStream;

        while (!ct.IsCancellationRequested)
        {
            DecodedPacket packet = await CompressedPacketReader
                .ReadAsync(clientStream, inspection.MaxServerboundFrameBytes, ct, inspection.MaxServerboundUncompressedBytes)
                .ConfigureAwait(false);

            _packetsSeen++;
            _bytesSeen += packet.RawFrame.Length;
            _firstPacketAt ??= _now();

            // Bounded: a client sending a thousand different packet IDs is itself the anomaly, and the
            // set must not become a way to make this connection allocate.
            if (_packetKinds.Count < 128)
                _packetKinds.Add(packet.PacketId);

            // Counted only once in Play state. Packet IDs live in per-phase namespaces, so a
            // Configuration-phase packet can share a number with a Play movement packet and would
            // otherwise be tallied as movement — the same namespace collision that once made the very
            // first packet of every connection get misidentified (see the note below).
            if (_inPlayState && packetIds.IsMovement(packet.PacketId))
                _movementPackets++;

            // Charged before anything is decided about the packet. A flood is defined by its volume,
            // not its contents, so the cheapest check has to be the first one.
            if (inspection.Enabled && _budget.Charge(packet.RawFrame.Length, _now()) is { } overBudget)
            {
                logger.LogWarning("[{Profile}] '{Username}' ({Ip}) exceeded its packet budget: {Detail}",
                    profile.Name, username, remoteAddress, overBudget);
                policyEngine.RegisterPacketFlood(remoteAddress, profile.Name, username, overBudget);
                HadViolation = true;
                DisconnectReason = messages.GenericDenied;
                return;
            }

            if (_inPlayState && inspection.Enabled && InspectPlayPacket(packet) is { } violation)
            {
                logger.LogWarning("[{Profile}] blocked a packet from '{Username}' ({Ip}): {Violation}",
                    profile.Name, username, remoteAddress, violation.Detail);
                policyEngine.RegisterProtocolViolation(remoteAddress, profile.Name, username, violation.Detail,
                    unambiguous: violation.Severity == PayloadSeverity.ProtocolViolation);
                HadViolation = true;
                DisconnectReason = messages.GenericDenied;
                return;
            }

            if (!_inPlayState)
            {
                if (_awaitingLoginAcknowledged)
                {
                    // The very first serverbound packet PlayStateInspector ever sees is always Login
                    // Acknowledged — the one fixed packet that ends the Login state, sent exactly once
                    // per connection, immediately after Login Start. It carries no fields, but its
                    // packet ID (0x03) is defined in the LOGIN state's own packet-ID namespace, which
                    // is completely independent from Configuration's — Configuration's own Finish
                    // Configuration (serverbound) *also* happens to be ID 0x03, coincidentally, in its
                    // own namespace. A live end-to-end run against a real client caught this: without
                    // this explicit first-packet step, that ID collision made the very first packet
                    // (Login Acknowledged) get misidentified as Finish Configuration, flipping
                    // _inPlayState a full protocol phase too early — which then meant every later
                    // Configuration-phase packet was inspected as if it were a Play-state message,
                    // including matching against chat/command detection on packet IDs that happen to
                    // coincide with Configuration's own (e.g. the serverbound Known Packs response
                    // sharing an ID with chat_command_signed). For a real grace-authentication-pending
                    // connection this would consume the player's one grace-auth attempt on garbage
                    // Configuration bytes before they ever reached Play state, failing every legitimate
                    // login. See docs/plan.md's live-verification note for how this was found.
                    _awaitingLoginAcknowledged = false;
                    await backendStream.WriteAsync(packet.RawFrame, ct).ConfigureAwait(false);
                    continue;
                }

                if (packet.PacketId == packetIds.ConfigurationFinishConfigurationServerbound && packet.Fields.Length == 0)
                {
                    _inPlayState = true;

                    if (AnnouncePremiumLockSucceeded)
                    {
                        AnnouncePremiumLockSucceeded = false;
                        SendToPlayer(messages.PremiumLockSucceeded);
                    }

                    if (graceAuth is not null && !_graceAuthResolved)
                    {
                        _authPromptedAt = _now();
                        _lastAuthReminder = _now();
                        PromptToAuthenticate();
                    }
                }

                await backendStream.WriteAsync(packet.RawFrame, ct).ConfigureAwait(false);
                continue;
            }

            // Held still until they authenticate. This is what makes server-wide registration mean
            // anything: without it the player is on the server, walking around and breaking blocks,
            // while the proxy waits politely for a password. Only packets that would let them *act*
            // are refused — keep-alives and the rest keep flowing, or the backend would disconnect
            // them for timing out and they would never see the prompt.
            if (_pendingRestoreTeleport is not null && _now() >= _restoreDeadline)
            {
                logger.LogDebug("[{Profile}] '{Username}' did not confirm the teleport back to their position; " +
                                "letting them move anyway.", profile.Name, username);
                _pendingRestoreTeleport = null;
            }

            if (_pendingRestoreTeleport is { } restoreId)
            {
                if (packet.PacketId == packetIds.PlayAcceptTeleportationServerbound &&
                    IsProxyTeleportConfirmation(packet))
                {
                    if (VarIntOrDefault(packet.Fields) == restoreId)
                        _pendingRestoreTeleport = null;

                    continue;
                }

                if (packetIds.IsMovement(packet.PacketId))
                    continue; // composed before the client knew it had been moved back
            }

            if (graceAuth is not null && !_graceAuthResolved)
            {
                if (HandleAuthenticationTimeout() || HandleDamageWhileHeld())
                    return;

                MaintainPositionLock();

                // The client answers every teleport with a confirmation carrying its id. The ones
                // answering the proxy's own pinning teleports have to be swallowed: the backend never
                // sent those, and a confirmation for a teleport it knows nothing about desynchronises
                // it. Its own must still go through untouched -- a backend waiting on an unanswered
                // teleport refuses to let the player move afterwards.
                if (packet.PacketId == packetIds.PlayAcceptTeleportationServerbound &&
                    IsProxyTeleportConfirmation(packet))
                {
                    continue;
                }

                if (packetIds.IsPlayerAction(packet.PacketId))
                {
                    RemindToAuthenticate();
                    continue; // swallowed: never reaches the server
                }
            }

            bool isChat = packet.PacketId == packetIds.PlayChatServerbound;
            bool isCommand = packet.PacketId == packetIds.PlayChatCommandServerbound || packet.PacketId == packetIds.PlayChatCommandSignedServerbound;

            if (!isChat && !isCommand)
            {
                await backendStream.WriteAsync(packet.RawFrame, ct).ConfigureAwait(false);
                continue;
            }

            string text = MinecraftPrimitives.ReadString(packet.Fields, out _);

            if (inspection.Enabled && inspection.ScanForInjectionPayloads &&
                PayloadScanner.Scan(text, inspection.MaxChatLength) is { } finding)
            {
                // Dropped whole, never cleaned and forwarded. A partially sanitised payload passed on
                // is how filters get bypassed, and the backend has no way to know this one was touched.
                logger.LogWarning("[{Profile}] blocked {Kind} from '{Username}' ({Ip}): {Rule} — {Detail}",
                    profile.Name, isCommand ? "a command" : "a chat message", username, remoteAddress,
                    finding.Rule, finding.Detail);
                policyEngine.RegisterProtocolViolation(remoteAddress, profile.Name, username,
                    $"{finding.Rule}: {finding.Detail}",
                    unambiguous: finding.Severity == PayloadSeverity.ProtocolViolation);
                HadViolation = true;
                DisconnectReason = messages.GenericDenied;
                return;
            }

            if (graceAuth is not null && !_graceAuthResolved)
            {
                // Taken whether it arrived as a command or as ordinary chat. Minecraft paints a
                // command red in the input box when the server has not declared it, and the proxy's
                // commands are ones the backend has never heard of -- so to a player they looked like
                // mistakes even while they worked. Accepting the same words without a slash removes
                // that entirely. Nothing typed here is forwarded either way, so a password sent as
                // plain chat still never reaches the backend, and still never reaches a log.
                HandleAuthenticationAttempt(text);
                if (DisconnectReason is not null)
                    return;
                continue; // consumed either way — never forwarded to the backend
            }

            if (isCommand && HandleCayaDevCheckCommand(text))
                continue; // /register or /login outside a grace-auth requirement — also swallowed

            _chatMessages++;
            LogCommandOrChat(isCommand, text);

            if (isCommand && !_isTrusted && DangerousCommandMatcher.IsMatch(text, dangerousCommands))
            {
                logger.LogWarning("[{Profile}] DANGEROUS COMMAND from non-trusted '{Username}' ({Ip}): {Command}",
                    profile.Name, username, remoteAddress, DangerousCommandMatcher.ExtractBaseCommand(text));
                policyEngine.RegisterDangerousCommand(remoteAddress, profile.Name, username, DangerousCommandMatcher.ExtractBaseCommand(text));
                HadViolation = true;
                DisconnectReason = messages.DangerousCommandBlocked;
                return;
            }

            await backendStream.WriteAsync(packet.RawFrame, ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Handles one message from a player who has not authenticated yet.
    ///
    /// Two situations share this path and differ in exactly one way. A player who already has a
    /// password gets a single attempt: a wrong one is the classic stolen-password probe, and letting
    /// somebody guess repeatedly against a name they do not own is the whole thing being defended
    /// against. A player who has never registered gets as many attempts as the timeout allows, because
    /// there is nothing to guess — they are choosing a password, not proving one, and kicking them for
    /// typing it wrong once would be hostile for no gain.
    /// </summary>
    private void HandleAuthenticationAttempt(string? commandText)
    {
        var parsed = commandText is not null ? CayaDevCheckCommandParser.Parse(commandText) : null;

        // Reachable from inside the hold, not only afterwards. Somebody who owns this name on a real
        // Minecraft account should not have to invent a password for a server that could simply
        // recognise them -- and until this was answered here, the only way to find it was to already
        // be past the prompt that was asking for the password.
        if (parsed is { Kind: CayaDevCheckCommandKind.PremiumLockAsk })
        {
            logger.LogInformation("[{Profile}] '{Username}' asked about locking their name to a Minecraft account.",
                profile.Name, username);
            SendToPlayer(messages.PremiumLockExplain);
            return;
        }

        if (parsed is { Kind: CayaDevCheckCommandKind.PremiumLockConfirm })
        {
            ArmPremiumClaim();
            return;
        }

        if (graceAuth!.NeedsRegistration)
        {
            HandleRegistrationAttempt(parsed);
            return;
        }

        _graceAuthResolved = true;

        if (parsed is { Kind: CayaDevCheckCommandKind.Login } && PasswordHasher.Verify(parsed.Password, graceAuth.PasswordHash!))
        {
            graceAuth.Entry.LearnIp(remoteAddress, identityOptions.LearnedIpTtl, identityOptions.MaxLearnedIpsPerUsername);
            graceAuth.Entry.Record(PlayerEventKind.LoggedIn, remoteAddress, "password accepted from a new address", _now());
            policyEngine.RegisterGraceAuthSuccess(remoteAddress, profile.Name, username);
            _isTrusted = true;
            ReleaseHold();
            SendToPlayer(messages.AuthenticationAccepted);
            logger.LogInformation("[{Profile}] '{Username}' authenticated from a new IP {Ip} — trusted for {Ttl}.",
                profile.Name, username, remoteAddress, identityOptions.LearnedIpTtl);
            return;
        }

        logger.LogWarning("[{Profile}] authentication FAILED for '{Username}' from {Ip} — the message was not a correct /login.",
            profile.Name, username, remoteAddress);
        graceAuth.Entry.Record(PlayerEventKind.LoginFailed, remoteAddress, "wrong password, or no login was sent", _now());
        policyEngine.RegisterGraceAuthFailure(remoteAddress, profile.Name, username);
        HadViolation = true;
        DisconnectReason = messages.GraceAuthenticationFailed;
    }

    /// <summary>
    /// A player changing their own password from inside the game, by proving the old one first.
    ///
    /// The old password is required even though this connection is already trusted. Being trusted here
    /// means the address is recognised or the session is authenticated, and neither of those is the
    /// same as knowing the password — a household, a shared flat or a games café all share an address.
    /// Without the check, sitting down at somebody else's computer would be enough to lock them out of
    /// their own name.
    /// </summary>
    private void HandleChangePassword(CayaDevCheckCommand parsed)
    {
        IdentityEntry entry = profile.IdentityStore.GetOrCreate(username);

        if (entry.PasswordHash is null)
        {
            SendToPlayer(messages.NoPasswordToChange);
            return;
        }

        if (!PasswordHasher.Verify(parsed.CurrentPassword, entry.PasswordHash))
        {
            logger.LogWarning("[{Profile}] '{Username}' ({Ip}) failed to change their password: the current one was wrong.",
                profile.Name, username, remoteAddress);
            entry.Record(PlayerEventKind.LoginFailed, remoteAddress, "wrong current password on a change attempt", _now());
            SendToPlayer(messages.CurrentPasswordWrong);
            return;
        }

        if (parsed.Password.Length < identityOptions.PasswordMinLength)
        {
            SendToPlayer(string.Format(messages.PasswordTooShort, identityOptions.PasswordMinLength));
            return;
        }

        entry.PasswordHash = PasswordHasher.Hash(parsed.Password);
        entry.Record(PlayerEventKind.PasswordChanged, remoteAddress, "changed their password in game", _now());

        logger.LogInformation("[{Profile}] '{Username}' ({Ip}) changed their password.", profile.Name, username, remoteAddress);
        SendToPlayer(messages.PasswordChanged);
    }

    /// <summary>Registration, for a player the server has never seen. Not resolved until they succeed,
    /// so a short password or a mistyped command simply prompts again.</summary>
    private void HandleRegistrationAttempt(CayaDevCheckCommand? parsed)
    {
        if (parsed is not { Kind: CayaDevCheckCommandKind.Register })
        {
            PromptToAuthenticate();
            return;
        }

        if (parsed.Password.Length < identityOptions.PasswordMinLength)
        {
            SendToPlayer(string.Format(messages.PasswordTooShort, identityOptions.PasswordMinLength));
            return;
        }

        graceAuth!.Entry.PasswordHash = PasswordHasher.Hash(parsed.Password);
        graceAuth.Entry.LearnIp(remoteAddress, identityOptions.LearnedIpTtl, identityOptions.MaxLearnedIpsPerUsername);
        graceAuth.Entry.RegisteredAt ??= _now();
        graceAuth.Entry.Record(PlayerEventKind.Registered, remoteAddress, "chose a password", _now());

        _graceAuthResolved = true;
        _isTrusted = true;
        ReleaseHold();
        SendToPlayer(messages.AuthenticationAccepted);

        logger.LogInformation("[{Profile}] '{Username}' registered from {Ip} under server-wide registration.",
            profile.Name, username, remoteAddress);
    }

    /// <summary>Repeats the prompt while the player is frozen. Minecraft chat scrolls, and a single
    /// message sent at join time is gone by the time somebody looks up from their inventory.</summary>
    private void RemindToAuthenticate()
    {
        DateTimeOffset now = _now();
        if (now - _lastAuthReminder < identityOptions.AuthenticationReminderInterval)
            return;

        _lastAuthReminder = now;
        PromptToAuthenticate();
    }

    /// <summary>Ends a connection that has been frozen too long. Returns true when the caller should
    /// stop reading. A kick that explains itself is kinder than an indefinite freeze nobody can
    /// interpret.</summary>
    private bool HandleAuthenticationTimeout()
    {
        if (_authPromptedAt is not { } promptedAt || _now() - promptedAt < identityOptions.AuthenticationTimeout)
            return false;

        logger.LogInformation("[{Profile}] '{Username}' ({Ip}) did not authenticate within {Timeout} — disconnecting.",
            profile.Name, username, remoteAddress, identityOptions.AuthenticationTimeout);

        DisconnectReason = messages.AuthenticationTimedOut;
        return true;
    }

    private bool HandleCayaDevCheckCommand(string commandText)
    {
        if (!CayaDevCheckCommandParser.LooksLikeCayaDevCheckCommand(commandText))
            return false;

        var parsed = CayaDevCheckCommandParser.Parse(commandText);

        switch (parsed.Kind)
        {
            case CayaDevCheckCommandKind.ChangePassword:
                HandleChangePassword(parsed);
                return true;

            case CayaDevCheckCommandKind.Register:
                if (parsed.Password.Length < identityOptions.PasswordMinLength)
                {
                    logger.LogInformation("[{Profile}] '{Username}' tried to register a password shorter than the minimum.", profile.Name, username);
                    SendToPlayer(string.Format(messages.PasswordTooShort, identityOptions.PasswordMinLength));
                    return true;
                }

                var entry = profile.IdentityStore.GetOrCreate(username);
                bool hadPassword = entry.PasswordHash is not null;

                // Somebody who already has a password has to prove it. They are trusted enough to be
                // here — recognised address, or already logged in — but "already at the keyboard" is
                // not the same as "knows the password", and a household shares an address.
                if (hadPassword)
                {
                    SendToPlayer(messages.AlreadyRegistered);
                    return true;
                }

                entry.PasswordHash = PasswordHasher.Hash(parsed.Password);
                entry.LearnIp(remoteAddress, identityOptions.LearnedIpTtl, identityOptions.MaxLearnedIpsPerUsername);
                entry.RegisteredAt ??= _now();
                entry.Record(hadPassword ? PlayerEventKind.PasswordChanged : PlayerEventKind.Registered,
                    remoteAddress, hadPassword ? "changed their password in game" : "chose a password", _now());
                _isTrusted = true;
                logger.LogInformation("[{Profile}] '{Username}' registered with CaYaDev-Check from {Ip}.", profile.Name, username, remoteAddress);
                return true;

            case CayaDevCheckCommandKind.PremiumLockAsk:
                // Answered rather than acted on. Locking a name is permanent and the next step is a
                // disconnect, so the player gets told what both of those mean before either happens.
                logger.LogInformation("[{Profile}] '{Username}' asked about locking their name to a Minecraft account.",
                    profile.Name, username);
                SendToPlayer(messages.PremiumLockExplain);
                return true;

            case CayaDevCheckCommandKind.PremiumLockConfirm:
                ArmPremiumClaim();
                return true;

            case CayaDevCheckCommandKind.Login:
                // Sent outside a grace-auth requirement (e.g. already on a recognized IP) — harmless
                // no-op; still swallowed so the backend never sees a bogus command.
                var existing = profile.IdentityStore.Find(username);
                if (existing?.PasswordHash is not null && PasswordHasher.Verify(parsed.Password, existing.PasswordHash))
                    existing.LearnIp(remoteAddress, identityOptions.LearnedIpTtl, identityOptions.MaxLearnedIpsPerUsername);
                return true;

            default:
                // Looked like a CaYaDev-Check command (first token matched) but didn't parse cleanly
                // (e.g. wrong argument count) — still swallow it so a mistyped password never leaks
                // to the backend or, via the branch this call short-circuits, to the command log.
                return true;
        }
    }

    /// <summary>
    /// Checks one Play-state packet, returning why it should be refused or null to let it through.
    ///
    /// Only the packet kinds whose layout is documented for this exact protocol version are opened;
    /// everything else is forwarded untouched. That is the same discipline the packet-ID registry
    /// follows, and for the same reason — a wrong guess about a field offset is not a missed
    /// detection, it is a firewall that mangles ordinary play.
    /// </summary>
    private PayloadFinding? InspectPlayPacket(DecodedPacket packet)
    {
        if (packetIds.IsMovement(packet.PacketId))
            return InspectMovement(packet);

        if (packet.PacketId == packetIds.PlayCustomPayloadServerbound)
            return InspectPluginMessage(packet);

        // Chat and commands are handled further down, where the grace-authentication and dangerous-command
        // logic also needs the decoded text; this covers the other two kinds IsTextCarrying names.
        if (packetIds.IsTextCarrying(packet.PacketId) && packet.PacketId != packetIds.PlayChatServerbound
            && packet.PacketId != packetIds.PlayChatCommandServerbound
            && packet.PacketId != packetIds.PlayChatCommandSignedServerbound)
        {
            return InspectWrittenText(packet);
        }

        if (packet.PacketId == packetIds.PlayInteractServerbound || packet.PacketId == packetIds.PlaySwingServerbound)
        {
            CountAttack();
            return null;
        }

        return null;
    }

    private PayloadFinding? InspectMovement(DecodedPacket packet)
    {
        bool positional = packet.PacketId == packetIds.PlayMovePlayerPosServerbound ||
                          packet.PacketId == packetIds.PlayMovePlayerPosRotServerbound;

        if (!positional)
        {
            _movement.NoteNonPositionalMovement();
            return null;
        }

        MovementFinding finding = _movement.Inspect(packet.Fields, _now());

        if (_movement.LayoutUnrecognised && !_reportedLayoutProblem)
        {
            _reportedLayoutProblem = true;
            logger.LogInformation(
                "[{Profile}] movement packets from '{Username}' do not match the layout recorded for this protocol " +
                "version — movement analysis is off for this connection. Play is unaffected.",
                profile.Name, username);
        }

        return finding.Severity switch
        {
            // Not a cheat and not a judgement call: no client produces these by playing.
            MovementSeverity.Invalid => new PayloadFinding("impossible-movement", finding.Detail, PayloadSeverity.ProtocolViolation),

            // A heuristic, so even when the admin has asked for a kick it must not weigh towards a ban.
            MovementSeverity.Suspicious when inspection.KickOnMovementAnomaly =>
                new PayloadFinding("movement-anomaly", finding.Detail, PayloadSeverity.Assumption),

            MovementSeverity.Suspicious => ReportMovementAnomaly(finding),

            _ => null,
        };
    }

    /// <summary>Records a movement anomaly without acting on it — the default, because this proxy
    /// cannot see the ice, boat, elytra or plugin teleport that would explain it. See
    /// InspectionOptions.KickOnMovementAnomaly.</summary>
    private PayloadFinding? ReportMovementAnomaly(MovementFinding finding)
    {
        logger.LogInformation("[{Profile}] '{Username}' ({Ip}) {Detail}. Not acted on — see KickOnMovementAnomaly.",
            profile.Name, username, remoteAddress, finding.Detail);
        return null;
    }

    /// <summary>
    /// Scans the text a player writes on a sign or into a book.
    ///
    /// Both were live Log4Shell vectors alongside chat, for the same reason: the text ends up
    /// somewhere that formats it. Books in particular are read back by plugins, shown in web maps and
    /// written into world data, so a payload placed in one persists long after the connection that
    /// delivered it has gone.
    ///
    /// Layouts are read defensively, exactly as movement is. If the fields do not decode cleanly the
    /// packet is forwarded untouched rather than guessed at — this project's rule is that an
    /// unverified field offset is never worth a wrong refusal.
    /// </summary>
    private PayloadFinding? InspectWrittenText(DecodedPacket packet)
    {
        List<string> texts;
        try
        {
            texts = packet.PacketId == packetIds.PlaySignUpdateServerbound
                ? ReadSignLines(packet.Fields)
                : ReadBookPages(packet.Fields);
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            return null;
        }

        foreach (string text in texts)
        {
            // A generous length ceiling rather than the chat one: book pages legitimately run to
            // hundreds of characters, and the frame-size cap already bounds the packet as a whole.
            if (PayloadScanner.Scan(text, MaxWrittenTextLength) is { } finding)
                return finding with { Rule = $"written-text/{finding.Rule}" };
        }

        return null;
    }

    /// <summary>Sign Update: a block position (8 bytes), a front/back flag (1 byte), then the four
    /// lines.</summary>
    private static List<string> ReadSignLines(ReadOnlySpan<byte> fields)
    {
        const int headerBytes = 8 + 1;
        var lines = new List<string>(4);

        ReadOnlySpan<byte> rest = fields[headerBytes..];
        for (int i = 0; i < 4; i++)
        {
            lines.Add(MinecraftPrimitives.ReadString(rest, out int read));
            rest = rest[read..];
        }

        return lines;
    }

    /// <summary>Edit Book: the hotbar slot, then a length-prefixed array of pages, then an optional
    /// title.</summary>
    private static List<string> ReadBookPages(ReadOnlySpan<byte> fields)
    {
        _ = VarInt.Decode(fields, out int slotLen);
        ReadOnlySpan<byte> rest = fields[slotLen..];

        int pageCount = VarInt.Decode(rest, out int countLen);
        rest = rest[countLen..];

        // Vanilla caps a book at 100 pages. A larger count is either a different layout or an attempt
        // to make this loop the denial of service, and neither is worth continuing into.
        if (pageCount is < 0 or > 100)
            throw new InvalidDataException($"Implausible book page count {pageCount}.");

        var pages = new List<string>(pageCount + 1);
        for (int i = 0; i < pageCount; i++)
        {
            pages.Add(MinecraftPrimitives.ReadString(rest, out int read));
            rest = rest[read..];
        }

        // The title is optional: one boolean, then the string if it is set.
        if (rest.Length > 0 && rest[0] == 1)
            pages.Add(MinecraftPrimitives.ReadString(rest[1..], out _));

        return pages;
    }

    private PayloadFinding? InspectPluginMessage(DecodedPacket packet)
    {
        if (packet.Fields.Length > inspection.MaxPluginMessageBytes)
        {
            return new PayloadFinding("oversized-plugin-message",
                $"plugin message of {packet.Fields.Length} bytes, over the {inspection.MaxPluginMessageBytes}-byte limit",
                PayloadSeverity.ProtocolViolation);
        }

        string channel;
        try
        {
            channel = MinecraftPrimitives.ReadString(packet.Fields, out _);
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException)
        {
            return new PayloadFinding("unreadable-channel", "plugin message whose channel name could not be read",
                PayloadSeverity.ProtocolViolation);
        }

        // An assumption rather than a certainty: the identifier rules are strict, but a mod inventing
        // its own channel naming is a far likelier explanation than an attack.
        return PayloadScanner.IsValidChannelName(channel)
            ? null
            : new PayloadFinding("malformed-channel",
                $"plugin message on \'{Truncate(channel)}\', which is not a valid channel name",
                PayloadSeverity.Assumption);
    }

    private void CountAttack()
    {
        int perSecond = _attacks.Record(_now());

        // Reported once per connection. Click rate is the weakest kind of evidence — a macro mouse and
        // an autoclicker look identical from here, and so does a player with a very fast finger — so
        // it goes in the log for a human to weigh, and never disconnects anyone.
        if (perSecond > inspection.MaxAttacksPerSecond && !_reportedAttackRate)
        {
            _reportedAttackRate = true;
            logger.LogInformation("[{Profile}] '{Username}' ({Ip}) sent {Rate} attack packets in one second " +
                                  "(above {Limit}), which suggests automated clicking. Not acted on.",
                profile.Name, username, remoteAddress, perSecond, inspection.MaxAttacksPerSecond);
        }
    }

    private static string Truncate(string value) => value.Length <= 48 ? value : value[..48] + "\u2026";

    /// <summary>Counts events inside the current second. Owned by one connection, so no locking.</summary>
    private sealed class SecondCounter
    {
        private long _windowStart;
        private int _count;

        public SecondCounter(DateTimeOffset start) => _windowStart = start.Ticks;

        public int Record(DateTimeOffset now)
        {
            if (now.Ticks - _windowStart >= TimeSpan.TicksPerSecond)
            {
                _windowStart = now.Ticks;
                _count = 0;
            }

            return ++_count;
        }
    }

    /// <summary>
    /// Arms the player's own request to lock this name, and disconnects them so they can come back
    /// with the account that owns it.
    ///
    /// The disconnect is the mechanism, not a punishment: the encryption challenge that proves account
    /// ownership happens during login, so there is no way to run it on a connection that is already
    /// past that point. Saying so plainly in the kick message is the difference between an instruction
    /// and an apparent failure.
    /// </summary>
    private void ArmPremiumClaim()
    {
        IdentityEntry entry = profile.IdentityStore.GetOrCreate(username);

        if (entry.PremiumRequired)
        {
            // Already locked. Worth answering rather than silently arming a claim that would change
            // nothing — and worth not disconnecting them over.
            SendToPlayer(messages.PremiumLockSucceeded);
            return;
        }

        entry.PremiumClaimRequested = new PremiumClaimRequest(_now());
        entry.Record(PlayerEventKind.PremiumClaimRequested, remoteAddress,
            "asked for this name to be locked to their Minecraft account", _now());

        logger.LogInformation("[{Profile}] '{Username}' ({Ip}) asked for their name to be locked to their Minecraft " +
                              "account. The next login with this name will be challenged once.",
            profile.Name, username, remoteAddress);

        DisconnectReason = messages.PremiumLockArmed;
    }

    // —— holding a player at the prompt —————————————————————————————

    /// <summary>
    /// Puts the instruction where somebody will actually see it: across the middle of the screen as
    /// well as in chat.
    ///
    /// Chat alone was not enough, and that only showed up when somebody who had not built this tried
    /// it. A player who has never met a login-required server does not read chat, and the message
    /// scrolls away while they are looking at their inventory. Every line here is configurable, so a
    /// server can say it in its own language and its own words.
    /// </summary>
    private void PromptToAuthenticate()
    {
        bool registering = graceAuth!.NeedsRegistration;

        SendToPlayer(registering ? messages.RegistrationPrompt : messages.LoginPrompt);

        // Only while registering. Somebody logging in already has a password; somebody choosing one
        // is exactly who should be told they may not need to.
        if (registering && !string.IsNullOrWhiteSpace(messages.PremiumOfferDuringRegistration))
            SendToPlayer(messages.PremiumOfferDuringRegistration);

        SendTitle(
            registering ? messages.RegistrationTitle : messages.LoginTitle,
            registering ? messages.RegistrationSubtitle : messages.LoginSubtitle,
            // Twenty ticks a second, and set to outlast the gap between reminders by a wide margin so
            // the prompt never blinks out and leaves somebody staring at nothing.
            stayTicks: (int)(identityOptions.AuthenticationReminderInterval.TotalSeconds * 20) + 100);
    }

    private void SendTitle(string title, string subtitle, int stayTicks)
    {
        WriteToClient(() => FrameWriter.WriteTitleFrames(
            packetIds.PlayTitleAnimationClientbound,
            packetIds.PlayTitleTextClientbound,
            packetIds.PlaySubtitleTextClientbound,
            title, subtitle, stayTicks));
    }

    /// <summary>
    /// Re-tells the client where it is, often enough that a held player never visibly drifts.
    ///
    /// Refusing their movement packets keeps them still as far as the server is concerned, but the
    /// client does not know that: it predicts its own movement and only corrects when contradicted.
    /// Without this, a held player walks around their own screen and then snaps back, which reads as a
    /// broken server rather than as a prompt — and gravity is a prediction too, so pinning them once
    /// simply starts them falling.
    ///
    /// Nothing happens until the backend has said where the player is. Until then there is no position
    /// to put back afterwards, and moving somebody the proxy cannot restore would be worse than
    /// leaving them be.
    /// </summary>
    private void MaintainPositionLock()
    {
        if (!identityOptions.LockPositionWhileAuthenticating || !_hold.HasBackendPosition)
            return;

        DateTimeOffset now = _now();
        if (_lastPositionLock != default && now - _lastPositionLock < identityOptions.PositionLockInterval)
            return;

        _lastPositionLock = now;

        int teleportId = _hold.NextProxyTeleportId();
        WriteToClient(() => FrameWriter.WritePlayerPositionFrame(
            packetIds.PlayPlayerPositionClientbound, packetIds.PositionLayout,
            identityOptions.LockPositionX, identityOptions.LockPositionY, identityOptions.LockPositionZ,
            yaw: 0f, pitch: 0f, teleportId));
    }

    /// <summary>The leading VarInt, or -1 if it cannot be read. Only used to match a confirmation
    /// already known to be the proxy's own, so an unreadable one simply fails to match.</summary>
    private static int VarIntOrDefault(ReadOnlySpan<byte> fields)
    {
        try
        {
            return VarInt.Decode(fields, out _);
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            return -1;
        }
    }

    /// <summary>True when this confirmation answers one of the proxy's own pinning teleports, which
    /// means the backend never sent it and must never see the answer.</summary>
    private bool IsProxyTeleportConfirmation(DecodedPacket packet)
    {
        try
        {
            return _hold.IsProxyTeleport(VarInt.Decode(packet.Fields, out _));
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            // Unreadable, so it cannot be shown to be ours. Forwarded, because withholding a teleport
            // confirmation the backend is waiting on would leave the player unable to move afterwards.
            return false;
        }
    }

    /// <summary>
    /// Ends the hold and puts the player back where the backend has them.
    ///
    /// The restore matters as much as the pin. Server-side they never moved, so their real position is
    /// still whatever it was at join; it is only their client that has been standing at the origin.
    /// Leaving it there would mean the first step they took got corrected out from under them.
    /// </summary>
    private void ReleaseHold()
    {
        _hold.Released = true;

        // Cleared rather than left to time out: the prompt was given a long stay so it would not blink
        // out while they read it, and that same length would otherwise hang over the game afterwards.
        SendTitle("", "", stayTicks: 1);

        if (!identityOptions.LockPositionWhileAuthenticating || _hold.BackendPosition is not { } position)
            return;

        int teleportId = _hold.NextProxyTeleportId();
        _pendingRestoreTeleport = teleportId;
        _restoreDeadline = _now() + RestoreConfirmationTimeout;

        WriteToClient(() => FrameWriter.WritePlayerPositionFrame(
            packetIds.PlayPlayerPositionClientbound, packetIds.PositionLayout,
            position.X, position.Y, position.Z, position.Yaw, position.Pitch, teleportId));
    }

    /// <summary>
    /// Reports the player's health, as observed on the backend's side of the connection.
    ///
    /// What counts is the decrease, not the number. The server announces a player's health as they
    /// join, so measuring against a fixed level would kick anyone who had simply logged off wounded
    /// — and tell them something had attacked them, which nothing had. The first announcement is
    /// the baseline; only a fall from it is damage.
    ///
    /// Called from the pump rather than from the inspector's own loop. The baseline is only ever
    /// touched here, on that one thread; the flag it sets crosses over, and is volatile for it.
    /// </summary>
    public void NoteBackendHealth(float health)
    {
        float? previous = _healthBaseline;
        _healthBaseline = health;

        if (previous is { } before && before - health >= identityOptions.DamageDisconnectMinimumDrop)
            _damageSeenWhileHeld = true;
    }

    /// <summary>
    /// Pulls a held player out if something has started hurting them. Returns true when the caller
    /// should stop reading.
    ///
    /// A firewall in front of a server cannot stop a creeper: the player really is standing in the
    /// world while they read the prompt, and their health is decided entirely by the server. Nothing
    /// this proxy refuses or rewrites changes that. What it can do is notice in time — a kick costs
    /// them a reconnect, and a death costs them everything they were carrying.
    /// </summary>
    private bool HandleDamageWhileHeld()
    {
        if (!_damageSeenWhileHeld || !identityOptions.DisconnectIfDamagedWhileAuthenticating)
            return false;

        logger.LogInformation("[{Profile}] '{Username}' ({Ip}) was taking damage while waiting to authenticate " +
                              "— disconnected before they could die.", profile.Name, username, remoteAddress);

        DisconnectReason = messages.DamagedWhileAuthenticating;
        return true;
    }

    /// <summary>
    /// Says something to the player without ending their connection.
    ///
    /// Best-effort and fire-and-forget: this is only ever used for the premium self-lock conversation,
    /// and a failure to deliver an explanatory message must not disturb a connection that is otherwise
    /// working. Nothing security-relevant depends on it arriving.
    /// </summary>
    private void SendToPlayer(string text)
    {
        WriteToClient(() => FrameWriter.WriteSystemChatFrame(packetIds.PlaySystemChatClientbound, text));
    }

    /// <summary>
    /// Sends something the proxy composed itself to the player, best-effort.
    ///
    /// Every one of these is an explanation or a correction, never a security decision — a prompt
    /// that fails to arrive is a worse experience, not a weaker firewall — so nothing here is allowed
    /// to disturb a connection that is otherwise working. The stream serialises its writes, because
    /// the pump carrying the backend's replies is writing to the same socket at the same time, and two
    /// interleaved length-prefixed frames produce one frame whose declared length does not match its
    /// contents and a disconnect nobody can explain.
    /// </summary>
    private void WriteToClient(Func<byte[]> build)
    {
        Stream? writer = _clientWriter;
        if (writer is null)
            return;

        try
        {
            writer.WriteAsync(build()).AsTask().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "[{Profile}] could not deliver a packet to '{Username}'.", profile.Name, username);
        }
    }

    private void LogCommandOrChat(bool isCommand, string text)
    {
        if (isCommand)
            logger.LogInformation("[{Profile}] command from '{Username}' ({Ip}): /{Command}", profile.Name, username, remoteAddress, text);
        else
            logger.LogDebug("[{Profile}] chat from '{Username}' ({Ip}): {Text}", profile.Name, username, remoteAddress, text);
    }
}
