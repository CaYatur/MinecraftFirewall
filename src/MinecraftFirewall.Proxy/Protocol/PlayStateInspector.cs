using System.Net;
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
    Func<DateTimeOffset>? clock = null)
{
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
               dangerousCommands, messages, policyEngine, inspection, logger, null)
    {
    }

    /// <summary>Set when a dangerous command or a failed grace-authentication means this connection
    /// must be cut off — the caller (ClientConnection) checks this after the loop ends to decide
    /// whether to send a Play-state Disconnect before closing.</summary>
    public string? DisconnectReason { get; private set; }

    public async Task RunAsync(Stream clientStream, Stream backendStream, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            DecodedPacket packet = await CompressedPacketReader
                .ReadAsync(clientStream, inspection.MaxServerboundFrameBytes, ct, inspection.MaxServerboundUncompressedBytes)
                .ConfigureAwait(false);

            // Charged before anything is decided about the packet. A flood is defined by its volume,
            // not its contents, so the cheapest check has to be the first one.
            if (inspection.Enabled && _budget.Charge(packet.RawFrame.Length, _now()) is { } overBudget)
            {
                logger.LogWarning("[{Profile}] '{Username}' ({Ip}) exceeded its packet budget: {Detail}",
                    profile.Name, username, remoteAddress, overBudget);
                policyEngine.RegisterPacketFlood(remoteAddress, profile.Name, username, overBudget);
                DisconnectReason = messages.GenericDenied;
                return;
            }

            if (_inPlayState && inspection.Enabled && InspectPlayPacket(packet) is { } violation)
            {
                logger.LogWarning("[{Profile}] blocked a packet from '{Username}' ({Ip}): {Violation}",
                    profile.Name, username, remoteAddress, violation.Detail);
                policyEngine.RegisterProtocolViolation(remoteAddress, profile.Name, username, violation.Detail,
                    unambiguous: violation.Severity == PayloadSeverity.ProtocolViolation);
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
                    _inPlayState = true;

                await backendStream.WriteAsync(packet.RawFrame, ct).ConfigureAwait(false);
                continue;
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
                DisconnectReason = messages.GenericDenied;
                return;
            }

            if (graceAuth is not null && !_graceAuthResolved)
            {
                // The very first Play-state message (chat OR command) is the grace-auth check. A
                // plain chat message here is an automatic failure — a valid /login can only ever
                // arrive as a command.
                HandleGraceAuthAttempt(isCommand ? text : null);
                if (DisconnectReason is not null)
                    return;
                continue; // consumed either way — success or failure, never forwarded to the backend
            }

            if (isCommand && HandleCayaDevCheckCommand(text))
                continue; // /register or /login outside a grace-auth requirement — also swallowed

            LogCommandOrChat(isCommand, text);

            if (isCommand && !_isTrusted && DangerousCommandMatcher.IsMatch(text, dangerousCommands))
            {
                logger.LogWarning("[{Profile}] DANGEROUS COMMAND from non-trusted '{Username}' ({Ip}): {Command}",
                    profile.Name, username, remoteAddress, DangerousCommandMatcher.ExtractBaseCommand(text));
                policyEngine.RegisterDangerousCommand(remoteAddress, profile.Name, username, DangerousCommandMatcher.ExtractBaseCommand(text));
                DisconnectReason = messages.DangerousCommandBlocked;
                return;
            }

            await backendStream.WriteAsync(packet.RawFrame, ct).ConfigureAwait(false);
        }
    }

    /// <summary>Handles the mandatory first-message grace-auth check — only ever called once, for the
    /// first Play-state chat/command message. <paramref name="commandText"/> is null when the first
    /// message was plain chat (not a command), which is an automatic failure.</summary>
    private void HandleGraceAuthAttempt(string? commandText)
    {
        _graceAuthResolved = true;

        var parsed = commandText is not null ? CayaDevCheckCommandParser.Parse(commandText) : null;

        if (parsed is { Kind: CayaDevCheckCommandKind.Login } && PasswordHasher.Verify(parsed.Password, graceAuth!.PasswordHash))
        {
            graceAuth.Entry.LearnIp(remoteAddress, identityOptions.LearnedIpTtl, identityOptions.MaxLearnedIpsPerUsername);
            policyEngine.RegisterGraceAuthSuccess(remoteAddress, profile.Name, username);
            _isTrusted = true;
            logger.LogInformation("[{Profile}] '{Username}' authenticated from a new IP {Ip} — trusted for {Ttl}.",
                profile.Name, username, remoteAddress, identityOptions.LearnedIpTtl);
            return;
        }

        logger.LogWarning("[{Profile}] grace-authentication FAILED for '{Username}' from {Ip} — first message was not a correct /login.",
            profile.Name, username, remoteAddress);
        policyEngine.RegisterGraceAuthFailure(remoteAddress, profile.Name, username);
        DisconnectReason = messages.GraceAuthenticationFailed;
    }

    private bool HandleCayaDevCheckCommand(string commandText)
    {
        if (!CayaDevCheckCommandParser.LooksLikeCayaDevCheckCommand(commandText))
            return false;

        var parsed = CayaDevCheckCommandParser.Parse(commandText);

        switch (parsed.Kind)
        {
            case CayaDevCheckCommandKind.Register:
                if (parsed.Password.Length < identityOptions.PasswordMinLength)
                {
                    logger.LogInformation("[{Profile}] '{Username}' tried to register a password shorter than the minimum.", profile.Name, username);
                    return true;
                }

                var entry = profile.IdentityStore.GetOrCreate(username);
                entry.PasswordHash = PasswordHasher.Hash(parsed.Password);
                entry.LearnIp(remoteAddress, identityOptions.LearnedIpTtl, identityOptions.MaxLearnedIpsPerUsername);
                _isTrusted = true;
                logger.LogInformation("[{Profile}] '{Username}' registered with CaYaDev-Check from {Ip}.", profile.Name, username, remoteAddress);
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

        if (packet.PacketId == packetIds.PlaySignUpdateServerbound || packet.PacketId == packetIds.PlayEditBookServerbound)
            return InspectWrittenText(packet);

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

    private void LogCommandOrChat(bool isCommand, string text)
    {
        if (isCommand)
            logger.LogInformation("[{Profile}] command from '{Username}' ({Ip}): /{Command}", profile.Name, username, remoteAddress, text);
        else
            logger.LogDebug("[{Profile}] chat from '{Username}' ({Ip}): {Text}", profile.Name, username, remoteAddress, text);
    }
}
