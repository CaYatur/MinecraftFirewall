using System.Net;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Policy;

namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>
/// Inspects the client-to-backend half of a Play-state connection. Parses the outer frame always;
/// decodes a packet's fields only for the handful of packet IDs it cares about (Configuration's
/// Finish Configuration, and Play's chat/chat_command/chat_command_signed); everything else is
/// forwarded byte-for-byte from DecodedPacket.RawFrame, never re-serialized. The backend-to-client
/// direction is NOT handled here — ClientConnection still uses a plain byte pump for that side, since
/// Stage 3 has no reason to inspect anything the server sends.
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
    PolicyEngine policyEngine,
    ILogger logger)
{
    private const int MaxServerboundFrameSize = 2 * 1024 * 1024;

    private bool _inPlayState;
    private bool _graceAuthResolved;
    private bool _isTrusted = startsTrusted;

    /// <summary>Set when a dangerous command or a failed grace-authentication means this connection
    /// must be cut off — the caller (ClientConnection) checks this after the loop ends to decide
    /// whether to send a Play-state Disconnect before closing.</summary>
    public string? DisconnectReason { get; private set; }

    public async Task RunAsync(Stream clientStream, Stream backendStream, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            DecodedPacket packet = await CompressedPacketReader.ReadAsync(clientStream, MaxServerboundFrameSize, ct).ConfigureAwait(false);

            if (!_inPlayState)
            {
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
                DisconnectReason = "Bu komut için yetkiniz yok. Bağlantınız güvenlik nedeniyle kesildi.";
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
            policyEngine.RegisterGraceAuthSuccess(remoteAddress);
            _isTrusted = true;
            logger.LogInformation("[{Profile}] '{Username}' authenticated from a new IP {Ip} — trusted for {Ttl}.",
                profile.Name, username, remoteAddress, identityOptions.LearnedIpTtl);
            return;
        }

        logger.LogWarning("[{Profile}] grace-authentication FAILED for '{Username}' from {Ip} — first message was not a correct /login.",
            profile.Name, username, remoteAddress);
        policyEngine.RegisterGraceAuthFailure(remoteAddress, profile.Name, username);
        DisconnectReason = "Kimlik doğrulama başarısız. Bu IP tanınmıyor ve doğru şifre girilmedi.";
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

    private void LogCommandOrChat(bool isCommand, string text)
    {
        if (isCommand)
            logger.LogInformation("[{Profile}] command from '{Username}' ({Ip}): /{Command}", profile.Name, username, remoteAddress, text);
        else
            logger.LogDebug("[{Profile}] chat from '{Username}' ({Ip}): {Text}", profile.Name, username, remoteAddress, text);
    }
}
