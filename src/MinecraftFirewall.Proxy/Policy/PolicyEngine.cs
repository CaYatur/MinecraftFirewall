using System.Net;
using MinecraftFirewall.Proxy.Alerts;
using MinecraftFirewall.Proxy.Anomaly;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.IpIntel;
using MinecraftFirewall.Proxy.RateLimiting;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Policy;

/// <summary>Carried on an Allow decision when the connection is a self-registered CaYaDev-Check
/// username on an unrecognized IP — the caller (ClientConnection/PlayStateInspector) must enforce
/// that the first Play-state message is a correct /login, per IdentityGate's AllowPendingGraceAuthentication.</summary>
/// <summary>
/// Carried on an Allow decision when the connection has to authenticate before it may do anything.
///
/// <see cref="PasswordHash"/> null means the player has no password yet and must register; non-null
/// means they have one and must log in. Both are the same state as far as the inspector is concerned —
/// the player is held still and nothing they do reaches the server — which is why they share a type
/// rather than being two parallel paths that could drift apart.
/// </summary>
public sealed record GraceAuthRequirement(IdentityEntry Entry, string? PasswordHash)
{
    public bool NeedsRegistration => PasswordHash is null;
}

/// <summary>Carried on an Allow decision when the username is admin-declared PremiumRequired. "Allow"
/// here means only "nothing in the IP/rate-limit/VPN layer objected" — the connection still has to
/// pass the full Mojang encryption + hasJoined challenge in ClientConnection before it reaches the
/// backend, and it never falls back to any weaker check if that fails.</summary>
public sealed record PremiumRequirement(IdentityEntry Entry);

public sealed record PolicyDecision(
    bool Allow,
    string Reason,
    GraceAuthRequirement? GraceAuth = null,
    PremiumRequirement? Premium = null);

/// <summary>
/// Combines identity, VPN/datacenter signal, and rate limiting into one Allow/Deny decision per
/// connection. Shared services (VPN table, firewall bans, strike counter) are process-wide; identity
/// and rate-limit state are profile-scoped (passed in via the ServerProfile).
/// </summary>
public sealed class PolicyEngine(
    VpnIntelligence vpnIntelligence,
    ConnectionRateLimiter rateLimiter,
    FirewallBanService banService,
    StrikeTracker strikeTracker,
    IIpInfoClient ipInfoClient,
    IAlertSender alerts,
    ThreatIntelligence threatIntelligence,
    ScannerDetector scannerDetector,
    BotDetector botDetector,
    AnomalyResponder anomalyResponder,
    IOptions<FirewallBanOptions> banOptions,
    IOptions<IpInfoOptions> ipInfoOptions,
    IOptions<DdosOptions> ddosOptions,
    IOptions<BotDefenseOptions> botOptions,
    IOptions<IdentityOptions> identityOptions,
    IOptions<AnomalyOptions> anomalyOptions,
    ILogger<PolicyEngine> logger)
{
    private readonly FirewallBanOptions _banOptions = banOptions.Value;
    private readonly IpInfoOptions _ipInfoOptions = ipInfoOptions.Value;
    private readonly DdosOptions _ddosOptions = ddosOptions.Value;
    private readonly BotDefenseOptions _botOptions = botOptions.Value;
    private readonly IdentityOptions _identityOptions = identityOptions.Value;
    private readonly AnomalyOptions _anomalyOptions = anomalyOptions.Value;

    /// <summary>Checked once per connection, right after the Handshake is parsed, before the
    /// status/login branch — see HostnameMatcher for the matching rules and its important caveat
    /// (this is not a cryptographic boundary; it only stops clients that don't lie about the field).</summary>
    public PolicyDecision EvaluateHostname(ServerProfile profile, IPAddress remoteAddress, string serverAddress)
    {
        if (banService.IsBanned(remoteAddress))
            return new PolicyDecision(false, "IP is currently firewall-banned.");

        // Checked here rather than in EvaluateLogin so it also covers status pings, which is where a
        // scanner shows up before it ever tries to log in — and ahead of the hostname check, so it
        // applies to every connection rather than only the ones already being turned away.
        if (threatIntelligence.Action == ThreatListAction.Block && threatIntelligence.IsOnImportedList(remoteAddress))
            return new PolicyDecision(false, "Address appears on an imported threat list.");

        if (HostnameMatcher.IsAllowed(serverAddress, profile.AllowedHostnames))
            return new PolicyDecision(true, "OK");

        string logged = HostnameMatcher.TruncateForLogging(serverAddress);
        string normalized = HostnameMatcher.Normalize(serverAddress);
        HostnameMismatchKind kind = ScannerDetector.Classify(normalized);

        // A crawler announces its own domain in the field meant for this server's name, and does it
        // every sweep. Once it has done so often enough, an ordinary six-hour ban is pointless: it will
        // be back on schedule. A raw IP in that field is a different matter entirely — that is what the
        // admin's own test connection looks like — so it never escalates.
        if (scannerDetector.RecordMismatch(remoteAddress, normalized, kind, DateTimeOffset.UtcNow) is { } banFor)
        {
            banService.Ban(remoteAddress, $"[{profile.Name}] server-indexing crawler: repeatedly announced hostnames this server does not serve", banFor);
            threatIntelligence.RecordLocalHit(remoteAddress, $"crawler announcing '{logged}'", DateTimeOffset.UtcNow);
            strikeTracker.Reset(remoteAddress);

            alerts.Send(AlertKind.Ban,
                $"🔎 **Crawler blocked** on `{AlertText.Field(profile.Name)}`\n" +
                $"`{AlertText.Field(remoteAddress.ToString())}` kept connecting under `{AlertText.Field(logged)}` — banned for {banFor.TotalDays:0} days.");

            return new PolicyDecision(false, "Address is a server-indexing crawler.");
        }

        RegisterStrikeAndMaybeBan(remoteAddress, $"[{profile.Name}] connection via disallowed hostname '{logged}'");
        return new PolicyDecision(false, $"Hostname '{logged}' is not in this server's allowed-domains list.");
    }

    public PolicyDecision EvaluateStatusPing(ServerProfile profile, IPAddress remoteAddress)
    {
        if (banService.IsBanned(remoteAddress))
            return new PolicyDecision(false, "IP is currently firewall-banned.");

        if (!rateLimiter.TryRegisterAttempt(profile.Name, remoteAddress, RateLimitKind.StatusPing))
        {
            // Refused, and that is all. A client refreshing its server list too eagerly is not an
            // attack, and banning a machine for it is out of all proportion to what it did. Genuine
            // volume is the admission-control governor's job, which refuses before a byte is read.
            logger.LogDebug("[{Profile}] status pings from {Ip} are coming too fast; refusing this one.",
                profile.Name, remoteAddress);

            return new PolicyDecision(false, "Status-ping rate limit exceeded.");
        }

        strikeTracker.Reset(remoteAddress);
        return new PolicyDecision(true, "OK");
    }

    public async Task<PolicyDecision> EvaluateLogin(ServerProfile profile, IPAddress remoteAddress, string username, CancellationToken ct = default)
    {
        if (banService.IsBanned(remoteAddress))
            return new PolicyDecision(false, "IP is currently firewall-banned.");

        if (!rateLimiter.TryRegisterAttempt(profile.Name, remoteAddress, RateLimitKind.LoginAttempt))
        {
            NoteLoginRateLimited(profile.Name, remoteAddress, username);
            return new PolicyDecision(false, "Login rate limit exceeded.");
        }

        var entry = profile.IdentityStore.Find(username);

        // A flagged address is asked to prove itself again even though it has connected before. Cheap
        // for a returning player — one password — and expensive for anyone who does not have it. The
        // requirement is consumed as it is read, so this costs one connection rather than putting the
        // address into a state somebody has to be rescued from.
        bool mustReauthenticate = anomalyResponder.ConsumeReauthenticationRequirement(remoteAddress, DateTimeOffset.UtcNow);
        if (mustReauthenticate && entry?.PasswordHash is not null)
        {
            logger.LogInformation("[{Profile}] '{Username}' ({Ip}) must authenticate again — this address was flagged by the anomaly model.",
                profile.Name, username, remoteAddress);
            return new PolicyDecision(true, "Anomaly model asked this address to re-authenticate.",
                new GraceAuthRequirement(entry, entry.PasswordHash));
        }

        var identityDecision = IdentityGate.Evaluate(entry, remoteAddress, _identityOptions.RequireRegistrationForEveryone);

        if (identityDecision.Outcome == IdentityOutcome.Deny)
        {
            RegisterStrikeAndMaybeBan(remoteAddress,
                $"[{profile.Name}] protected username '{username}' denied: {identityDecision.Reason}");
            return new PolicyDecision(false, $"Protected username denied: {identityDecision.Reason}");
        }

        // A pending-grace-auth or premium-challenge connection is a security-relevant identity too,
        // so both are treated the same as an outright-Allow for VPN/hosting-signal policy purposes.
        bool isProtectedUsername = identityDecision.Outcome
            is IdentityOutcome.Allow
            or IdentityOutcome.AllowPendingGraceAuthentication
            or IdentityOutcome.PremiumVerificationRequired;

        bool isVpnFlagged = profile.UseDatacenterList
            ? vpnIntelligence.IsKnownVpnOrDatacenter(remoteAddress)
            : vpnIntelligence.IsKnownVpn(remoteAddress);
        string vpnFlagSource = "X4BNet VPN/datacenter list";

        // Secondary, real-time signal — different provider, different mechanism (see IpInfoOptions).
        // Only worth the network round-trip if the primary list didn't already decide this, and only
        // in-scope per config (default: protected usernames only).
        if (!isVpnFlagged && (_ipInfoOptions.ApplyToAllConnections || isProtectedUsername))
        {
            var ipInfoResult = await ipInfoClient.LookupAsync(remoteAddress, ct).ConfigureAwait(false);
            if (ipInfoResult.LooksLikeHostingProvider)
            {
                isVpnFlagged = true;
                vpnFlagSource = $"ipinfo.io ASN/org heuristic ('{ipInfoResult.AsName}')";
            }
        }

        if (isVpnFlagged)
        {
            bool shouldBlock = profile.VpnPolicy switch
            {
                VpnPolicy.BlockForEveryone => true,
                VpnPolicy.BlockForProtectedUsernamesOnly => isProtectedUsername,
                VpnPolicy.LogOnly => false,
                _ => false,
            };

            if (shouldBlock)
            {
                RegisterStrikeAndMaybeBan(remoteAddress,
                    $"[{profile.Name}] VPN/datacenter IP denied for username '{username}' (source: {vpnFlagSource})");
                return new PolicyDecision(false, "Connection originates from a known VPN/datacenter IP.");
            }

            logger.LogInformation("[{Profile}] VPN/datacenter IP {Ip} allowed (log-only policy) for username '{Username}' (source: {Source}).",
                profile.Name, remoteAddress, username, vpnFlagSource);
        }

        // A clean, fully-allowed login clears any accumulated strikes for this IP — a legitimate
        // admin who fumbles their allowlist a few times and then connects correctly must not carry
        // those near-misses toward an eventual ban. A pending grace-auth isn't "clean" yet (the
        // password hasn't been checked), so strikes are only cleared once that succeeds — see
        // ClientConnection/PlayStateInspector, which calls RegisterGraceAuthSuccess itself.
        // Same reasoning as grace-auth below: verification hasn't happened yet, so strikes stay.
        if (identityDecision.Outcome == IdentityOutcome.PremiumVerificationRequired)
        {
            return new PolicyDecision(true, identityDecision.Reason, Premium: new PremiumRequirement(entry!));
        }

        if (identityDecision.Outcome == IdentityOutcome.AllowPendingGraceAuthentication)
        {
            return new PolicyDecision(true, identityDecision.Reason, new GraceAuthRequirement(entry!, entry!.PasswordHash!));
        }

        if (identityDecision.Outcome == IdentityOutcome.RegistrationRequired)
        {
            // The entry may not exist yet — this is a name nobody has registered. Creating it here
            // rather than in the inspector keeps the store the single owner of identity records, and
            // an entry with no password protects nothing on its own, so nothing is granted by it.
            IdentityEntry registrationTarget = entry ?? profile.IdentityStore.GetOrCreate(username);
            return new PolicyDecision(true, identityDecision.Reason, new GraceAuthRequirement(registrationTarget, null));
        }

        strikeTracker.Reset(remoteAddress);
        return new PolicyDecision(true, "OK");
    }

    /// <summary>Called by PlayStateInspector when a grace-authentication first-message check succeeds.
    /// This is deliberately alerted on even though it's a *success*: it's the moment a password was
    /// used from an IP nobody had seen before, so if the password has been stolen this is where it
    /// becomes visible rather than silently working.</summary>
    public void RegisterGraceAuthSuccess(IPAddress remoteAddress, string profileName, string username)
    {
        strikeTracker.Reset(remoteAddress);
        alerts.Send(AlertKind.NewTrustedIp,
            $"🔑 **New trusted IP** for `{AlertText.Field(username)}` on `{AlertText.Field(profileName)}`: `{AlertText.Field(remoteAddress.ToString())}`\nIf this wasn't them, their password may be compromised.");
    }

    /// <summary>Called by PlayStateInspector when a grace-authentication check fails (wrong password,
    /// wrong first message, or timeout) — a much stronger signal than a generic rate-limit trip, so it
    /// weighs enough strikes to reach the ban threshold immediately rather than needing repeats.</summary>
    public void RegisterGraceAuthFailure(IPAddress remoteAddress, string profileName, string username)
    {
        RegisterStrikeAndMaybeBan(remoteAddress,
            $"[{profileName}] grace-authentication failed for registered username '{username}'",
            weight: _banOptions.StrikesBeforeBan);
    }

    /// <summary>Called by ClientConnection when a PremiumRequired username passes the full Mojang
    /// challenge — the strongest possible proof of identity this proxy can obtain, so it clears any
    /// strikes the same way a clean allowlisted login does.</summary>
    public void RegisterPremiumVerificationSuccess(IPAddress remoteAddress) => strikeTracker.Reset(remoteAddress);

    /// <summary>
    /// Called by ClientConnection when a PremiumRequired username fails verification.
    ///
    /// Deliberately NOT fast-tracked in the ordinary case, unlike a grace-authentication failure. A
    /// wrong password is unambiguous; a failed hasJoined check is not — a genuine owner caught by a
    /// Mojang session-API outage produces byte-for-byte the same failure as a cracked client, and
    /// this proxy cannot tell them apart. A normal-weight strike still bans an attacker who keeps
    /// hammering the name, while a single outage-time failure costs the real owner one strike rather
    /// than immediate machine-wide banishment.
    ///
    /// <paramref name="pinnedToDifferentAccount"/> is the one case that IS unambiguous and is
    /// fast-tracked: someone passed Mojang's check as a real, different account and tried to take a
    /// name already pinned to someone else. That is a deliberate impersonation attempt with genuine
    /// credentials, not an outage.
    /// </summary>
    public void RegisterPremiumVerificationFailure(IPAddress remoteAddress, string profileName, string username, string reason, bool pinnedToDifferentAccount)
    {
        RegisterStrikeAndMaybeBan(remoteAddress,
            $"[{profileName}] premium verification failed for '{username}': {reason}",
            weight: pinnedToDifferentAccount ? _banOptions.StrikesBeforeBan : 1);

        string headline = pinnedToDifferentAccount
            ? "🛑 **Impersonation attempt**: a different verified Minecraft account tried to take a pinned username"
            : "⚠️ **Premium verification failed** (a cracked client — or a Mojang outage hitting the real owner)";
        alerts.Send(AlertKind.PremiumVerificationFailure,
            $"{headline}\n`{AlertText.Field(username)}` on `{AlertText.Field(profileName)}` from `{AlertText.Field(remoteAddress.ToString())}` — {AlertText.Field(reason)}");
    }

    /// <summary>Called by PlayStateInspector when a non-trusted connection issues a dangerous command —
    /// same fast-track reasoning as a grace-authentication failure.</summary>
    public void RegisterDangerousCommand(IPAddress remoteAddress, string profileName, string username, string command)
    {
        RegisterStrikeAndMaybeBan(remoteAddress,
            $"[{profileName}] dangerous command '{command}' from non-trusted username '{username}'",
            weight: _banOptions.StrikesBeforeBan);

        // Only the base command is sent, never its arguments — the caller already extracts it, and
        // arguments are free-form player input that could carry anything.
        alerts.Send(AlertKind.DangerousCommand,
            $"☢️ **Dangerous command blocked** on `{AlertText.Field(profileName)}`\n`{AlertText.Field(username)}` from `{AlertText.Field(remoteAddress.ToString())}` tried `/{AlertText.Field(command)}`");
    }

    /// <summary>
    /// Called by the accept loop when the connection governor turned an address away.
    ///
    /// Only a light strike, on purpose. The addresses that reach this point completed a TCP handshake,
    /// so they are real rather than spoofed — but a single refusal can just as easily be a household
    /// NAT with several players behind it during a busy evening. A sustained flood accumulates enough
    /// of these to reach the ban threshold within seconds; one burst does not.
    /// </summary>
    public void RegisterFloodRefusal(IPAddress address, string profileName, AdmissionVerdict verdict) =>
        RegisterStrikeAndMaybeBan(address, $"[{profileName}] connection refused by admission control ({verdict})",
            weight: _ddosOptions.StrikeWeightOnFlood);

    /// <summary>Called when the bot score was high enough to refuse a login. The alert carries the
    /// individual signals rather than just the total, because a score on its own gives nobody enough
    /// to judge whether the refusal was right.</summary>
    public void RegisterBotDenial(IPAddress remoteAddress, string profileName, string username, BotAssessment assessment)
    {
        RegisterStrikeAndMaybeBan(remoteAddress,
            $"[{profileName}] '{username}' refused as automated (score {assessment.Score}): {assessment.Explain()}",
            weight: _botOptions.StrikeWeightOnDeny);

        alerts.Send(AlertKind.Ban,
            $"🤖 **Refused as a bot** on `{AlertText.Field(profileName)}`\n" +
            $"`{AlertText.Field(username)}` from `{AlertText.Field(remoteAddress.ToString())}` — score {assessment.Score}\n" +
            $"{AlertText.Field(assessment.Explain())}");
    }

    /// <summary>Called when the bot score was worth reporting but not acting on — either because the
    /// score sat between the two thresholds, or because scoring is still in log-only mode.</summary>
    public void ReportBotSuspicion(IPAddress remoteAddress, string profileName, string username, BotAssessment assessment) =>
        logger.LogWarning("[{Profile}] '{Username}' from {Ip} scored {Score} on bot signals but was allowed through: {Signals}",
            profileName, username, remoteAddress, assessment.Score, assessment.Explain());

    /// <summary>
    /// Called when an authorised connection blew through its per-connection packet or byte budget.
    ///
    /// Struck at full weight. Unlike a refusal at the accept loop, this comes from a connection that
    /// already passed every identity check, so there is no shared-NAT ambiguity about who sent it —
    /// this exact session did.
    /// </summary>
    public void RegisterPacketFlood(IPAddress remoteAddress, string profileName, string username, string detail)
    {
        RegisterStrikeAndMaybeBan(remoteAddress,
            $"[{profileName}] '{username}' exceeded its packet budget: {detail}",
            weight: _banOptions.StrikesBeforeBan);

        alerts.Send(AlertKind.Ban,
            $"🌊 **Packet flood** on `{AlertText.Field(profileName)}`\n" +
            $"`{AlertText.Field(username)}` from `{AlertText.Field(remoteAddress.ToString())}` — {AlertText.Field(detail)}");
    }

    /// <summary>
    /// Called when deep inspection refused a packet.
    ///
    /// The packet is blocked and the connection closed either way; <paramref name="unambiguous"/> only
    /// decides how much this costs the address on its record. An injection lookup, a NaN coordinate or
    /// a username past the protocol's own length limit is impossible under the protocol whatever
    /// client is involved, and weighs enough to reach the ban threshold at once. A rule resting on how
    /// clients are expected to behave — a formatting code that a vanilla client would have stripped, a
    /// chat message longer than vanilla allows — weighs one strike instead.
    ///
    /// The distinction matters because of a guarantee this whole project is built around: the genuine
    /// owner of a premium-locked username must never be refused. A machine-wide firewall ban would
    /// refuse them from every address at once, and it is the one consequence here that cannot be
    /// walked back. It must not be reachable by a single chat message from a client whose behaviour
    /// merely surprised us.
    /// </summary>
    public void RegisterProtocolViolation(IPAddress remoteAddress, string profileName, string username, string detail,
        bool unambiguous = true)
    {
        RegisterStrikeAndMaybeBan(remoteAddress,
            $"[{profileName}] '{username}' sent something no client sends: {detail}",
            weight: unambiguous ? _banOptions.StrikesBeforeBan : 1);

        alerts.Send(AlertKind.DangerousCommand,
            $"🧬 **Blocked packet** on `{AlertText.Field(profileName)}`\n" +
            $"`{AlertText.Field(username)}` from `{AlertText.Field(remoteAddress.ToString())}` — {AlertText.Field(detail)}");
    }

    /// <summary>
    /// Carries out whatever the anomaly responder decided.
    ///
    /// Every branch here acts on the *next* connection from the address rather than the one that was
    /// just scored, and that is inherent rather than a shortcut: the model judges a whole session, so
    /// by the time it has an opinion the session is over. What that buys is a system whose response is
    /// proportionate by construction — the worst it can do to somebody mid-game is nothing.
    /// </summary>
    public void ApplyAnomalyAction(IPAddress remoteAddress, string profileName, string username,
        AnomalyVerdict verdict, AnomalyAction action)
    {
        AnomalyResponder responder = anomalyResponder;

        string summary = $"anomaly score {verdict.Score:0.00} — {verdict.Description}";

        switch (action)
        {
            case AnomalyAction.Report:
                logger.LogWarning("[{Profile}] '{Username}' ({Ip}) does not resemble this server's usual traffic " +
                                  "({Summary}). Reported only — nothing was refused.",
                    profileName, username, remoteAddress, summary);
                return;

            case AnomalyAction.Score:
                botDetector.RecordAnomaly(remoteAddress, _anomalyOptions.ScoreWeight);
                logger.LogWarning("[{Profile}] '{Username}' ({Ip}) flagged repeatedly by the anomaly model ({Summary}). " +
                                  "It now counts towards this address's bot score.",
                    profileName, username, remoteAddress, summary);
                return;

            case AnomalyAction.RequireReauthentication:
                responder.RequireReauthentication(remoteAddress, DateTimeOffset.UtcNow);
                logger.LogWarning("[{Profile}] '{Username}' ({Ip}) flagged repeatedly by the anomaly model ({Summary}). " +
                                  "The next connection from this address must authenticate again.",
                    profileName, username, remoteAddress, summary);
                break;

            case AnomalyAction.Throttle:
                responder.Throttle(remoteAddress, DateTimeOffset.UtcNow);
                logger.LogWarning("[{Profile}] '{Username}' ({Ip}) flagged repeatedly by the anomaly model ({Summary}). " +
                                  "Connection limits for this address are tightened for {Duration}.",
                    profileName, username, remoteAddress, summary, _anomalyOptions.ActionDuration);
                break;

            case AnomalyAction.Ban:
                banService.Ban(remoteAddress, $"[{profileName}] repeatedly flagged by the anomaly model: {summary}",
                    _anomalyOptions.ActionDuration);
                break;
        }

        alerts.Send(AlertKind.Ban,
            $"🧠 **Anomaly action: {action}** on `{AlertText.Field(profileName)}`\n" +
            $"`{AlertText.Field(username)}` from `{AlertText.Field(remoteAddress.ToString())}` — {AlertText.Field(summary)}");
    }

    /// <summary>
    /// Handles a login refused for arriving too fast.
    ///
    /// Refusing it is the response. It used to also earn a strike, and five strikes is a six-hour
    /// machine-wide ban — so somebody impatiently reconnecting banned themselves in about a minute,
    /// having done nothing but try to join. That was reported by somebody it happened to, and it is
    /// the wrong shape of answer: the rate limit already stopped them, and a ban is for behaviour, not
    /// for impatience.
    ///
    /// What still escalates is the thing a player cannot do however fast they click — arriving under
    /// a series of different names. One person retrying produces one name; a list being worked through
    /// produces many, and that is what this looks at instead of the clock.
    /// </summary>
    private void NoteLoginRateLimited(string profileName, IPAddress remoteAddress, string username)
    {
        // Recorded first, then counted. A refused attempt never reaches the bot detector's own
        // assessment, so without this the names an address burned through while being rate-limited
        // would all be thrown away with the connections that carried them.
        int names = botDetector.NoteAttemptedUsername(remoteAddress, username);

        if (names <= _banOptions.RateLimitUsernamesBeforeStrike)
        {
            logger.LogInformation(
                "[{Profile}] '{Username}' ({Ip}) is reconnecting faster than the limit allows. Refused, " +
                "not counted against them — one name arriving quickly is impatience, not an attack.",
                profileName, username, remoteAddress);

            return;
        }

        RegisterStrikeAndMaybeBan(remoteAddress,
            $"[{profileName}] login rate limit exceeded across {names} different usernames from one address");
    }

    private void RegisterStrikeAndMaybeBan(IPAddress address, string reason, int weight = 1)
    {
        int strikes = strikeTracker.RegisterStrike(address, weight);
        if (strikes >= _banOptions.StrikesBeforeBan)
        {
            banService.Ban(address, $"{reason} (strike {strikes}/{_banOptions.StrikesBeforeBan})");
            strikeTracker.Reset(address);
        }
    }
}
