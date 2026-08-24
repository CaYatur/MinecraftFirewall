# MinecraftFirewall — Windows Reverse-Proxy Firewall for Minecraft Java Edition

## Status (as of this writing)

- **Stage 1 — done.** Multi-server reverse proxy, static IP-allowlist identity gate, X4BNet VPN/datacenter
  IP intelligence, per-profile rate limiting, real Windows Firewall bans (`INetFwPolicy2`, with an
  in-process fallback + startup elevation probe), never-ban list.
- **Stage 2 — done.** Compression frame format confirmed empirically against a real Paper 1.21.11
  server (see the Stage 2 section below); packet IDs sourced from Mojang's own generated data report,
  not a wiki. The "hold Play-state traffic" question was decided *not* to be pursued without a real
  graphical client to test against — see the Stage 3 section for the fallback design that resulted.
- **Stage 3 — done, 171 automated tests passing (`dotnet test`).** Compression-aware frame reading,
  `ProtocolVersionRegistry` (protocol 774 populated), `PlayStateInspector` (command auditing +
  dangerous-command detection + fast-track bans), the CaYaDev-Check self-service `/register`/`/login`
  gate with grace-authentication, PBKDF2 password hashing, TTL/cap-bounded learned IPs.
- **Live end-to-end verification — done, and it found a real bug.** Ran the actual compiled
  `MinecraftFirewall.Proxy` against a real local Paper 1.21.11 server, driven through the proxy's
  public port by a real protocol-correct client (`tools/MinecraftFirewall.ProtocolSpike`, extended
  with `playMode` — `register:<pw>`/`login:<pw>`/`chat` — and a `bindAddress` argument to simulate
  connecting from a second source IP without needing a second machine). This is exactly the
  verification step flagged as outstanding at the end of the previous session, and it justified doing
  it before Stage 4: **it caught a real, serious bug that no synthetic unit test could have found.**
  - **The bug**: `PlayStateInspector.RunAsync` started reading immediately after Login Start, so the
    very first packet it ever saw was the client's Login Acknowledged — but its Play-state-entry check
    only looked for packet ID 0x03 with empty fields, which is *also* Login Acknowledged's own ID
    (0x03, empty fields) in the Login state's own packet-ID namespace. Each protocol state has an
    independent ID space, so Login Acknowledged and Configuration's Finish Configuration coincidentally
    share ID 0x03 without being the same packet at all. The result: `_inPlayState` flipped a full
    protocol phase too early, on the very first packet, every single connection — so every
    Configuration-phase packet after it got inspected as if it were a Play-state message. The real
    damage: the Configuration-phase serverbound Known Packs response happens to share its ID with
    `PlayChatCommandSignedServerbound`, so it was consistently misread as a chat command (garbage
    bytes from misaligned field parsing, observed live as a literal tab character logged as the
    "command"). For any grace-authentication-pending connection — i.e. **every CaYaDev-Check
    registered player reconnecting from an unrecognized IP, which is the feature's whole reason to
    exist** — this consumed the player's one grace-auth attempt on that garbage before they ever
    reached Play state, meaning **every legitimate grace-authentication would have failed, unconditionally,
    for every real client**, not just malicious ones. This was completely invisible to
    `PlayStateInspectorTests.cs` because every test's synthetic input started exactly at a
    hand-built Finish Configuration frame, skipping Login Acknowledged entirely — a simplification in
    the test fixture that hid the exact packet sequence a real client actually sends.
  - **The fix**: `PlayStateInspector` now tracks an explicit `_awaitingLoginAcknowledged` step before
    its existing Configuration-vs-Play detection — the first serverbound packet it reads is always
    unconditionally forwarded and treated as Login Acknowledged, whatever its content, and only
    packets *after* that are checked against the real Finish Configuration ID. See the code comment at
    its use site in `PlayStateInspector.cs` for the full explanation. `PlayStateInspectorTests.cs` was
    updated so every test supplies this frame first (via a new `LoginAckFrame()` helper), plus a new
    dedicated regression test (`GraceAuth_RealisticConfigurationTraffic_BeforeFinishConfiguration_DoesNotConsumeGraceAuthEarly`)
    that reproduces the exact scenario: a Configuration-phase packet sharing an ID with a Play-state
    chat/command packet, arriving before Finish Configuration, must not be treated as the player's
    first Play-state message.
  - **Confirmed fixed, live, after the fix**: registered a fresh username via a real `/register` sent
    by the spike client through the real proxy; reconnected as that username bound to a second local
    address (`127.0.0.2` — Windows treats all of `127.0.0.0/8` as loopback, so this simulates a second
    source IP without a second machine) with a wrong password; the proxy correctly ran the
    grace-authentication check *only* on the real first Play-state message (no more spurious
    Configuration-phase misfire), correctly failed it, and sent a real Play-state Disconnect kick that
    the spike client — acting as a real protocol-correct client, not this project's own reader — parsed
    successfully as valid NBT with the exact configured message text. This is also the first live
    confirmation that `TrySendPlayDisconnectAsync`'s NBT/compressed-frame kick format is correct
    against a real client, which was a separately-flagged, previously-unverified risk.
  - **Also confirmed live**: normal login → CaYaDev-Check registration → Play-state traffic relay,
    end-to-end through the real compiled service.
  - **Still not exercised**: an actual graphical Minecraft client (this environment has none) — the
    spike client is a real, protocol-correct implementation, not a mock, but it is still this
    project's own code. A real launcher/client run remains a reasonable follow-up if anyone wants
    additional confidence before relying on this in production.
- **Stage 4a (the verifier) — done, deliberately unwired. Stage 4b (the login splice) — not started.**
  Per an advisor consultation before starting: build Stage 4 in two commits, a pure-logic verifier
  first (no sockets, fully unit-testable), then the login splice separately, since the splice is real
  new production risk (a framing bug there breaks connections, not just kicks) that deserves its own
  live-verification pass, the same way the Stage 3 bug above was only found by one.
  - **Empirical field-layout verification, not a guess from the wiki.** Earlier research in this
    project (minecraft.wiki, protocol 776 — one version ahead of this project's verified 774) gave a
    *plausible* Encryption Request/Response shape, but this project has already been burned once by
    trusting a wiki's packet layout over the actual tested version (the Stage 3 chat/command ID
    mismatch). So before writing any Stage 4a code: `test-server/server.properties` was flipped to
    `online-mode=true` temporarily, and `tools/MinecraftFirewall.ProtocolSpike` got a new
    `encryption-probe` mode that connects straight to the real backend, dumps the real Encryption
    Request's raw bytes and field-by-field decode, then mechanically completes the crypto handshake
    (generates a random shared secret, RSA-PKCS1-encrypts it and the verify token with the server's
    own public key, sends a real Encryption Response) — not to actually authenticate as a real
    Microsoft account (there isn't one behind the test username), but because Paper's own reaction is
    the diagnostic signal either way: a clean `Failed to verify username!` in Paper's log means Paper
    decrypted successfully and only failed at the Mojang session-server call (i.e. the field layout is
    right); a decrypt/framing error instead would mean it's wrong. Live result against a real Paper
    1.21.11 (protocol 774) server: **`Failed to verify username!` / `Username 'SpikeTestUser' tried to
    join with an invalid session`** — confirming both directions of the field layout. Confirmed
    concretely: Server ID is an empty string; Public Key is a 162-byte X.509 SubjectPublicKeyInfo DER
    (i.e. a 1024-bit RSA key, matching real Notchian/Paper server behavior); Verify Token is 4 bytes;
    a trailing Boolean `Should Authenticate` field is present and was `true`; the Encryption Response
    is exactly two Prefixed-Array-of-Byte fields (no message-signing fields — that mechanism was
    removed in 1.19.3, confirmed still absent here) and RSA-PKCS1v1.5 padding is what Paper expects
    (OAEP would have made decryption fail, which it didn't). `server.properties` was reverted to
    `online-mode=false` immediately afterward.
  - **The verifier itself** (`Identity/Premium/`, all pure logic, no sockets, 28 new unit tests):
    `RsaServerKeyPair` (one 1024-bit keypair generated once, matching Paper's own "Generating keypair"
    happening once at startup, not per-connection), `EncryptionRequestPacket`/`EncryptionResponsePacket`
    (builder/parser for the field layout confirmed above), `PremiumSessionHash` (the Mojang session
    hash: SHA-1 over serverId+sharedSecret+publicKeyDer, formatted as Java's
    `new BigInteger(digest).toString(16)` — signed, two's-complement, no leading-zero padding, which
    can produce a leading `-`; **this is the one place in Stage 4a where a bug would be silently
    invisible to a round-trip test**, since a round-trip of broken sign/endianness handling against
    itself still passes — verified instead against the three published known-answer vectors for this
    exact function, `SHA1("Notch"/"jeb_"/"simon")`), `IPremiumSessionClient`/`MojangSessionClient` (the
    real `hasJoined` HTTP call, `FakeHttpMessageHandler`-tested), and `PremiumVerifier` (orchestrates:
    RSA-decrypt both fields, constant-time verify-token comparison, compute the session hash, call
    `hasJoined`, return success + the real UUID or a typed failure reason).
  - **Deliberately fail-*closed*, the opposite of every other network-dependent signal in this
    project.** `IpInfoClient` and the X4BNet VPN lists both fail *open* (an outage never blocks a
    legitimate player) because they're heuristic secondary signals. `MojangSessionClient` fails
    *closed* — a timeout, a non-success status, or a malformed body all come back as `NotJoined`,
    never a fallback to "allow, we couldn't check" — because this is the strong gate an admin
    explicitly declared for this exact username; falling open here would silently defeat the entire
    point of `PremiumRequired`. Documented directly in `IPremiumSessionClient`'s doc comment specifically
    so this asymmetry isn't "fixed" into consistency with the other clients by a future change.
  - **Deliberately not wired into `IdentityGate`/`ClientConnection` yet.** `IdentityGate`'s existing
    fail-closed `Deny` for `PremiumRequired` names (see Stage 3 above) is untouched — a `PremiumRequired`
    name is still denied outright for everyone, exactly as before. Wiring the verifier in requires the
    login splice (Stage 4b): the proxy has to actually own the client's encrypted Login sequence to
    ever get an Encryption Response to hand this verifier, which doesn't exist yet. Leaving the
    verifier connected to nothing rather than half-wired avoids a state where a `PremiumRequired`
    name silently behaves differently depending on how far a refactor got.
- **Admin CLI / named pipe — done (Task #18).** `Admin/AdminProtocol.cs` (a tiny newline-delimited-JSON
  request/response contract), `Admin/AdminCommandHandler.cs` (the actual command logic, unit-testable
  without a real pipe), `Admin/AdminPipeServer.cs` (the transport — a `BackgroundService` hosting a
  `NamedPipeServerStream`), and `MinecraftFirewall.Admin`'s `Program.cs` (the console client). Commands:
  `whitelist-add-me <profile> <username> <ip-or-cidr>`, `list-bans`, `unban <ip>`,
  `require-premium <profile> <username>`, `reload`, `list-profiles`.
  - **`whitelist-add-me` doesn't actually detect "your" IP** — corrected during design: the pipe is
    loopback-only (see the security note below), so the only address a connection to it could ever
    reveal is 127.0.0.1, useless for allowlisting a remote admin's real IP. It takes an explicit
    IP/CIDR argument instead of guessing one, with the reasoning documented directly in the command's
    own usage/help text so it isn't a silent surprise.
  - **Security**: the pipe is created via `NamedPipeServerStreamAcl.Create` with a `PipeSecurity`
    granting exactly one explicit Allow ACE (BuiltinAdministratorsSid, ReadWrite) — a `NamedPipeServerStream`
    created without an explicit ACL gets Windows' default DACL, which is reachable by any local user's
    process, not just Administrators, and would hand `unban`/`require-premium` to anyone with a session
    on the box. Verified two ways: `AdminAclTests` inspects the constructed `PipeSecurity` directly
    (exactly one rule, for the Administrators SID, nothing for Everyone/Authenticated Users); separately,
    this build environment's shell was confirmed non-elevated (`WindowsPrincipal.IsInRole(Administrator)
    == false`), so `AdminPipeServerIntegrationTests.AdministratorsOnlyAcl_NonElevatedProcess_IsRefusedConnection`
    is a *real*, not simulated, non-admin-process rejection against the real ACL. What was **not**
    verified: a separate OS process (as opposed to this same non-elevated test process) connecting
    against a *running* service instance — recommended as a manual check before relying on this in
    production (see README's honesty note on this).
  - **Persistence**: `whitelist-add-me` and `require-premium` mutate `IdentityStore` in-memory only —
    there is no on-disk persistence for identity records. Both commands' own response text says this
    explicitly (not just the CLI's `--help`), since a silent "it forgot after reboot" would be a
    security failure, not a UX wrinkle. `ProtectedUsernameConfig` gained a `RequirePremium` field
    (`ServerProfileFactory` now sets `IdentityEntry.PremiumRequired` from it) specifically so the
    persistent equivalent of `require-premium` actually exists in config, making the CLI's "add this to
    appsettings.json to persist it" guidance a true, actionable statement rather than an empty promise.
  - **`reload`'s scope is deliberately narrow** — it re-triggers `IpListRefreshService.RefreshNowAsync`
    (a new public method extracted from the existing timer loop) to refresh the X4BNet VPN/datacenter
    CIDR lists on demand. It does **not** reload `ServerProfiles`, ports, protected usernames, or any
    other config section — those still require a service restart. Named `reload` (matching the
    originally-planned command name) but documented precisely everywhere it appears so it isn't
    mistaken for a full config reload.
  - **Found, not fixed (flagged out of scope for this task)**: `FirewallBanService._activeBans` is
    in-memory only, with no persistence of its own — if the service restarts while an IP has an active
    OS-level Windows Firewall block rule, the app loses track of that ban's expiry entirely, so
    `CleanupExpired()` can never call `Unban()` for it again. The OS firewall rule keeps blocking the IP
    (no security regression), but it now never gets cleaned up on its own — a real, pre-existing latent
    bug from Stage 1, unrelated to the Admin CLI itself, noted here rather than fixed inline to avoid
    scope creep on this change.
- **Allowed-domains restriction — done.** Per-profile `AllowedHostnames` allowlist (`Policy/HostnameMatcher.cs`
  + `PolicyEngine.EvaluateHostname`), checked right after the Handshake is parsed, before the status/login
  branch. Supports exact hostnames and `*.example.com` wildcards; a mismatch on a login attempt sends a
  kick message and registers a strike (not a fast-track ban — a stale server-list entry is a
  plausible legitimate cause). Empty list (default) is fully backward-compatible: no restriction. See the
  requirement-7 honesty note below — **this is not a cryptographic boundary**, only the literal
  IP-firewall-rule setup described there makes it one.
- **Configurable player-facing messages — done.** All 5 kick/disconnect strings (generic policy deny,
  unsupported-client-version, hostname-not-allowed, dangerous-command-blocked, grace-auth-failed) moved
  out of hardcoded literals into `Messages/MessagesOptions.cs`, bound from a `Messages` section in
  `appsettings.json` via the same `IOptions<T>` pattern as every other section. Code defaults are
  English; the shipped `appsettings.json` carries a commented-out Turkish block as a ready-to-use
  alternative (the project's earlier hardcoded strings were Turkish — that text didn't disappear, it
  moved to being an opt-in example instead of the compiled-in default). `AppSettingsJsonBindingTests`
  loads the real shipped file through the actual config pipeline (not a fixture) specifically to catch
  a JSON/comment syntax error in that file, since nothing else ever parses it.
- **Real-time ipinfo.io secondary VPN signal — done (Task #19).** `IpIntel/IpInfoClient.cs` (behind
  `IIpInfoClient` so `PolicyEngine`'s tests never make a real HTTP call — see `FakeIpInfoClient`),
  per-IP TTL-cached (default 6h — without this a login flood becomes an outbound-request flood against
  ipinfo's rate limit), fails open on any error/timeout/missing token. `PolicyEngine.EvaluateLogin`
  became `async Task<PolicyDecision>` to support this (was synchronous through Stage 3). **Corrected a
  wrong premise from earlier in this project**: a live unauthenticated probe
  (`curl https://api.ipinfo.io/lite/8.8.8.8`) returns HTTP 403 "Unknown token" — ipinfo's free Lite
  tier requires a signup token, it is not keyless as originally assumed when ipinfo was chosen. Ships
  disabled by default (empty `Token` in `appsettings.json` → zero outbound requests); the user must
  sign up free and paste a token in to turn it on. Also corrected mid-build: the Lite API returns ASN
  + organization/domain name, not a dedicated "is this a VPN" flag (that's a separate paid ipinfo
  product) — implemented as a configurable hosting-provider keyword match against the returned org
  name, explicitly documented as a heuristic, feeding the same `VpnPolicy` decision as the X4BNet list
  rather than being a new independent gate. Scope defaults to protected-usernames-only, configurable to
  every connection via `ApplyToAllConnections`, per the user's original answer to this question — and
  the primary X4BNet list is checked first, skipping the ipinfo call entirely when it already decided
  the outcome.

**Next session should start with:** Stage 4b — the login splice. Stage 4a (the verifier — RSA keypair,
Encryption Request/Response, shared-secret decrypt + verify-token check, session hash, `hasJoined` call)
is done and unit-tested, its field layout empirically confirmed live against a real Paper 1.21.11 server
(see the Stage 4a entry above), but it is not wired into anything yet — `IdentityGate` still denies every
`PremiumRequired` name outright. Stage 4b is the largest single remaining piece of work in this project:
the proxy has to actually terminate the client's Login sequence itself (send the real Encryption Request,
receive the real Encryption Response, hand it to `PremiumVerifier`), then open a *separate*, plaintext,
offline-mode login to the backend as a normal client would — from that point the client side of the
connection is AES-CFB8 encrypted while the backend side stays plaintext, so `PlayStateInspector` needs a
decrypt/encrypt shim for these specific connections, not just frame reads. This is real new risk (a
framing bug here breaks connections outright, not just kicks — unlike Stage 4a, which fails safely by
construction), so plan a second live end-to-end pass before calling it done, the same way the Stage 3
kick path was verified live this session. A real premium Microsoft/Mojang account is needed for a true
positive-path live test; without one, the negative path (a cracked client denied) can still be verified
the same way Stage 4a's field layout was — see the `encryption-probe` mode's approach.

## Context

The user runs (or plans to run) one or more Minecraft Java Edition servers, on the same Windows machine, with `online-mode=false` and no protection plugins. In that configuration Minecraft never authenticates usernames against Mojang, so anyone can connect claiming to be an admin/OP name, and bots can mass-probe usernames. The user wants this solved **outside Minecraft** — no plugin/mod — as a standalone Windows application, with real-time blocking of proxy/VPN-based connection attempts.

Requirements gathered across this planning session, in the order they came up:
1. Java Edition, C#/.NET, free third-party IP intelligence, architecture delegated to me → **reverse proxy**.
2. Must front **multiple Minecraft servers on the same machine**, each its own port, from one running instance.
3. Static per-username IP allowlisting isn't enough — the same real player legitimately connects from different IPs. Needed something smarter than IP-matching alone.
4. If possible, commands executed by players after joining should be observable/audited.
5. An additional, branded, lightweight subsystem — **"CaYaDev-Check"** — where players can register/log in, get remembered by IP so they aren't re-prompted, alongside everything above.
6. **The strongest request**: if a player's *first* login under a given username is done from a genuine (premium/Microsoft-licensed) Minecraft account, that username should be permanently theirs — nobody else, cracked or otherwise, should ever be able to use that name again, even though the server itself stays `online-mode=false`.
7. **Allowed-domains restriction** (added after Stage 3 shipped): only certain domain names should be able to reach the server at all — a connection using the raw server IP directly should be blocked, even if the attacker knows it, and multiple allowed domains must be supported.
8. **Configurable, English-by-default messages** (added after requirement 7): every kick/disconnect message the app can send must be editable without touching code, and an English version must exist and be the default (the app's messages were originally hardcoded in Turkish).

**Architecture: reverse proxy**, not raw packet-level filtering (WinDivert) — Minecraft's VarInt-length-prefixed TCP stream is far simpler to parse via `NetworkStream` than via reassembled raw IP packets, and this is the architecture real Minecraft firewall/anti-DDoS products use. One Windows process hosts N listeners (one per configured server profile) and shares IP-intel and firewall-ban infrastructure across all of them, so a block on one server applies machine-wide.

**Requirement 6 needed real correction during design, recorded here so it isn't silently re-proposed later:** the first instinct was to auto-probe every *brand-new* username with a Mojang encryption challenge the first time it's ever seen, and lock the name to whoever passes. That's backwards — it means an attacker who connects with a cracked client to an unclaimed name *first* gets the name marked "not premium, offline-eligible" forever, which is the exact attack this feature exists to prevent. The correct version, used below: **premium-required is something the admin declares** (per username, via config or a CLI command), not something discovered by probing traffic. A declared name always gets challenged and a failure is always a denial — no fallback, no race, no one-time hiccup imposed on ordinary cracked players who were never at risk in the first place.

**Compression is the other thing that had to be corrected, and it now gates two separate features.** `online-mode=false` disables encryption (no AES) but does **not** disable packet compression. Once the backend sends `Set Compression` during login (default threshold 256), every later frame becomes `[length][dataLength][zlib payload]` instead of `[length][payload]`. Any code that reads Play-state packets — command auditing *and* the CaYaDev-Check chat-based register/login gate both need this — will silently read garbage the moment compression turns on unless the frame reader accounts for it. This must be verified empirically before either feature is built (see Stage 2).

**Requirement 7 also needed an honesty correction, recorded here so the limitation isn't lost:** the Handshake packet's Server Address field — the only place a "which domain did they connect through" signal exists in the Minecraft protocol — is client-supplied and not cryptographically bound to how the TCP connection was actually made. A stock client pointed at a raw IP (Direct Connect, or the vast majority of scanning bots) sends that IP as the Server Address, so `Policy/HostnameMatcher.cs` correctly rejects it. But a custom/scripted client can simply put an allowed domain string in that field while still dialing the IP directly, and this check alone does not catch that. It's genuine defense-in-depth (stops IP-scanners and casual direct-IP joins), not a hard guarantee. Turning it into an actual hard guarantee — matching the literal "even if the IP is known, only the allowed domain works" ask — requires an OS-level control the Handshake field can't fake: a TCP-fronting proxy (Cloudflare Spectrum, TCPShield, etc.) in front, the allowed domain(s) pointed at it, and a Windows Firewall inbound rule on the public port that only permits that fronting proxy's IP ranges. That firewall step is a manual, user-owned setup decision (see "Manual steps" below), not something built into the app — the app's part is the hostname check, documented plainly as defense-in-depth in both this doc and the README.

**Honesty notes to keep visible, not bury:**
- This is defense-in-depth for a server that must stay `online-mode=false`, not a replacement for Mojang authentication.
- Premium-lock only protects a name from the moment the admin declares it and the real owner successfully claims it. It cannot retroactively un-claim a name an attacker already grabbed in plain offline mode before that point — same first-come dynamic as Minecraft usernames generally.
- For a premium-required connection, the *backend* server (still offline-mode) computes its own `OfflinePlayer:<name>` UUID and has no idea the proxy just verified a real Microsoft account — the real UUID does not reach the backend's world data. The proxy's verification is authoritative for *access control*, not for what the backend stores.
- `AllowedHostnames` (per-profile, empty = unrestricted) is not a cryptographic boundary — see the requirement-7 note above. It also has no built-in loopback exemption: an admin testing from the same machine must add `localhost` to the list themselves, or they'll lock themselves out and reasonably assume it's a bug.

## Delivery is staged, not one flat build

The scope above is four substantial subsystems on top of a proxy core, and none of it exists yet. Building it as one undifferentiated pass risks nothing reaching a testable state. Order matters because later stages depend on earlier ones being verified, not just written:

- **Stage 1 — Core proxy.** Multi-server reverse proxy, Handshake/Login-Start parsing, VPN/datacenter IP-intel, per-profile rate limiting, Windows Firewall ban enforcement, never-ban list, structured logging. Fully testable and useful on its own (static IP-allowlist protection + bot/VPN mitigation), before any Play-state work begins.
- **Stage 2 — Protocol spikes (small, empirical, blocking).** Two things must be verified against a real server/client before Stage 3 is designed further, not assumed: (a) exact compression frame format and how `Set Compression` behaves with a real Paper/vanilla backend at the default threshold; (b) whether a vanilla client tolerates the proxy withholding Play-state traffic while waiting for a chat response, or whether login must instead be rejected outright with a retry-with-CLI message. Both determine the *shape* of Stage 3, so they come first.
- **Stage 3 — Play-state features.** Command auditing + dangerous-command detection, and the CaYaDev-Check password gate (self-registration and admin-configured names alike), built on whichever frame-reader/holding strategy Stage 2 validated.
- **Stage 4 — Premium/Mojang verification.** Admin-declared premium-required names: real encryption handshake + `hasJoined` check, login-splice to the backend, UUID pinning. Highest complexity, highest external-dependency risk (Mojang's session API), built last and independently toggleable.

## Stage 1 — Core proxy

1. Each Minecraft server on the box binds only to `127.0.0.1` on its own internal port. One proxy instance binds **one public port per server profile**, config-driven — adding a server later is an `appsettings.json` edit, not a code change.
2. Proxy parses the Handshake packet (`next_state`, client protocol version — the latter needed by Stage 3/4 for feature gating) and, only if `next_state == 2` (login), the Login Start username. Status/ping (`next_state == 1`) passes through untouched and is separately rate-limited (cheapest DoS surface).
3. Policy decision combines: identity-store lookup (Stage 1 ships with static IP/CIDR allowlist only — passwords and premium-lock arrive in Stages 3–4 on the *same* store, see below), VPN/datacenter IP flag (severity configurable per profile, default "block only for identity-protected usernames, log-only for everyone else"), and a per-profile-per-IP sliding-window rate limit.
4. On allow: bytes already read are replayed verbatim to the backend, then the connection becomes a byte pump (Stage 1 has no reason to keep parsing — that starts in Stage 3).
5. On deny: connection is dropped or sent a disconnect packet before it reaches the real server.
6. Repeat offenders get a real Windows Firewall block rule via `INetFwPolicy2` COM (never shelling out to `netsh` with interpolated input — usernames arrive from the network), TTL + cleanup, applied **globally across every profile**.
7. Hardcoded never-ban list (loopback, RFC1918, configured admin allowlist) can never be auto-banned.
8. IP intelligence: periodically-downloaded plain-CIDR lists, not per-connection API calls. Verified source: **X4BNet/lists_vpn** (MIT licensed, GitHub-Actions-updated) — `output/vpn/ipv4.txt`, `output/datacenter/ipv4.txt`. Downloaded on startup + daily timer, disk-cached, fails open (keeps last good list, logs a warning) on refresh failure. No usable free IPv6 CIDR source exists — IPv6 for identity-protected usernames requires an exact allowlist/learned-IP match; no VPN-flag signal is available for IPv6.
9. Structured logging (file + console), every line tagged with server profile; optional Discord webhook alerts (config-gated, off by default) for denials, learned-IP events (Stage 3+), and ban escalations.

### The identity store — one store, one gate, built once and extended in place

Every later stage adds *fields* to the same per-username record and *branches* in the same gate function — not a parallel mechanism. Designing it this way from Stage 1 avoids the two-parallel-auth-paths drift that would otherwise happen between "protected admin names" and "self-registered player names."

```
IdentityEntry {
  Username
  StaticAllowlist: [IP/CIDR]        // Stage 1
  LearnedIps: [{ip, expiresAt}]     // Stage 3 (populated by successful password/passphrase checks)
  PasswordHash: string?             // Stage 3 (self-registration or admin-set)
  PremiumRequired: bool             // Stage 4 (admin-declared only, never auto-set)
  PinnedUuid: Guid?                 // Stage 4 (recorded on first successful premium verification)
}
```

Gate precedence, fixed now so it isn't improvised later: **`PremiumRequired` always wins.** If set, the connection must pass the Stage 4 encryption+`hasJoined` challenge (matching `PinnedUuid` once set) — the password/IP-allowlist fields are not consulted at all for that name, so a weaker mechanism can never bypass the strong one. If not set, fall through to IP allowlist / learned IP / password gate as configured. A name with no `IdentityEntry` at all behaves exactly like vanilla offline mode — no gate, immediate join — which is what keeps this "low resource" for the common case, per the user's ask: gating logic only runs for names someone has actually opted into protecting.

**Explicit guarantee for the genuine owner of a `PremiumRequired` name:** the real Microsoft/Mojang account is never shown a CaYaDev-Check password prompt, from any IP, ever — the two paths don't intersect. The moment `PremiumRequired` is set, the password/IP-allowlist fields stop being consulted entirely (see above), so there is no code path left that could ask the real owner for a password. Their own Minecraft launcher answers the cryptographic challenge automatically and silently, from whatever network they happen to be on — nothing to type, nothing to remember. The only two outcomes for a `PremiumRequired` name are: the crypto+`hasJoined` check passes (real account, join proceeds immediately, no prompt) or it fails (anyone else, denied outright, also no prompt — never a fallback into asking for a password instead).

Entries are created three ways: (a) admin config (`ServerProfiles[].ProtectedUsernames`, can set allowlist and/or `PremiumRequired`), (b) self-service `/register <password>` in chat (Stage 3, creates a plain password entry, no admin involvement), (c) an admin CLI command to declare `PremiumRequired` after the fact.

## Stage 2 — Protocol spikes (done)

**Compression, fully confirmed empirically.** A real local Paper 1.21.11 server (protocol 774, default
`network-compression-threshold=256`, `online-mode=false`) was stood up and driven with a hand-built
client (`tools/MinecraftFirewall.ProtocolSpike`) all the way from Handshake through Login →
Configuration → Play, over a real socket. Result: exactly the frame format Stage 1 assumed —
`[frameLength][dataLength][payload]` post-compression, `dataLength=0` meaning "sent uncompressed,"
`dataLength>0` meaning the rest is zlib/deflate compressed to that length. Confirmed over 3,370 real
frames (full world join, chunk data, registries, keep-alives) with zero parse errors. `Set Compression`
is packet `0x03` (Login, clientbound), threshold value follows as a single VarInt — also exactly as
assumed.

Packet IDs were **not** taken from a wiki — they were pulled straight from Mojang's own data generator
(`java -jar paper.jar --reports` → `generated/reports/packets.json`, copied into
`docs/protocol/packets-774.json`) run against the exact server build tested, and cross-checked against
every packet actually observed on the wire during the live spike. Both sources agreed on every ID. This
also caught a real version-drift case: a wiki page for protocol 776 (two versions newer) listed
different Play-state serverbound chat/command IDs than protocol 774 actually uses — see
`docs/protocol/README.md` for the specifics. This is the concrete justification for why
`ProtocolVersionRegistry` (Stage 3) hardcodes IDs per-version from generated reports, never by
extrapolating from a nearby version.

**Held Play-state traffic ("does the client tolerate a delayed join"), not independently verified —
defaulting to the documented safe fallback.** This question is about a real graphical Minecraft client's
tolerance, not server wire behavior, and no such client was available to test against in this
environment (the spike client is a headless protocol driver, not the real game). Per the plan's own
fallback design, **Stage 3's CaYaDev-Check gate uses the reject-and-retry strategy unconditionally**: an
unrecognized IP for a registered name gets denied outright with a disconnect message pointing at
`/register`/`/login` on retry or the admin CLI — the connection is never held open mid-protocol waiting
for a chat response. This is simpler to build and correctness-verify than the holding approach, and
carries no unverified assumption about client behavior. If real-client testing later shows holding is
tolerated, it can be added as an opt-in enhancement — it is not required for the gate to work.

## Stage 3 — Play-state features

- **Frame reader** (`Protocol/FrameReader.cs`): outer VarInt length frame always parsed (cheap, version-stable); payload only decoded for the specific packet IDs being inspected (chat/command, clientbound `Set Compression`, clientbound `Disconnect`); everything else forwarded byte-for-byte, never re-serialized. Compression-aware per Stage 2's findings.
- **`Protocol/ProtocolVersionRegistry.cs`**: table of MC protocol versions → verified packet IDs, sourced from the protocol reference for the specific versions tested during implementation (never guessed from memory). Unknown client version → Play-state inspection is skipped for that connection (logged once, not per-packet), connection still proxies at the frame level. The fallback on an unrecognized version is always "stop inspecting," never "guess an ID."
- **Command auditing**: decode chat/command packets, log (profile, username, IP, timestamp). Match against a configurable, normalized dangerous-command list (strip leading `/`, strip `minecraft:`-style namespace, lowercase, basic aliases — documented as heuristic defense-in-depth, not a guarantee). A match always alerts; if the sender isn't identity-verified (passed the gate below or premium-locked), the proxy also disconnects them and fast-tracks firewall-ban escalation.
- **CaYaDev-Check password gate**, using the Stage 2 result:
  - Unregistered name → normal join, no gate (matches vanilla behavior; a player can `/register <password>` any time after joining to opt in).
  - Registered name (password set, no `PremiumRequired`), IP matches static allowlist or a non-expired learned IP → immediate join, no prompt — this is the "same IP doesn't get asked again" behavior the user asked for.
  - Registered name, unrecognized IP → password challenge via chat (`/login <password>`) using whichever strategy Stage 2 validated (held Play-state traffic, or reject-and-retry). Correct password → join, learn this IP (TTL-capped, e.g. 30 days, max N per username, oldest-expiring evicted first), send an alert ("new IP trusted for `<username>`") so a stolen password shows up as a visible event, not silently. Wrong/timeout → disconnect, fast-track ban escalation (far fewer strikes than the generic rate limiter).
  - Password-related chat messages (`/register`, `/login`) are intercepted, **never forwarded to the backend**, and redacted at the point of interception in every log/alert sink — never logged in plaintext even transiently.
- The manual local-only admin CLI (`whitelist-add-me`, etc., over a loopback-only named pipe) remains as an admin override independent of the chat-based gate.

## Stage 4 — Premium/Mojang verification (admin-declared, highest complexity)

- Admin marks a username `PremiumRequired` via config or CLI — never set automatically by observing traffic.
- On every connection attempt for such a name: proxy sends a real `Encryption Request` (RSA keypair generated at startup, server-id string, verify token), waits for `Encryption Response`, decrypts the shared secret, verifies the token, computes the session hash, and calls Mojang's `hasJoined` session endpoint. Success → identity confirmed; if `PinnedUuid` is unset, record the returned UUID as the permanent pin; if set, the returned UUID must match it. Failure (bad response, timeout, `hasJoined` rejection, or UUID mismatch) → deny, no fallback to offline mode for that name, ever.
- **This is not a byte-relay anymore for these connections — it's a login splice**, the largest single piece of work in the feature: the proxy terminates the *client's* Login sequence itself (it sent Encryption Request, so it owns Login Success and the UUID in it), and separately opens a fresh, unencrypted, offline-mode login to the backend as a normal client would. From that point, the client side of the connection is AES-CFB8 encrypted (proxy↔client) while the backend side stays plaintext (proxy↔backend) — the proxy is a translating relay between the two, which also means Stage 3's Play-state inspector needs a decrypt/encrypt shim for these specific connections, not just frame reads.
- State plainly in the README (this is the UUID-mismatch honesty note from above): the backend never learns the real Microsoft UUID; its own player data still keys off its own offline UUID for that name.
- Feature-flagged independently (`Features.PremiumVerification.Enabled`) so it can be disabled without affecting Stages 1–3 if Mojang's session API changes or causes issues.

## Explicitly out of scope / explicitly rejected

- **Auto-probing new usernames for premium status** — rejected during design, see the correction note above; kept here so it doesn't get silently re-proposed.
- BungeeCord-style IP forwarding to the backend (v2 candidate once Stage 1's backend-unreachability guarantee is proven in practice).
- Bedrock Edition / RakNet-UDP support.
- Full IPv6 VPN/proxy intelligence (no good free source found).
- Impossible-travel / geo-velocity heuristics — needs an unsourced geo database, noisy on mobile/CGNAT, can only ever produce a log line, and the password/premium gates already cover the case it would flag.
- A GUI dashboard (service + CLI + log files + optional Discord alerts).

## Project structure (`MinecraftFirewall.sln`)

- **`MinecraftFirewall.Proxy`** (Windows Service, Generic Host, `UseWindowsService()`)
  - `Program.cs` — host wiring, DI, starts one `ProxyListener` per configured `ServerProfile`
  - `Protocol/VarInt.cs`, `Protocol/HandshakeReader.cs` — stable, always parsed
  - `Protocol/FrameReader.cs`, `Protocol/ProtocolVersionRegistry.cs`, `Protocol/PlayStateInspector.cs` — Stage 3
  - `Identity/IdentityStore.cs` — the single record type and store described above, per profile, reloadable, persisted across restarts
  - `Identity/IdentityGate.cs` — the one gate function implementing the precedence rule (premium > password/IP > none)
  - `Identity/PremiumVerifier.cs`, `Identity/LoginSplice.cs`, `Identity/Aes Cfb8Stream.cs` — Stage 4
  - `ServerProfile.cs` — name, public/backend port, its identity entries, per-profile policy overrides
  - `ProxyListener.cs`, `ClientConnection.cs` — accept loop and per-connection orchestration; short pre-login read deadline (~2s) against slowloris connections
  - `Policy/PolicyEngine.cs` — combines identity result, VPN severity, rate limit, never-ban check
  - `IpIntel/IpRangeTable.cs`, `IpIntel/IpListRefreshService.cs` — shared across all profiles
  - `RateLimiting/ConnectionRateLimiter.cs` — per-`(profile, IP)`, separate thresholds for ping vs login
  - `Enforcement/FirewallBanService.cs` — `INetFwPolicy2` COM wrapper, TTL + cleanup, never-ban check, shared/global, exposes a fast-track (fewer strikes) path for password/dangerous-command triggers
  - `Admin/AdminPipeServer.cs` — loopback-only named pipe for the CLI
  - `Logging/`, `Alerts/DiscordAlertSender.cs`
  - `appsettings.json` — `ServerProfiles[]`, VPN/rate-limit defaults, ban TTL/fast-track strikes, dangerous-command list, IP list source URLs, fail-open toggle, Discord webhook, `Features.PremiumVerification.Enabled`
- **`MinecraftFirewall.Admin`** — CLI (`whitelist-add-me`, `require-premium <profile> <username>`, `list-bans`, `unban`, `reload`, `list-profiles`)
- **`MinecraftFirewall.Tests`** — xUnit, organized by stage:
  - Stage 1: VarInt/Handshake parsing, IP range lookup, policy-engine decision table, rate limiter window, never-ban list, two-profile isolation + shared ban integration test
  - Stage 3: frame reader compressed/uncompressed/threshold-boundary cases, dangerous-command normalization, identity-gate precedence table (unregistered→open, registered+known-IP→open, registered+unknown-IP+correct→learn+alert, wrong→deny+fast-track), password/passphrase redaction (assert the raw secret never appears in any log sink)
  - Stage 4: premium-gate precedence over password/IP, UUID pin mismatch → deny, `hasJoined` failure → deny with no offline fallback

## Manual steps that stay with the user (not auto-executed by me)

- Editing `server.properties` per server (`server-ip=127.0.0.1`, internal port, `network-compression-threshold` decision per Stage 2's findings)
- Per-server verification: no inbound Windows Firewall rule for the backend port, no router port-forward, confirmed failure connecting to the backend port from a non-loopback address
- Installing the compiled app as a Windows Service and granting it firewall-modification rights
- Live Windows Firewall rule creation happens only when the running service (under the user's control) decides to ban an IP — not something I execute during this build/planning session
- If the user wants `AllowedHostnames` to be an actual hard guarantee rather than defense-in-depth: pointing the allowed domain(s)' DNS at a TCP-fronting proxy, and adding a Windows Firewall inbound rule on the public port restricted to that proxy's published IP ranges — a deliberate, user-owned network decision, not something the app configures itself

## Verification plan

- `dotnet build` / `dotnet test` after each stage — every automated test above runs without a real Minecraft server, admin rights, or touching the real Windows Firewall
- Manual end-to-end, staged: Stage 1 first against one real server (normal login, protected-name-from-wrong-IP denial, VPN-flagged IP denial, status ping still works), then a second profile/server to confirm isolation + shared bans. Stage 3 adds command logging/dangerous-command and the register/login chat flow against the compression settings Stage 2 determined. Stage 4 adds a real premium account connecting to a `PremiumRequired` name, and a cracked-client attempt against the same name confirmed denied.
