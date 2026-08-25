# MinecraftFirewall

Windows reverse-proxy firewall for Minecraft Java Edition servers running `online-mode=false` with no
protection plugins. It sits in front of the real server (which binds to `127.0.0.1` only) and decides,
per connection, whether to forward it — without any plugin/mod inside Minecraft itself.

## Status: all 4 stages complete (231 automated tests passing)

This is an in-progress build. See [`docs/plan.md`](docs/plan.md) for the complete staged design doc and
current status. What's implemented right now:

- **Multi-server reverse proxy** — one process fronts multiple Minecraft servers on the same machine,
  each with its own public port, config-driven (`ServerProfiles` in `appsettings.json`).
- **Protected usernames** — a static IP/CIDR allowlist per username, per server profile, for
  admin-declared names (strict: unrecognized IP is a hard deny, no exceptions).
- **CaYaDev-Check** — self-service `/register <password>` / `/login <password>` for any player, PBKDF2
  hashed, with TTL/cap-bounded IP learning so a returning player from a known IP isn't re-prompted. An
  unrecognized IP gets one grace-authentication attempt (first Play-state message must be a correct
  `/login`) before being kicked and fast-tracked toward a ban.
- **Command auditing** — Play-state chat/command packets are decoded (packet IDs sourced from Mojang's
  own generated data report for the exact tested version, never guessed), logged, and checked against a
  configurable dangerous-command list; a match from a non-trusted identity kicks and fast-track bans.
- **VPN/datacenter IP detection** — free, MIT-licensed CIDR lists from
  [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn), refreshed daily, cached to disk, fails open
  if the source is unreachable.
- **Real-time secondary VPN/hosting signal (ipinfo.io)** — optional, off by default (needs a free
  ipinfo.io token — verified empirically that one is required even for their "Lite" tier, it's not
  keyless). Per-IP cached, fails open, scoped to protected usernames by default or every connection if
  configured. Matches the returned ASN/organization name against a keyword list — this is a heuristic,
  not a dedicated VPN-detection flag (that's a separate paid ipinfo product).
- **Per-profile rate limiting** — sliding window, separate thresholds for status pings vs. login attempts.
- **Allowed-domains restriction** — an optional per-profile allowlist of hostnames (exact or
  `*.example.com` wildcard); a connection whose Handshake Server Address doesn't match one of them is
  denied before it ever reaches the backend, even if the attacker knows the server's raw IP. **Read the
  honesty note below before relying on this** — it stops IP-scanning bots and casual direct-IP joins,
  but a client that deliberately fakes this field is not stopped by this check alone.
- **Windows Firewall bans** — repeat offenders get a real, machine-wide block rule via the
  `INetFwPolicy2` COM API (never `netsh` with interpolated input), with a TTL, a hardcoded never-ban list
  (loopback/RFC1918/admin allowlist), and an in-process fallback if the service isn't running elevated.
- **Configurable, English-by-default kick messages** — every player-facing disconnect string lives in
  one `Messages` section of `appsettings.json` (English defaults, nothing hardcoded in the binary); a
  ready-to-uncomment Turkish example ships alongside it.
- **Admin CLI** (`MinecraftFirewall.Admin`) — `whitelist-add-me`, `list-bans`, `unban`, `require-premium`,
  `reload`, `list-profiles`, talking to the running service over a named pipe that only Administrators
  can connect to (must be run elevated). Every mutating command is in-memory only and says so in its own
  output — it does not survive a service restart unless you also add it to `appsettings.json`.

- **Premium account lock (the original strongest request)** — mark a username `"RequirePremium": true`
  and it is permanently bound to its genuine Microsoft/Mojang account, even though the backend stays
  `online-mode=false`. Such a connection gets a real encryption handshake (RSA + AES-CFB8) and a real
  Mojang `hasJoined` session check during login; the first account to pass claims the name forever, and
  every later connection must match that UUID. **The real owner is never shown a password prompt from
  any IP** — their own launcher answers the cryptographic challenge silently. Nobody else can use the
  name, and there is no fallback to any weaker check: if verification fails, or the feature is switched
  off in config, the name is denied outright rather than dropping back to password/IP.

- **Persistent identity store** — self-registered passwords, learned IPs, and premium UUID pins
  survive a service restart (`C:\ProgramData\MinecraftFirewall\identity-store.json`, written with
  inheritance disabled and access limited to Administrators, SYSTEM, and the service's own account,
  since it holds password hashes). Admin-declared settings (`AllowedIps`, `RequirePremium`) are
  deliberately *not* stored there — `appsettings.json` stays their single source of truth, so removing
  a name from config really does remove it.

**Not implemented (designed for, never built):** ban-expiry persistence across restarts (an active OS
firewall rule survives, but the app forgets when to lift it), and Discord webhook alerts (everything
currently goes to the log file and console).

**Verified end-to-end, not just with synthetic unit tests:** the compiled service was run against a
real local Paper server, driven through the proxy's public port by a real protocol-correct client. This
found and fixed a real bug in `PlayStateInspector`'s phase tracking that would have made CaYaDev-Check's
grace-authentication fail for every legitimate reconnecting player — see `docs/plan.md`'s "Live
end-to-end verification" note for the full story. Not exercised: an actual graphical Minecraft
client/launcher (none was available in this environment) — the diagnostic client used is a real,
protocol-correct implementation, not a mock, but it is still this project's own code.

## Honesty notes

- This is defense-in-depth for a server that must stay `online-mode=false`. It does not replace Mojang
  authentication.
- **The identity store holds password hashes — treat the file accordingly.** It is written with
  restrictive ACLs automatically, but it will end up in any backup or disk image you take of the
  machine. Hashes are PBKDF2, not plaintext, so this is not an emergency — just don't hand the file
  around. Deleting it resets every self-registration and un-pins every premium name (they get
  re-claimed by whoever next passes verification), so it is not a "safe to clear" cache.
- **Firewall bans still don't survive a restart.** If the service restarts while an IP has an active
  Windows Firewall block rule, the OS rule keeps blocking — no security regression — but the app
  forgets its expiry and will never lift it. Remove such a rule by hand if you need it gone.
- **The premium *positive* path has not been verified against a real Microsoft account.** The denial
  path is confirmed end-to-end against a live server (a cracked client is challenged, checked against
  Mojang, denied, and receives a correctly-encrypted kick), the AES-CFB8 implementation is verified
  against NIST SP 800-38A vectors for all three key sizes, and the logic is unit-tested — but no
  genuine premium account was available in this build environment to confirm the "real owner is
  admitted" half. If you own the account, test it before relying on it: mark your own username
  `RequirePremium`, connect with a normal launcher, and confirm you get in without a prompt.
- **Requires Administrator rights** to actually create Windows Firewall rules. Without it, bans are still
  tracked and enforced in-process (denied at the proxy), but not blocked at the OS level — the service
  logs a clear warning at startup if it can't reach the firewall.
- **You must ensure the real Minecraft server's port is not reachable from outside the machine** — no
  inbound firewall rule for it, no router port-forward. This is the single most important setup step;
  the proxy provides no protection if the real server is still directly reachable.
- **`AllowedHostnames` is not a cryptographic boundary.** The Handshake's Server Address field is
  whatever string the connecting client sends — it is not bound to how the TCP connection was actually
  made. A stock Minecraft client pointed at a raw IP (Direct Connect, or most scanning bots) sends that
  IP as the Server Address and is correctly rejected. A custom/scripted client that deliberately fakes
  this field to match an allowed domain, while still connecting straight to the server's IP, is **not**
  stopped by this check alone. If you need that to be an actual hard guarantee rather than
  defense-in-depth, put a TCP-fronting proxy (e.g. Cloudflare Spectrum, TCPShield) in front, point your
  domain(s) at it, and add a Windows Firewall inbound rule on the public port that only permits that
  fronting proxy's IP ranges — then a direct-IP connection dies at the OS firewall regardless of what
  the Handshake claims. Also: if you're testing from the same machine, add `localhost` to
  `AllowedHostnames`, or you will lock out your own local connections once the list is non-empty.
- **The Admin CLI's ACL was verified by inspecting the constructed permission set and, in this
  project's own build environment, by confirming a genuinely non-elevated process is refused a
  connection** (`AdminAclTests`, `AdminPipeServerIntegrationTests`). It was not additionally verified
  by spawning a separate non-admin OS process against a *running* service — if you want that level of
  proof before trusting it in production, test it yourself: run the service elevated, then run
  `MinecraftFirewall.Admin.exe` from a non-elevated prompt and confirm it's refused.

## Project layout

```
src/MinecraftFirewall.Proxy/       Windows Service — the proxy itself
src/MinecraftFirewall.Admin/       Companion CLI — talks to the running service over an
                                    Administrators-only named pipe (see "Admin CLI" below)
tests/MinecraftFirewall.Tests/     xUnit tests — no real Minecraft server, no admin rights, no real firewall touched
tools/MinecraftFirewall.ProtocolSpike/  Manual diagnostic client used to empirically verify wire behavior
                                         against a real server (see docs/plan.md Stage 2, docs/protocol/)
docs/protocol/                     Sourced packet-ID reference data (Mojang's own generated report)
```

## Setup

1. In each Minecraft server's `server.properties`, set `server-ip=127.0.0.1` and change `server-port` to
   an internal-only port (e.g. `25566`).
2. Confirm that internal port is **not** reachable from outside the machine (no firewall rule, no
   port-forward).
3. Edit `src/MinecraftFirewall.Proxy/appsettings.json` — add a `ServerProfiles` entry per server with the
   public port, the backend host/port from step 1, and any protected usernames.
   - Optional: to restrict which domain(s) players may connect through, set `AllowedHostnames`.
     Point an A/CNAME record for each domain at the proxy machine's public IP first — the client just
     needs to resolve the name before connecting, the proxy doesn't do DNS itself. Read the honesty
     note above before relying on this for anything more than defense-in-depth.
   - Optional: edit the top-level `Messages` section to change any kick/disconnect wording, or to
     switch the shipped Turkish example block in for the English defaults.
   - Optional: for the real-time ipinfo.io secondary signal, sign up free at
     [ipinfo.io/signup](https://ipinfo.io/signup) and paste the token into the top-level `IpInfo`
     section. Leave it empty to keep this signal off (default) — the X4BNet lists above still apply.
   - Optional: to lock a username to its genuine Minecraft account owner, add it to that profile's
     `ProtectedUsernames` with `"RequirePremium": true` (no `AllowedIps` needed). This needs no API
     key — Mojang's session endpoint is public — and is on by default; the top-level `Premium` section
     only exists to switch the whole mechanism off, which denies such names rather than downgrading
     them. Read the two honesty notes above about restart behaviour and the unverified positive path
     first.
4. Build and run:

```bash
dotnet build
dotnet run --project src/MinecraftFirewall.Proxy
```

For production use, install it as a Windows Service (`sc.exe create` or `New-Service`) running as
Administrator so firewall bans actually take effect.

## Admin CLI

The service must already be running (as a service or via `dotnet run`) for the CLI to have anything to
talk to. Run the CLI itself **elevated** — the pipe refuses non-Administrator connections outright:

```bash
dotnet run --project src/MinecraftFirewall.Admin -- list-profiles
dotnet run --project src/MinecraftFirewall.Admin -- list-bans
dotnet run --project src/MinecraftFirewall.Admin -- unban 203.0.113.7
dotnet run --project src/MinecraftFirewall.Admin -- whitelist-add-me TestServer YourAdminUsername 203.0.113.7
dotnet run --project src/MinecraftFirewall.Admin -- require-premium TestServer YourAdminUsername
dotnet run --project src/MinecraftFirewall.Admin -- reload
```

`whitelist-add-me` and `require-premium` change in-memory state only — the command's own output says so.
To make either permanent, add it to that server's `ProtectedUsernames` in `appsettings.json` (the latter
via `"RequirePremium": true`) and restart the service. `reload` only refreshes the VPN/datacenter IP
lists on demand; it does not re-read `ServerProfiles` or anything else — that still needs a restart.

## Tests

```bash
dotnet test
```
