# MinecraftFirewall

Windows reverse-proxy firewall for Minecraft Java Edition servers running `online-mode=false` with no
protection plugins. It sits in front of the real server (which binds to `127.0.0.1` only) and decides,
per connection, whether to forward it — without any plugin/mod inside Minecraft itself.

## Status: Stage 3 of 4 (130 automated tests passing)

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
- **Per-profile rate limiting** — sliding window, separate thresholds for status pings vs. login attempts.
- **Allowed-domains restriction** — an optional per-profile allowlist of hostnames (exact or
  `*.example.com` wildcard); a connection whose Handshake Server Address doesn't match one of them is
  denied before it ever reaches the backend, even if the attacker knows the server's raw IP. **Read the
  honesty note below before relying on this** — it stops IP-scanning bots and casual direct-IP joins,
  but a client that deliberately fakes this field is not stopped by this check alone.
- **Windows Firewall bans** — repeat offenders get a real, machine-wide block rule via the
  `INetFwPolicy2` COM API (never `netsh` with interpolated input), with a TTL, a hardcoded never-ban list
  (loopback/RFC1918/admin allowlist), and an in-process fallback if the service isn't running elevated.

**Not implemented yet:** admin-declared premium (real Mojang account) verification that permanently
locks a username to its genuine owner (Stage 4 — the feature behind the strongest original request), and
the admin CLI/named pipe (`whitelist-add-me`, `list-bans`, `unban`, `require-premium`). Also still
outstanding: a live end-to-end run of the compiled service against a real Minecraft client, as opposed
to the unit/integration tests (which use synthetic but protocol-verified packets) — see `docs/plan.md`
for exactly what to run next.

## Honesty notes

- This is defense-in-depth for a server that must stay `online-mode=false`. It does not replace Mojang
  authentication.
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

## Project layout

```
src/MinecraftFirewall.Proxy/       Windows Service — the proxy itself
src/MinecraftFirewall.Admin/       Companion CLI (not yet implemented beyond scaffold)
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
4. Build and run:

```bash
dotnet build
dotnet run --project src/MinecraftFirewall.Proxy
```

For production use, install it as a Windows Service (`sc.exe create` or `New-Service`) running as
Administrator so firewall bans actually take effect.

## Tests

```bash
dotnet test
```
