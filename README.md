# MinecraftFirewall

Windows reverse-proxy firewall for Minecraft Java Edition servers running `online-mode=false` with no
protection plugins. It sits in front of the real server (which binds to `127.0.0.1` only) and decides,
per connection, whether to forward it — without any plugin/mod inside Minecraft itself.

## Status: Stage 1 of 4

This is an early, in-progress build. See [`docs/plan.md`](docs/plan.md) for the complete staged design
doc. What's implemented right now:

- **Multi-server reverse proxy** — one process fronts multiple Minecraft servers on the same machine,
  each with its own public port, config-driven (`ServerProfiles` in `appsettings.json`).
- **Protected usernames** — a static IP/CIDR allowlist per username, per server profile. A username with
  no allowlist behaves exactly like vanilla offline mode.
- **VPN/datacenter IP detection** — free, MIT-licensed CIDR lists from
  [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn), refreshed daily, cached to disk, fails open
  if the source is unreachable.
- **Per-profile rate limiting** — sliding window, separate thresholds for status pings vs. login attempts.
- **Windows Firewall bans** — repeat offenders get a real, machine-wide block rule via the
  `INetFwPolicy2` COM API (never `netsh` with interpolated input), with a TTL, a hardcoded never-ban list
  (loopback/RFC1918/admin allowlist), and an in-process fallback if the service isn't running elevated.

**Not implemented yet** (later stages): Play-state command auditing, the chat-based
register/login ("CaYaDev-Check") gate, and admin-declared premium (real Mojang account) verification that
permanently locks a username to its genuine owner. Static IP allowlisting is the only identity mechanism
right now — the plan's whole point is that this is *not* the final word on "smarter than IP."

## Honesty notes

- This is defense-in-depth for a server that must stay `online-mode=false`. It does not replace Mojang
  authentication.
- **Requires Administrator rights** to actually create Windows Firewall rules. Without it, bans are still
  tracked and enforced in-process (denied at the proxy), but not blocked at the OS level — the service
  logs a clear warning at startup if it can't reach the firewall.
- **You must ensure the real Minecraft server's port is not reachable from outside the machine** — no
  inbound firewall rule for it, no router port-forward. This is the single most important setup step;
  the proxy provides no protection if the real server is still directly reachable.

## Project layout

```
src/MinecraftFirewall.Proxy/   Windows Service — the proxy itself
src/MinecraftFirewall.Admin/   Companion CLI (not yet implemented beyond scaffold)
tests/MinecraftFirewall.Tests/ xUnit tests — no real Minecraft server, no admin rights, no real firewall touched
```

## Setup

1. In each Minecraft server's `server.properties`, set `server-ip=127.0.0.1` and change `server-port` to
   an internal-only port (e.g. `25566`).
2. Confirm that internal port is **not** reachable from outside the machine (no firewall rule, no
   port-forward).
3. Edit `src/MinecraftFirewall.Proxy/appsettings.json` — add a `ServerProfiles` entry per server with the
   public port, the backend host/port from step 1, and any protected usernames.
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
