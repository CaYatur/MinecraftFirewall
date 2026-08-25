<p align="center">
  <img src="docs/images/banner.svg" alt="MinecraftFirewall — a reverse-proxy firewall between players and a Minecraft server running in offline mode" width="100%">
</p>

<p align="center">
  <img alt="Tests" src="https://img.shields.io/badge/tests-503%20passing-4ade80?style=flat-square">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows-0078d4?style=flat-square">
  <img alt=".NET" src="https://img.shields.io/badge/.NET-10-512bd4?style=flat-square">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square">
</p>

If you run a Minecraft Java server with `online-mode=false`, Minecraft never checks who anyone is.
Anyone can type your admin's username and join as them. **MinecraftFirewall** sits in front of your
server and decides, per connection, who actually gets through — with no plugin or mod inside Minecraft
at all.

It can even lock a username to its **real Microsoft/Mojang account** while your server stays in offline
mode. The genuine owner joins normally and is never asked for a password; everyone else is refused.

---

## Quick start

**1.** Download **`MinecraftFirewall-setup.exe`** from
[Releases](https://github.com/CaYatur/MinecraftFirewall/releases) and run it. It installs the
background service, sets it to start with Windows, and puts a control panel in your Start Menu.
Nothing else needs installing first — not even .NET.

**2.** In your server's `server.properties`, move the real server out of the way and hide it:

```properties
server-ip=127.0.0.1
server-port=25566
```

> This is the single most important step. The firewall protects nothing if players can still reach
> your server directly. Once you have done it, the control panel's **Security check** page will
> confirm it for you — it genuinely tries to connect, rather than taking your word for it.

**3.** Open the control panel, go to **Servers**, and point it at your server. VPN policy, protected
usernames and allowed domains are all here, per server:

<p align="center">
  <img src="docs/images/screens/servers.png" alt="The Servers page: name, public port, real server address and port, protected usernames, and allowed domains" width="820">
</p>

**4.** Press **Save and restart service**. Players keep connecting to your normal address on port
`25565` — nothing changes for them.

**5.** Run the **Security check**. Four green rows mean the firewall is genuinely in front of your
server rather than beside it:

<p align="center">
  <img src="docs/images/screens/security.png" alt="The Security check page showing four passing checks: real server binding, reachability from the network, the firewall accepting players, and Windows Firewall rules" width="820">
</p>

<details>
<summary><b>Prefer to run it by hand, without the installer?</b></summary>

Download the plain zip from Releases instead, unzip it somewhere permanent, edit `appsettings.json`
directly, and run:

```bash
MinecraftFirewall.Proxy.exe
```

```
[10:14:02 INF] [MyServer] listening on port 25565, forwarding to 127.0.0.1:25566.
[10:14:03 INF] Refreshed .../output/vpn/ipv4.txt (6567 ranges).
[10:14:03 INF] Refreshed .../output/datacenter/ipv4.txt (29062 ranges).
```

Run it **as Administrator** for real machine-wide firewall bans. Without elevation everything still
works, but repeat offenders are only blocked inside the proxy — it says so clearly at startup. To keep
it running permanently:

```bash
sc.exe create MinecraftFirewall binPath= "\"C:\MinecraftFirewall\MinecraftFirewall.Proxy.exe\"" start= auto
```

The inner quotes are not a typo: without them Windows stores an unquoted service path, which is a
privilege-escalation hazard whenever the path contains a space.

</details>

---

## The control panel

Everything is manageable from the app — you never have to edit JSON unless you want to.

<p align="center">
  <img src="docs/images/screens/status.png" alt="The Status page: service controls, a security check summary, the servers being protected, and recent activity" width="820">
</p>

| Page | What it answers |
|---|---|
| **Status** | Is protection running? Start, stop, install or remove the service; see live activity. |
| **Servers** | Which servers am I fronting, on which ports, with which protected usernames? |
| **Security check** | Can anyone reach past me to the real server? |
| **Protection** | What is the firewall holding off right now? Every defence layer, with switches. |
| **Players** | Who has an account on each server, when did they register, and what is held against the address they use? Reset a password, forget their trusted addresses, lock a name to its Minecraft account, or remove them. |
| **Blocked IPs** | Who is banned right now, and until when? Unban with one click. |
| **Activity log** | What just happened? The service's own log, tailed live. |
| **Settings** | Language, start-up behaviour, and the optional features that are off by default. |

<p align="center">
  <img src="docs/images/screens/players.png" alt="The Players page: the accounts one server knows, and one of them opened to show its history, the weighted reasons its address looks suspicious, and the actions available" width="820">
</p>

English and Turkish, switchable without restarting — every page, not just the menus:

<p align="center">
  <img src="docs/images/screens/protection-turkish.png" alt="The Protection page rendered in Turkish" width="820">
</p>

<p align="center">
  <img src="docs/images/screens/servers-turkish.png" alt="The Servers page rendered in Turkish" width="820">
</p>

<p align="center">
  <img src="docs/images/screens/settings.png" alt="The Settings page with English and Turkish language options, start-up mode, and optional features" width="820">
</p>

It also lives in the system tray, so closing the window leaves protection running.

---

## Layers of defence

Identity is only the first question. Everything below runs whether or not a username is protected.

<p align="center">
  <img src="docs/images/screens/protection.png" alt="The Protection page: live counters, flood limits, bot scoring, decoy ports with a captured address, and movement settings" width="820">
</p>

| Layer | What it stops | Default |
|---|---|---|
| **Admission control** | Connection floods. Separate caps per address, per /24, per minute, and overall — because a botnet spread across one subnet is invisible per-address and obvious per-subnet. | On |
| **Bot scoring** | Automated joins. Logging in without ever asking for the server list, working through a list of usernames, reconnecting on a metronome. | On, **reports only** |
| **Deep inspection** | Packets no Minecraft client sends: impossible coordinates, oversized frames, malformed plugin messages, and Log4j-style payloads in chat, usernames, signs and books. | On |
| **Crawler blocking** | Server-indexing sites that sweep for Minecraft servers. They announce their own domain in the field meant for yours, so they identify themselves. | On, when allowed domains are set |
| **Decoy ports** | Port scanners. Nothing advertises these ports, so anything touching one is enumerating rather than playing. | Off |
| **Threat lists** | Addresses seen attacking elsewhere, imported from public feeds. | On, **scores only** |
| **Anomaly detection** | Whatever the rules above did not anticipate. Learns the shape of ordinary connections to *your* server and reports what does not fit. | Off, **reports only** |

Three of those ship deliberately switched off or limited to reporting, and it is worth saying why
rather than leaving it looking like an oversight.

**Bot scoring** starts in report-only mode because nobody knows what your server's own traffic scores
until they have watched it for a few days. Turning a heuristic loose before that is how a firewall
ends up refusing its owner. Watch the Activity log, then switch it to refuse.

**Movement analysis** reports and does not kick. This proxy sees coordinates and nothing else — not
ice, boats, elytra, riptide tridents, speed potions, or a plugin teleporting somebody. All of those
look exactly like a speed cheat from here. A server-side anti-cheat plugin has the world state to tell
them apart; this does not. What it *does* enforce by default is coordinates that are not numbers at
all — NaN, infinity, positions outside the world — because those are crash inputs, not cheats, and no
client produces them by playing.

**Anomaly detection** is off because it learns from live traffic, which means an attacker present
during the learning window becomes part of the baseline. Switch it on at a quiet time.

What it may do about a repeated anomaly is yours to choose, in increasing order of consequence:

| Action | What happens |
|---|---|
| **Report** (default) | Written to the log, nothing else. |
| **Score** | Counts towards that address's bot score, alongside the behavioural signals. |
| **Require re-authentication** | Their next connection must log in again, even from a known address. |
| **Throttle** | That address's connection limits are tightened for a while. |
| **Ban** | A real firewall ban for the configured duration. |

Nothing happens on a single odd session — sessions are odd for innocent reasons constantly — and
nothing happens at all until the model has been settled for an hour, because a freshly trained
baseline is least reliable exactly when it is newest.

Every action lands on the address's **next** connection rather than the one just scored, which is
inherent rather than a limitation: the model judges a whole session, so by the time it has an opinion
the session is over. The upshot is that the worst it can do to somebody mid-game is nothing.

### Which Minecraft versions work

**Every version.** Ordinary players connect through the firewall whatever client they use, including
anything arriving via ViaVersion or ViaBackwards — the proxy relays a connection it cannot inspect
rather than refusing it.

Inspection is a different matter. Reading chat means knowing that version's packet IDs, and those move
between releases: serverbound chat is `0x06` on protocol 767, `0x07` on 768–770 and `0x08` from 771.
Guessing them is how a firewall corrupts a login, so this project never does — every table is
generated by running that version's own server jar through Mojang's data generator.

Tables ship for **1.20.2 through the newest release** (protocols 764–775). Where Mojang's own
generator produces them — 1.21 onwards — they come from that. Below it the generator did not emit
packet IDs at all, so those come from [minecraft-data](https://github.com/PrismarineJS/minecraft-data),
and are only accepted because the same script first reproduces every Mojang-generated table from it
and refuses to go further unless all of them match exactly. On any other version:

| | |
|---|---|
| An ordinary player | Joins normally. Nothing is inspected, nothing is refused. |
| Server-wide registration | Cannot be enforced for that connection, so they are let in and the log says so. |
| A **premium-locked** name | Refused. Skipping the check would mean anyone could claim the name by sending an odd version number. |
| A **password-registered** name from a new address | Refused, for the same reason. |

Only those last two see a kick, and the message says other players are unaffected. To add a new
version:

```bash
python tools/generate-protocol-tables.py work-dir   # Mojang's generator, 1.21+
python tools/extend-protocol-tables.py work-dir     # minecraft-data, cross-checked against the above
python tools/apply-protocol-tables.py work-dir      # rewrite the registry
```

The floor is 1.20.2, where Minecraft gained the Configuration protocol state this proxy's inspection
is built around. Older clients — including everything a server running ViaVersion accepts — connect
and play normally; they simply cannot be held for a password.

The **Security check** page reads your server's own files to tell you which of these applies to you: it
finds the server by matching its `server.properties` against the backend port, then reports its version
and whether ViaVersion or ViaBackwards is installed.

### Accounts and passwords (CaYaDev-Check)

The AuthMe equivalent, built into the proxy rather than into your server. Two modes:

**Off (default).** Any player can type `/register <password>` to protect their own name; everyone else
plays exactly as before. Opt-in, per player.

**On.** Nobody reaches your world until they have an account. A player joins and is **held still** —
movement, hitting, placing, item use and container clicks are refused and never reach your server.
Only chat gets through, which is how they type the command. They are prompted on arrival and reminded
periodically, because Minecraft chat scrolls.

```
/register <password>    → first time
/login <password>       → afterwards, from a new address
```

Keep-alives keep flowing while a player is frozen, so your server does not time them out while they
read the prompt. Once they authenticate, their address is remembered and they are not asked again from
it.

**Premium-locked names skip the whole thing.** Their Microsoft account has already proved who they
are; asking for a password on top would mean making the real owner prove themselves twice, which is
the one thing this firewall promises never to do.

Switch it on from the Protection page, or set `Identity.RequireRegistrationForEveryone`.

### Server-indexing crawlers

Sites that catalogue Minecraft servers sweep address ranges looking for them, and they give
themselves away. A Minecraft client puts the address the player typed into its Handshake packet, so
somebody who was given a raw IP sends that IP. A crawler has no address to send — it found you by
scanning — so it sends its own domain instead: its brand, in the field meant for your server's name.

Once an address has announced three different domains that aren't yours, it is banned for a month
rather than the usual few hours, because an indexing service is on a schedule and will otherwise be
back next week. A **raw IP** in that field never escalates, which matters more than it sounds: testing
your own server by IP produces exactly that pattern, and treating the two the same would ban you from
your own machine.

This only does anything if you have set allowed domains — with no list, nothing is a mismatch.

### Injection payloads

Log4Shell reached Minecraft servers through chat, and the reason it worked is still true: player text
ends up in log formatters, plugin config parsers and web panels, each a different interpreter. This
scans chat, commands, usernames, signs and books — signs and books included because a payload written
into one persists in world data long after the connection that delivered it.

The scan de-obfuscates rather than pattern-matches. Log4j's lookup syntax lets `${jndi:...}` be
written as `${${::-j}${::-n}${::-d}${::-i}:...}`, which no search for "jndi" will ever find, so the
text is stripped of the syntax that does the obfuscating and the search runs on what is left. That
inverts the problem: instead of enumerating obfuscations, it removes the tools used to build them.

---

## What happens to a connection

```mermaid
flowchart TD
    A[Player connects] --> B{"Banned IP, disallowed domain,<br/>or too many attempts?"}
    B -->|yes| X[Refused]
    B -->|no| E{Is this username protected?}

    E -->|"no — ordinary player"| V
    E -->|"premium-locked"| F{"A real Mojang account —<br/>and the right one?"}
    E -->|"pinned to certain IPs"| G{IP on the list?}
    E -->|"has a password"| H{IP seen before?}

    F -->|no| X
    F -->|yes| V
    G -->|no| X
    G -->|yes| V
    H -->|yes| V
    H -->|no| J["Joins — but their first message<br/>must be /login &lt;password&gt;"]
    J -->|wrong| X
    J -->|correct| V

    V{VPN or datacenter IP?} -->|"yes, if your policy blocks it"| X
    V -->|no| PASS[Forwarded to your server]

    style X fill:#7f1d1d,stroke:#dc2626,color:#fff
    style PASS fill:#14532d,stroke:#22c55e,color:#fff
    style J fill:#78350f,stroke:#f59e0b,color:#fff
```

An unprotected name behaves exactly like vanilla offline mode — the gate only runs for names someone
has actually opted into protecting. Everything past this point is relayed byte-for-byte, so your
server behaves exactly as it always did.

---

## Premium account lock

This is the headline feature. Mark a username as premium and it belongs to one real Microsoft account,
permanently — even though your server never leaves offline mode.

```jsonc
{ "Username": "YourAdminName", "RequirePremium": true }
```

```mermaid
sequenceDiagram
    participant P as Player
    participant F as MinecraftFirewall
    participant M as Mojang
    participant S as Your server

    P->>F: I'm "YourAdminName"
    Note over F: This name is premium-locked
    F->>P: Encryption Request (RSA challenge)
    P->>F: Encryption Response
    Note over P,F: A real launcher answers this<br/>automatically — no prompt, no password
    F->>M: hasJoined? Is this a valid session?

    alt Genuine owner
        M-->>F: Yes — UUID abc123
        Note over F: Matches the UUID this<br/>name is pinned to
        F->>S: Forward the connection
        S-->>P: Welcome back
    else Anyone else
        M-->>F: No valid session
        F-->>P: ❌ Refused — no password fallback
    end
```

**What this means in practice**

| | |
|---|---|
| The real owner | Joins normally from any IP. Never sees a password prompt, ever. |
| A cracked client | Refused. It cannot answer the cryptographic challenge. |
| Someone with a *different* real account | Refused — the name is pinned to one UUID. |
| Mojang is down | Refused, deliberately. Falling back to "let them in" would defeat the point. |

> The first account to successfully verify claims the name **permanently**. Set this up before someone
> else takes the name — it can't retroactively un-claim a name an attacker already grabbed.

### Players can lock their own name

You don't have to list every name worth protecting. Any player can type **`/premium`** in chat to be
told what locking their name would do, and **`/premium confirm`** to go ahead. They're disconnected
with instructions, rejoin with the genuine Minecraft account, and the name is theirs permanently.

```
/premium            → explains what this does, and that it can't be undone
/premium confirm    → arms it; rejoin with the real account
```

This works whether or not you've switched on auto-claim, because that setting decides whether
*everyone* is offered the challenge — a different question from whether one person asked to be.

It's safe for the same reason auto-claim is, and the reason is the whole argument: Mojang is asked
whether *that username* has an active session, so the only account that can ever answer for a name is
the one that owns it. Somebody squatting a name with a cracked client can arm this all they like —
the challenge they then have to pass is one only the real owner can pass, and a failure records
nothing at all.

---

## Everything it does

| Feature | What it's for |
|---|---|
| 🔐 **Premium account lock** | Bind a username to its real Microsoft account, on an offline-mode server. |
| 🧾 **CaYaDev-Check** | AuthMe-style accounts. Optional server-wide: nobody reaches your world until they register or log in. PBKDF2 hashed, remembers known IPs so nobody is nagged twice. |
| 📋 **Protected usernames** | Pin a name to specific IPs or CIDR ranges. Unknown IP is a hard refusal. |
| 🌐 **VPN & datacenter blocking** | Free MIT-licensed IP lists, refreshed daily, cached to disk. Optional real-time ipinfo.io lookup on top. |
| 🚪 **Allowed domains** | Only accept players arriving through your domain — IP-scanning bots get nothing. |
| ⛔ **Real firewall bans** | Repeat offenders get a genuine machine-wide Windows Firewall rule, and each ban lasts twice as long as the last — 6 hours, 12, a day, two days — so persistence costs more every time. |
| 🕵️ **Command auditing** | Play-state commands are logged and checked against a dangerous-command list. |
| 🚦 **Rate limiting** | Separate sliding windows for server-list pings and login attempts. |
| 💬 **Discord alerts** | Optional webhook for bans, new trusted IPs, and failed premium checks. |
| 🖥️ **Multi-server** | One process in front of as many servers as you like, each on its own port. |
| 🗣️ **Every message editable** | All player-facing text lives in config — the chat prompts and the on-screen title alike. English by default, Turkish example included. |
| 👤 **Player management** | Per server: who registered and when, when they were last seen, from where, and the itemised reasons that address looks suspicious. Reset a password, forget trusted addresses, lock or unlock a name, remove it. |
| 🧬 **Real player IPs** | PROXY protocol or BungeeCord-style forwarding, so your server log and your plugins see the player rather than 127.0.0.1. |
| 🧱 **Malformed packet refusal** | What PacketFixer-style plugins do, a step earlier — before the server's own decoder sees the packet. |
| 🔁 **Self-updating version support** | A Minecraft version this build has never seen is learned at runtime, checked against every table it already has, and used without anyone being asked to do anything. |

---

## What players actually see

A player registering a password for their name:

```
[10:22:15 INF] [MyServer] login allowed for 'Steve' from 203.0.113.44.
[10:22:16 INF] [MyServer] 'Steve' registered with CaYaDev-Check from 203.0.113.44.
```

Someone trying that same name from a new IP without the password:

```
[10:31:07 WRN] [MyServer] grace-authentication FAILED for 'Steve' from 198.51.100.9
               — first message was not a correct /login.
```

A cracked client going after a premium-locked name:

```
[10:44:51 INF] Mojang hasJoined check for 'YourAdminName' found no valid session — denying.
[10:44:51 WRN] [MyServer] premium verification FAILED for 'YourAdminName' from 198.51.100.9
```

The player sees a normal Minecraft kick screen with whatever wording you configured.

---

## Configuration

Everything lives in `appsettings.json`. Every section is optional — leave one out and sensible defaults
apply.

| Section | What it controls |
|---|---|
| `ServerProfiles` | Your servers, ports, protected usernames, allowed domains. **The only section you must edit.** |
| `Messages` | Every kick/disconnect message. English defaults; a Turkish block ships commented out. |
| `Premium` | Master switch for premium verification (on by default, needs no API key). |
| `VpnIntel` / `IpInfo` | VPN list sources; optional ipinfo.io token for the real-time signal. |
| `RateLimit` / `FirewallBan` / `NeverBan` | Thresholds, ban duration, and IPs that can never be banned. |
| `Alerts` | Discord webhook URL and which events to report. Off until you add a URL. |
| `Identity` | Server-wide registration, password rules, how long a known address stays trusted. |
| `DdosProtection` | Per-address, per-subnet and overall connection limits, and the defensive mode. |
| `BotDefense` | Signal weights and whether a high score reports or refuses. |
| `DeepInspection` | Packet size and rate caps, injection scanning, movement analysis. |
| `Honeypot` | Decoy ports. Off by default; ports are pre-filled. |
| `ThreatIntel` | Imported public threat feeds, and where this machine writes its own findings. |
| `AnomalyDetection` | The learned baseline. Off by default, and reports only. |

### Upgrading

Your `appsettings.json` is never overwritten — it holds your servers and protected usernames. That
means a config written by an older version has no section for settings added since, and the Protection
page will say so and offer to add them, copying the shipped defaults across without touching anything
you set.
| `IdentityPersistence` | Where learned passwords, IPs and premium pins are stored between restarts. |

### Turkish messages

Open the `Messages` section — a full Turkish translation ships commented out. Swap the values in and
restart:

```jsonc
"Messages": {
  "GenericDenied": "Bu bağlantı MinecraftFirewall tarafından engellendi.",
  "HostnameNotAllowed": "Bu sunucuya sadece izin verilen adres(ler) üzerinden bağlanılabilir.",
  "GraceAuthenticationFailed": "Kimlik doğrulama başarısız. Bu IP tanınmıyor ve doğru şifre girilmedi."
}
```

---

## Admin CLI

Run **elevated** — the control pipe refuses non-Administrator connections outright.

```bash
MinecraftFirewall.Admin.exe list-bans
MinecraftFirewall.Admin.exe unban 203.0.113.7
MinecraftFirewall.Admin.exe list-profiles
MinecraftFirewall.Admin.exe whitelist-add-me MyServer YourAdminName 203.0.113.7
MinecraftFirewall.Admin.exe require-premium MyServer YourAdminName
MinecraftFirewall.Admin.exe reload
MinecraftFirewall.Admin.exe defense-status
MinecraftFirewall.Admin.exe list-threats
```

> **`require-premium` must be followed up in `appsettings.json` straight away.** Every other command
> lapsing on restart just denies someone — safe. This one lapsing leaves the name **open to anyone
> again**. Add `"RequirePremium": true` in the same sitting.

`reload` only refreshes the VPN/datacenter IP lists. Ports and profiles still need a restart.

---

## Waiting at the login prompt

When server-wide registration is on, a player who has not logged in yet is held. That used to mean
their packets were refused and nothing else, which was correct and looked broken:

- Minecraft predicts movement on the client and only corrects when the server disagrees, so a held
  player walked around their own screen and then snapped back.
- Their real coordinates sat on the HUD for anyone watching, before they had proved they owned the
  name.
- Mobs went on hitting them while they read the prompt, and they could die at it.
- The prompt was one line of chat, which scrolls away while you are in your inventory.
- The commands it told them to type rendered **red**, because the backend has never heard of them —
  the firewall answers first.

All of that is fixed. The client is now told where it is, repeatedly, at the origin rather than at
the player's real position; put back exactly where the server has them the moment they log in; shown
the prompt across the middle of the screen as well as in chat; and offered the premium route, which
until now could only be found from the far side of the prompt asking for a password. The words work
without a slash, so nothing renders as an error, and a player can change their own password in game
with `changepassword <current> <new>` — the current one is required even from a trusted address,
because a household shares an address.

Damage is the one this cannot fix outright, and the reason is worth stating: a firewall in front of a
server cannot stop a creeper. The player really is standing in the world and only the server decides
their health. What it can do is notice — so a held player who starts taking damage is disconnected
before they die. A kick costs them a reconnect; a death costs them their inventory.

Every line of it is configurable, including the on-screen title.

---

## Real player IP addresses

By default a reverse proxy hides everyone behind itself: your server log shows `127.0.0.1` for every
join, and so does every plugin that reads an address. Banning an IP there bans the proxy, which is
everyone.

Set `IpForwarding` on a server profile (or pick it on the **Servers** page) to fix that:

| Setting | What it does | Your server needs |
|---|---|---|
| `ProxyProtocol` | A small binary header before the first Minecraft byte. Knows nothing about Minecraft, so it does not move when the protocol does, and it covers the server-list ping too. | Paper: `proxies.proxy-protocol: true` in `config/paper-global.yml` |
| `BungeeCord` | The real address spliced into the handshake, the way BungeeCord does it. | Spigot/Paper: `bungeecord: true` under `settings` in `spigot.yml` |

Both need the server configured to expect the same thing, and **neither is safe on its own**: a server
told to read a forwarded address believes whoever it is talking to. Keep the backend port bound to
`127.0.0.1`, which is exactly what the Security check page tests.

---

## Honest limitations

This section is deliberately not marketing copy. Read it before relying on any of this.

There is a longer, item-by-item version in **[docs/requested-features.md](docs/requested-features.md)**:
every capability that has been asked of this project, marked as already present, added, feasible but
not built, or not possible from where this software sits — with the reason in each case.

- **A firewall in front of a server cannot stop mob damage.** A player held at the login prompt is
  genuinely standing in your world, and only the server decides their health — nothing this proxy
  refuses or rewrites changes that. It notices and disconnects them before they die, which is the
  best a thing outside the server can do. If you want them not to be in the world at all, that needs
  a plugin inside it.
- **The anti-bot risk figures score an address, not a person.** One address carries several names, and
  the Players page says so where it shows them. Nothing here correlates alt accounts; presenting an
  address score as a player score would quietly imply that it did.
- **This is defence in depth, not Mojang authentication.** It raises the cost of impersonation
  enormously; it does not make an offline-mode server equivalent to an online-mode one.
- **Premium lock protects a name from the moment you enable it.** It cannot take back a name an
  attacker already claimed in plain offline mode beforehand.
- **Your server must be unreachable directly.** If players can still connect to port `25566`, none of
  this applies to them. Verify it yourself; the proxy cannot check this for you.
- **`AllowedHostnames` is not a cryptographic boundary, and cannot be made into one.** The hostname is
  whatever string the client chose to send; nothing binds it to how the connection was actually made.
  A stock client pointed at your raw IP is correctly refused, and so is the bulk of IP-scanning
  traffic — but a custom client that simply *lies* about the field walks straight past it, and no
  amount of work on this check changes that. Two things were done about it instead. A refused mismatch
  now counts towards the address's bot score, so an address that keeps trying is treated as
  enumerating rather than being forgotten between connections. And the control that genuinely enforces
  "only through my domain" is stated plainly: your real server being unreachable except from this
  proxy, which is exactly what the Security check page tests. For a hard guarantee at the network
  level, put a TCP-fronting proxy (Cloudflare Spectrum, TCPShield) in front and firewall the public
  port to its IP ranges.
- **Movement analysis is advisory, not anti-cheat.** See the layers table above. Crash inputs are
  blocked; "moved too fast" is reported, because this proxy cannot see the ice, boat, elytra or plugin
  teleport that would explain it.
- **Anomaly detection learns from live traffic**, so an attacker present during its learning window
  becomes part of the baseline. Only connections that ended cleanly and were never struck are learned
  from, and a few hundred are required before it says anything — but that narrows the problem rather
  than removing it.
- **The bot score is beatable, and its weights say how.** A bot that sends one status ping before each
  login defeats the highest-weighted signal for a one-line change. The others exist because it then
  still has to use one username and reconnect at human intervals, which costs considerably more. The
  arithmetic of what actually reaches the refusal threshold is written into `appsettings.json` rather
  than left for you to discover.
- **Your server still sees its own offline UUID** for a premium-verified player, not their real one.
  Verification is authoritative for *access*, not for what your world files record.
- **The identity store holds password hashes.** They're PBKDF2, not plaintext, but don't hand the file
  around. Deleting it un-pins every premium name.
- **Two things were never tested in this project's build environment**, and are called out rather than
  glossed over: a *successful* premium login by a genuine Microsoft account (there was no real account
  available — the *refusal* path is verified end-to-end against a live server), and the real Windows
  Firewall COM path (rule creation needs elevation). Both are covered by automated tests; neither was
  observed against the real thing. If you depend on them, verify once yourself.

---

## Building from source

```bash
git clone https://github.com/CaYatur/MinecraftFirewall.git
cd MinecraftFirewall
dotnet test
dotnet run --project src/MinecraftFirewall.Proxy
```

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download). Windows only — it uses the Windows
Firewall COM API and Windows named-pipe ACLs.

```
src/MinecraftFirewall.Proxy/    The service itself
src/MinecraftFirewall.App/      The control panel (WPF)
src/MinecraftFirewall.Admin/    Companion CLI
installer/                      Inno Setup script + build.ps1 that produces the setup .exe
tests/MinecraftFirewall.Tests/  503 tests — no real server, no admin rights, no real firewall touched
tools/                          Diagnostic client used to verify wire behaviour against a real server
docs/plan.md                    Full design doc: every decision, and how each was verified
```

---

## License

[MIT](LICENSE) — free to use, modify and redistribute.

VPN and datacenter IP data comes from [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn), also MIT.
