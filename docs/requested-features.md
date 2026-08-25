# What was asked for, and what it actually is

A long list of capabilities was requested for this project — an Identity Engine, a DDoS/Network
Security Engine, a Sonar/LimboFilter-class bot engine, an anti-cheat, and a PacketFixer replacement.
Much of it already existed under different names, some of it was added, some of it is worth building
and has not been, and a few items cannot be done from where this software sits.

This file says which is which, item by item. It exists because a security product that quietly leaves
half a list unimplemented while claiming the whole list is worse than one that never claimed it.

Legend: **✅ done** · **➕ added in 1.7.0** · **🔨 feasible, not built** · **🚫 not possible here**

---

## Identity & session security

| Asked for | State | Where it is, or why not |
|---|---|---|
| Microsoft/Minecraft account verification | ✅ | `Identity/Premium/` — a real encryption challenge and a Mojang `hasJoined` check, the same handshake an online-mode server runs. |
| Offline-mode protection | ✅ | The whole product. |
| Premium username lock | ✅ | `PremiumRequired` plus a permanently pinned UUID; the genuine owner is never shown a password prompt, from any address. |
| Username spoof detection | ✅ | `Inspection/UsernameGuard.cs` (length and character rules, applied before the name reaches a log) and `Defense/UsernameShape.cs` (names with the shape of a generated one). |
| IP change detection | ✅ | A registered player arriving from an unrecognised address is held and must prove the password. |
| Trusted session | ✅ | Addresses are remembered per name, TTL-capped and count-capped, so nobody is nagged twice. |
| Login velocity | ✅ | `RateLimiting/ConnectionRateLimiter.cs`, plus the bot detector's reconnect-cadence measure — a bot looping every five minutes is as mechanical as one looping every two seconds, and a scale-free measure says so. |
| Account takeover detection | ➕ | Failed logins, password changes and resets are now recorded per player, with the address, and shown on the Players page. Six failures from four addresses is a question an administrator can now actually ask. |
| 2FA / passphrase | 🔨 | A password is the second factor today. A real second factor needs somewhere to send a code, which means an account system this does not have. A shared-secret TOTP typed in chat is possible and would work; it has not been built. |
| Session binding | 🔨 | Partly present: a session is bound to the address it authenticated from for its lifetime. Binding it to something harder to move — a per-session token echoed back — needs a client that cooperates, so it would only bind honest clients. |
| Device fingerprint | 🔨 | Genuinely possible from here, and not yet done. The protocol version, the exact set of plugin-message channels a client registers, and its brand string together identify a client build fairly precisely. Worth adding as a *signal*, never as a gate: a fingerprint is trivially copied by whoever wants to. |
| Alt-account correlation | 🚫 | Deliberately not built, and the Players page says so where it would matter. All that is observable from here is "these names used this address", which is also true of a family, a shared flat, a school and a games café. Presenting that as an alt-account link would produce confident, wrong accusations. |

---

## Network and denial-of-service

| Asked for | State | Where it is, or why not |
|---|---|---|
| Per-IP connection quotas | ✅ | `Defense/DdosOptions.cs` — concurrent connections and new-connections-per-minute, both per address. |
| Per-CIDR limits | ✅ | Same file, `MaxConcurrentPerSubnet` and `MaxNewConnectionsPerSubnetPerMinute` — one host in a /24 renting more addresses does not multiply their budget. |
| Global connection budget | ✅ | `ConnectionGovernor` refuses before a byte is read, which is the only place a flood can be refused cheaply. |
| Adaptive rate limiting | ✅ | Defensive mode tightens every limit automatically once the shape of a flood appears, and relaxes again. |
| Connection reputation | ✅ | `Enforcement/StrikeTracker.cs` plus the bot detector's per-address memory. |
| Temporary quarantine | ✅ | Bans are time-boxed and each repeat lasts twice as long as the last — six hours, twelve, a day, two days. |
| Automatic Windows Firewall rules | ✅ | `Enforcement/WindowsFirewallGateway.cs` — a real machine-wide rule, not an application-level drop. |
| Threat intelligence | ✅ | Imported public lists, plus this machine's own first-hand observations, kept separate because they are not equally trustworthy. |
| Decoy ports | ✅ | `Defense/HoneypotService.cs`, off by default. Anything that touches one has no legitimate reason to be there. |
| Port-scanner detection | ✅ | `Defense/ScannerDetector.cs` — the server-indexing crawlers announce their own domain in the field meant for the server's name, which is unusually clean evidence, and repeat offenders are banned for far longer than the usual ban. |
| Geo / ASN policy | 🔨 | Partly present as VPN and datacentre range lists. Real ASN policy needs a routing table (an MRT or RIB dump, refreshed) — perfectly buildable, a meaningful amount of work, and not yet done. |
| Botnet correlation | 🔨 | Partly present: imported lists carry known botnet ranges, and the anomaly model notices connections that do not look like the others. Correlating a coordinated set of addresses *as one campaign* is a bigger idea and has not been built. |
| SYN flood protection | 🚫 | Not this software's layer. A SYN flood is answered before a connection exists, by the network stack and the machine's own firewall — `netsh int tcp set global synattackprotect` and an upstream provider. What this can do, and does, is refuse completed connections cheaply. |

---

## Bots

The existing bot engine scores each connection against several independent signals and either logs or
denies, per configuration. Present: joins with no preceding server-list ping, many distinct usernames
from one address, mechanically even reconnect cadence, generated-looking names, protocol versions no
real client uses, abandoned handshakes, imported-list membership, and a repeatedly anomalous history.
Added in 1.7.0: the hostname-mismatch signal is now a window rather than a tally, and connecting by
raw IP no longer counts as one at all — the previous behaviour scored a server's own owner at full
weight on every join they ever made.

What a Sonar/LimboFilter-class engine has that this does not is a **verification limbo**: the client
is dropped into a tiny fake world and made to demonstrate gravity, collision and a plausible response
to a position correction before it is let near the real server. That is the strongest anti-bot method
there is, because a bot has to implement physics to pass it.

It is **🔨 feasible but not built**, and the reason is stated plainly: it means implementing enough of
a Minecraft server to hold a client in a world — per version, across every version this supports —
including the registry data the client demands during configuration. Done partially, it does not
degrade into a weaker check; it degrades into players unable to join. That is a project of its own,
not a feature to append.

---

## Anti-cheat

Requested: flight, teleport, reach, hitbox, speed. What exists today is movement analysis —
`Inspection/MovementAnalyzer.cs` — which refuses coordinates that are not numbers or not places
(NaN, infinity, outside the world border) and reports implausible horizontal speed without acting on
it. Added in 1.7.0: the same "is this a number, is it a place" rule now applies to interaction
coordinates as well.

Everything else on that list is **🔨 feasible only in part, and honestly quite weakly**, for one
reason that does not go away: **a proxy cannot see the world.**

- **Flight** requires knowing whether there is a block underneath the player. This process has no
  world data, and a legitimate elytra, boat, ice, ladder, slime block, levitation effect or plugin
  teleport all look identical from here.
- **Reach and hitbox** require knowing where the other entity is. Entity positions come from the
  server in packets this does not track, and tracking them would mean maintaining a shadow copy of
  every entity in every world — which is the expensive half of writing a server.
- **Speed** is already measured, and already only reported, because the false-positive list above is
  exactly why. `KickOnMovementAnomaly` exists for administrators who want it to act; it defaults off
  deliberately.
- **Teleport** is the one that works well from here, and it does: an impossible position delta is
  refused outright rather than scored.

An anti-cheat that acts on guesses about a world it cannot see would kick legitimate players, and the
kicks would look random to everyone including the administrator. The place for the rest of this list
is a plugin with access to the server's own state — and this firewall does not stop you running one.

---

## PacketFixer

**➕ Done in 1.7.0**, and a step earlier than the plugins do it. See `Inspection/PacketSanitiser.cs`.

The argument for putting it here is order. A plugin runs after the server has already parsed the
packet, and parsing it is where the damage happens; "the plugin then rejected it" is no comfort if
the decoder threw. This refuses structurally impossible packets before the server sees them at all.

What it refuses is short and every entry is a certainty rather than a judgement: an interaction type
outside the three that exist, a hand that is neither hand, a negative entity id, an interaction
coordinate that is NaN or infinite or further out than the world goes, and bytes trailing a packet
whose length is fixed. Alongside what was already there — decompression bombs, oversized frames,
malformed plugin-message channels, implausible book page counts, unreadable sign layouts, injection
payloads in anything a player can type.

The rule it follows is the one the whole project follows: **only layouts that come out of the
generated packet tables are opened, and a packet whose fields do not decode cleanly is forwarded
rather than refused.** An unverified field offset is not a missed detection, it is a firewall that
breaks ordinary play.
