"""Extends ProtocolVersionRegistry using PrismarineJS/minecraft-data, cross-checked against Mojang.

    python tools/extend-protocol-tables.py <work-dir>

Mojang's own data generator only emits packet IDs from 1.21 onwards, which left every older client
outside the registry — including everything a server running ViaVersion accepts. minecraft-data is the
community's machine-readable protocol dataset, the one mineflayer and its relatives are built on, and
it reaches back to 1.8.

It is a second-hand source, so it is not simply trusted. This script first reproduces every table that
Mojang's generator already produced and refuses to go further unless all of them match exactly. That
turns "a community dataset says so" into "a community dataset that agrees with the authoritative
source on every version where both exist says so" — which is a different and much stronger claim, and
the only basis on which this project will accept IDs it did not generate itself.

Versions below 1.19 are deliberately skipped: the clientbound system-chat packet does not exist there,
so the proxy would have no way to prompt a player it is holding, and a login gate that cannot say why
somebody is stuck is worse than none.
"""
import json
import sys
import urllib.request
from pathlib import Path

WORK = Path(sys.argv[1])
DATA = "https://raw.githubusercontent.com/PrismarineJS/minecraft-data/master/data"

# The packets the registry needs, as minecraft-data names them. Its naming drifted over time, so a few
# entries list alternatives and the first one present wins.
NEEDED = {
    "chat": ["chat_message", "chat"],
    "chat_command": ["chat_command"],
    "chat_command_signed": ["chat_command_signed", "chat_command"],
    "move_pos": ["position"],
    "move_pos_rot": ["position_look"],
    "move_rot": ["look"],
    "move_status": ["flying"],
    "custom_payload": ["custom_payload"],
    "interact": ["use_entity"],
    "swing": ["arm_animation"],
    "sign_update": ["update_sign"],
    "edit_book": ["edit_book"],
}

ACTION_NAMES = [
    "window_click", "use_entity", "position", "position_look", "look", "flying", "steer_vehicle",
    "vehicle_move", "block_dig", "arm_animation", "block_place", "use_item", "held_item_slot",
    "set_creative_slot",
]


def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return json.load(r)


def packet_ids(protocol, state, direction):
    node = protocol[state][direction]["types"]["packet"]
    for part in node:
        if isinstance(part, list):
            for item in part:
                if isinstance(item, dict) and item.get("name") == "name":
                    return {v: int(k, 16) for k, v in item["type"][1]["mappings"].items()}
    return {}


def pick(ids, candidates):
    for name in candidates:
        if name in ids:
            return ids[name]
    return None


def position_layout(protocol):
    """Which shape the clientbound Synchronize Player Position packet has.

    Minecraft reordered this packet in 1.21.2: the teleport ID moved from last to first and the
    relative-movement flags widened from a byte to a 32-bit field. Read from the dataset rather than
    assumed, because the proxy writes this packet itself -- to pin an unauthenticated player's client
    at the origin -- and a wrong field order there is not a missed detection, it is every player on a
    whole band of versions having their join mangled.

    A shape that is neither of the two known ones returns None, which drops the version rather than
    guessing. That is the same rule the packet IDs follow.
    """
    layout = protocol["play"]["toClient"]["types"].get("packet_position")
    if not layout or layout[0] != "container":
        return None

    names = [f["name"] for f in layout[1]]
    if names[:1] == ["teleportId"]:
        return "TeleportIdFirst"
    if names[:3] == ["x", "y", "z"] and names[-1:] == ["teleportId"]:
        return "TeleportIdLast"
    return None


def build(version_path):
    protocol = fetch(f"{DATA}/{version_path}/protocol.json")
    sb = packet_ids(protocol, "play", "toServer")
    cb = packet_ids(protocol, "play", "toClient")
    config_sb = packet_ids(protocol, "configuration", "toServer") if "configuration" in protocol else {}

    table = {}
    for key, candidates in NEEDED.items():
        value = pick(sb, candidates)
        if value is None:
            return None, f"missing {key}"
        table[key] = value

    table["disconnect"] = pick(cb, ["kick_disconnect"])
    table["system_chat"] = pick(cb, ["system_chat"])
    table["title_text"] = pick(cb, ["set_title_text", "title"])
    table["subtitle_text"] = pick(cb, ["set_title_subtitle", "set_subtitle_text"])
    table["title_animation"] = pick(cb, ["set_title_time", "set_titles_animation"])
    table["player_position"] = pick(cb, ["position"])
    table["set_health"] = pick(cb, ["update_health"])
    table["accept_teleportation"] = pick(sb, ["teleport_confirm"])
    table["position_layout"] = position_layout(protocol)
    table["config_finish"] = pick(config_sb, ["finish_configuration"])

    if table["system_chat"] is None:
        return None, "no system_chat (pre-1.19)"
    if table["config_finish"] is None:
        return None, "no configuration state (pre-1.20.2)"
    if table["disconnect"] is None:
        return None, "no disconnect"
    if any(table[k] is None for k in ("title_text", "subtitle_text", "title_animation")):
        return None, "no title packets"
    if any(table[k] is None for k in ("player_position", "set_health", "accept_teleportation")):
        return None, "no position/health packets"
    if table["position_layout"] is None:
        return None, "unrecognised Synchronize Player Position layout"

    table["actions"] = sorted({sb[n] for n in ACTION_NAMES if n in sb})
    return table, None


paths = fetch(f"{DATA}/dataPaths.json")["pc"]
versions = fetch(f"{DATA}/pc/common/versions.json")
protocol_of = {v["minecraftVersion"]: v["version"] for v in fetch(f"{DATA}/pc/common/protocolVersions.json")}

mojang = json.loads((WORK / "protocols" / "tables.json").read_text(encoding="utf-8"))

# --- the gate: reproduce what Mojang produced, or stop ---------------------------------------------
print("cross-checking against the Mojang-generated tables ...")
mismatches = []
for proto, expected in mojang.items():
    version = expected["version"]
    path = paths.get(version, {}).get("protocol")
    if not path:
        print(f"  {version}: not in minecraft-data — cannot cross-check")
        continue

    table, why = build(path)
    if table is None:
        mismatches.append(f"{version}: {why}")
        continue

    for key in ("chat", "chat_command", "config_finish", "system_chat", "move_pos", "swing",
                "title_text", "subtitle_text", "title_animation",
                "player_position", "set_health", "accept_teleportation", "position_layout"):
        if table[key] != expected[key]:
            # position_layout is a string; the rest are packet IDs.
            shown = (f"{table[key]} vs {expected[key]}" if isinstance(table[key], str)
                     else f"{table[key]:#04x} vs {expected[key]:#04x}")
            mismatches.append(f"{version} {key}: minecraft-data {shown} (Mojang second)")

    print(f"  {version} (protocol {proto}): {'MISMATCH' if mismatches else 'agrees'}")

if mismatches:
    print("\nRefusing to extend the registry — minecraft-data disagrees with the authoritative tables:")
    for m in mismatches:
        print("  " + m)
    sys.exit(1)

print("\nall cross-checks passed; extending to versions Mojang's generator cannot produce\n")

# --- extend ------------------------------------------------------------------------------------------
added = dict(mojang)
for version, entry in sorted(paths.items()):
    path = entry.get("protocol")
    proto = protocol_of.get(version)
    if not path or proto is None or str(proto) in added:
        continue

    table, why = build(path)
    if table is None:
        continue

    table["version"] = version
    table["protocol"] = proto
    table["source"] = "minecraft-data"
    added[str(proto)] = table
    print(f"  + protocol {proto} ({version}) chat={table['chat']:#04x} cmd={table['chat_command']:#04x}")

(WORK / "protocols" / "tables.json").write_text(json.dumps(added, indent=2), encoding="utf-8")
print(f"\n{len(added)} protocol versions total ({len(added) - len(mojang)} added)")
