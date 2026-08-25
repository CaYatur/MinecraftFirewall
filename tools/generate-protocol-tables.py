"""Generates authoritative packet tables for Minecraft releases, for ProtocolVersionRegistry.

    python tools/generate-protocol-tables.py <work-dir>
    python tools/apply-protocol-tables.py <work-dir>

The first downloads each version's own server jar, runs Mojang's data generator, and writes
tables.json. The second rewrites ProtocolVersionRegistry.cs from it. Run both when a new Minecraft
version comes out; the jars are cached in the work directory, so a rerun only fetches what is new.

Note the floor: `packets.json` did not exist as a generated report before 1.21. Versions older than
that cannot be covered this way, and this project does not guess packet IDs — see
docs/protocol/README.md for what that rule has already caught.

The project's rule, written into docs/protocol/README.md and earned the hard way, is that packet IDs
are never extrapolated from a nearby version — a single Configuration-state field addition once
shifted the Play-state chat IDs between two versions only two protocol numbers apart. So each version
gets its own report, produced by that version's own server jar running Mojang's data generator.
"""
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

WORK = Path(sys.argv[1])
WORK.mkdir(parents=True, exist_ok=True)

MANIFEST = "https://launchermeta.mojang.com/mc/game/version_manifest_v2.json"


def fetch_json(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return json.load(r)


manifest = fetch_json(MANIFEST)
PREFIXES = ("1.19", "1.20", "1.21")
releases = [v for v in manifest["versions"]
            if v["type"] == "release" and any(v["id"].startswith(pre) for pre in PREFIXES)]

results = {}

for entry in sorted(releases, key=lambda v: v["id"]):
    version = entry["id"]
    out = WORK / version
    packets = out / "generated" / "reports" / "packets.json"
    jar = WORK / f"server-{version}.jar"

    if not packets.exists():
        meta = fetch_json(entry["url"])
        server = meta.get("downloads", {}).get("server")
        if not server:
            print(f"{version}: no server download listed, skipping")
            continue

        if not jar.exists():
            print(f"{version}: downloading server jar ...", flush=True)
            urllib.request.urlretrieve(server["url"], jar)

        out.mkdir(parents=True, exist_ok=True)
        print(f"{version}: generating reports ...", flush=True)
        proc = subprocess.run(
            ["java", "-DbundlerMainClass=net.minecraft.data.Main", "-jar", str(jar), "--reports"],
            cwd=out, capture_output=True, text=True, timeout=600)

        if not packets.exists():
            print(f"{version}: report generation failed\n{proc.stdout[-600:]}\n{proc.stderr[-600:]}")
            continue

    # The protocol number lives in the jar's own version.json, not in the generated reports.
    protocol = None
    if jar.exists():
        import zipfile
        with zipfile.ZipFile(jar) as z:
            protocol = json.loads(z.read("version.json")).get("protocol_version")

    if protocol is None:
        print(f"{version}: no protocol version in the report, skipping")
        continue

    data = json.loads(packets.read_text(encoding="utf-8"))

    def pid(state, direction, name):
        return data[state][direction][f"minecraft:{name}"]["protocol_id"]

    try:
        table = {
            "version": version,
            "protocol": protocol,
            "config_finish": pid("configuration", "serverbound", "finish_configuration"),
            "chat": pid("play", "serverbound", "chat"),
            "chat_command": pid("play", "serverbound", "chat_command"),
            "chat_command_signed": pid("play", "serverbound", "chat_command_signed"),
            "disconnect": pid("play", "clientbound", "disconnect"),
            "system_chat": pid("play", "clientbound", "system_chat"),
            "title_text": pid("play", "clientbound", "set_title_text"),
            "subtitle_text": pid("play", "clientbound", "set_subtitle_text"),
            "title_animation": pid("play", "clientbound", "set_titles_animation"),
            "player_position": pid("play", "clientbound", "player_position"),
            "set_health": pid("play", "clientbound", "set_health"),
            "accept_teleportation": pid("play", "serverbound", "accept_teleportation"),
            # Mojang's reports carry packet IDs but not field layouts, so this one entry is a rule
            # rather than an observation: Synchronize Player Position was reordered in 1.21.2, moving
            # the teleport ID to the front and widening the relative-movement flags. The rule is not
            # trusted on its own -- extend-protocol-tables.py reads the real layout for every one of
            # these versions out of minecraft-data and refuses to run if the two ever disagree.
            "position_layout": "TeleportIdFirst" if protocol >= 768 else "TeleportIdLast",
            "move_pos": pid("play", "serverbound", "move_player_pos"),
            "move_pos_rot": pid("play", "serverbound", "move_player_pos_rot"),
            "move_rot": pid("play", "serverbound", "move_player_rot"),
            "move_status": pid("play", "serverbound", "move_player_status_only"),
            "custom_payload": pid("play", "serverbound", "custom_payload"),
            "interact": pid("play", "serverbound", "interact"),
            "swing": pid("play", "serverbound", "swing"),
            "sign_update": pid("play", "serverbound", "sign_update"),
            "edit_book": pid("play", "serverbound", "edit_book"),
            "actions": sorted({
                pid("play", "serverbound", n) for n in (
                    "container_click", "interact", "move_player_pos", "move_player_pos_rot",
                    "move_player_rot", "move_player_status_only", "move_vehicle", "player_action",
                    "player_input", "set_carried_item", "set_creative_mode_slot", "swing",
                    "use_item_on", "use_item")
            }),
        }
    except KeyError as e:
        print(f"{version} (protocol {protocol}): missing packet {e} — skipping")
        continue

    if protocol in results:
        # Two releases sharing a protocol number must agree, or the number does not identify a wire
        # format and the whole registry premise is wrong.
        if results[protocol] != {**table, "version": results[protocol]["version"]}:
            print(f"!! protocol {protocol}: {version} disagrees with {results[protocol]['version']}")
        continue

    results[protocol] = table
    print(f"{version}: protocol {protocol}  chat={table['chat']:#04x} cmd={table['chat_command']:#04x} "
          f"finish={table['config_finish']:#04x} syschat={table['system_chat']:#04x}", flush=True)

(WORK / "tables.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
print(f"\n{len(results)} distinct protocol versions written to tables.json")
