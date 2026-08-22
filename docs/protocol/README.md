# Protocol reference data

`packets-774.json` is the **unmodified** `generated/reports/packets.json` produced by running the
real Paper 1.21.11 server jar (protocol version 774) with Mojang's own data-generator flag:

```bash
java -DbundlerMainClass=net.minecraft.data.Main -jar paper.jar --reports
```

This is the authoritative source for packet IDs for that exact version — straight from the game's own
code, not a wiki summary or something recalled from memory. It's why `ProtocolVersionRegistry` in
`MinecraftFirewall.Proxy` hardcodes numeric packet IDs only for protocol 774: those are the only ones
this project has actually verified this way. Cross-checked live too: `tools/MinecraftFirewall.ProtocolSpike`
walked a real connection through Handshake → Login → Configuration → Play against the same server (see
its `Program.cs`) and every packet ID it observed on the wire (Login Success `0x02`, Set Compression
`0x03`, Known Packs `0x0E`/`0x07`, Finish Configuration `0x03`, the Play `login` packet `0x30`, ...)
matched this file exactly.

**When you need to support a new Minecraft version:** run a server jar for that version with the same
`--reports` flag, diff the new `packets.json` against this one for the packets
`ProtocolVersionRegistry` actually cares about (see that file for the current list — mainly Login
Compression/Success, Configuration Finish/Known Packs, and Play Disconnect/Chat/Chat Command), and add
a new entry to the registry. Don't extrapolate IDs from a nearby version by pattern — this project
already caught one real case (see below) where a single Configuration-state field addition shifted the
Play-state serverbound chat/command IDs between two versions only two protocol numbers apart.

**One thing this caught in practice:** the current minecraft.wiki protocol page (as fetched during this
project's Stage 2 work) documented protocol 776 with Chat Message = `0x09`, Chat Command = `0x07`. The
actual protocol-774 report here says Chat = `0x08`, Chat Command = `0x06`. Different by one across two
point releases — confirming why per-version verification isn't optional.
