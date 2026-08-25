namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>Packet IDs a specific protocol version needs for Play-state inspection. Configuration's
/// Finish Configuration (serverbound) is included too — it's the client's Play-state entry marker.</summary>
public sealed record PlayStatePacketIds(
    int ConfigurationFinishConfigurationServerbound,
    int PlayChatServerbound,
    int PlayChatCommandServerbound,
    int PlayChatCommandSignedServerbound,
    int PlayDisconnectClientbound,
    int PlayMovePlayerPosServerbound,
    int PlayMovePlayerPosRotServerbound,
    int PlayMovePlayerRotServerbound,
    int PlayMovePlayerStatusOnlyServerbound,
    int PlayCustomPayloadServerbound,
    int PlayInteractServerbound,
    int PlaySwingServerbound,
    int PlaySignUpdateServerbound,
    int PlayEditBookServerbound,
    int PlaySystemChatClientbound,
    int[] PlayActionServerbound)
{
    /// <summary>True for any of the four serverbound movement packets — the ones carrying coordinates
    /// a malformed or hostile client can use to upset a server, and the ones a movement cheat has to
    /// send in order to cheat.</summary>
    public bool IsMovement(int packetId) =>
        packetId == PlayMovePlayerPosServerbound ||
        packetId == PlayMovePlayerPosRotServerbound ||
        packetId == PlayMovePlayerRotServerbound ||
        packetId == PlayMovePlayerStatusOnlyServerbound;

    /// <summary>
    /// True for the packets that let a player act on the world: moving, hitting, placing, opening
    /// containers, using items.
    ///
    /// A blocklist rather than an allowlist, and deliberately so. Holding a player still while they
    /// authenticate means refusing what they *do*, not refusing everything — a connection that stops
    /// answering keep-alives is disconnected by the backend within thirty seconds, and the player would
    /// see a timeout rather than the password prompt they were sent. Everything not named here keeps
    /// flowing, so the session stays healthy while the player is frozen.
    /// </summary>
    public bool IsPlayerAction(int packetId) => Array.IndexOf(PlayActionServerbound, packetId) >= 0;

    /// <summary>Packets carrying free-form player text. These are what a payload scanner needs to see:
    /// every one of them ends up somewhere that interprets strings — a log line, a plugin, a sign, a
    /// book — which is exactly where a string-injection exploit lands.</summary>
    public bool IsTextCarrying(int packetId) =>
        packetId == PlayChatServerbound ||
        packetId == PlayChatCommandServerbound ||
        packetId == PlayChatCommandSignedServerbound ||
        packetId == PlaySignUpdateServerbound ||
        packetId == PlayEditBookServerbound;
}

/// <summary>
/// Maps a client's declared protocol version to the packet IDs Stage 3 needs to inspect. Every entry
/// here must be sourced from Mojang's own generated data report for that exact version
/// (`java -jar server.jar --reports` → generated/reports/packets.json — see docs/protocol/README.md),
/// never extrapolated from a nearby version: protocol 774 and 776 (two releases apart) already
/// disagreed on these exact IDs during this project's own verification. An unrecognized version means
/// "stop inspecting, keep proxying at the frame level" — never a best-guess fallback.
/// </summary>
public static class ProtocolVersionRegistry
{
    private static readonly Dictionary<int, PlayStatePacketIds> Versions = new()
    {
        // Protocol 774 = Minecraft 1.21.11 (Paper build 1.21.11-57). Sourced from
        // docs/protocol/packets-774.json and cross-verified live via tools/MinecraftFirewall.ProtocolSpike.
        [774] = new PlayStatePacketIds(
            ConfigurationFinishConfigurationServerbound: 0x03,
            PlayChatServerbound: 0x08,
            PlayChatCommandServerbound: 0x06,
            PlayChatCommandSignedServerbound: 0x07,
            PlayDisconnectClientbound: 0x20,
            PlayMovePlayerPosServerbound: 0x1D,
            PlayMovePlayerPosRotServerbound: 0x1E,
            PlayMovePlayerRotServerbound: 0x1F,
            PlayMovePlayerStatusOnlyServerbound: 0x20,
            PlayCustomPayloadServerbound: 0x15,
            PlayInteractServerbound: 0x19,
            PlaySwingServerbound: 0x3C,
            PlaySignUpdateServerbound: 0x3B,
            PlayEditBookServerbound: 0x17,
            PlaySystemChatClientbound: 0x77,
            // Everything that lets a player *do* something in the world. Held back while a connection
            // is waiting to authenticate — see PlayStateInspector.
            PlayActionServerbound:
            [
                0x11, // container_click
                0x19, // interact
                0x1D, // move_player_pos
                0x1E, // move_player_pos_rot
                0x1F, // move_player_rot
                0x20, // move_player_status_only
                0x21, // move_vehicle
                0x28, // player_action
                0x2A, // player_input
                0x34, // set_carried_item
                0x37, // set_creative_mode_slot
                0x3C, // swing
                0x3F, // use_item_on
                0x40, // use_item
            ]),
    };

    public static bool TryGet(int protocolVersion, out PlayStatePacketIds ids) =>
        Versions.TryGetValue(protocolVersion, out ids!);
}
