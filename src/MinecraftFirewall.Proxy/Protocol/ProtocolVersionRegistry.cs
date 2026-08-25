namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>
/// Which shape the clientbound Synchronize Player Position packet has for a given version.
///
/// Minecraft reordered it in 1.21.2 (protocol 768): the teleport ID moved from the last field to the
/// first, and the relative-movement flags widened from one byte to a 32-bit bitfield. This matters
/// because the proxy writes this packet itself rather than only reading it — it is how an
/// unauthenticated player's client is pinned at the origin — and a wrong field order would not be a
/// missed detection but a mangled join for every player on a whole band of versions.
///
/// Never inferred at runtime: it comes out of the same generated tables as the packet IDs, where
/// tools/extend-protocol-tables.py reads the real layout from minecraft-data and refuses to produce
/// a registry at all if it disagrees with the rule the Mojang-side generator applies.
/// </summary>
public enum PositionLayout
{
    /// <summary>Protocols 764–767: x, y, z, yaw, pitch, byte flags, then the teleport ID.</summary>
    TeleportIdLast,

    /// <summary>Protocol 768 and later: teleport ID, x, y, z, delta x/y/z, yaw, pitch, int flags.</summary>
    TeleportIdFirst,
}

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
    int PlayTitleTextClientbound,
    int PlaySubtitleTextClientbound,
    int PlayTitleAnimationClientbound,
    int PlayPlayerPositionClientbound,
    int PlaySetHealthClientbound,
    int PlayAcceptTeleportationServerbound,
    PositionLayout PositionLayout,
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
/// never extrapolated from a nearby version. The generated tables below show exactly why: serverbound
/// chat is 0x06 on protocol 767, 0x07 on 768-770 and 0x08 from 771, and clientbound system chat moves
/// four times across the same range. An unrecognized version means "stop inspecting, keep proxying at
/// the frame level" — never a best-guess fallback.
/// </summary>
public static class ProtocolVersionRegistry
{
    /// <summary>
    /// Every protocol version whose packet IDs this project has actually verified, generated by
    /// running each version's own server jar with Mojang's data generator. Regenerate with
    /// tools/generate-protocol-tables.py when a new Minecraft release comes out.
    ///
    /// Currently: 1.21 (767), 1.21.2 (768), 1.21.4 (769), 1.21.5 (770), 1.21.6 (771), 1.21.7 (772), 1.21.10 (773), 1.21.11 (774).
    /// </summary>
    /// <summary>
    /// Every protocol version whose packet IDs this project has actually verified, generated by
    /// running each version's own server jar with Mojang's data generator. Regenerate with
    /// tools/generate-protocol-tables.py when a new Minecraft release comes out.
    ///
    /// Currently: 1.20.2 (764), 1.20.3 (765), 1.20.5 (766), 1.21 (767), 1.21.2 (768), 1.21.4 (769), 1.21.5 (770), 1.21.6 (771), 1.21.7 (772), 1.21.10 (773), 1.21.11 (774), 26.1 (775).
    /// </summary>
    /// <summary>
    /// Every protocol version whose packet IDs this project has actually verified, generated by
    /// running each version's own server jar with Mojang's data generator. Regenerate with
    /// tools/generate-protocol-tables.py when a new Minecraft release comes out.
    ///
    /// Currently: 1.21 (767), 1.21.2 (768), 1.21.4 (769), 1.21.5 (770), 1.21.6 (771), 1.21.7 (772), 1.21.10 (773), 1.21.11 (774).
    /// </summary>
    /// <summary>
    /// Every protocol version whose packet IDs this project has actually verified, generated by
    /// running each version's own server jar with Mojang's data generator. Regenerate with
    /// tools/generate-protocol-tables.py when a new Minecraft release comes out.
    ///
    /// Currently: 1.20.2 (764), 1.20.3 (765), 1.20.5 (766), 1.21 (767), 1.21.2 (768), 1.21.4 (769), 1.21.5 (770), 1.21.6 (771), 1.21.7 (772), 1.21.10 (773), 1.21.11 (774), 26.1 (775).
    /// </summary>
    /// <summary>
    /// Every protocol version whose packet IDs this project has actually verified, generated by
    /// running each version's own server jar with Mojang's data generator. Regenerate with
    /// tools/generate-protocol-tables.py when a new Minecraft release comes out.
    ///
    /// Currently: 1.20.2 (764), 1.20.3 (765), 1.20.5 (766), 1.21 (767), 1.21.2 (768), 1.21.4 (769), 1.21.5 (770), 1.21.6 (771), 1.21.7 (772), 1.21.10 (773), 1.21.11 (774), 26.1 (775).
    /// </summary>
    private static readonly Dictionary<int, PlayStatePacketIds> Versions = new()
    {
        // Protocol 764 = Minecraft 1.20.2. Sourced from
        // docs/protocol/packets-764.json, the unmodified report that version's own server
        // jar produced.
        [764] = new PlayStatePacketIds(
            ConfigurationFinishConfigurationServerbound: 0x02,
            PlayChatServerbound: 0x05,
            PlayChatCommandServerbound: 0x04,
            PlayChatCommandSignedServerbound: 0x04,
            PlayDisconnectClientbound: 0x1B,
            PlayMovePlayerPosServerbound: 0x16,
            PlayMovePlayerPosRotServerbound: 0x17,
            PlayMovePlayerRotServerbound: 0x18,
            PlayMovePlayerStatusOnlyServerbound: 0x19,
            PlayCustomPayloadServerbound: 0x0F,
            PlayInteractServerbound: 0x12,
            PlaySwingServerbound: 0x32,
            PlaySignUpdateServerbound: 0x31,
            PlayEditBookServerbound: 0x10,
            PlaySystemChatClientbound: 0x67,
            PlayTitleTextClientbound: 0x61,
            PlaySubtitleTextClientbound: 0x5F,
            PlayTitleAnimationClientbound: 0x62,
            PlayPlayerPositionClientbound: 0x3E,
            PlaySetHealthClientbound: 0x59,
            PlayAcceptTeleportationServerbound: 0x00,
            PositionLayout: PositionLayout.TeleportIdLast,
            PlayActionServerbound: [0x0D, 0x12, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x20, 0x22, 0x2B, 0x2E, 0x32, 0x34, 0x35]),
        // Protocol 765 = Minecraft 1.20.3. Sourced from
        // docs/protocol/packets-765.json, the unmodified report that version's own server
        // jar produced.
        [765] = new PlayStatePacketIds(
            ConfigurationFinishConfigurationServerbound: 0x02,
            PlayChatServerbound: 0x05,
            PlayChatCommandServerbound: 0x04,
            PlayChatCommandSignedServerbound: 0x04,
            PlayDisconnectClientbound: 0x1B,
            PlayMovePlayerPosServerbound: 0x17,
            PlayMovePlayerPosRotServerbound: 0x18,
            PlayMovePlayerRotServerbound: 0x19,
            PlayMovePlayerStatusOnlyServerbound: 0x1A,
            PlayCustomPayloadServerbound: 0x10,
            PlayInteractServerbound: 0x13,
            PlaySwingServerbound: 0x33,
            PlaySignUpdateServerbound: 0x32,
            PlayEditBookServerbound: 0x11,
            PlaySystemChatClientbound: 0x69,
            PlayTitleTextClientbound: 0x63,
            PlaySubtitleTextClientbound: 0x61,
            PlayTitleAnimationClientbound: 0x64,
            PlayPlayerPositionClientbound: 0x3E,
            PlaySetHealthClientbound: 0x5B,
            PlayAcceptTeleportationServerbound: 0x00,
            PositionLayout: PositionLayout.TeleportIdLast,
            PlayActionServerbound: [0x0D, 0x13, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x21, 0x23, 0x2C, 0x2F, 0x33, 0x35, 0x36]),
        // Protocol 766 = Minecraft 1.20.5. Sourced from
        // docs/protocol/packets-766.json, the unmodified report that version's own server
        // jar produced.
        [766] = new PlayStatePacketIds(
            ConfigurationFinishConfigurationServerbound: 0x03,
            PlayChatServerbound: 0x06,
            PlayChatCommandServerbound: 0x04,
            PlayChatCommandSignedServerbound: 0x05,
            PlayDisconnectClientbound: 0x1D,
            PlayMovePlayerPosServerbound: 0x1A,
            PlayMovePlayerPosRotServerbound: 0x1B,
            PlayMovePlayerRotServerbound: 0x1C,
            PlayMovePlayerStatusOnlyServerbound: 0x1D,
            PlayCustomPayloadServerbound: 0x12,
            PlayInteractServerbound: 0x16,
            PlaySwingServerbound: 0x36,
            PlaySignUpdateServerbound: 0x35,
            PlayEditBookServerbound: 0x14,
            PlaySystemChatClientbound: 0x6C,
            PlayTitleTextClientbound: 0x65,
            PlaySubtitleTextClientbound: 0x63,
            PlayTitleAnimationClientbound: 0x66,
            PlayPlayerPositionClientbound: 0x40,
            PlaySetHealthClientbound: 0x5D,
            PlayAcceptTeleportationServerbound: 0x00,
            PositionLayout: PositionLayout.TeleportIdLast,
            PlayActionServerbound: [0x0E, 0x16, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x24, 0x26, 0x2F, 0x32, 0x36, 0x38, 0x39]),
        // Protocol 767 = Minecraft 1.21. Sourced from
        // docs/protocol/packets-767.json, the unmodified report that version's own server
        // jar produced.
        [767] = new PlayStatePacketIds(
            ConfigurationFinishConfigurationServerbound: 0x03,
            PlayChatServerbound: 0x06,
            PlayChatCommandServerbound: 0x04,
            PlayChatCommandSignedServerbound: 0x05,
            PlayDisconnectClientbound: 0x1D,
            PlayMovePlayerPosServerbound: 0x1A,
            PlayMovePlayerPosRotServerbound: 0x1B,
            PlayMovePlayerRotServerbound: 0x1C,
            PlayMovePlayerStatusOnlyServerbound: 0x1D,
            PlayCustomPayloadServerbound: 0x12,
            PlayInteractServerbound: 0x16,
            PlaySwingServerbound: 0x36,
            PlaySignUpdateServerbound: 0x35,
            PlayEditBookServerbound: 0x14,
            PlaySystemChatClientbound: 0x6C,
            PlayTitleTextClientbound: 0x65,
            PlaySubtitleTextClientbound: 0x63,
            PlayTitleAnimationClientbound: 0x66,
            PlayPlayerPositionClientbound: 0x40,
            PlaySetHealthClientbound: 0x5D,
            PlayAcceptTeleportationServerbound: 0x00,
            PositionLayout: PositionLayout.TeleportIdLast,
            PlayActionServerbound: [0x0E, 0x16, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x24, 0x26, 0x2F, 0x32, 0x36, 0x38, 0x39]),
        // Protocol 768 = Minecraft 1.21.2. Sourced from
        // docs/protocol/packets-768.json, the unmodified report that version's own server
        // jar produced.
        [768] = new PlayStatePacketIds(
            ConfigurationFinishConfigurationServerbound: 0x03,
            PlayChatServerbound: 0x07,
            PlayChatCommandServerbound: 0x05,
            PlayChatCommandSignedServerbound: 0x06,
            PlayDisconnectClientbound: 0x1D,
            PlayMovePlayerPosServerbound: 0x1C,
            PlayMovePlayerPosRotServerbound: 0x1D,
            PlayMovePlayerRotServerbound: 0x1E,
            PlayMovePlayerStatusOnlyServerbound: 0x1F,
            PlayCustomPayloadServerbound: 0x14,
            PlayInteractServerbound: 0x18,
            PlaySwingServerbound: 0x38,
            PlaySignUpdateServerbound: 0x37,
            PlayEditBookServerbound: 0x16,
            PlaySystemChatClientbound: 0x73,
            PlayTitleTextClientbound: 0x6C,
            PlaySubtitleTextClientbound: 0x6A,
            PlayTitleAnimationClientbound: 0x6D,
            PlayPlayerPositionClientbound: 0x42,
            PlaySetHealthClientbound: 0x62,
            PlayAcceptTeleportationServerbound: 0x00,
            PositionLayout: PositionLayout.TeleportIdFirst,
            PlayActionServerbound: [0x10, 0x18, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x26, 0x28, 0x31, 0x34, 0x38, 0x3A, 0x3B]),
        // Protocol 769 = Minecraft 1.21.4. Sourced from
        // docs/protocol/packets-769.json, the unmodified report that version's own server
        // jar produced.
        [769] = new PlayStatePacketIds(
            ConfigurationFinishConfigurationServerbound: 0x03,
            PlayChatServerbound: 0x07,
            PlayChatCommandServerbound: 0x05,
            PlayChatCommandSignedServerbound: 0x06,
            PlayDisconnectClientbound: 0x1D,
            PlayMovePlayerPosServerbound: 0x1C,
            PlayMovePlayerPosRotServerbound: 0x1D,
            PlayMovePlayerRotServerbound: 0x1E,
            PlayMovePlayerStatusOnlyServerbound: 0x1F,
            PlayCustomPayloadServerbound: 0x14,
            PlayInteractServerbound: 0x18,
            PlaySwingServerbound: 0x3A,
            PlaySignUpdateServerbound: 0x39,
            PlayEditBookServerbound: 0x16,
            PlaySystemChatClientbound: 0x73,
            PlayTitleTextClientbound: 0x6C,
            PlaySubtitleTextClientbound: 0x6A,
            PlayTitleAnimationClientbound: 0x6D,
            PlayPlayerPositionClientbound: 0x42,
            PlaySetHealthClientbound: 0x62,
            PlayAcceptTeleportationServerbound: 0x00,
            PositionLayout: PositionLayout.TeleportIdFirst,
            PlayActionServerbound: [0x10, 0x18, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x27, 0x29, 0x33, 0x36, 0x3A, 0x3C, 0x3D]),
        // Protocol 770 = Minecraft 1.21.5. Sourced from
        // docs/protocol/packets-770.json, the unmodified report that version's own server
        // jar produced.
        [770] = new PlayStatePacketIds(
            ConfigurationFinishConfigurationServerbound: 0x03,
            PlayChatServerbound: 0x07,
            PlayChatCommandServerbound: 0x05,
            PlayChatCommandSignedServerbound: 0x06,
            PlayDisconnectClientbound: 0x1C,
            PlayMovePlayerPosServerbound: 0x1C,
            PlayMovePlayerPosRotServerbound: 0x1D,
            PlayMovePlayerRotServerbound: 0x1E,
            PlayMovePlayerStatusOnlyServerbound: 0x1F,
            PlayCustomPayloadServerbound: 0x14,
            PlayInteractServerbound: 0x18,
            PlaySwingServerbound: 0x3B,
            PlaySignUpdateServerbound: 0x3A,
            PlayEditBookServerbound: 0x16,
            PlaySystemChatClientbound: 0x72,
            PlayTitleTextClientbound: 0x6B,
            PlaySubtitleTextClientbound: 0x69,
            PlayTitleAnimationClientbound: 0x6C,
            PlayPlayerPositionClientbound: 0x41,
            PlaySetHealthClientbound: 0x61,
            PlayAcceptTeleportationServerbound: 0x00,
            PositionLayout: PositionLayout.TeleportIdFirst,
            PlayActionServerbound: [0x10, 0x18, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x27, 0x29, 0x33, 0x36, 0x3B, 0x3E, 0x3F]),
        // Protocol 771 = Minecraft 1.21.6. Sourced from
        // docs/protocol/packets-771.json, the unmodified report that version's own server
        // jar produced.
        [771] = new PlayStatePacketIds(
            ConfigurationFinishConfigurationServerbound: 0x03,
            PlayChatServerbound: 0x08,
            PlayChatCommandServerbound: 0x06,
            PlayChatCommandSignedServerbound: 0x07,
            PlayDisconnectClientbound: 0x1C,
            PlayMovePlayerPosServerbound: 0x1D,
            PlayMovePlayerPosRotServerbound: 0x1E,
            PlayMovePlayerRotServerbound: 0x1F,
            PlayMovePlayerStatusOnlyServerbound: 0x20,
            PlayCustomPayloadServerbound: 0x15,
            PlayInteractServerbound: 0x19,
            PlaySwingServerbound: 0x3C,
            PlaySignUpdateServerbound: 0x3B,
            PlayEditBookServerbound: 0x17,
            PlaySystemChatClientbound: 0x72,
            PlayTitleTextClientbound: 0x6B,
            PlaySubtitleTextClientbound: 0x69,
            PlayTitleAnimationClientbound: 0x6C,
            PlayPlayerPositionClientbound: 0x41,
            PlaySetHealthClientbound: 0x61,
            PlayAcceptTeleportationServerbound: 0x00,
            PositionLayout: PositionLayout.TeleportIdFirst,
            PlayActionServerbound: [0x11, 0x19, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x28, 0x2A, 0x34, 0x37, 0x3C, 0x3F, 0x40]),
        // Protocol 772 = Minecraft 1.21.7. Sourced from
        // docs/protocol/packets-772.json, the unmodified report that version's own server
        // jar produced.
        [772] = new PlayStatePacketIds(
            ConfigurationFinishConfigurationServerbound: 0x03,
            PlayChatServerbound: 0x08,
            PlayChatCommandServerbound: 0x06,
            PlayChatCommandSignedServerbound: 0x07,
            PlayDisconnectClientbound: 0x1C,
            PlayMovePlayerPosServerbound: 0x1D,
            PlayMovePlayerPosRotServerbound: 0x1E,
            PlayMovePlayerRotServerbound: 0x1F,
            PlayMovePlayerStatusOnlyServerbound: 0x20,
            PlayCustomPayloadServerbound: 0x15,
            PlayInteractServerbound: 0x19,
            PlaySwingServerbound: 0x3C,
            PlaySignUpdateServerbound: 0x3B,
            PlayEditBookServerbound: 0x17,
            PlaySystemChatClientbound: 0x72,
            PlayTitleTextClientbound: 0x6B,
            PlaySubtitleTextClientbound: 0x69,
            PlayTitleAnimationClientbound: 0x6C,
            PlayPlayerPositionClientbound: 0x41,
            PlaySetHealthClientbound: 0x61,
            PlayAcceptTeleportationServerbound: 0x00,
            PositionLayout: PositionLayout.TeleportIdFirst,
            PlayActionServerbound: [0x11, 0x19, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x28, 0x2A, 0x34, 0x37, 0x3C, 0x3F, 0x40]),
        // Protocol 773 = Minecraft 1.21.10. Sourced from
        // docs/protocol/packets-773.json, the unmodified report that version's own server
        // jar produced.
        [773] = new PlayStatePacketIds(
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
            PlayTitleTextClientbound: 0x70,
            PlaySubtitleTextClientbound: 0x6E,
            PlayTitleAnimationClientbound: 0x71,
            PlayPlayerPositionClientbound: 0x46,
            PlaySetHealthClientbound: 0x66,
            PlayAcceptTeleportationServerbound: 0x00,
            PositionLayout: PositionLayout.TeleportIdFirst,
            PlayActionServerbound: [0x11, 0x19, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x28, 0x2A, 0x34, 0x37, 0x3C, 0x3F, 0x40]),
        // Protocol 774 = Minecraft 1.21.11. Sourced from
        // docs/protocol/packets-774.json, the unmodified report that version's own server
        // jar produced.
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
            PlayTitleTextClientbound: 0x70,
            PlaySubtitleTextClientbound: 0x6E,
            PlayTitleAnimationClientbound: 0x71,
            PlayPlayerPositionClientbound: 0x46,
            PlaySetHealthClientbound: 0x66,
            PlayAcceptTeleportationServerbound: 0x00,
            PositionLayout: PositionLayout.TeleportIdFirst,
            PlayActionServerbound: [0x11, 0x19, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x28, 0x2A, 0x34, 0x37, 0x3C, 0x3F, 0x40]),
        // Protocol 775 = Minecraft 26.1. Sourced from
        // docs/protocol/packets-775.json, the unmodified report that version's own server
        // jar produced.
        [775] = new PlayStatePacketIds(
            ConfigurationFinishConfigurationServerbound: 0x03,
            PlayChatServerbound: 0x09,
            PlayChatCommandServerbound: 0x07,
            PlayChatCommandSignedServerbound: 0x08,
            PlayDisconnectClientbound: 0x20,
            PlayMovePlayerPosServerbound: 0x1E,
            PlayMovePlayerPosRotServerbound: 0x1F,
            PlayMovePlayerRotServerbound: 0x20,
            PlayMovePlayerStatusOnlyServerbound: 0x21,
            PlayCustomPayloadServerbound: 0x16,
            PlayInteractServerbound: 0x1A,
            PlaySwingServerbound: 0x3F,
            PlaySignUpdateServerbound: 0x3D,
            PlayEditBookServerbound: 0x18,
            PlaySystemChatClientbound: 0x79,
            PlayTitleTextClientbound: 0x72,
            PlaySubtitleTextClientbound: 0x70,
            PlayTitleAnimationClientbound: 0x73,
            PlayPlayerPositionClientbound: 0x48,
            PlaySetHealthClientbound: 0x68,
            PlayAcceptTeleportationServerbound: 0x00,
            PositionLayout: PositionLayout.TeleportIdFirst,
            PlayActionServerbound: [0x12, 0x1A, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x29, 0x35, 0x38, 0x3F, 0x42, 0x43]),
    };

    /// <summary>
    /// Which Minecraft release each compiled-in protocol number belongs to.
    ///
    /// Only used to cross-check a fetched dataset against these tables — the learner needs to ask that
    /// dataset about "1.21.6" rather than about "771". Generated alongside the tables above.
    /// </summary>
    private static readonly Dictionary<int, string> BuiltInVersionNames = new()
    {
        [764] = "1.20.2",
        [765] = "1.20.3",
        [766] = "1.20.5",
        [767] = "1.21",
        [768] = "1.21.2",
        [769] = "1.21.4",
        [770] = "1.21.5",
        [771] = "1.21.6",
        [772] = "1.21.7",
        [773] = "1.21.10",
        [774] = "1.21.11",
        [775] = "26.1",
    };

    /// <summary>
    /// Tables the firewall taught itself at runtime for versions this build was never given.
    ///
    /// Separate from <see cref="Versions"/> rather than merged into it, and that separation is what
    /// makes the whole arrangement checkable: the compiled-in tables came from Mojang's own data
    /// generator and are the reference every learned table is validated against, so nothing learned is
    /// ever allowed to overwrite one. See ProtocolLearningService.
    /// </summary>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<int, PlayStatePacketIds> Learned = new();

    public static bool TryGet(int protocolVersion, out PlayStatePacketIds ids) =>
        Versions.TryGetValue(protocolVersion, out ids!) || Learned.TryGetValue(protocolVersion, out ids!);

    /// <summary>Looks only at what was compiled in, ignoring anything learned. The learner uses this
    /// to compare a fetched dataset against ground truth.</summary>
    public static bool TryGetBuiltIn(int protocolVersion, out PlayStatePacketIds ids) =>
        Versions.TryGetValue(protocolVersion, out ids!);

    public static bool IsBuiltIn(int protocolVersion) => Versions.ContainsKey(protocolVersion);

    public static string? BuiltInVersionName(int protocolVersion) =>
        BuiltInVersionNames.GetValueOrDefault(protocolVersion);

    public static IReadOnlyCollection<int> BuiltInProtocols => Versions.Keys;

    /// <summary>Installs a learned table. Refuses to shadow a compiled-in one — see
    /// <see cref="Learned"/> for why that refusal is the point rather than a precaution.</summary>
    public static bool AddLearned(int protocolVersion, PlayStatePacketIds ids)
    {
        if (Versions.ContainsKey(protocolVersion))
            return false;

        Learned[protocolVersion] = ids;
        return true;
    }

    /// <summary>Every protocol this instance can inspect right now, learned ones included, for a log
    /// line that tells an admin where they stand rather than only what went wrong.</summary>
    public static string SupportedVersionsDescription =>
        string.Join(", ", Versions.Keys.Concat(Learned.Keys).Distinct().Order());

    public static IReadOnlyCollection<int> SupportedVersions => [.. Versions.Keys.Concat(Learned.Keys).Distinct()];

    public static IReadOnlyCollection<int> LearnedProtocols => [.. Learned.Keys];
}
