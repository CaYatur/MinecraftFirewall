namespace MinecraftFirewall.Proxy.Inspection;

/// <summary>
/// Deep inspection of what a client sends after it has been let in.
///
/// The split running through this whole section is between *protocol violations* and *suspicious
/// play*. A coordinate of NaN, a chat string longer than the protocol allows, a plugin message on a
/// channel that is not a valid identifier — these are things no Minecraft client produces, so
/// refusing them costs nobody anything and they are on by default. Moving faster than a player should
/// be able to is a different kind of claim entirely: the proxy has no idea whether that player is on
/// ice, riding a boat, wearing an elytra, holding a riptide trident, or was just teleported by a
/// plugin. Those checks ship switched off, and the reason is written into the option that turns them
/// on.
///
/// Only the client-to-server direction is inspected in depth. That is where an attack on the server
/// comes from, and it is also the direction whose packets are small: an oversized chunk packet is
/// something the server sends to the player, not a way in. The other direction gets a size and rate
/// ceiling and is otherwise relayed byte-for-byte, which keeps a busy server from paying a parsing
/// cost per chunk for no security gain.
/// </summary>
public sealed class InspectionOptions
{
    public const string SectionName = "DeepInspection";

    public bool Enabled { get; set; } = true;

    // ---- protocol violations: on by default -----------------------------------------------------

    /// <summary>
    /// Largest serverbound frame accepted, before decompression.
    ///
    /// Vanilla's own ceiling is 2 MiB in both directions, but that figure exists for the server's
    /// side of the conversation, where a chunk or a map really can be that big. Nothing a client
    /// sends comes close: the largest is a book edit, capped by the game well under 100 KB. 256 KiB
    /// leaves an order of magnitude of headroom over any legitimate use and still refuses the
    /// multi-megabyte frames used to make a server allocate.
    /// </summary>
    public int MaxServerboundFrameBytes { get; set; } = 256 * 1024;

    /// <summary>
    /// Whether packets that are structurally impossible are refused.
    ///
    /// On by default, because none of what this rejects is a judgement call: an interaction type
    /// outside the three that exist, a hand that is neither hand, a negative entity id, a coordinate
    /// that is not a number. A real client has exactly one possible answer in each case, and the
    /// server would otherwise be the thing that has to survive the wrong one — which is the whole
    /// argument for doing this in front of it rather than in a plugin behind it.
    ///
    /// Only layouts that come out of the generated tables are opened, and a packet whose fields do not
    /// decode cleanly is forwarded rather than refused. A mod inventing its own traffic is far likelier
    /// than an attack, and an unverified field offset is never worth a wrong refusal.
    /// </summary>
    public bool RefuseMalformedPackets { get; set; } = true;

    /// <summary>Largest size a single serverbound frame may decompress to. See
    /// CompressedPacketReader for why the compressed and uncompressed sizes need separate limits.</summary>
    public int MaxServerboundUncompressedBytes { get; set; } = 512 * 1024;

    /// <summary>
    /// Largest clientbound frame the proxy will read while it is watching the backend's side.
    ///
    /// Far more generous than the serverbound ceiling, and deliberately so: the two directions carry
    /// completely different traffic. A chunk, a map or a full inventory really can be enormous, and
    /// this side of the connection is being observed rather than policed — the proxy is looking for
    /// two small packets among the backend's replies, not deciding what the backend is allowed to
    /// say. A limit set too low here would not block an attack, it would break joining the server.
    /// </summary>
    public int MaxClientboundFrameBytes { get; set; } = 8 * 1024 * 1024;

    /// <summary>Serverbound packets per second from one connection before it is cut off. A vanilla
    /// client sends about 20 movement packets a second plus occasional others; 200 is roughly ten
    /// times what playing normally produces.</summary>
    public int MaxPacketsPerSecond { get; set; } = 200;

    /// <summary>Serverbound bytes per second from one connection. Generous — a client uploading a
    /// full book barely registers against it — but it bounds a connection that has been let in and
    /// then starts shouting.</summary>
    public int MaxBytesPerSecond { get; set; } = 512 * 1024;

    /// <summary>Refuse chat and command text longer than the protocol permits. Vanilla caps chat at
    /// 256 characters, and anything longer is by definition not a vanilla client.</summary>
    public int MaxChatLength { get; set; } = 256;

    /// <summary>Scan player text for string-injection payloads — the Log4Shell family, which reached
    /// servers through chat and usernames, and its obfuscated variants.</summary>
    public bool ScanForInjectionPayloads { get; set; } = true;

    /// <summary>Largest plugin-message (custom payload) a client may send.</summary>
    public int MaxPluginMessageBytes { get; set; } = 32 * 1024;

    /// <summary>Refuse coordinates that are NaN, infinite, or outside the world border's absolute
    /// limit. These are crash inputs rather than cheats — no client produces them by playing.</summary>
    public bool BlockImpossibleCoordinates { get; set; } = true;

    // ---- movement heuristics: reported, not enforced, unless asked -------------------------------

    /// <summary>Watch movement for speed and flight anomalies and report them.</summary>
    public bool AnalyseMovement { get; set; } = true;

    /// <summary>
    /// Whether a movement anomaly may disconnect the player.
    ///
    /// Off by default, and it should stay off unless you have watched your own server's reports for a
    /// while first. This proxy sees coordinates and nothing else: no blocks, no potion effects, no
    /// vehicles, no elytra, no knockback, no plugin teleports. Ice, a boat, a riptide trident, a speed
    /// potion, a slime-block launcher and a `/tp` all look identical to a cheat from here. Server-side
    /// anti-cheat plugins have the world state to tell them apart; this does not, and a firewall that
    /// kicks legitimate players is worse than no firewall at all.
    /// </summary>
    public bool KickOnMovementAnomaly { get; set; }

    /// <summary>Horizontal blocks per second beyond which movement is reported. A sprinting player
    /// manages about 5.6; the default leaves room for ice, boats and speed effects.</summary>
    public double MaxHorizontalBlocksPerSecond { get; set; } = 22.0;

    /// <summary>Sustained upward blocks per second beyond which movement is reported. Jumping peaks
    /// well under this; sustained ascent without a vehicle does not happen by playing.</summary>
    public double MaxVerticalBlocksPerSecond { get; set; } = 14.0;

    /// <summary>Consecutive anomalous movements before anything is reported, so one lag spike or a
    /// single teleport does not produce a finding.</summary>
    public int MovementAnomaliesBeforeReport { get; set; } = 6;

    /// <summary>Attack (swing plus interact) packets per second beyond which the pattern is reported.
    /// A player clicking as fast as they can manages roughly 15; automation goes far higher.</summary>
    public int MaxAttacksPerSecond { get; set; } = 30;
}
