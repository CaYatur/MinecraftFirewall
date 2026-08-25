using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>One packet table as it is stored on disk. Flat and named, so a person can read the file
/// and see exactly what the firewall believes about a version it taught itself.</summary>
public sealed class LearnedProtocolTable
{
    public int Protocol { get; set; }
    public string MinecraftVersion { get; set; } = "";
    public string Source { get; set; } = "";
    public DateTimeOffset LearnedAt { get; set; }

    public int ConfigFinish { get; set; }
    public int Chat { get; set; }
    public int ChatCommand { get; set; }
    public int ChatCommandSigned { get; set; }
    public int Disconnect { get; set; }
    public int SystemChat { get; set; }
    public int TitleText { get; set; }
    public int SubtitleText { get; set; }
    public int TitleAnimation { get; set; }
    public int PlayerPosition { get; set; }
    public int SetHealth { get; set; }
    public int AcceptTeleportation { get; set; }
    public PositionLayout PositionLayout { get; set; }
    public int MovePos { get; set; }
    public int MovePosRot { get; set; }
    public int MoveRot { get; set; }
    public int MoveStatus { get; set; }
    public int CustomPayload { get; set; }
    public int Interact { get; set; }
    public int Swing { get; set; }
    public int SignUpdate { get; set; }
    public int EditBook { get; set; }
    public int[] Actions { get; set; } = [];

    public PlayStatePacketIds ToPacketIds() => new(
        ConfigurationFinishConfigurationServerbound: ConfigFinish,
        PlayChatServerbound: Chat,
        PlayChatCommandServerbound: ChatCommand,
        PlayChatCommandSignedServerbound: ChatCommandSigned,
        PlayDisconnectClientbound: Disconnect,
        PlayMovePlayerPosServerbound: MovePos,
        PlayMovePlayerPosRotServerbound: MovePosRot,
        PlayMovePlayerRotServerbound: MoveRot,
        PlayMovePlayerStatusOnlyServerbound: MoveStatus,
        PlayCustomPayloadServerbound: CustomPayload,
        PlayInteractServerbound: Interact,
        PlaySwingServerbound: Swing,
        PlaySignUpdateServerbound: SignUpdate,
        PlayEditBookServerbound: EditBook,
        PlaySystemChatClientbound: SystemChat,
        PlayTitleTextClientbound: TitleText,
        PlaySubtitleTextClientbound: SubtitleText,
        PlayTitleAnimationClientbound: TitleAnimation,
        PlayPlayerPositionClientbound: PlayerPosition,
        PlaySetHealthClientbound: SetHealth,
        PlayAcceptTeleportationServerbound: AcceptTeleportation,
        PositionLayout: PositionLayout,
        PlayActionServerbound: Actions);

    /// <summary>Turns a compiled-in table back into this shape, so the learner can compare what a
    /// source claims about a version against what this build already knows for certain.</summary>
    public static LearnedProtocolTable From(int protocol, PlayStatePacketIds ids) => new()
    {
        Protocol = protocol,
        ConfigFinish = ids.ConfigurationFinishConfigurationServerbound,
        Chat = ids.PlayChatServerbound,
        ChatCommand = ids.PlayChatCommandServerbound,
        ChatCommandSigned = ids.PlayChatCommandSignedServerbound,
        Disconnect = ids.PlayDisconnectClientbound,
        SystemChat = ids.PlaySystemChatClientbound,
        TitleText = ids.PlayTitleTextClientbound,
        SubtitleText = ids.PlaySubtitleTextClientbound,
        TitleAnimation = ids.PlayTitleAnimationClientbound,
        PlayerPosition = ids.PlayPlayerPositionClientbound,
        SetHealth = ids.PlaySetHealthClientbound,
        AcceptTeleportation = ids.PlayAcceptTeleportationServerbound,
        PositionLayout = ids.PositionLayout,
        MovePos = ids.PlayMovePlayerPosServerbound,
        MovePosRot = ids.PlayMovePlayerPosRotServerbound,
        MoveRot = ids.PlayMovePlayerRotServerbound,
        MoveStatus = ids.PlayMovePlayerStatusOnlyServerbound,
        CustomPayload = ids.PlayCustomPayloadServerbound,
        Interact = ids.PlayInteractServerbound,
        Swing = ids.PlaySwingServerbound,
        SignUpdate = ids.PlaySignUpdateServerbound,
        EditBook = ids.PlayEditBookServerbound,
        Actions = ids.PlayActionServerbound,
    };

    /// <summary>Compares the fields a mismatch would actually matter for. Used to check a source
    /// against the compiled-in tables before anything it says is believed.</summary>
    public bool MatchesCoreOf(LearnedProtocolTable other) =>
        ConfigFinish == other.ConfigFinish &&
        Chat == other.Chat &&
        ChatCommand == other.ChatCommand &&
        Disconnect == other.Disconnect &&
        SystemChat == other.SystemChat &&
        MovePos == other.MovePos &&
        MovePosRot == other.MovePosRot &&
        Swing == other.Swing &&
        PlayerPosition == other.PlayerPosition &&
        AcceptTeleportation == other.AcceptTeleportation &&
        PositionLayout == other.PositionLayout;
}

/// <summary>
/// Packet tables the firewall taught itself, kept beside its other state so they survive a restart.
///
/// These exist because a Minecraft release should not need a new build of this software. A version
/// nobody has generated a table for is one where protected usernames cannot be defended, and the gap
/// lasts from the release until somebody notices, rebuilds and redeploys — which on a small server is
/// forever.
///
/// Learned tables never override a compiled-in one. The built-in tables were generated from Mojang's
/// own data generator and are the reference every learned table is checked against; letting a fetched
/// file replace one would remove the only thing making the fetched files trustworthy.
/// </summary>
public sealed class LearnedProtocolStore(string filePath, ILogger logger)
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    private readonly ConcurrentDictionary<int, LearnedProtocolTable> _tables = new();

    public string FilePath { get; } = filePath;

    public int Count => _tables.Count;

    public IReadOnlyCollection<int> Protocols => [.. _tables.Keys];

    /// <summary>Loads what was learned previously and installs it into the registry. Anything the
    /// build already knows for certain wins, so an old learned file cannot shadow a table that has
    /// since been generated properly and compiled in.</summary>
    public void Load()
    {
        try
        {
            if (!File.Exists(FilePath))
                return;

            LearnedProtocolTable[]? tables = JsonSerializer.Deserialize<LearnedProtocolTable[]>(
                File.ReadAllText(FilePath), Json);

            if (tables is null)
                return;

            int installed = 0;
            foreach (LearnedProtocolTable table in tables)
            {
                if (ProtocolVersionRegistry.IsBuiltIn(table.Protocol))
                    continue;

                _tables[table.Protocol] = table;
                ProtocolVersionRegistry.AddLearned(table.Protocol, table.ToPacketIds());
                installed++;
            }

            if (installed > 0)
            {
                logger.LogInformation("Loaded {Count} previously learned protocol table(s): {Protocols}.",
                    installed, string.Join(", ", _tables.Keys.Order()));
            }
        }
        catch (Exception ex)
        {
            // A damaged file must never stop the service starting. Losing these costs one refetch.
            logger.LogWarning(ex, "Could not read {Path} — starting with no learned protocol tables.", FilePath);
        }
    }

    /// <summary>Installs a newly learned table and writes the file. Returns false when the protocol is
    /// one this build already knows, which is not an error — it is the rule.</summary>
    public bool Add(LearnedProtocolTable table)
    {
        if (ProtocolVersionRegistry.IsBuiltIn(table.Protocol))
            return false;

        table.LearnedAt = DateTimeOffset.UtcNow;
        _tables[table.Protocol] = table;
        ProtocolVersionRegistry.AddLearned(table.Protocol, table.ToPacketIds());

        Save();
        return true;
    }

    private void Save()
    {
        try
        {
            string? directory = Path.GetDirectoryName(FilePath);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);

            string temporary = FilePath + ".tmp";
            File.WriteAllText(temporary, JsonSerializer.Serialize(_tables.Values.OrderBy(t => t.Protocol), Json));
            File.Move(temporary, FilePath, overwrite: true);
        }
        catch (Exception ex)
        {
            // In memory it still works for this run; it will simply be relearned after a restart.
            logger.LogWarning(ex, "Could not write {Path}. The learned tables still apply until restart.", FilePath);
        }
    }
}
