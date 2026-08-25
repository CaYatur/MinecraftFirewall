using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Protocol;

public sealed class ProtocolLearningOptions
{
    public const string SectionName = "ProtocolLearning";

    /// <summary>
    /// Whether the firewall teaches itself the packet table for a Minecraft version it does not know.
    ///
    /// On by default, because the alternative is worse and silent. Without it, the day a new Minecraft
    /// version ships is the day protected usernames stop being defensible on it — and that gap lasts
    /// until somebody notices, a new build is made, and the server operator installs it. On a small
    /// server that is indefinitely.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Where the packet tables come from.
    ///
    /// minecraft-data is the community's machine-readable protocol dataset — the one mineflayer and
    /// its relatives are built on — and it usually carries a new Minecraft version within days. It is
    /// plain JSON over HTTPS: nothing is downloaded that runs, which is the reason this and not
    /// Mojang's own generator. That would mean fetching a fifty-megabyte server jar and executing it,
    /// and a security product should not quietly do that on its own initiative.
    /// </summary>
    public string DataSourceUrl { get; set; } = "https://raw.githubusercontent.com/PrismarineJS/minecraft-data/master/data";

    public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>How long to wait before trying again for a version that could not be learned, so a
    /// client on something genuinely unknown cannot make this fetch on every connection.</summary>
    public TimeSpan RetryInterval { get; set; } = TimeSpan.FromHours(6);

    public string StorePath { get; set; } = @"C:\ProgramData\MinecraftFirewall\learned-protocols.json";
}

/// <summary>
/// Teaches the firewall the packet table for a Minecraft version it has never seen.
///
/// The trust argument is the whole design, and it is the same one the offline tooling uses — moved to
/// runtime. minecraft-data is a second-hand source, so nothing it says is believed on its own.
/// Before a single new table is accepted, the fetched dataset must first reproduce **every** table
/// this build compiled in from Mojang's own data generator, exactly. If any one of them disagrees, the
/// entire fetch is discarded and nothing is learned.
///
/// That check is what makes this safe to run unattended. A source that agrees with the authoritative
/// tables on twelve versions is not guessing about the thirteenth, and a source that has been
/// tampered with or has drifted fails the check long before it can teach the firewall to misread a
/// packet.
///
/// Three further limits, each closing a way this could go wrong:
///
/// A learned table never replaces a compiled-in one. The built-in tables are the reference; letting a
/// fetched file overwrite one would dissolve the thing making fetched files checkable.
///
/// Failure changes nothing. If the fetch fails, the validation fails, or the version simply is not in
/// the dataset yet, the firewall behaves exactly as it did before: unknown version, fail closed for
/// protected names, ordinary players unaffected.
///
/// And it never runs on the connection path. A player arriving on an unknown version records the
/// number and is handled immediately; the learning happens afterwards, on a background loop.
/// </summary>
public sealed class ProtocolLearningService(
    IOptions<ProtocolLearningOptions> options,
    LearnedProtocolStore store,
    IHttpClientFactory httpClientFactory,
    ILogger<ProtocolLearningService> logger) : BackgroundService
{
    /// <summary>minecraft-data's names for the packets this project needs. Its naming drifted across
    /// versions, so several entries list alternatives and the first one present wins.</summary>
    private static readonly Dictionary<string, string[]> PacketNames = new()
    {
        ["chat"] = ["chat_message", "chat"],
        ["chat_command"] = ["chat_command"],
        ["chat_command_signed"] = ["chat_command_signed", "chat_command"],
        ["move_pos"] = ["position"],
        ["move_pos_rot"] = ["position_look"],
        ["move_rot"] = ["look"],
        ["move_status"] = ["flying"],
        ["custom_payload"] = ["custom_payload"],
        ["interact"] = ["use_entity"],
        ["swing"] = ["arm_animation"],
        ["sign_update"] = ["update_sign"],
        ["edit_book"] = ["edit_book"],
    };

    private static readonly string[] ActionNames =
    [
        "window_click", "use_entity", "position", "position_look", "look", "flying", "steer_vehicle",
        "vehicle_move", "block_dig", "arm_animation", "block_place", "use_item", "held_item_slot",
        "set_creative_slot",
    ];

    private readonly ProtocolLearningOptions _options = options.Value;
    private readonly ConcurrentDictionary<int, DateTimeOffset> _lastAttempt = new();

    /// <summary>Protocol versions seen on the wire that this build has no table for. Written from the
    /// connection path, so it does nothing but record a number.</summary>
    private readonly ConcurrentDictionary<int, byte> _wanted = new();

    /// <summary>Called when a client arrives on a version the registry does not know. Cheap by
    /// design — a dictionary write and nothing else.</summary>
    public void NoteUnknownVersion(int protocolVersion)
    {
        if (_options.Enabled && protocolVersion is > 0 and < 100_000)
            _wanted.TryAdd(protocolVersion, 0);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
            return;

        store.Load();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await LearnPendingAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Protocol learning pass failed. The firewall is unaffected.");
            }

            try
            {
                // Short, because the case that matters is a player standing at a connect screen right
                // now, and the work is a small JSON fetch only when something is actually pending.
                await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task LearnPendingAsync(CancellationToken ct)
    {
        int[] pending =
        [
            .. _wanted.Keys
                .Where(p => !ProtocolVersionRegistry.TryGet(p, out _))
                .Where(p => !_lastAttempt.TryGetValue(p, out DateTimeOffset last) || DateTimeOffset.UtcNow - last > _options.RetryInterval)
        ];

        if (pending.Length == 0)
            return;

        foreach (int protocol in pending)
            _lastAttempt[protocol] = DateTimeOffset.UtcNow;

        logger.LogInformation("Trying to learn the packet table for protocol version(s) {Versions}, seen from a real client.",
            string.Join(", ", pending.Order()));

        using HttpClient http = httpClientFactory.CreateClient();
        http.Timeout = _options.HttpTimeout;

        JsonDocument paths = await GetJsonAsync(http, "dataPaths.json", ct).ConfigureAwait(false);
        JsonDocument protocolVersions = await GetJsonAsync(http, "pc/common/protocolVersions.json", ct).ConfigureAwait(false);

        using (paths)
        using (protocolVersions)
        {
            // The gate. Everything below depends on this having passed.
            if (!await SourceAgreesWithBuiltInTablesAsync(http, paths, ct).ConfigureAwait(false))
                return;

            foreach (int protocol in pending)
            {
                string? version = MinecraftVersionFor(protocolVersions, protocol);
                if (version is null)
                {
                    logger.LogInformation("Protocol {Protocol} is not in the protocol dataset yet. Nothing learned; " +
                                          "ordinary players on it are unaffected, and it will be tried again later.", protocol);
                    continue;
                }

                string? path = ProtocolPathFor(paths, version);
                if (path is null)
                    continue;

                LearnedProtocolTable? table = await BuildTableAsync(http, path, ct).ConfigureAwait(false);
                if (table is null)
                    continue;

                table.Protocol = protocol;
                table.MinecraftVersion = version;
                table.Source = "minecraft-data (cross-checked against this build's Mojang-generated tables)";

                if (store.Add(table))
                {
                    _wanted.TryRemove(protocol, out _);
                    logger.LogWarning(
                        "Learned the packet table for protocol {Protocol} (Minecraft {Version}) and it is now in use. " +
                        "Protected usernames are defensible on that version from this moment. Source: {Source}.",
                        protocol, version, table.Source);
                }
            }
        }
    }

    /// <summary>
    /// Reproduces every compiled-in table from the fetched dataset and requires all of them to match.
    ///
    /// This is the only reason anything fetched is believed. A dataset that agrees with Mojang's own
    /// generator on every version this build verified is not guessing about the one it has not; a
    /// dataset that has drifted, or been tampered with, disagrees somewhere in those twelve and the
    /// whole fetch is thrown away.
    /// </summary>
    private async Task<bool> SourceAgreesWithBuiltInTablesAsync(HttpClient http, JsonDocument paths, CancellationToken ct)
    {
        int checkedCount = 0;

        foreach (int protocol in ProtocolVersionRegistry.BuiltInProtocols)
        {
            if (!ProtocolVersionRegistry.TryGetBuiltIn(protocol, out PlayStatePacketIds builtIn))
                continue;

            string? version = ProtocolVersionRegistry.BuiltInVersionName(protocol);
            if (version is null)
                continue;

            string? path = ProtocolPathFor(paths, version);
            if (path is null)
                continue; // that version is not in the dataset — nothing to compare, not a disagreement

            LearnedProtocolTable? fetched = await BuildTableAsync(http, path, ct).ConfigureAwait(false);
            if (fetched is null)
                continue;

            if (!fetched.MatchesCoreOf(LearnedProtocolTable.From(protocol, builtIn)))
            {
                logger.LogError(
                    "Refusing to learn any protocol table: the packet dataset disagrees with this build's " +
                    "own generated table for protocol {Protocol} (Minecraft {Version}). Nothing was changed.",
                    protocol, version);
                return false;
            }

            checkedCount++;
        }

        if (checkedCount == 0)
        {
            logger.LogWarning("Could not cross-check the packet dataset against any known version, so nothing will be " +
                              "learned from it. Refusing to trust an unverified source.");
            return false;
        }

        logger.LogInformation("Packet dataset agrees with all {Count} of this build's generated tables.", checkedCount);
        return true;
    }

    private async Task<LearnedProtocolTable?> BuildTableAsync(HttpClient http, string versionPath, CancellationToken ct)
    {
        try
        {
            using JsonDocument protocol = await GetJsonAsync(http, $"{versionPath}/protocol.json", ct).ConfigureAwait(false);

            Dictionary<string, int> serverbound = PacketIds(protocol.RootElement, "play", "toServer");
            Dictionary<string, int> clientbound = PacketIds(protocol.RootElement, "play", "toClient");
            Dictionary<string, int> configuration = PacketIds(protocol.RootElement, "configuration", "toServer");

            int? Pick(Dictionary<string, int> ids, params string[] names)
            {
                foreach (string name in names)
                {
                    if (ids.TryGetValue(name, out int value))
                        return value;
                }

                return null;
            }

            var table = new LearnedProtocolTable();
            foreach ((string key, string[] names) in PacketNames)
            {
                if (Pick(serverbound, names) is not { } value)
                    return null;

                switch (key)
                {
                    case "chat": table.Chat = value; break;
                    case "chat_command": table.ChatCommand = value; break;
                    case "chat_command_signed": table.ChatCommandSigned = value; break;
                    case "move_pos": table.MovePos = value; break;
                    case "move_pos_rot": table.MovePosRot = value; break;
                    case "move_rot": table.MoveRot = value; break;
                    case "move_status": table.MoveStatus = value; break;
                    case "custom_payload": table.CustomPayload = value; break;
                    case "interact": table.Interact = value; break;
                    case "swing": table.Swing = value; break;
                    case "sign_update": table.SignUpdate = value; break;
                    case "edit_book": table.EditBook = value; break;
                }
            }

            // A version without these is one this proxy's inspection cannot work on at all — before
            // 1.20.2 there is no Configuration state, and before 1.19 no way to speak to a held player.
            if (Pick(clientbound, "kick_disconnect") is not { } disconnect ||
                Pick(clientbound, "system_chat") is not { } systemChat ||
                Pick(configuration, "finish_configuration") is not { } finish)
            {
                return null;
            }

            // Everything needed to hold a player at the login prompt: the title to show them, the
            // position packet that pins their client in place, and the confirmation they send back.
            // A version missing any of these is dropped rather than half-learned — a table with a
            // zero in it would not fail, it would send the wrong packet.
            if (Pick(clientbound, "set_title_text", "title") is not { } titleText ||
                Pick(clientbound, "set_title_subtitle", "set_subtitle_text") is not { } subtitleText ||
                Pick(clientbound, "set_title_time", "set_titles_animation") is not { } titleAnimation ||
                Pick(clientbound, "position") is not { } playerPosition ||
                Pick(clientbound, "update_health") is not { } setHealth ||
                Pick(serverbound, "teleport_confirm") is not { } acceptTeleportation ||
                ReadPositionLayout(protocol.RootElement) is not { } layout)
            {
                return null;
            }

            table.Disconnect = disconnect;
            table.SystemChat = systemChat;
            table.ConfigFinish = finish;
            table.TitleText = titleText;
            table.SubtitleText = subtitleText;
            table.TitleAnimation = titleAnimation;
            table.PlayerPosition = playerPosition;
            table.SetHealth = setHealth;
            table.AcceptTeleportation = acceptTeleportation;
            table.PositionLayout = layout;
            table.Actions = [.. ActionNames.Select(n => serverbound.TryGetValue(n, out int id) ? id : -1).Where(id => id >= 0).Distinct().Order()];

            return table;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogDebug(ex, "Could not build a packet table from {Path}.", versionPath);
            return null;
        }
    }

    /// <summary>
    /// Reads the field order of the clientbound Synchronize Player Position packet.
    ///
    /// Observed, never assumed. The proxy writes this packet itself to pin an unauthenticated
    /// player's client at the origin, so a wrong field order is not a missed detection — it is a
    /// mangled join for everyone on that version. Minecraft reordered it once already, in 1.21.2.
    ///
    /// A shape that is neither of the two known ones returns null, which drops the whole version.
    /// That is the same refusal the packet IDs get, and for the same reason: this project does not
    /// guess a layout it has not seen.
    /// </summary>
    private static PositionLayout? ReadPositionLayout(JsonElement root)
    {
        if (!root.TryGetProperty("play", out JsonElement play) ||
            !play.TryGetProperty("toClient", out JsonElement toClient) ||
            !toClient.TryGetProperty("types", out JsonElement types) ||
            !types.TryGetProperty("packet_position", out JsonElement packet) ||
            packet.ValueKind != JsonValueKind.Array || packet.GetArrayLength() != 2)
        {
            return null;
        }

        JsonElement fields = packet[1];
        if (fields.ValueKind != JsonValueKind.Array)
            return null;

        var names = new List<string>();
        foreach (JsonElement field in fields.EnumerateArray())
        {
            if (field.TryGetProperty("name", out JsonElement name) && name.GetString() is { } text)
                names.Add(text);
        }

        if (names.Count == 0)
            return null;

        if (names[0] == "teleportId")
            return PositionLayout.TeleportIdFirst;

        if (names.Count >= 4 && names[0] == "x" && names[1] == "y" && names[2] == "z" && names[^1] == "teleportId")
            return PositionLayout.TeleportIdLast;

        return null;
    }

    /// <summary>Digs the packet-name to id map out of minecraft-data's discriminated union for one
    /// state and direction.</summary>
    private static Dictionary<string, int> PacketIds(JsonElement root, string state, string direction)
    {
        var ids = new Dictionary<string, int>(StringComparer.Ordinal);

        if (!root.TryGetProperty(state, out JsonElement stateElement) ||
            !stateElement.TryGetProperty(direction, out JsonElement directionElement) ||
            !directionElement.TryGetProperty("types", out JsonElement types) ||
            !types.TryGetProperty("packet", out JsonElement packet))
        {
            return ids;
        }

        foreach (JsonElement part in packet.EnumerateArray())
        {
            if (part.ValueKind != JsonValueKind.Array)
                continue;

            foreach (JsonElement item in part.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object ||
                    !item.TryGetProperty("name", out JsonElement name) ||
                    name.GetString() != "name" ||
                    !item.TryGetProperty("type", out JsonElement type) ||
                    type.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (JsonElement typePart in type.EnumerateArray())
                {
                    if (typePart.ValueKind != JsonValueKind.Object || !typePart.TryGetProperty("mappings", out JsonElement mappings))
                        continue;

                    foreach (JsonProperty mapping in mappings.EnumerateObject())
                    {
                        if (mapping.Value.GetString() is { } packetName &&
                            int.TryParse(mapping.Name.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out int id))
                        {
                            ids[packetName] = id;
                        }
                    }
                }
            }
        }

        return ids;
    }

    private static string? MinecraftVersionFor(JsonDocument protocolVersions, int protocol)
    {
        foreach (JsonElement entry in protocolVersions.RootElement.EnumerateArray())
        {
            if (entry.TryGetProperty("version", out JsonElement version) && version.GetInt32() == protocol &&
                entry.TryGetProperty("minecraftVersion", out JsonElement name))
            {
                return name.GetString();
            }
        }

        return null;
    }

    private static string? ProtocolPathFor(JsonDocument paths, string version) =>
        paths.RootElement.TryGetProperty("pc", out JsonElement pc) &&
        pc.TryGetProperty(version, out JsonElement entry) &&
        entry.TryGetProperty("protocol", out JsonElement path)
            ? path.GetString()
            : null;

    private async Task<JsonDocument> GetJsonAsync(HttpClient http, string relative, CancellationToken ct)
    {
        string body = await http.GetStringAsync($"{_options.DataSourceUrl}/{relative}", ct).ConfigureAwait(false);
        return JsonDocument.Parse(body);
    }
}
