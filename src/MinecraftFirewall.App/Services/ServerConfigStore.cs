using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace MinecraftFirewall.App.Services;

/// <summary>One protected username as the UI edits it — a flat shape, deliberately not the service's
/// own config type, so the editor stays simple and the mapping is explicit.</summary>
public sealed class ProtectedNameEdit
{
    public string Username { get; set; } = "";
    public bool RequirePremium { get; set; }
    public List<string> AllowedIps { get; set; } = [];

    /// <summary>Round-trips through one line of text, which is how the UI presents these:
    /// <c>Name</c>, <c>Name|premium</c>, <c>Name|ip=1.2.3.4|ip=10.0.0.0/8</c>.</summary>
    public static ProtectedNameEdit? Parse(string line)
    {
        string[] parts = line.Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || parts[0].Length == 0)
            return null;

        var entry = new ProtectedNameEdit { Username = parts[0] };
        foreach (string part in parts.Skip(1))
        {
            if (part.Equals("premium", StringComparison.OrdinalIgnoreCase))
                entry.RequirePremium = true;
            else if (part.StartsWith("ip=", StringComparison.OrdinalIgnoreCase))
                entry.AllowedIps.Add(part[3..]);
        }

        return entry;
    }

    public override string ToString()
    {
        var text = new System.Text.StringBuilder(Username);
        if (RequirePremium)
            text.Append("|premium");
        foreach (string ip in AllowedIps)
            text.Append("|ip=").Append(ip);
        return text.ToString();
    }
}

public sealed class ServerProfileEdit
{
    public string Name { get; set; } = "MyServer";
    public int PublicPort { get; set; } = 25565;
    public string BackendHost { get; set; } = "127.0.0.1";
    public int BackendPort { get; set; } = 25566;
    public List<string> AllowedHostnames { get; set; } = [];
    public List<ProtectedNameEdit> ProtectedUsernames { get; set; } = [];

    /// <summary>
    /// LogOnly, BlockForProtectedUsernamesOnly, or BlockForEveryone. Kept as a string rather than a
    /// copy of the service's enum so the editor never has to be rebuilt when the service gains a
    /// policy — an unrecognised value round-trips untouched instead of being silently reset to the
    /// default, which is what would happen if it were parsed.
    /// </summary>
    public string VpnPolicy { get; set; } = "BlockForProtectedUsernamesOnly";

    public bool UseDatacenterList { get; set; }
}

/// <summary>
/// Reads and writes the parts of the service's appsettings.json that the control panel edits.
///
/// Writes go through <see cref="JsonTextSurgery"/>, which splices new text over the exact span of the
/// value being changed and leaves the rest of the file untouched. The first version of this class
/// intended the same thing but did not achieve it: it parsed with <c>JsonCommentHandling.Skip</c> and
/// wrote the document back through <c>JsonNode</c>, and "Skip" means the comments are dropped, not set
/// aside. The shipped file is more explanation than configuration — a hundred-odd lines saying why the
/// honeypot ships off, why movement analysis only reports, why disabling premium verification denies
/// rather than falls back — and renaming a server from the UI would have deleted every word of it.
///
/// A round-trip test asserts the comment count is unchanged, because this is a failure nobody would
/// notice until they went looking for an explanation that used to be there.
/// </summary>
public sealed class ServerConfigStore
{
    private static readonly JsonSerializerOptions ReadOptions = new()
    {
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        PropertyNameCaseInsensitive = true,
    };

    private static readonly JsonSerializerOptions WriteOptions = new() { WriteIndented = true };

    /// <summary>Defaults to the file next to the executable — the control panel and the service are
    /// installed into the same directory, which is what makes that the right place to look. The
    /// parameter exists so tests can exercise the real writer against a disposable copy of the real
    /// file rather than against a hand-built fixture that would not have the comments in it.</summary>
    public ServerConfigStore(string? configPath = null) =>
        ConfigPath = configPath ?? Path.Combine(AppContext.BaseDirectory, "appsettings.json");

    public string ConfigPath { get; }

    public bool Exists => File.Exists(ConfigPath);

    public (List<ServerProfileEdit> Profiles, string? Error) Load()
    {
        try
        {
            JsonNode root = JsonNode.Parse(File.ReadAllText(ConfigPath), documentOptions: new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            }) ?? throw new InvalidDataException("Configuration file is empty.");

            var profiles = new List<ServerProfileEdit>();
            if (root["ServerProfiles"] is JsonArray array)
            {
                foreach (JsonNode? node in array)
                {
                    if (node is null)
                        continue;

                    var profile = new ServerProfileEdit
                    {
                        Name = node["Name"]?.GetValue<string>() ?? "",
                        PublicPort = TryInt(node["PublicPort"], 25565),
                        BackendHost = node["BackendHost"]?.GetValue<string>() ?? "127.0.0.1",
                        BackendPort = TryInt(node["BackendPort"], 25566),
                        VpnPolicy = node["VpnPolicy"]?.GetValue<string>() ?? "BlockForProtectedUsernamesOnly",
                        UseDatacenterList = node["UseDatacenterList"]?.GetValue<bool>() ?? false,
                    };

                    if (node["AllowedHostnames"] is JsonArray hostnames)
                        profile.AllowedHostnames = [.. hostnames.Select(h => h?.GetValue<string>() ?? "").Where(h => h.Length > 0)];

                    if (node["ProtectedUsernames"] is JsonArray names)
                    {
                        foreach (JsonNode? entry in names)
                        {
                            if (entry is null)
                                continue;

                            var edit = new ProtectedNameEdit
                            {
                                Username = entry["Username"]?.GetValue<string>() ?? "",
                                RequirePremium = entry["RequirePremium"]?.GetValue<bool>() ?? false,
                            };
                            if (entry["AllowedIps"] is JsonArray ips)
                                edit.AllowedIps = [.. ips.Select(i => i?.GetValue<string>() ?? "").Where(i => i.Length > 0)];

                            if (edit.Username.Length > 0)
                                profile.ProtectedUsernames.Add(edit);
                        }
                    }

                    profiles.Add(profile);
                }
            }

            return (profiles, null);
        }
        catch (Exception ex)
        {
            return ([], ex.Message);
        }
    }

    public (bool Success, string Message) Save(IReadOnlyList<ServerProfileEdit> profiles)
    {
        try
        {
            string original = File.ReadAllText(ConfigPath);

            var array = new JsonArray();
            foreach (ServerProfileEdit profile in profiles)
            {
                array.Add(new JsonObject
                {
                    ["Name"] = profile.Name,
                    ["PublicPort"] = profile.PublicPort,
                    ["BackendHost"] = profile.BackendHost,
                    ["BackendPort"] = profile.BackendPort,
                    // Written back explicitly. Leaving them out did not leave them alone: the save
                    // replaces the whole ServerProfiles array, so any key the editor did not know
                    // about was deleted, and the service silently fell back to its compiled default.
                    // Somebody who had set BlockForEveryone lost it the first time they renamed a
                    // server, with nothing to indicate it had happened.
                    ["VpnPolicy"] = profile.VpnPolicy,
                    ["UseDatacenterList"] = profile.UseDatacenterList,
                    ["AllowedHostnames"] = new JsonArray([.. profile.AllowedHostnames.Select(h => (JsonNode)h!)]),
                    ["ProtectedUsernames"] = new JsonArray([.. profile.ProtectedUsernames.Select(ToNode)]),
                });
            }

            string? updated = JsonTextSurgery.ReplaceValue(original, ["ServerProfiles"], array.ToJsonString(WriteOptions));
            if (updated is null)
            {
                return (false, "Could not find a ServerProfiles section in the configuration file. " +
                               "Nothing was written — add the section by hand, or restore appsettings.default.json.");
            }

            return WriteAtomically(original, updated);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    /// <summary>Writes through a temp file and keeps one backup. The surgery above means a crash
    /// mid-write is the only way to lose anything now, and this closes that too.</summary>
    private (bool Success, string Message) WriteAtomically(string original, string updated)
    {
        string backup = ConfigPath + ".backup";
        File.WriteAllText(backup, original);

        string temp = ConfigPath + ".tmp";
        File.WriteAllText(temp, updated);
        File.Move(temp, ConfigPath, overwrite: true);

        return (true, $"Saved. A copy of the previous file is at {Path.GetFileName(backup)}.");
    }

    // ---- upgrade repair --------------------------------------------------------------------------

    /// <summary>Sections the control panel needs, in the order they should be added back.</summary>
    private static readonly string[] ExpectedSections =
    [
        "Identity", "DdosProtection", "BotDefense", "Honeypot", "ThreatIntel", "DeepInspection", "AnomalyDetection",
    ];

    /// <summary>The pristine copy the installer drops beside the live file. It is the source for
    /// anything the live one is missing, and is refreshed on every install.</summary>
    public string DefaultConfigPath => Path.Combine(Path.GetDirectoryName(ConfigPath) ?? ".", "appsettings.default.json");

    /// <summary>
    /// Sections this release expects that the user's configuration does not have.
    ///
    /// Upgrades are the reason this exists. The installer deliberately never overwrites
    /// appsettings.json — it holds the servers, the protected usernames and the webhook, none of which
    /// can be regenerated — so an installation that predates a feature keeps a file with no section
    /// for it. Nothing about that is visible until a switch fails, which is the worst moment to find
    /// out.
    /// </summary>
    public IReadOnlyList<string> MissingSections()
    {
        try
        {
            JsonNode? root = JsonNode.Parse(File.ReadAllText(ConfigPath), documentOptions: new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });

            return root is null ? [] : [.. ExpectedSections.Where(name => root[name] is null)];
        }
        catch
        {
            // An unreadable file is a different problem, reported elsewhere. Claiming everything is
            // missing would offer a repair that could not work.
            return [];
        }
    }

    /// <summary>
    /// Copies any missing sections across from the shipped default, comments and all.
    ///
    /// Deliberately a thing the user asks for rather than something that happens on startup. Silently
    /// adding settings to somebody's configuration file is the same class of behaviour as silently
    /// removing their comments, and the whole point of the surgical writer is that this app does not
    /// do that.
    /// </summary>
    public (bool Success, string Message) AddMissingSections()
    {
        try
        {
            IReadOnlyList<string> missing = MissingSections();
            if (missing.Count == 0)
                return (true, "Your configuration already has every section this version uses.");

            if (!File.Exists(DefaultConfigPath))
            {
                return (false, $"Could not find {Path.GetFileName(DefaultConfigPath)} next to the app, " +
                               "so there is nothing to copy the missing settings from.");
            }

            string original = File.ReadAllText(ConfigPath);
            string? updated = JsonTextSurgery.CopySections(original, File.ReadAllText(DefaultConfigPath), missing);

            if (updated is null)
                return (false, "Could not read those sections out of the shipped defaults. Nothing was written.");

            (bool success, string message) = WriteAtomically(original, updated);
            return success
                ? (true, $"Added {string.Join(", ", missing)}. Restart the service to apply them.")
                : (false, message);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    // ---- generic settings access ---------------------------------------------------------------
    // The control panel exposes a handful of individual switches from sections it does not otherwise
    // understand (premium auto-claim, the honeypot, bot enforcement, movement kicking). Rather than a
    // bespoke reader and writer for each, these two walk a property path — and the write goes through
    // the same surgery as everything else, so flipping one checkbox does not rewrite the file.

    /// <summary>Reads a boolean at a property path, falling back when it is missing or unreadable.
    /// The fallback should always be the safe direction, since a damaged file must not silently turn
    /// a protection on or off.</summary>
    public bool GetBool(string[] path, bool fallback)
    {
        try
        {
            JsonNode? node = JsonNode.Parse(File.ReadAllText(ConfigPath), documentOptions: new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });

            foreach (string segment in path)
            {
                node = node?[segment];
                if (node is null)
                    return fallback;
            }

            return node!.GetValue<bool>();
        }
        catch
        {
            return fallback;
        }
    }

    /// <summary>Reads a string at a property path — used for the enum-valued settings (BotDefense
    /// Action, ThreatIntel Action) the UI presents as a choice.</summary>
    public string GetString(string[] path, string fallback)
    {
        try
        {
            JsonNode? node = JsonNode.Parse(File.ReadAllText(ConfigPath), documentOptions: new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });

            foreach (string segment in path)
            {
                node = node?[segment];
                if (node is null)
                    return fallback;
            }

            return node!.GetValue<string>();
        }
        catch
        {
            return fallback;
        }
    }

    public (bool Success, string Message) SetBool(string[] path, bool value) =>
        SetLiteral(path, value ? "true" : "false");

    public (bool Success, string Message) SetString(string[] path, string value) =>
        SetLiteral(path, JsonSerializer.Serialize(value));

    /// <summary>
    /// Splices a JSON literal over the value at a property path.
    ///
    /// A missing path is reported rather than created. Adding a section by hand would mean guessing
    /// where in the file it belongs and what to say about it, and every setting the UI offers is one
    /// the shipped appsettings.json already documents — so a path that is not there means the user is
    /// editing a file this app did not ship, and silently appending to it would be the wrong help.
    /// </summary>
    private (bool Success, string Message) SetLiteral(string[] path, string literal)
    {
        try
        {
            string original = File.ReadAllText(ConfigPath);
            string? updated = JsonTextSurgery.ReplaceValue(original, path, literal);

            if (updated is null)
            {
                return (false, $"Could not find \"{string.Join(" > ", path)}\" in the configuration file. " +
                               "Nothing was written — check appsettings.default.json for the section this setting lives in.");
            }

            return WriteAtomically(original, updated);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    /// <summary>Reads Premium.AutoClaimOnVerifiedLogin. Defaults to false — the safe direction, and
    /// the same default the service itself uses if the key is absent.</summary>
    public bool GetAutoPremium() => GetBool(["Premium", "AutoClaimOnVerifiedLogin"], false);

    public (bool Success, string Message) SetAutoPremium(bool enabled) =>
        SetBool(["Premium", "AutoClaimOnVerifiedLogin"], enabled);

    private static JsonNode ToNode(ProtectedNameEdit entry)
    {
        var node = new JsonObject
        {
            ["Username"] = entry.Username,
            ["AllowedIps"] = new JsonArray([.. entry.AllowedIps.Select(i => (JsonNode)i!)]),
        };

        // Only written when true, so the shipped file stays readable and a name that isn't premium
        // doesn't carry a misleading explicit "false".
        if (entry.RequirePremium)
            node["RequirePremium"] = true;

        return node;
    }

    private static int TryInt(JsonNode? node, int fallback)
    {
        try
        {
            return node?.GetValue<int>() ?? fallback;
        }
        catch
        {
            return fallback;
        }
    }
}
