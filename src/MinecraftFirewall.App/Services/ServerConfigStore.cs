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
}

/// <summary>
/// Reads and writes the <c>ServerProfiles</c> section of the service's appsettings.json on behalf of
/// the UI.
///
/// Edits are applied to the parsed JSON document and written back, rather than the whole file being
/// regenerated from a model. The shipped file is full of explanatory comments and sections this
/// editor knows nothing about (Serilog, VpnIntel, Messages, and so on); regenerating it would silently
/// destroy all of that the first time someone renamed a server.
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

    public string ConfigPath { get; } = Path.Combine(AppContext.BaseDirectory, "appsettings.json");

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
            JsonNode root = JsonNode.Parse(original, documentOptions: new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            }) ?? throw new InvalidDataException("Configuration file is empty.");

            var array = new JsonArray();
            foreach (ServerProfileEdit profile in profiles)
            {
                var node = new JsonObject
                {
                    ["Name"] = profile.Name,
                    ["PublicPort"] = profile.PublicPort,
                    ["BackendHost"] = profile.BackendHost,
                    ["BackendPort"] = profile.BackendPort,
                    ["AllowedHostnames"] = new JsonArray([.. profile.AllowedHostnames.Select(h => (JsonNode)h!)]),
                    ["ProtectedUsernames"] = new JsonArray([.. profile.ProtectedUsernames.Select(ToNode)]),
                };
                array.Add(node);
            }

            root["ServerProfiles"] = array;

            // Back up before overwriting: this file also holds hand-written settings and comments the
            // editor drops (JsonNode does not preserve them), so a recoverable copy matters.
            string backup = ConfigPath + ".backup";
            File.WriteAllText(backup, original);

            string temp = ConfigPath + ".tmp";
            File.WriteAllText(temp, root.ToJsonString(WriteOptions));
            File.Move(temp, ConfigPath, overwrite: true);

            return (true, $"Saved. A copy of the previous file is at {Path.GetFileName(backup)}.");
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    /// <summary>Reads Premium.AutoClaimOnVerifiedLogin. Defaults to false — the safe direction, and
    /// the same default the service itself uses if the key is absent.</summary>
    public bool GetAutoPremium()
    {
        try
        {
            JsonNode? root = JsonNode.Parse(File.ReadAllText(ConfigPath), documentOptions: new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });
            return root?["Premium"]?["AutoClaimOnVerifiedLogin"]?.GetValue<bool>() ?? false;
        }
        catch
        {
            return false;
        }
    }

    public (bool Success, string Message) SetAutoPremium(bool enabled)
    {
        try
        {
            string original = File.ReadAllText(ConfigPath);
            JsonNode root = JsonNode.Parse(original, documentOptions: new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            }) ?? throw new InvalidDataException("Configuration file is empty.");

            if (root["Premium"] is not JsonObject premium)
            {
                premium = [];
                root["Premium"] = premium;
            }

            premium["AutoClaimOnVerifiedLogin"] = enabled;

            File.WriteAllText(ConfigPath + ".backup", original);
            string temp = ConfigPath + ".tmp";
            File.WriteAllText(temp, root.ToJsonString(WriteOptions));
            File.Move(temp, ConfigPath, overwrite: true);

            return (true, "Saved.");
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

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
