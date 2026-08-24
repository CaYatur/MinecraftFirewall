using MinecraftFirewall.Proxy.Identity;

namespace MinecraftFirewall.Proxy;

/// <summary>Plain DTO shape for binding ServerProfiles[] out of appsettings.json (kept separate from
/// ServerProfile itself since that type owns a live IdentityStore, not a serializable one).</summary>
public sealed class ServerProfileConfig
{
    public string Name { get; set; } = "";
    public int PublicPort { get; set; }
    public string BackendHost { get; set; } = "127.0.0.1";
    public int BackendPort { get; set; }
    public VpnPolicy VpnPolicy { get; set; } = VpnPolicy.BlockForProtectedUsernamesOnly;
    public bool UseDatacenterList { get; set; }
    public List<ProtectedUsernameConfig> ProtectedUsernames { get; set; } = [];
    public List<string> AllowedHostnames { get; set; } = [];
}

public sealed class ProtectedUsernameConfig
{
    public string Username { get; set; } = "";
    public List<string> AllowedIps { get; set; } = [];

    /// <summary>Admin-declared only, never auto-set — see IdentityGate's precedence rule and Stage 4
    /// in docs/plan.md. Persists a `require-premium` Admin CLI change across a service restart.</summary>
    public bool RequirePremium { get; set; }
}

public static class ServerProfileFactory
{
    public static List<ServerProfile> Build(IEnumerable<ServerProfileConfig> configs)
    {
        var profiles = new List<ServerProfile>();

        foreach (var config in configs)
        {
            var profile = new ServerProfile
            {
                Name = config.Name,
                PublicPort = config.PublicPort,
                BackendHost = config.BackendHost,
                BackendPort = config.BackendPort,
                VpnPolicy = config.VpnPolicy,
                UseDatacenterList = config.UseDatacenterList,
                AllowedHostnames = config.AllowedHostnames,
            };

            foreach (var protectedUsername in config.ProtectedUsernames)
            {
                var entry = new IdentityEntry { Username = protectedUsername.Username, PremiumRequired = protectedUsername.RequirePremium };
                foreach (var ip in protectedUsername.AllowedIps)
                    entry.StaticAllowlist.Add(CidrRange.Parse(ip));

                profile.IdentityStore.AddOrReplace(entry);
            }

            profiles.Add(profile);
        }

        return profiles;
    }
}
