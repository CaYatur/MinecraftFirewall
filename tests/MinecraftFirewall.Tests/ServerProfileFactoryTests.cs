using MinecraftFirewall.Proxy;

namespace MinecraftFirewall.Tests;

public class ServerProfileFactoryTests
{
    [Fact]
    public void Build_ProtectedUsername_RequirePremiumTrue_SetsPremiumRequiredOnEntry()
    {
        var configs = new List<ServerProfileConfig>
        {
            new()
            {
                Name = "TestServer",
                PublicPort = 25565,
                BackendPort = 25566,
                ProtectedUsernames =
                [
                    new ProtectedUsernameConfig { Username = "Notch", RequirePremium = true },
                ],
            },
        };

        var profiles = ServerProfileFactory.Build(configs);

        var entry = profiles[0].IdentityStore.Find("Notch");
        Assert.NotNull(entry);
        Assert.True(entry!.PremiumRequired);
    }

    [Fact]
    public void Build_ProtectedUsername_RequirePremiumOmitted_DefaultsToFalse()
    {
        var configs = new List<ServerProfileConfig>
        {
            new()
            {
                Name = "TestServer",
                PublicPort = 25565,
                BackendPort = 25566,
                ProtectedUsernames = [new ProtectedUsernameConfig { Username = "RegularAdmin", AllowedIps = ["203.0.113.7"] }],
            },
        };

        var profiles = ServerProfileFactory.Build(configs);

        var entry = profiles[0].IdentityStore.Find("RegularAdmin");
        Assert.NotNull(entry);
        Assert.False(entry!.PremiumRequired);
    }
}
