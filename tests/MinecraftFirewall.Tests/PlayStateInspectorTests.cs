using System.Net;
using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.IpIntel;
using MinecraftFirewall.Proxy.Policy;
using MinecraftFirewall.Proxy.Protocol;
using MinecraftFirewall.Proxy.RateLimiting;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Tests;

public class PlayStateInspectorTests
{
    private static readonly PlayStatePacketIds Ids = GetIds();
    private static readonly IPAddress RemoteIp = IPAddress.Parse("203.0.113.1");
    private static readonly IdentityOptions DefaultIdentityOptions = new() { LearnedIpTtl = TimeSpan.FromDays(30), MaxLearnedIpsPerUsername = 5, PasswordMinLength = 4 };
    private static readonly string[] DangerousCommands = ["op", "ban", "stop"];

    private static PlayStatePacketIds GetIds()
    {
        Assert.True(ProtocolVersionRegistry.TryGet(774, out var ids));
        return ids;
    }

    private sealed record Fixture(ServerProfile Profile, PolicyEngine PolicyEngine, FakeWindowsFirewallGateway Gateway, FirewallBanService BanService);

    private static Fixture CreateFixture(int strikesBeforeBan = 3)
    {
        var profile = new ServerProfile { Name = "test", PublicPort = 25565, BackendHost = "127.0.0.1", BackendPort = 25566 };
        var vpnIntel = new VpnIntelligence();
        var rateLimiter = new ConnectionRateLimiter(Options.Create(new RateLimitOptions()));
        var gateway = new FakeWindowsFirewallGateway();
        var neverBanList = new NeverBanList(Options.Create(new NeverBanOptions()));
        var banOptions = Options.Create(new FirewallBanOptions { StrikesBeforeBan = strikesBeforeBan });
        var banService = new FirewallBanService(banOptions, neverBanList, gateway, NullLogger<FirewallBanService>.Instance);
        var strikeTracker = new StrikeTracker();
        var policyEngine = new PolicyEngine(vpnIntel, rateLimiter, banService, strikeTracker, banOptions, NullLogger<PolicyEngine>.Instance);
        return new Fixture(profile, policyEngine, gateway, banService);
    }

    private static PlayStateInspector CreateInspector(Fixture fixture, string username, GraceAuthRequirement? graceAuth = null, bool startsTrusted = true) =>
        new(fixture.Profile, username, RemoteIp, Ids, graceAuth, startsTrusted, DefaultIdentityOptions, DangerousCommands, fixture.PolicyEngine, NullLogger.Instance);

    private static byte[] ConfigFinishFrame() =>
        MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(Ids.ConfigurationFinishConfigurationServerbound);

    private static byte[] ChatFrame(string text) =>
        MinecraftPacketBuilder.BuildCompressedStringPacketFrame(Ids.PlayChatServerbound, text);

    private static byte[] CommandFrame(string text) =>
        MinecraftPacketBuilder.BuildCompressedStringPacketFrame(Ids.PlayChatCommandServerbound, text);

    private static async Task<(byte[] Forwarded, string? DisconnectReason)> RunAsync(PlayStateInspector inspector, params byte[][] clientFrames)
    {
        byte[] input = clientFrames.SelectMany(f => f).ToArray();
        using var clientStream = new MemoryStream(input);
        using var backendStream = new MemoryStream();

        try
        {
            await inspector.RunAsync(clientStream, backendStream, CancellationToken.None);
        }
        catch (Exception ex) when (ex is EndOfStreamException or IOException)
        {
            // Expected once the synthetic client input is exhausted.
        }

        return (backendStream.ToArray(), inspector.DisconnectReason);
    }

    [Fact]
    public async Task ConfigurationPhaseFrames_AreForwardedVerbatim_WithoutInspection()
    {
        var fixture = CreateFixture();
        var inspector = CreateInspector(fixture, "Player1");

        // An arbitrary Configuration-phase frame (not Finish Configuration) before entering Play state.
        byte[] someConfigFrame = MinecraftPacketBuilder.BuildCompressedStringPacketFrame(0x02, "minecraft:brand-ish-payload");

        var (forwarded, disconnect) = await RunAsync(inspector, someConfigFrame);

        Assert.Equal<byte>(someConfigFrame, forwarded);
        Assert.Null(disconnect);
    }

    [Fact]
    public async Task PlainChat_IsForwardedUnchanged()
    {
        var fixture = CreateFixture();
        var inspector = CreateInspector(fixture, "Player1");
        byte[] chat = ChatFrame("hello world");

        var (forwarded, disconnect) = await RunAsync(inspector, ConfigFinishFrame(), chat);

        // The Finish Configuration frame itself is legitimately forwarded too — the real backend
        // needs it to make its own Configuration->Play transition.
        Assert.Equal<byte>([.. ConfigFinishFrame(), .. chat], forwarded);
        Assert.Null(disconnect);
    }

    [Fact]
    public async Task NonDangerousCommand_IsForwardedUnchanged()
    {
        var fixture = CreateFixture();
        var inspector = CreateInspector(fixture, "Player1");
        byte[] command = CommandFrame("spawn");

        var (forwarded, disconnect) = await RunAsync(inspector, ConfigFinishFrame(), command);

        Assert.Equal<byte>([.. ConfigFinishFrame(), .. command], forwarded);
        Assert.Null(disconnect);
    }

    [Fact]
    public async Task DangerousCommand_FromNonTrustedIdentity_IsBlockedAndBansFast()
    {
        var fixture = CreateFixture(strikesBeforeBan: 3);
        var inspector = CreateInspector(fixture, "Attacker", startsTrusted: false);
        byte[] command = CommandFrame("op Attacker");

        var (forwarded, disconnect) = await RunAsync(inspector, ConfigFinishFrame(), command);

        Assert.Equal<byte>(ConfigFinishFrame(), forwarded); // the dangerous command itself never reached the backend
        Assert.NotNull(disconnect);
        Assert.True(fixture.BanService.IsBanned(RemoteIp)); // one dangerous command == immediate ban, not 3 strikes
    }

    [Fact]
    public async Task DangerousCommand_FromTrustedIdentity_IsExemptAndForwarded()
    {
        var fixture = CreateFixture();
        var inspector = CreateInspector(fixture, "Admin", startsTrusted: true);
        byte[] command = CommandFrame("op SomeoneElse");

        var (forwarded, disconnect) = await RunAsync(inspector, ConfigFinishFrame(), command);

        Assert.Equal<byte>([.. ConfigFinishFrame(), .. command], forwarded);
        Assert.Null(disconnect);
        Assert.False(fixture.BanService.IsBanned(RemoteIp));
    }

    [Fact]
    public async Task RegisterCommand_CreatesEntryAndLearnsIp_AndIsSwallowed()
    {
        var fixture = CreateFixture();
        var inspector = CreateInspector(fixture, "NewPlayer", startsTrusted: false);
        byte[] register = CommandFrame("register hunter2");

        var (forwarded, disconnect) = await RunAsync(inspector, ConfigFinishFrame(), register);

        Assert.Equal<byte>(ConfigFinishFrame(), forwarded); // password command must never reach the backend
        Assert.Null(disconnect);

        var entry = fixture.Profile.IdentityStore.Find("NewPlayer");
        Assert.NotNull(entry);
        Assert.NotNull(entry!.PasswordHash);
        Assert.True(PasswordHasher.Verify("hunter2", entry.PasswordHash!));
        Assert.True(entry.IsIpRecognized(RemoteIp));
    }

    [Fact]
    public async Task RegisterCommand_TooShortPassword_IsRejectedAndNoEntryCreated()
    {
        var fixture = CreateFixture();
        var inspector = CreateInspector(fixture, "NewPlayer", startsTrusted: false);
        byte[] register = CommandFrame("register ab"); // shorter than PasswordMinLength=4

        await RunAsync(inspector, ConfigFinishFrame(), register);

        Assert.Null(fixture.Profile.IdentityStore.Find("NewPlayer"));
    }

    [Fact]
    public async Task GraceAuth_CorrectLoginAsFirstMessage_Succeeds_LearnsIpAndTrustsSession()
    {
        var fixture = CreateFixture();
        var entry = new IdentityEntry { Username = "Player1", PasswordHash = PasswordHasher.Hash("correctpw") };
        var graceAuth = new GraceAuthRequirement(entry, entry.PasswordHash!);
        var inspector = CreateInspector(fixture, "Player1", graceAuth, startsTrusted: false);

        byte[] login = CommandFrame("login correctpw");
        byte[] followUpDangerousCommand = CommandFrame("op Player1"); // should now be exempt, since trust flipped

        var (forwarded, disconnect) = await RunAsync(inspector, ConfigFinishFrame(), login, followUpDangerousCommand);

        Assert.Null(disconnect);
        Assert.True(entry.IsIpRecognized(RemoteIp));
        Assert.Equal<byte>([.. ConfigFinishFrame(), .. followUpDangerousCommand], forwarded); // login itself swallowed, the command after wasn't blocked
        Assert.False(fixture.BanService.IsBanned(RemoteIp));
    }

    [Fact]
    public async Task GraceAuth_WrongPasswordAsFirstMessage_FailsAndBansFast()
    {
        var fixture = CreateFixture(strikesBeforeBan: 3);
        var entry = new IdentityEntry { Username = "Player1", PasswordHash = PasswordHasher.Hash("correctpw") };
        var graceAuth = new GraceAuthRequirement(entry, entry.PasswordHash!);
        var inspector = CreateInspector(fixture, "Player1", graceAuth, startsTrusted: false);

        byte[] wrongLogin = CommandFrame("login wrongpassword");

        var (forwarded, disconnect) = await RunAsync(inspector, ConfigFinishFrame(), wrongLogin);

        Assert.Equal<byte>(ConfigFinishFrame(), forwarded);
        Assert.NotNull(disconnect);
        Assert.False(entry.IsIpRecognized(RemoteIp));
        Assert.True(fixture.BanService.IsBanned(RemoteIp));
    }

    [Fact]
    public async Task GraceAuth_PlainChatAsFirstMessage_IsAutomaticFailure()
    {
        var fixture = CreateFixture(strikesBeforeBan: 3);
        var entry = new IdentityEntry { Username = "Player1", PasswordHash = PasswordHasher.Hash("correctpw") };
        var graceAuth = new GraceAuthRequirement(entry, entry.PasswordHash!);
        var inspector = CreateInspector(fixture, "Player1", graceAuth, startsTrusted: false);

        byte[] plainChat = ChatFrame("hi everyone");

        var (forwarded, disconnect) = await RunAsync(inspector, ConfigFinishFrame(), plainChat);

        Assert.Equal<byte>(ConfigFinishFrame(), forwarded);
        Assert.NotNull(disconnect);
        Assert.True(fixture.BanService.IsBanned(RemoteIp));
    }
}
