using System.Net;
using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Inspection;
using MinecraftFirewall.Proxy.IpIntel;
using MinecraftFirewall.Proxy.Messages;
using MinecraftFirewall.Proxy.Policy;
using MinecraftFirewall.Proxy.Protocol;
using MinecraftFirewall.Proxy.RateLimiting;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Server-wide registration — the AuthMe-style mode where nobody reaches the world until they have an
/// account.
///
/// The gap this closes was real and visible on a live server: with the password system switched on,
/// a player could join and simply play. The proxy consumed their first chat message looking for a
/// /login and let every movement, block break and container click through untouched. "Requiring"
/// authentication meant nothing at all until something actually held the player still.
/// </summary>
public class RegistrationGateTests
{
    private static readonly IPAddress Player = IPAddress.Parse("203.0.113.60");
    private static readonly PlayStatePacketIds Ids = GetIds();

    private static PlayStatePacketIds GetIds()
    {
        Assert.True(ProtocolVersionRegistry.TryGet(774, out PlayStatePacketIds ids));
        return ids;
    }

    // ---- the gate's own decision ----------------------------------------------------------------

    [Fact]
    public void WithTheModeOff_AnUnknownNameIsSimplyLetIn()
    {
        // Vanilla offline behaviour, which is what everyone gets today.
        IdentityDecision decision = IdentityGate.Evaluate(null, Player, requireRegistration: false);

        Assert.Equal(IdentityOutcome.NotProtected, decision.Outcome);
    }

    [Fact]
    public void WithTheModeOn_AnUnknownNameMustRegister()
    {
        IdentityDecision decision = IdentityGate.Evaluate(null, Player, requireRegistration: true);

        Assert.Equal(IdentityOutcome.RegistrationRequired, decision.Outcome);
    }

    [Fact]
    public void APremiumLockedNameSkipsRegistrationEntirely()
    {
        // The guarantee the whole project rests on. That account has already been authenticated by
        // Mojang — something far stronger than a password this server stores — and asking for one on
        // top would mean making the genuine owner prove themselves twice.
        var entry = new IdentityEntry { Username = "Owner", PremiumRequired = true };

        IdentityDecision decision = IdentityGate.Evaluate(entry, Player, requireRegistration: true);

        Assert.Equal(IdentityOutcome.PremiumVerificationRequired, decision.Outcome);
    }

    [Fact]
    public void ARegisteredPlayerOnAKnownAddress_IsNotAskedAgain()
    {
        // Otherwise every reconnect would demand a password, which is how people end up switching the
        // whole feature off.
        var entry = new IdentityEntry { Username = "Steve", PasswordHash = "hash" };
        entry.LearnIp(Player, TimeSpan.FromDays(30), 5);

        IdentityDecision decision = IdentityGate.Evaluate(entry, Player, requireRegistration: true);

        Assert.Equal(IdentityOutcome.Allow, decision.Outcome);
    }

    [Fact]
    public void ARegisteredPlayerOnANewAddress_MustLogIn()
    {
        var entry = new IdentityEntry { Username = "Steve", PasswordHash = "hash" };

        IdentityDecision decision = IdentityGate.Evaluate(entry, Player, requireRegistration: true);

        Assert.Equal(IdentityOutcome.AllowPendingGraceAuthentication, decision.Outcome);
    }

    // ---- the freeze, through the real inspector --------------------------------------------------

    private sealed record Harness(PlayStateInspector Inspector, MemoryStream Backend);

    private static Harness Create(GraceAuthRequirement grace, IdentityOptions? identity = null)
    {
        var profile = new ServerProfile { Name = "test", PublicPort = 25565, BackendHost = "127.0.0.1", BackendPort = 25566 };
        IOptions<FirewallBanOptions> banOptions = Options.Create(new FirewallBanOptions { StrikesBeforeBan = 100 });

        var banService = new FirewallBanService(banOptions, new NeverBanList(Options.Create(new NeverBanOptions())),
            new FakeWindowsFirewallGateway(), new RecordingAlertSender(), NullLogger<FirewallBanService>.Instance);

        var policy = new PolicyEngine(new VpnIntelligence(), new ConnectionRateLimiter(Options.Create(new RateLimitOptions())),
            banService, new StrikeTracker(), new FakeIpInfoClient(), new RecordingAlertSender(),
            DefenseTestFactory.CreateThreatIntelligence(), DefenseTestFactory.CreateScannerDetector(),
            banOptions, Options.Create(new IpInfoOptions()), Options.Create(new DdosOptions()),
            Options.Create(new BotDefenseOptions()), Options.Create(new IdentityOptions()), NullLogger<PolicyEngine>.Instance);

        var inspector = new PlayStateInspector(profile, "Steve", Player, Ids, grace, startsTrusted: false,
            identity ?? new IdentityOptions { PasswordMinLength = 6 }, [], new MessagesOptions(), policy,
            new InspectionOptions(), NullLogger.Instance);

        return new Harness(inspector, new MemoryStream());
    }

    private static async Task<string?> RunAsync(Harness harness, params byte[][] playFrames)
    {
        byte[] prologue =
        [
            .. MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(0x03),
            .. MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(Ids.ConfigurationFinishConfigurationServerbound),
        ];

        // A duplex double, not a MemoryStream: the inspector writes prompts back to the player on the
        // same stream it reads packets from, and against a MemoryStream those writes land on top of
        // the packets the test has not fed it yet.
        using var client = new DuplexTestStream([.. prologue, .. playFrames.SelectMany(f => f)]);

        try
        {
            await harness.Inspector.RunAsync(client, harness.Backend, CancellationToken.None);
        }
        catch (EndOfStreamException)
        {
            // Running out of input is how these tests end.
        }

        return harness.Inspector.DisconnectReason;
    }

    private static byte[] Movement(double x) =>
        MinecraftPacketBuilder.BuildMovementFrame(Ids.PlayMovePlayerPosServerbound, x, 64, 0);

    private static byte[] Command(string text) =>
        MinecraftPacketBuilder.BuildCompressedStringPacketFrame(Ids.PlayChatCommandServerbound, text);

    [Fact]
    public async Task AnUnregisteredPlayerCannotMove()
    {
        // The behaviour that was missing entirely. Before this, all of these reached the server.
        Harness harness = Create(new GraceAuthRequirement(new IdentityEntry { Username = "Steve" }, null));

        await RunAsync(harness, Movement(1), Movement(2), Movement(3));

        // Only the two prologue frames were forwarded; not one movement packet.
        Assert.Equal(PrologueLength(), harness.Backend.Length);
    }

    [Fact]
    public async Task EverythingThatLetsAPlayerActIsHeldBack()
    {
        Harness harness = Create(new GraceAuthRequirement(new IdentityEntry { Username = "Steve" }, null));

        byte[][] actions =
        [
            Movement(1),
            MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(Ids.PlaySwingServerbound),
            MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(Ids.PlayInteractServerbound),
            MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(0x28), // player_action
            MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(0x3F), // use_item_on
            MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(0x11), // container_click
        ];

        await RunAsync(harness, actions);

        Assert.Equal(PrologueLength(), harness.Backend.Length);
    }

    [Fact]
    public async Task KeepAlivesStillReachTheServer()
    {
        // The reason this is a blocklist rather than an allowlist. A frozen player who stops answering
        // keep-alives is disconnected by the backend within thirty seconds, and would see a timeout
        // instead of the password prompt they were sent.
        Harness harness = Create(new GraceAuthRequirement(new IdentityEntry { Username = "Steve" }, null));

        byte[] keepAlive = MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(0x1B);
        await RunAsync(harness, keepAlive, keepAlive);

        Assert.Equal(PrologueLength() + (keepAlive.Length * 2), harness.Backend.Length);
    }

    [Fact]
    public async Task RegisteringUnfreezesThePlayer()
    {
        var entry = new IdentityEntry { Username = "Steve" };
        Harness harness = Create(new GraceAuthRequirement(entry, null));

        byte[] afterAuth = Movement(5);
        string? disconnect = await RunAsync(harness, Movement(1), Command("register hunter22"), afterAuth);

        Assert.Null(disconnect);
        Assert.NotNull(entry.PasswordHash);

        // The movement before registering was swallowed; the one after was forwarded.
        Assert.Equal(PrologueLength() + afterAuth.Length, harness.Backend.Length);
    }

    [Fact]
    public async Task RegisteringAlsoRemembersTheAddress()
    {
        // So the next reconnect does not demand a password again.
        var entry = new IdentityEntry { Username = "Steve" };
        Harness harness = Create(new GraceAuthRequirement(entry, null));

        await RunAsync(harness, Command("register hunter22"));

        Assert.True(entry.IsIpRecognized(Player));
    }

    [Fact]
    public async Task AShortPasswordPromptsAgainRatherThanKicking()
    {
        // They are choosing a password, not proving one. There is nothing to guess, so kicking them
        // for a typo would be hostile for no gain.
        var entry = new IdentityEntry { Username = "Steve" };
        Harness harness = Create(new GraceAuthRequirement(entry, null));

        string? disconnect = await RunAsync(harness, Command("register ab"), Command("register hunter22"));

        Assert.Null(disconnect);
        Assert.NotNull(entry.PasswordHash);
    }

    [Fact]
    public async Task AWrongPasswordFromARegisteredPlayerIsOneAttemptOnly()
    {
        // The opposite case, and the reason it differs: a wrong password against a name that already
        // exists is the classic stolen-credential probe, and letting somebody guess repeatedly is the
        // whole thing being defended against.
        var entry = new IdentityEntry { Username = "Steve", PasswordHash = PasswordHasher.Hash("correcthorse") };
        Harness harness = Create(new GraceAuthRequirement(entry, entry.PasswordHash));

        string? disconnect = await RunAsync(harness, Command("login wrongpassword"), Command("login correcthorse"));

        Assert.NotNull(disconnect);
    }

    [Fact]
    public async Task TheRightPasswordUnfreezesThem()
    {
        var entry = new IdentityEntry { Username = "Steve", PasswordHash = PasswordHasher.Hash("correcthorse") };
        Harness harness = Create(new GraceAuthRequirement(entry, entry.PasswordHash));

        byte[] afterAuth = Movement(9);
        string? disconnect = await RunAsync(harness, Movement(1), Command("login correcthorse"), afterAuth);

        Assert.Null(disconnect);
        Assert.Equal(PrologueLength() + afterAuth.Length, harness.Backend.Length);
    }

    [Fact]
    public async Task AnAuthenticatedPlayerIsNotFrozenAtAll()
    {
        // No requirement means no freeze — the ordinary case for the overwhelming majority of
        // connections, and it must cost them nothing.
        Harness harness = Create(new GraceAuthRequirement(new IdentityEntry { Username = "Steve" }, null));

        // Once the requirement is resolved by registering, later movement flows untouched.
        byte[] a = Movement(1), b = Movement(2);
        await RunAsync(harness, Command("register hunter22"), a, b);

        Assert.Equal(PrologueLength() + a.Length + b.Length, harness.Backend.Length);
    }

    private static int PrologueLength() =>
        MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(0x03).Length +
        MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(Ids.ConfigurationFinishConfigurationServerbound).Length;
}
