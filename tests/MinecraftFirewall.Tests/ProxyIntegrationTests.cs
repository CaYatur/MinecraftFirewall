using System.Net;
using System.Net.Sockets;
using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Identity.Premium;
using MinecraftFirewall.Proxy.IpIntel;
using MinecraftFirewall.Proxy.Messages;
using MinecraftFirewall.Proxy.Policy;
using MinecraftFirewall.Proxy.Protocol;
using MinecraftFirewall.Proxy.RateLimiting;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Inspection;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Two real ProxyListeners in front of two real (fake) backends, sharing one PolicyEngine — proves
/// routing correctness and per-profile rate-limit isolation over actual sockets. The cross-profile
/// shared-ban guarantee is covered directly at the PolicyEngine level instead (see
/// PolicyEngineTests.EvaluateLogin_BanTriggeredViaOneProfile_BlocksSameIpOnAnotherProfile) because
/// every real connection here necessarily originates from loopback, and loopback is deliberately
/// exempt from ever receiving an actual firewall ban (NeverBanList) — so this class can't exercise
/// that path over real sockets without weakening a real safety mechanism just to make a test pass.
/// </summary>
public class ProxyIntegrationTests : IAsyncLifetime
{
    private FakeBackendServer _backendA = null!;
    private FakeBackendServer _backendB = null!;
    private ServerProfile _profileA = null!;
    private ServerProfile _profileB = null!;
    private PolicyEngine _policyEngine = null!;
    private CancellationTokenSource _listenersCts = null!;
    private FirewallBanService _banService = null!;
    private RsaServerKeyPair _serverKey = null!;
    private ConnectionGovernor _governor = null!;
    private BotDetector _botDetector = null!;

    public async Task InitializeAsync()
    {
        _backendA = new FakeBackendServer();
        _backendB = new FakeBackendServer();
        _backendA.Start();
        _backendB.Start();

        int publicPortA = GetFreeTcpPort();
        int publicPortB = GetFreeTcpPort();

        _profileA = new ServerProfile { Name = "profileA", PublicPort = publicPortA, BackendHost = "127.0.0.1", BackendPort = _backendA.Port };
        _profileB = new ServerProfile { Name = "profileB", PublicPort = publicPortB, BackendHost = "127.0.0.1", BackendPort = _backendB.Port };

        var vpnIntel = new VpnIntelligence();
        var rateLimiter = new ConnectionRateLimiter(Options.Create(new RateLimitOptions
        {
            LoginMaxPerWindow = 2,
            LoginWindow = TimeSpan.FromSeconds(30),
            StatusPingMaxPerWindow = 20,
            StatusPingWindow = TimeSpan.FromSeconds(10),
        }));
        var gateway = new FakeWindowsFirewallGateway();
        var neverBanList = new NeverBanList(Options.Create(new NeverBanOptions()));
        var banOptions = Options.Create(new FirewallBanOptions { StrikesBeforeBan = 100 }); // effectively disabled for this test
        _banService = new FirewallBanService(banOptions, neverBanList, gateway, new RecordingAlertSender(), NullLogger<FirewallBanService>.Instance);
        var strikeTracker = new StrikeTracker();

        _policyEngine = new PolicyEngine(vpnIntel, rateLimiter, _banService, strikeTracker, new FakeIpInfoClient(), new RecordingAlertSender(),
            DefenseTestFactory.CreateThreatIntelligence(), banOptions, Options.Create(new IpInfoOptions()),
            Options.Create(new DdosOptions()), Options.Create(new BotDefenseOptions()), NullLogger<PolicyEngine>.Instance);

        var identityOptions = new IdentityOptions();
        var dangerousCommands = new DangerousCommandOptions().Commands;
        var messages = new MessagesOptions();

        _serverKey = new RsaServerKeyPair();
        var premiumHandshake = PremiumTestFactory.CreateHandshake(_serverKey);

        _listenersCts = new CancellationTokenSource();
        _governor = DefenseTestFactory.CreateGovernor();
        _botDetector = DefenseTestFactory.CreateBotDetector();
        var inspection = new InspectionOptions();
        var listenerA = new ProxyListener(_profileA, _policyEngine, identityOptions, dangerousCommands, messages,
            premiumHandshake, _governor, _botDetector, inspection, NullLogger.Instance);
        var listenerB = new ProxyListener(_profileB, _policyEngine, identityOptions, dangerousCommands, messages,
            premiumHandshake, _governor, _botDetector, inspection, NullLogger.Instance);
        _ = listenerA.RunAsync(_listenersCts.Token);
        _ = listenerB.RunAsync(_listenersCts.Token);

        await WaitUntilAsync(() => IsPortListening(publicPortA) && IsPortListening(publicPortB), TimeSpan.FromSeconds(5));
    }

    public async Task DisposeAsync()
    {
        await _listenersCts.CancelAsync();
        _governor.Dispose();
        _botDetector.Dispose();
        _banService.Dispose();
        _serverKey.Dispose();
        await _backendA.DisposeAsync();
        await _backendB.DisposeAsync();
    }

    [Fact]
    public async Task Login_RoutesToCorrectBackend_AndForwardsBytesVerbatim()
    {
        byte[] handshake = MinecraftPacketBuilder.BuildHandshakeFrame(767, "localhost", (ushort)_profileA.PublicPort, nextState: 2);
        byte[] loginStart = MinecraftPacketBuilder.BuildLoginStartFrame("PlayerX");

        await SendAndHalfCloseAsync(_profileA.PublicPort, [.. handshake, .. loginStart]);

        Assert.True(await WaitUntilAsync(() => _backendA.ConnectionCount == 1, TimeSpan.FromSeconds(3)));
        Assert.Equal(0, _backendB.ConnectionCount);
        Assert.NotNull(_backendA.LastReceived);
        Assert.Equal<byte>([.. handshake, .. loginStart], _backendA.LastReceived!);
    }

    [Fact]
    public async Task Login_RateLimitOnOneProfile_DoesNotAffectAnother()
    {
        byte[] handshakeA = MinecraftPacketBuilder.BuildHandshakeFrame(767, "localhost", (ushort)_profileA.PublicPort, nextState: 2);

        // LoginMaxPerWindow is 2 for both profiles' rate limiter, but limits are keyed per-profile —
        // exhaust profile A's window, then confirm profile B (same source IP: loopback) is unaffected.
        for (int i = 0; i < 2; i++)
            await SendAndHalfCloseAsync(_profileA.PublicPort, [.. handshakeA, .. MinecraftPacketBuilder.BuildLoginStartFrame($"P{i}")]);

        await WaitUntilAsync(() => _backendA.ConnectionCount == 2, TimeSpan.FromSeconds(3));

        // Third attempt on profile A should be denied (rate limit exceeded) — backend A connection count stays at 2.
        await SendAndHalfCloseAsync(_profileA.PublicPort, [.. handshakeA, .. MinecraftPacketBuilder.BuildLoginStartFrame("P2")]);
        await Task.Delay(200); // give the denied attempt a moment to (not) reach the backend
        Assert.Equal(2, _backendA.ConnectionCount);

        // Profile B, same source IP, must still accept its own first attempt.
        byte[] handshakeB = MinecraftPacketBuilder.BuildHandshakeFrame(767, "localhost", (ushort)_profileB.PublicPort, nextState: 2);
        await SendAndHalfCloseAsync(_profileB.PublicPort, [.. handshakeB, .. MinecraftPacketBuilder.BuildLoginStartFrame("Q0")]);

        Assert.True(await WaitUntilAsync(() => _backendB.ConnectionCount == 1, TimeSpan.FromSeconds(3)));
    }

    [Fact]
    public async Task Login_DeniedProtectedUsername_ReceivesActualDisconnectPacket_NotJustAReset()
    {
        var entry = new IdentityEntry { Username = "Admin" };
        entry.StaticAllowlist.Add(CidrRange.Parse("198.51.100.0/24")); // never matches loopback test traffic
        _profileA.IdentityStore.AddOrReplace(entry);

        byte[] handshake = MinecraftPacketBuilder.BuildHandshakeFrame(767, "localhost", (ushort)_profileA.PublicPort, nextState: 2);
        byte[] loginStart = MinecraftPacketBuilder.BuildLoginStartFrame("Admin");

        byte[] response = await SendAndCaptureResponseAsync(_profileA.PublicPort, [.. handshake, .. loginStart]);

        Assert.NotEmpty(response);
        // A real Login Disconnect frame: VarInt frame length, then VarInt packet ID 0x00.
        int frameLength = VarInt.Decode(response, out int prefixLen);
        Assert.True(frameLength > 0);
        int packetId = VarInt.Decode(response.AsSpan(prefixLen), out _);
        Assert.Equal(0x00, packetId);

        Assert.Equal(0, _backendA.ConnectionCount);
    }

    private static async Task SendAndHalfCloseAsync(int port, byte[] payload)
    {
        await SendAndCaptureResponseAsync(port, payload);
    }

    private static async Task<byte[]> SendAndCaptureResponseAsync(int port, byte[] payload)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        var stream = client.GetStream();
        await stream.WriteAsync(payload);
        client.Client.Shutdown(SocketShutdown.Send);

        using var ms = new MemoryStream();
        var buffer = new byte[1024];
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
            int read;
            while ((read = await stream.ReadAsync(buffer, cts.Token)) > 0)
                ms.Write(buffer, 0, read);
        }
        catch
        {
            // Timeout/reset is fine — we only needed to send and observe whatever came back.
        }

        return ms.ToArray();
    }

    private static int GetFreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static bool IsPortListening(int port)
    {
        try
        {
            using var probe = new TcpClient();
            probe.Connect(IPAddress.Loopback, port);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
                return true;
            await Task.Delay(25);
        }
        return condition();
    }
}
