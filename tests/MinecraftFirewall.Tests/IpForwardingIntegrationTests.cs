using System.Net;
using System.Net.Sockets;
using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Inspection;
using MinecraftFirewall.Proxy.Messages;
using MinecraftFirewall.Proxy.Network;
using MinecraftFirewall.Proxy.Policy;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Tests;

/// <summary>
/// IP forwarding over a real socket, and what happens when the server on the other end is not expecting
/// it.
///
/// The second half is why this file exists. Both forwarding modes need the backend configured to match,
/// and a backend that is not configured does not fail politely — it reads the forwarding data as the
/// first Minecraft packet, cannot decode it, and drops the connection at once. That is a
/// misconfiguration a person will make, so the only question is what they see when they do. What they
/// saw first was a forty-line stack trace logged at error level, from a live server, with nothing in it
/// naming the cause.
/// </summary>
public class IpForwardingIntegrationTests : IAsyncLifetime
{
    private FakeBackendServer _backend = null!;
    private CancellationTokenSource _cts = null!;
    private FirewallBanService _banService = null!;
    private ConnectionGovernor _governor = null!;
    private BotDetector _botDetector = null!;
    private MinecraftFirewall.Proxy.Anomaly.AnomalyDetector _anomaly = null!;
    private MinecraftFirewall.Proxy.Protocol.ProtocolLearningService _learning = null!;
    private int _publicPort;

    public async Task InitializeAsync()
    {
        _backend = new FakeBackendServer();
        _backend.Start();

        _publicPort = GetFreeTcpPort();
        var profile = new ServerProfile
        {
            Name = "forwarding",
            PublicPort = _publicPort,
            BackendHost = "127.0.0.1",
            BackendPort = _backend.Port,
            IpForwarding = IpForwardingMode.ProxyProtocol,
        };

        var banOptions = Options.Create(new FirewallBanOptions { StrikesBeforeBan = 100 });
        _banService = new FirewallBanService(banOptions, new NeverBanList(Options.Create(new NeverBanOptions())),
            new FakeWindowsFirewallGateway(), new RecordingAlertSender(), NullLogger<FirewallBanService>.Instance);

        PolicyEngine policy = DefenseTestFactory.CreatePolicyEngine(_banService,
            banOptions: new FirewallBanOptions { StrikesBeforeBan = 100 });

        _cts = new CancellationTokenSource();
        _governor = DefenseTestFactory.CreateGovernor();
        _botDetector = DefenseTestFactory.CreateBotDetector();
        _anomaly = DefenseTestFactory.CreateAnomalyDetector();
        _learning = DefenseTestFactory.CreateProtocolLearning();

        using var key = new MinecraftFirewall.Proxy.Identity.Premium.RsaServerKeyPair();
        var listener = new ProxyListener(profile, policy, new IdentityOptions(),
            new DangerousCommandOptions().Commands, new MessagesOptions(),
            PremiumTestFactory.CreateHandshake(key), _governor, _botDetector,
            new InspectionOptions(), _anomaly, _learning, NullLogger.Instance);

        _ = listener.RunAsync(_cts.Token);

        await WaitUntilAsync(() => IsPortListening(_publicPort), TimeSpan.FromSeconds(5));
    }

    public async Task DisposeAsync()
    {
        await _cts.CancelAsync();
        _governor.Dispose();
        _botDetector.Dispose();
        _anomaly.Dispose();
        _banService.Dispose();
        await _backend.DisposeAsync();
    }

    [Fact]
    public async Task TheBackendIsToldTheRealAddressBeforeAnyMinecraftBytes()
    {
        // Over a real socket, through the real listener — the unit tests build the header, this proves
        // it actually goes out, first, and ahead of the handshake it is describing.
        byte[] handshake = MinecraftPacketBuilder.BuildHandshakeFrame(767, "localhost", (ushort)_publicPort, nextState: 2);
        byte[] loginStart = MinecraftPacketBuilder.BuildLoginStartFrame("PlayerX");

        await SendAndHalfCloseAsync(_publicPort, [.. handshake, .. loginStart]);

        Assert.True(await WaitUntilAsync(() => _backend.ConnectionCount == 1, TimeSpan.FromSeconds(3)));

        byte[] received = _backend.LastReceived!;
        Assert.Equal<byte>([0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A], received[..12]);
        Assert.Equal(0x21, received[12]); // version 2, command PROXY

        // The Minecraft conversation follows the header, byte for byte, unchanged.
        Assert.Equal<byte>([.. handshake, .. loginStart], received[28..]);
    }

    [Fact]
    public async Task TheHeaderCarriesTheConnectingAddressRatherThanTheProxys()
    {
        // The entire point. Both ends are loopback in a test, so what is actually checked is that the
        // source port is the client's own — the field that would be wrong if the two ends were swapped.
        byte[] handshake = MinecraftPacketBuilder.BuildHandshakeFrame(767, "localhost", (ushort)_publicPort, nextState: 2);

        int clientPort = await SendAndHalfCloseAsync(_publicPort, [.. handshake, .. MinecraftPacketBuilder.BuildLoginStartFrame("PlayerX")]);

        Assert.True(await WaitUntilAsync(() => _backend.ConnectionCount == 1, TimeSpan.FromSeconds(3)));

        byte[] received = _backend.LastReceived!;
        Assert.Equal(new byte[] { 127, 0, 0, 1 }, received[16..20]);
        Assert.Equal(clientPort, (received[24] << 8) | received[25]);

        // The public port, not the backend one. A PROXY header describes the connection the client
        // actually made — where they came from and what they connected to — not the second leg the
        // proxy opened on their behalf. A server reading it wants to know which of its front doors the
        // player used, and the backend port is a detail of the plumbing in between.
        Assert.Equal(_publicPort, (received[26] << 8) | received[27]);
    }

    [Fact]
    public async Task ABackendThatDropsTheConnectionDoesNotCrashTheHandler()
    {
        // What a misconfigured server does: it reads the header as a Minecraft packet, finds packet id
        // 0x0A where a handshake's 0x00 belongs, and closes. Reproduced here by simply closing.
        //
        // The proxy must survive it and keep serving. Before this, the write that followed threw an
        // IOException that nothing caught, and it surfaced as an unhandled error with a full stack.
        await using var rude = new ClosesImmediatelyServer();

        var profile = new ServerProfile
        {
            Name = "rude",
            PublicPort = GetFreeTcpPort(),
            BackendHost = "127.0.0.1",
            BackendPort = rude.Port,
            IpForwarding = IpForwardingMode.ProxyProtocol,
        };

        var banOptions = Options.Create(new FirewallBanOptions { StrikesBeforeBan = 100 });
        using var banService = new FirewallBanService(banOptions,
            new NeverBanList(Options.Create(new NeverBanOptions())), new FakeWindowsFirewallGateway(),
            new RecordingAlertSender(), NullLogger<FirewallBanService>.Instance);

        using var governor = DefenseTestFactory.CreateGovernor();
        using var bots = DefenseTestFactory.CreateBotDetector();
        using var anomaly = DefenseTestFactory.CreateAnomalyDetector();
        using var key = new MinecraftFirewall.Proxy.Identity.Premium.RsaServerKeyPair();
        using var cts = new CancellationTokenSource();

        var listener = new ProxyListener(profile,
            DefenseTestFactory.CreatePolicyEngine(banService, banOptions: new FirewallBanOptions { StrikesBeforeBan = 100 }),
            new IdentityOptions(), new DangerousCommandOptions().Commands, new MessagesOptions(),
            PremiumTestFactory.CreateHandshake(key), governor, bots, new InspectionOptions(),
            anomaly, DefenseTestFactory.CreateProtocolLearning(), NullLogger.Instance);

        Task running = listener.RunAsync(cts.Token);
        Assert.True(await WaitUntilAsync(() => IsPortListening(profile.PublicPort), TimeSpan.FromSeconds(5)));

        byte[] traffic =
        [
            .. MinecraftPacketBuilder.BuildHandshakeFrame(767, "localhost", (ushort)profile.PublicPort, nextState: 2),
            .. MinecraftPacketBuilder.BuildLoginStartFrame("PlayerX"),
        ];

        // Several in a row: one survived connection proves nothing if the listener dies on the second.
        for (int i = 0; i < 3; i++)
            await SendAndHalfCloseAsync(profile.PublicPort, traffic);

        await Task.Delay(300);

        Assert.False(running.IsFaulted, "the listener faulted on a backend that hung up");
        Assert.True(IsPortListening(profile.PublicPort), "the listener stopped accepting after a backend hung up");

        await cts.CancelAsync();
    }

    /// <summary>A backend that accepts and immediately closes, the way a Minecraft server does when the
    /// first thing it reads is not a packet it can decode.</summary>
    private sealed class ClosesImmediatelyServer : IAsyncDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts = new();

        public int Port { get; }

        public ClosesImmediatelyServer()
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _ = AcceptAsync(_cts.Token);
        }

        private async Task AcceptAsync(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    using TcpClient client = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);

                    // Reset rather than a graceful close, which is what an abrupt server-side decode
                    // failure produces and what makes the proxy's next write throw.
                    client.LingerState = new LingerOption(true, 0);
                    client.Close();
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
            {
            }
        }

        public async ValueTask DisposeAsync()
        {
            await _cts.CancelAsync();
            _listener.Stop();
            _cts.Dispose();
        }
    }

    private static async Task<int> SendAndHalfCloseAsync(int port, byte[] payload)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);

        int localPort = ((IPEndPoint)client.Client.LocalEndPoint!).Port;

        NetworkStream stream = client.GetStream();
        await stream.WriteAsync(payload);
        await stream.FlushAsync();
        client.Client.Shutdown(SocketShutdown.Send);

        await Task.Delay(150);
        return localPort;
    }

    private static int GetFreeTcpPort()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        int port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
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
        catch (SocketException)
        {
            return false;
        }
    }

    private static async Task<bool> WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
    {
        DateTime deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
                return true;

            await Task.Delay(50);
        }

        return condition();
    }
}
