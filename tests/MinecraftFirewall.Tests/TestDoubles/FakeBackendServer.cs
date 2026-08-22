using System.Net;
using System.Net.Sockets;

namespace MinecraftFirewall.Tests.TestDoubles;

/// <summary>A minimal loopback TCP server standing in for a real Minecraft server backend in integration tests.</summary>
public sealed class FakeBackendServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly List<byte[]> _receivedPerConnection = [];
    private readonly object _lock = new();
    private readonly CancellationTokenSource _cts = new();
    private Task? _acceptLoop;

    public int Port { get; }

    public FakeBackendServer()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
    }

    public void Start() => _acceptLoop = AcceptLoopAsync(_cts.Token);

    public int ConnectionCount
    {
        get { lock (_lock) return _receivedPerConnection.Count; }
    }

    public byte[]? LastReceived
    {
        get { lock (_lock) return _receivedPerConnection.Count > 0 ? _receivedPerConnection[^1] : null; }
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                _ = HandleAsync(client, ct);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task HandleAsync(TcpClient client, CancellationToken ct)
    {
        using var _ = client;
        using var ms = new MemoryStream();
        var buffer = new byte[4096];

        try
        {
            var stream = client.GetStream();
            int read;
            while ((read = await stream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
                ms.Write(buffer, 0, read);
        }
        catch
        {
            // Connection reset/aborted — still record whatever was read before that happened.
        }

        lock (_lock)
        {
            _receivedPerConnection.Add(ms.ToArray());
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _listener.Stop();
        if (_acceptLoop is not null)
        {
            try { await _acceptLoop; } catch { }
        }
    }
}
