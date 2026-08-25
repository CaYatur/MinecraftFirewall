using System.Net;
using System.Net.Sockets;
using System.Text;
using MinecraftFirewall.Proxy.Alerts;
using MinecraftFirewall.Proxy.Enforcement;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Defense;

/// <summary>
/// Listens on decoy ports and reports whoever knocks.
///
/// Three things about how this is wired matter more than the listening itself.
///
/// It never bans directly. Every hit goes through the same StrikeTracker and FirewallBanService the
/// rest of the firewall uses, which is what keeps the allowlist honest: loopback, the local network
/// and anything in NeverBan stay unbannable, so an admin running a port scan on their own machine
/// cannot lock themselves out, and the guarantee that a premium username's real owner is never
/// refused survives a honeypot being switched on.
///
/// A port it cannot bind is a warning, not a failure. Decoys are an optional extra; a collision with
/// something the machine already runs must not stop the actual firewall from starting.
///
/// And ports already in use by a configured server profile are dropped before any binding is
/// attempted, because losing that race would mean the decoy either fails or — far worse, depending on
/// start order — wins, and real players are banned for connecting to their own server.
/// </summary>
public sealed class HoneypotService(
    IOptions<HoneypotOptions> options,
    IOptions<FirewallBanOptions> banOptions,
    IReadOnlyList<ServerProfile> profiles,
    StrikeTracker strikeTracker,
    FirewallBanService banService,
    ThreatIntelligence threatIntelligence,
    IAlertSender alerts,
    ILogger<HoneypotService> logger) : BackgroundService
{
    private readonly HoneypotOptions _options = options.Value;
    private readonly FirewallBanOptions _banOptions = banOptions.Value;

    private int _hits;

    public int TotalHits => Volatile.Read(ref _hits);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
            return;

        int[] ports = UsablePorts();
        if (ports.Length == 0)
        {
            logger.LogWarning("Honeypot is enabled but no usable ports are left after removing ones your servers already use.");
            return;
        }

        logger.LogInformation("Honeypot listening on {Ports}. Anything that connects here is enumerating, not playing.",
            string.Join(", ", ports));

        await Task.WhenAll(ports.Select(port => ListenAsync(port, stoppingToken))).ConfigureAwait(false);
    }

    /// <summary>Configured ports minus any a real server profile is already using. Both the public
    /// and backend ports are excluded: binding a decoy on a backend port would sit between the proxy
    /// and the actual Minecraft server.</summary>
    private int[] UsablePorts()
    {
        var taken = new HashSet<int>();
        foreach (ServerProfile profile in profiles)
        {
            taken.Add(profile.PublicPort);
            taken.Add(profile.BackendPort);
        }

        var usable = new List<int>();
        foreach (int port in _options.Ports.Distinct())
        {
            if (port is < 1 or > 65535)
            {
                logger.LogWarning("Honeypot port {Port} is not a valid port number — ignoring it.", port);
            }
            else if (taken.Contains(port))
            {
                logger.LogWarning("Honeypot port {Port} is already used by one of your servers — ignoring it. " +
                                  "Pick a port nothing you run listens on.", port);
            }
            else
            {
                usable.Add(port);
            }
        }

        return [.. usable];
    }

    private async Task ListenAsync(int port, CancellationToken ct)
    {
        TcpListener listener;
        try
        {
            listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
        }
        catch (SocketException ex)
        {
            // Almost always something else already has the port. Worth saying clearly, worth not
            // taking the service down over.
            logger.LogWarning("Could not open honeypot port {Port} ({Message}). The rest of the firewall is unaffected.",
                port, ex.Message);
            return;
        }

        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (SocketException ex)
                {
                    logger.LogDebug("Honeypot accept on port {Port} failed: {Message}", port, ex.Message);
                    continue;
                }

                _ = HandleProbeAsync(client, port, ct);
            }
        }
        finally
        {
            listener.Stop();
        }
    }

    private async Task HandleProbeAsync(TcpClient client, int port, CancellationToken ct)
    {
        using (client)
        {
            try
            {
                if (client.Client.RemoteEndPoint is not IPEndPoint endpoint)
                    return;

                string fingerprint = await ReadProbeAsync(client, ct).ConfigureAwait(false);
                Report(endpoint.Address, port, fingerprint);
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "Honeypot probe handling failed on port {Port}.", port);
            }
        }
    }

    /// <summary>Reads the opening bytes so the log can say what kind of scanner this was, then stops.
    /// Never replies: a decoy that answers is a decoy that can be used to reflect traffic.</summary>
    private async Task<string> ReadProbeAsync(TcpClient client, CancellationToken ct)
    {
        try
        {
            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readCts.CancelAfter(_options.ProbeReadTimeout);

            var buffer = new byte[_options.ProbeBytesToRead];
            int read = await client.GetStream().ReadAsync(buffer, readCts.Token).ConfigureAwait(false);

            return read <= 0 ? "connected and sent nothing" : Describe(buffer.AsSpan(0, read));
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or SocketException)
        {
            return "connected and sent nothing";
        }
    }

    /// <summary>Turns the opening bytes into something readable without letting attacker-chosen data
    /// into a log line unfiltered — the same discipline the Discord alert text uses.</summary>
    private static string Describe(ReadOnlySpan<byte> probe)
    {
        // A Minecraft handshake starts with a length VarInt then packet id 0x00; an HTTP probe starts
        // with a verb. Naming the two common cases makes the log immediately legible.
        if (probe.Length >= 2 && probe[1] == 0x00)
            return $"sent a Minecraft-shaped handshake ({probe.Length} bytes)";

        var text = new StringBuilder(probe.Length);
        foreach (byte b in probe[..Math.Min(probe.Length, 24)])
            text.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');

        return $"sent {probe.Length} bytes starting '{text}'";
    }

    private void Report(IPAddress address, int port, string fingerprint)
    {
        Interlocked.Increment(ref _hits);

        logger.LogWarning("HONEYPOT: {Ip} touched decoy port {Port} — {Fingerprint}.", address, port, fingerprint);

        if (_options.RecordToThreatList)
            threatIntelligence.RecordLocalHit(address, $"honeypot port {port}", DateTimeOffset.UtcNow);

        // Through the shared strike/ban path, never around it — the allowlist checks live in there.
        int strikes = strikeTracker.RegisterStrike(address, _options.StrikeWeight);
        if (strikes >= _banOptions.StrikesBeforeBan)
        {
            banService.Ban(address, $"touched honeypot port {port} ({fingerprint})");
            strikeTracker.Reset(address);
        }

        alerts.Send(AlertKind.Ban,
            $"🍯 **Honeypot hit** on port `{port}` from `{AlertText.Field(address.ToString())}` — {AlertText.Field(fingerprint)}");
    }
}
