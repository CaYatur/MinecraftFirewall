using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Alerts;

/// <summary>
/// Posts alerts to a Discord webhook from a background pump.
///
/// <see cref="Send"/> only enqueues — it never awaits HTTP, never blocks, and never throws, because
/// every caller is on a live connection's path. The queue is bounded and drops the oldest entry when
/// full: under the sustained attack that generates the most alerts, an unbounded queue would be a
/// memory leak in precisely the moment the proxy most needs to stay up. Drops are counted and
/// reported rather than hidden, so a quiet channel is never mistaken for a quiet server.
/// </summary>
public sealed class DiscordAlertSender : IAlertSender, IDisposable
{
    private readonly AlertOptions _options;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<DiscordAlertSender> _logger;
    private readonly Channel<string> _queue;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Task _pump;
    private int _droppedSinceLastReport;

    public DiscordAlertSender(
        IOptions<AlertOptions> options,
        IHttpClientFactory httpClientFactory,
        ILogger<DiscordAlertSender> logger)
    {
        _options = options.Value;
        _httpClientFactory = httpClientFactory;
        _logger = logger;

        _queue = Channel.CreateBounded<string>(new BoundedChannelOptions(Math.Max(1, _options.MaxQueuedAlerts))
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
        });

        _pump = Task.Run(PumpAsync);
    }

    public bool IsEnabled => !string.IsNullOrWhiteSpace(_options.DiscordWebhookUrl);

    public void Send(AlertKind kind, string message)
    {
        if (!IsEnabled || !IsKindEnabled(kind))
            return;

        if (!_queue.Writer.TryWrite(AlertText.Truncate(message)))
            Interlocked.Increment(ref _droppedSinceLastReport);
    }

    private bool IsKindEnabled(AlertKind kind) => kind switch
    {
        AlertKind.Ban => _options.OnBan,
        AlertKind.NewTrustedIp => _options.OnNewTrustedIp,
        AlertKind.PremiumVerificationFailure => _options.OnPremiumVerificationFailure,
        AlertKind.DangerousCommand => _options.OnDangerousCommand,
        _ => false,
    };

    private async Task PumpAsync()
    {
        try
        {
            await foreach (string message in _queue.Reader.ReadAllAsync(_shutdown.Token).ConfigureAwait(false))
            {
                await PostAsync(message).ConfigureAwait(false);

                // Pace the pump rather than the producer: Discord rate-limits webhooks, and a burst
                // of bans would otherwise get most of its alerts rejected instead of delivered late.
                await Task.Delay(_options.MinimumInterval, _shutdown.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
        catch (Exception ex)
        {
            // The pump dying silently would mean alerts stop forever with no indication.
            _logger.LogError(ex, "The Discord alert pump stopped unexpectedly. Alerts are no longer being delivered.");
        }
    }

    private async Task PostAsync(string message)
    {
        int dropped = Interlocked.Exchange(ref _droppedSinceLastReport, 0);
        string body = dropped > 0
            ? $"{message}\n_({dropped} further alert(s) dropped — alerts are arriving faster than Discord accepts them.)_"
            : message;

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(_shutdown.Token);
            timeoutCts.CancelAfter(_options.HttpTimeout);

            var client = _httpClientFactory.CreateClient(nameof(DiscordAlertSender));
            using var response = await client
                .PostAsJsonAsync(_options.DiscordWebhookUrl, new { content = AlertText.Truncate(body) }, timeoutCts.Token)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                // Deliberately does not log the URL — it's a secret, and a failing webhook is exactly
                // when someone is most likely to paste a log into a support thread.
                _logger.LogWarning("Discord webhook returned {Status}; this alert was not delivered.", response.StatusCode);
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException or JsonException)
        {
            _logger.LogWarning(ex, "Could not deliver a Discord alert. The alert is lost; proxying is unaffected.");
        }
    }

    public void Dispose()
    {
        _queue.Writer.TryComplete();
        _shutdown.Cancel();

        try
        {
            // Cancelling above already aborts any in-flight post, so this is just letting the pump
            // task observe it. Kept well under HttpTimeout on purpose: waiting the full timeout would
            // add a guaranteed stall to every service stop that happens to catch a post in flight.
            _pump.Wait(TimeSpan.FromMilliseconds(500));
        }
        catch
        {
            // Shutting down anyway; a stuck HTTP call must not hold up service stop.
        }

        _shutdown.Dispose();
    }
}
