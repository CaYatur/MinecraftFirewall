using MinecraftFirewall.Proxy.IpIntel;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Defense;

/// <summary>
/// Keeps the imported threat lists current and writes this installation's own findings to disk.
///
/// Fails open in both directions, deliberately. A feed that cannot be fetched leaves whatever table
/// is already loaded in place — an outage at the list host must never become "refuse everyone" here,
/// any more than it may in the VPN lists. And the disk cache means a machine that boots without
/// internet still starts with the last good copy rather than nothing.
/// </summary>
public sealed class ThreatFeedService(
    ThreatIntelligence intelligence,
    IOptions<ThreatIntelOptions> options,
    IHttpClientFactory httpClientFactory,
    ILogger<ThreatFeedService> logger) : BackgroundService
{
    private const string CacheFileName = "threat-feed-ipv4.txt";
    private static readonly TimeSpan SaveInterval = TimeSpan.FromSeconds(30);

    private readonly ThreatIntelOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // The local observation log is loaded and saved whether or not the imported feeds are
        // switched on. Those are two different things wearing one section name: what this machine
        // caught on its own honeypot ports belongs to the honeypot, and turning off a subscription to
        // other people's lists should not quietly stop recording your own catches. An earlier version
        // gated both on Enabled, so a server with the honeypot on and the feed off recorded hits in
        // memory and lost them at every restart, silently.
        intelligence.Load();

        // Written far more often than the feeds are fetched, so it runs on its own cadence.
        Task saving = SaveLoopAsync(stoppingToken);

        if (_options.Enabled)
        {
            Directory.CreateDirectory(_options.CacheDirectory);
            LoadFromDiskCache();

            while (!stoppingToken.IsCancellationRequested)
            {
                await RefreshNowAsync(stoppingToken).ConfigureAwait(false);

                try
                {
                    await Task.Delay(_options.RefreshInterval, stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        await saving.ConfigureAwait(false);

        // One last write on the way out, so a clean shutdown never loses the last few observations.
        intelligence.SaveIfChanged();
    }

    public async Task RefreshNowAsync(CancellationToken ct)
    {
        if (_options.FeedUrls.Count == 0)
        {
            // Enabled with nothing to fetch. Silence here reads as "working" while the imported list
            // stays empty forever — and the way it happens in practice is an upgrade from a release
            // that predates this section, leaving the option object on its (empty) compiled defaults.
            logger.LogWarning(
                "Threat intelligence is enabled but no feed URLs are configured, so no list will be imported. " +
                "Add a ThreatIntel section to appsettings.json — the control panel offers to do this for you, " +
                "or copy it from appsettings.default.json.");
            return;
        }

        var lines = new List<string>();
        int fetched = 0;

        // Distinct because the same URL listed twice would double the download for no extra coverage,
        // and configuration binding makes accidental duplicates easy to introduce.
        foreach (string url in _options.FeedUrls.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            string[]? body = await FetchAsync(url, ct).ConfigureAwait(false);
            if (body is null)
                continue;

            lines.AddRange(body);
            fetched++;
        }

        if (fetched == 0)
        {
            logger.LogWarning("No threat feed could be fetched — keeping the {Count} range(s) already loaded.",
                intelligence.ImportedRangeCount);
            return;
        }

        Ipv4RangeTable table = Ipv4RangeTable.Parse(lines);
        intelligence.UpdateImported(table);
        logger.LogInformation("Threat feed refreshed: {Count} range(s) from {Feeds} source(s).", table.RangeCount, fetched);

        TryWriteDiskCache(lines);
    }

    private async Task<string[]?> FetchAsync(string url, CancellationToken ct)
    {
        try
        {
            using HttpClient http = httpClientFactory.CreateClient();
            http.Timeout = _options.HttpTimeout;

            string body = await http.GetStringAsync(url, ct).ConfigureAwait(false);
            return body.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            logger.LogWarning("Could not fetch threat feed {Url}: {Message}", url, ex.Message);
            return null;
        }
    }

    private void LoadFromDiskCache()
    {
        string path = Path.Combine(_options.CacheDirectory, CacheFileName);
        try
        {
            if (!File.Exists(path))
                return;

            Ipv4RangeTable table = Ipv4RangeTable.Parse(File.ReadLines(path));
            intelligence.UpdateImported(table);
            logger.LogInformation("Loaded the threat feed from disk cache ({Count} ranges).", table.RangeCount);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not read the cached threat feed at {Path}.", path);
        }
    }

    private void TryWriteDiskCache(List<string> lines)
    {
        try
        {
            File.WriteAllLines(Path.Combine(_options.CacheDirectory, CacheFileName), lines);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not cache the threat feed to disk. It will be re-fetched next start.");
        }
    }

    private async Task SaveLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(SaveInterval, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            intelligence.SaveIfChanged();
        }
    }
}
