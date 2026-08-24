using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.IpIntel;

/// <summary>
/// Downloads the free VPN/datacenter CIDR lists on startup and on a daily timer. Disk-caches the
/// last good copy so a cold start without internet still has data, and fails open (keeps whatever
/// table is already loaded, logs a warning) if a refresh fails — an outage in the list source must
/// never turn into "block everyone."
/// </summary>
public sealed class IpListRefreshService(
    VpnIntelligence intelligence,
    IOptions<VpnIntelOptions> options,
    IHttpClientFactory httpClientFactory,
    ILogger<IpListRefreshService> logger) : BackgroundService
{
    private readonly VpnIntelOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(_options.CacheDirectory);

        LoadFromDiskCache("vpn-ipv4.txt", intelligence.UpdateVpnOnly);
        LoadFromDiskCache("datacenter-ipv4.txt", intelligence.UpdateVpnAndDatacenter);

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

    /// <summary>Refreshes both lists immediately, bypassing the daily timer — used at startup and by
    /// the Admin CLI's `reload` command.</summary>
    public async Task RefreshNowAsync(CancellationToken ct)
    {
        await RefreshOneAsync(_options.VpnListUrl, "vpn-ipv4.txt", intelligence.UpdateVpnOnly, ct).ConfigureAwait(false);
        await RefreshOneAsync(_options.DatacenterListUrl, "datacenter-ipv4.txt", intelligence.UpdateVpnAndDatacenter, ct).ConfigureAwait(false);
    }

    private void LoadFromDiskCache(string fileName, Action<Ipv4RangeTable> update)
    {
        string path = Path.Combine(_options.CacheDirectory, fileName);
        try
        {
            if (!File.Exists(path))
                return;

            var table = Ipv4RangeTable.Parse(File.ReadLines(path));
            update(table);
            logger.LogInformation("Loaded {File} from disk cache ({Count} ranges).", fileName, table.RangeCount);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to load disk cache {File}; starting with no data for it until the next refresh.", fileName);
        }
    }

    private async Task RefreshOneAsync(string url, string cacheFileName, Action<Ipv4RangeTable> update, CancellationToken ct)
    {
        try
        {
            using var client = httpClientFactory.CreateClient(nameof(IpListRefreshService));
            client.Timeout = _options.HttpTimeout;

            string content = await client.GetStringAsync(url, ct).ConfigureAwait(false);
            var lines = content.Split('\n');
            var table = Ipv4RangeTable.Parse(lines);

            string path = Path.Combine(_options.CacheDirectory, cacheFileName);
            await File.WriteAllTextAsync(path, content, ct).ConfigureAwait(false);

            update(table);
            logger.LogInformation("Refreshed {Url} ({Count} ranges).", url, table.RangeCount);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to refresh {Url}; keeping the previously loaded list (fail-open).", url);
        }
    }
}
