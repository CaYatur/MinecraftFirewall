using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.IpIntel;

/// <summary>
/// Real ipinfo.io Lite API client — real-time per-connection lookup, per-IP TTL cache, fails open
/// (returns NoSignal, never throws) on a missing token, timeout, non-success response, or malformed
/// body. An outage or misconfiguration here must never be able to block a legitimate player or leak
/// as an unhandled exception into PolicyEngine.
/// </summary>
public sealed class IpInfoClient(
    IHttpClientFactory httpClientFactory,
    IOptions<IpInfoOptions> options,
    ILogger<IpInfoClient> logger) : IIpInfoClient
{
    private readonly IpInfoOptions _options = options.Value;
    private readonly ConcurrentDictionary<IPAddress, (IpInfoLookupResult Result, DateTimeOffset ExpiresAt)> _cache = new();

    public async Task<IpInfoLookupResult> LookupAsync(IPAddress address, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_options.Token))
            return IpInfoLookupResult.NoSignal; // feature disabled — no token configured

        if (_cache.TryGetValue(address, out var cached) && cached.ExpiresAt > DateTimeOffset.UtcNow)
            return cached.Result;

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(_options.HttpTimeout);

            var client = httpClientFactory.CreateClient(nameof(IpInfoClient));
            string url = $"https://api.ipinfo.io/lite/{address}?token={Uri.EscapeDataString(_options.Token)}";

            using var response = await client.GetAsync(url, timeoutCts.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogDebug("ipinfo.io lookup for {Ip} returned {Status}; treating as no signal (fail-open).", address, response.StatusCode);
                return IpInfoLookupResult.NoSignal;
            }

            var payload = await response.Content.ReadFromJsonAsync<IpInfoLiteResponse>(timeoutCts.Token).ConfigureAwait(false);
            var result = Evaluate(payload);

            _cache[address] = (result, DateTimeOffset.UtcNow.Add(_options.CacheTtl));
            return result;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException
            or System.Text.Json.JsonException or NotSupportedException)
        {
            logger.LogDebug(ex, "ipinfo.io lookup for {Ip} failed; treating as no signal (fail-open).", address);
            return IpInfoLookupResult.NoSignal;
        }
    }

    private IpInfoLookupResult Evaluate(IpInfoLiteResponse? payload)
    {
        if (payload is null)
            return IpInfoLookupResult.NoSignal;

        string haystack = $"{payload.AsName} {payload.AsDomain}";
        bool isHostingLike = _options.HostingKeywords.Any(keyword =>
            haystack.Contains(keyword, StringComparison.OrdinalIgnoreCase));

        return new IpInfoLookupResult(isHostingLike, payload.AsName, payload.Asn);
    }

    private sealed record IpInfoLiteResponse(
        [property: JsonPropertyName("asn")] string? Asn,
        [property: JsonPropertyName("as_name")] string? AsName,
        [property: JsonPropertyName("as_domain")] string? AsDomain);
}
