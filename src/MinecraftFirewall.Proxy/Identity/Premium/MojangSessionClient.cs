using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Identity.Premium;

/// <summary>Real Mojang session-server client. See IPremiumSessionClient's doc comment for why this
/// fails CLOSED (any error -> NotJoined), the opposite of IpInfoClient's fail-open behavior.</summary>
public sealed class MojangSessionClient(
    IHttpClientFactory httpClientFactory,
    IOptions<PremiumOptions> options,
    ILogger<MojangSessionClient> logger) : IPremiumSessionClient
{
    private readonly PremiumOptions _options = options.Value;

    public async Task<HasJoinedResult> HasJoinedAsync(string username, string serverIdHash, CancellationToken ct)
    {
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(_options.HttpTimeout);

            var client = httpClientFactory.CreateClient(nameof(MojangSessionClient));
            string url = $"https://sessionserver.mojang.com/session/minecraft/hasJoined?username={Uri.EscapeDataString(username)}&serverId={Uri.EscapeDataString(serverIdHash)}";

            using var response = await client.GetAsync(url, timeoutCts.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                // 204 No Content (no matching session) or any other non-success — always "not
                // joined", never a fallback. See IPremiumSessionClient's doc comment.
                logger.LogWarning("Mojang hasJoined check for '{Username}' returned {Status} — treating as verification failure.", username, response.StatusCode);
                return HasJoinedResult.NotJoined;
            }

            var payload = await response.Content.ReadFromJsonAsync<HasJoinedResponse>(timeoutCts.Token).ConfigureAwait(false);
            if (payload is null || !Guid.TryParse(InsertUuidDashes(payload.Id), out Guid uuid))
            {
                logger.LogWarning("Mojang hasJoined check for '{Username}' returned an unparseable body — treating as verification failure.", username);
                return HasJoinedResult.NotJoined;
            }

            return new HasJoinedResult(true, uuid, payload.Name);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException
            or JsonException or NotSupportedException)
        {
            logger.LogWarning(ex, "Mojang hasJoined check for '{Username}' failed — treating as verification failure (fail-closed, unlike the ipinfo.io signal).", username);
            return HasJoinedResult.NotJoined;
        }
    }

    private static string InsertUuidDashes(string compact) =>
        compact.Length == 32
            ? $"{compact[..8]}-{compact[8..12]}-{compact[12..16]}-{compact[16..20]}-{compact[20..]}"
            : compact;

    private sealed record HasJoinedResponse(
        [property: JsonPropertyName("id")] string Id,
        [property: JsonPropertyName("name")] string Name);
}
