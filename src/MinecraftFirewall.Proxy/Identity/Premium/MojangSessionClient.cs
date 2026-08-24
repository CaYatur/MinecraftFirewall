using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Identity.Premium;

/// <summary>
/// Real Mojang session-server client. See IPremiumSessionClient's doc comment for why this fails
/// CLOSED (any error -> NotJoined), the opposite of IpInfoClient's fail-open behavior.
///
/// Deliberately never sends the optional `&amp;ip=` query parameter (Mojang's session server would
/// cross-check it against the IP the client's own launcher reported when it called Mojang's
/// joinServer API). A live check confirmed this proxy's `Should Authenticate` field (sent to the
/// client in Encryption Request, always true here — see EncryptionRequestPacket) is NOT the same
/// knob as this: toggling a real Paper server's `prevent-proxy-connections` between true/false left
/// `Should Authenticate` unchanged (still true both times) — so the two are independent, and
/// `Should Authenticate` is this proxy telling the CLIENT to actually verify, not a signal about
/// whether the server-side call should assert an IP. Whether to assert `ip` is this proxy's own
/// separate decision, and it deliberately never does: in this architecture the client connects to
/// the proxy, not directly to whatever backend/fronting setup sits beyond it (see the README's
/// TCP-fronting-proxy honesty note), so the proxy's own observed remote address is not guaranteed to
/// match what the client's launcher told Mojang. Sending a wrong `ip` fails CLOSED, i.e. it would
/// deny a genuine premium owner — exactly the outcome this feature's design explicitly forbids — so
/// omitting it is the safe default. This could not be fully settled without a real Microsoft
/// account's positive-path behavior; revisit if that becomes available for a live 4b test.
/// </summary>
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
                logger.LogWarning("Mojang hasJoined check for '{Username}' returned {Status} — treating as verification failure.", username, response.StatusCode);
                return HasJoinedResult.NotJoined;
            }

            string body = await response.Content.ReadAsStringAsync(timeoutCts.Token).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(body))
            {
                // The ordinary "no such session" answer, and the single most common outcome in
                // production — every cracked client attempting a premium-locked name lands here.
                // Verified live: Mojang answers it with HTTP 200 and an EMPTY BODY, not the 204 No
                // Content its documentation implies. Handling it explicitly (rather than letting the
                // JSON deserializer throw on empty input and catching that below) keeps a routine,
                // expected denial from writing an exception stack trace into the log every time.
                logger.LogInformation("Mojang hasJoined check for '{Username}' found no valid session — denying.", username);
                return HasJoinedResult.NotJoined;
            }

            HasJoinedResponse? payload = JsonSerializer.Deserialize<HasJoinedResponse>(body);
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
