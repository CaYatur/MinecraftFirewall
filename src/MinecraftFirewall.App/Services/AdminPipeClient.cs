using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using MinecraftFirewall.Proxy.Admin;

namespace MinecraftFirewall.App.Services;

/// <summary>
/// Talks to the running service over its Administrators-only pipe, using exactly the same
/// newline-delimited JSON contract as the CLI.
///
/// One connection per request, matching the server's accept loop, which creates a fresh pipe
/// instance per connection. The console polls on a timer, so the timeout here is deliberately short:
/// a stopped service should show as "stopped" within a second or two, not hang the UI while a
/// connect attempt runs down a long timeout.
/// </summary>
public sealed class AdminPipeClient
{
    private const int ConnectTimeoutMs = 1500;

    public async Task<AdminResponse> SendAsync(string command, string[]? args = null, CancellationToken ct = default)
    {
        try
        {
            await using var pipe = new NamedPipeClientStream(".", AdminProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(ConnectTimeoutMs, ct).ConfigureAwait(false);

            await using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true, NewLine = "\n" };
            using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);

            await writer.WriteLineAsync(JsonSerializer.Serialize(new AdminRequest(command, args ?? []))).ConfigureAwait(false);

            string? line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            if (line is null)
                return new AdminResponse(false, "The service closed the connection without replying.");

            return JsonSerializer.Deserialize<AdminResponse>(line)
                ?? new AdminResponse(false, "The service sent an empty reply.");
        }
        catch (TimeoutException)
        {
            return new AdminResponse(false, "The service is not responding on its admin pipe. Is it running?");
        }
        catch (UnauthorizedAccessException)
        {
            // Should be unreachable: the manifest forces elevation. Kept because the failure would
            // otherwise be a bare access-denied with no hint as to why.
            return new AdminResponse(false, "Access denied to the service's admin pipe. This app must run as Administrator.");
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or JsonException)
        {
            return new AdminResponse(false, ex.Message);
        }
    }

    public Task<AdminResponse> ListBansAsync(CancellationToken ct = default) => SendAsync("list-bans", ct: ct);

    public Task<AdminResponse> ListProfilesAsync(CancellationToken ct = default) => SendAsync("list-profiles", ct: ct);

    public Task<AdminResponse> UnbanAsync(string ip, CancellationToken ct = default) => SendAsync("unban", [ip], ct);

    public Task<AdminResponse> ReloadIpListsAsync(CancellationToken ct = default) => SendAsync("reload", ct: ct);
}
