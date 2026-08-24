using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace MinecraftFirewall.Proxy.Admin;

/// <summary>
/// Loopback-only, Administrators-only named pipe server for the MinecraftFirewall.Admin CLI.
///
/// SECURITY: a NamedPipeServerStream created without an explicit PipeSecurity gets Windows' default
/// pipe DACL, which is reachable by any local user's process — not just Administrators. That would
/// hand `unban` and `require-premium` to anyone with a session on the box. BuildAdministratorsOnlyAcl
/// grants exactly one explicit Allow ACE (BuiltinAdministratorsSid, ReadWrite) and nothing else — a
/// DACL with only that one explicit Allow implicitly denies every other principal, which is standard
/// Windows ACL semantics, not something that needs an explicit Deny entry. See
/// AdminAclTests.BuildAdministratorsOnlyAcl_GrantsExactlyOneExplicitRule_ForAdministratorsOnly for the
/// automated check on this specific property; a live non-elevated-process rejection was not exercised
/// in this environment (see docs/plan.md) — treat that as unverified, not proven, until it is.
/// </summary>
public sealed class AdminPipeServer(AdminCommandHandler handler, ILogger<AdminPipeServer> logger) : BackgroundService
{
    public static PipeSecurity BuildAdministratorsOnlyAcl()
    {
        var security = new PipeSecurity();
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        security.AddAccessRule(new PipeAccessRule(administrators, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return security;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var pipe = NamedPipeServerStreamAcl.Create(
                    AdminProtocol.PipeName,
                    PipeDirection.InOut,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    inBufferSize: 4096,
                    outBufferSize: 4096,
                    BuildAdministratorsOnlyAcl());

                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
                await HandleOneConnectionAsync(pipe, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Admin pipe server error; will keep accepting new connections.");
            }
        }
    }

    /// <summary>Internal (not private) so integration tests can exercise the real JSON wire framing
    /// over a plain, non-ACL-restricted pipe pair — the ACL itself is tested separately in
    /// AdminAclTests/the elevation-dependent connect-rejection test, since this environment cannot
    /// both run non-elevated (needed to prove rejection) and connect successfully (needed to prove
    /// the framing) through the *same* ACL-restricted pipe.</summary>
    internal async Task HandleOneConnectionAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
        await using var writer = new StreamWriter(pipe, new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };

        string? line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
        if (line is null)
            return;

        AdminResponse response;
        try
        {
            var request = JsonSerializer.Deserialize<AdminRequest>(line) ?? throw new JsonException("Empty request.");
            response = await handler.HandleAsync(request, ct).ConfigureAwait(false);
        }
        catch (JsonException ex)
        {
            response = new AdminResponse(false, $"Malformed request: {ex.Message}");
        }

        await writer.WriteLineAsync(JsonSerializer.Serialize(response)).ConfigureAwait(false);
        pipe.WaitForPipeDrain();
    }
}
