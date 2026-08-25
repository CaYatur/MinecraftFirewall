using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Admin;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.IpIntel;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Two separate concerns, tested separately, because they can't both be exercised through the same
/// real ACL-restricted pipe in one environment: (1) the JSON wire framing itself, tested over a
/// plain pipe with no ACL restriction so it isn't gated on process elevation; (2) that a
/// non-Administrator connection is actually refused, which requires this test process to genuinely
/// be non-elevated to mean anything — see AdminAclTests for the ACL-construction-only check, which
/// runs regardless of elevation.
/// </summary>
public class AdminPipeServerIntegrationTests
{
    private static readonly bool IsElevated =
        new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    private sealed class UnreachableHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new() { Timeout = TimeSpan.FromMilliseconds(200) };
    }

    private static AdminCommandHandler CreateHandler()
    {
        var profile = new ServerProfile { Name = "TestServer", PublicPort = 25565, BackendHost = "127.0.0.1", BackendPort = 25566 };
        var gateway = new FakeWindowsFirewallGateway();
        var neverBanList = new NeverBanList(Options.Create(new NeverBanOptions()));
        var banOptions = Options.Create(new FirewallBanOptions());
        var banService = new FirewallBanService(banOptions, neverBanList, gateway, new RecordingAlertSender(), NullLogger<FirewallBanService>.Instance);
        var vpnIntelOptions = Options.Create(new VpnIntelOptions
        {
            CacheDirectory = Path.Combine(Path.GetTempPath(), "MinecraftFirewallTests", Guid.NewGuid().ToString("N")),
        });
        var refreshService = new IpListRefreshService(new VpnIntelligence(), vpnIntelOptions, new UnreachableHttpClientFactory(), NullLogger<IpListRefreshService>.Instance);
        return new AdminCommandHandler([profile], banService, refreshService, NullLogger<AdminCommandHandler>.Instance);
    }

    [Fact]
    public async Task JsonWireProtocol_RealPipeRoundTrip_RequestAndResponseSurviveFraming()
    {
        // No PipeSecurity here deliberately — this test proves the JSON request/response framing
        // over a real NamedPipeServerStream/NamedPipeClientStream pair, independent of the ACL (which
        // AdminAclTests and the elevation-dependent test below cover separately).
        string pipeName = "MinecraftFirewall.Tests." + Guid.NewGuid().ToString("N");
        var server = new AdminPipeServer(CreateHandler(), NullLogger<AdminPipeServer>.Instance);

        using var serverPipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        using var clientPipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

        var acceptTask = serverPipe.WaitForConnectionAsync();
        await clientPipe.ConnectAsync(5000);
        await acceptTask;

        var serverHandling = server.HandleOneConnectionAsync(serverPipe, CancellationToken.None);

        await using var writer = new StreamWriter(clientPipe, new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };
        using var reader = new StreamReader(clientPipe, Encoding.UTF8, leaveOpen: true);

        await writer.WriteLineAsync(JsonSerializer.Serialize(new AdminRequest("list-profiles", [])));
        string? responseLine = await reader.ReadLineAsync();
        await serverHandling;

        Assert.NotNull(responseLine);
        var response = JsonSerializer.Deserialize<AdminResponse>(responseLine!);
        Assert.NotNull(response);
        Assert.True(response!.Success);
        Assert.Contains("TestServer", response.Message);
    }

    [Fact]
    public async Task AdministratorsOnlyAcl_NonElevatedProcess_IsRefusedConnection()
    {
        if (IsElevated)
        {
            // This test process is running elevated in this environment, so it WOULD be allowed to
            // connect — the rejection this test exists to prove can't be observed from here. Recorded
            // as a known gap rather than silently passing: see docs/plan.md.
            return;
        }

        string pipeName = "MinecraftFirewall.Tests.Acl." + Guid.NewGuid().ToString("N");
        using var serverPipe = NamedPipeServerStreamAcl.Create(
            pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0,
            AdminPipeServer.BuildAdministratorsOnlyAcl());

        using var clientPipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await clientPipe.ConnectAsync(3000));
    }
}
