using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using MinecraftFirewall.Proxy.Admin;

if (args.Length == 0)
{
    PrintUsage();
    return 1;
}

string command = args[0];
string[] commandArgs = args[1..];

using var pipe = new NamedPipeClientStream(".", AdminProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

try
{
    using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
    await pipe.ConnectAsync(connectCts.Token);
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("Could not connect to MinecraftFirewall.Proxy's admin pipe within 5 seconds. Is the service running?");
    return 1;
}
catch (UnauthorizedAccessException)
{
    Console.Error.WriteLine("Access denied connecting to the admin pipe — this CLI must be run as Administrator.");
    return 1;
}

using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
await using var writer = new StreamWriter(pipe, new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };

var request = new AdminRequest(command, commandArgs);
await writer.WriteLineAsync(JsonSerializer.Serialize(request));

string? responseLine = await reader.ReadLineAsync();
if (responseLine is null)
{
    Console.Error.WriteLine("The service closed the connection without responding.");
    return 1;
}

var response = JsonSerializer.Deserialize<AdminResponse>(responseLine);
if (response is null)
{
    Console.Error.WriteLine("The service sent a response this CLI could not parse.");
    return 1;
}

Console.WriteLine(response.Message);
return response.Success ? 0 : 1;

static void PrintUsage()
{
    Console.WriteLine("MinecraftFirewall.Admin — must be run as Administrator (the service's admin pipe only accepts Administrators).");
    Console.WriteLine();
    Console.WriteLine("Usage: MinecraftFirewall.Admin <command> [args...]");
    Console.WriteLine();
    Console.WriteLine("Commands:");
    Console.WriteLine("  whitelist-add-me <profile> <username> <ip-or-cidr>  Add an IP/CIDR to a username's static allowlist");
    Console.WriteLine("  list-bans                                           List active firewall bans");
    Console.WriteLine("  unban <ip>                                          Remove a firewall ban");
    Console.WriteLine("  require-premium <profile> <username>                Require a verified Mojang account for this username");
    Console.WriteLine("  reload                                              Refresh the VPN/datacenter IP lists now");
    Console.WriteLine("  list-profiles                                       List configured server profiles");
}
