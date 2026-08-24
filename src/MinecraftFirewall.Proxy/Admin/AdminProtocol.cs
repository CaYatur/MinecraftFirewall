namespace MinecraftFirewall.Proxy.Admin;

/// <summary>
/// Wire contract between MinecraftFirewall.Admin (the CLI) and AdminPipeServer (in the running
/// service). One request, one newline-delimited JSON line each way, then the connection closes —
/// see AdminPipeServer for the transport and its access-control setup.
/// </summary>
public static class AdminProtocol
{
    public const string PipeName = "MinecraftFirewall.Admin";
}

public sealed record AdminRequest(string Command, string[] Args);

public sealed record AdminResponse(bool Success, string Message);
