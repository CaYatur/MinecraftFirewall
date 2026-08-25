using System.Diagnostics;
using System.IO;
using System.ServiceProcess;

namespace MinecraftFirewall.App.Services;

public enum ServiceState
{
    /// <summary>The service isn't registered with Windows at all — a fresh machine, or an install
    /// that didn't complete. This is the only state where the console offers to create it.</summary>
    NotInstalled,
    Stopped,
    Running,
    Pending,
    /// <summary>Windows returned something we couldn't interpret. Shown as-is rather than guessed at.</summary>
    Unknown,
}

/// <summary>How Windows starts the service — the setting that actually decides whether the server is
/// protected after a reboot with nobody logged in.</summary>
public enum ServiceStartMode
{
    Automatic,
    Manual,
    Disabled,
    Unknown,
}

public sealed record ServiceStatus(ServiceState State, ServiceStartMode StartMode, string? Detail = null);

/// <summary>
/// Wraps the Windows service the proxy actually runs as.
///
/// Querying, starting and stopping go through <see cref="ServiceController"/>; creating, deleting and
/// reconfiguring have no managed API, so they shell out to <c>sc.exe</c> — but always via
/// <see cref="ProcessStartInfo.ArgumentList"/>, never a formatted command string. That keeps the same
/// discipline the proxy uses for firewall rules: arguments are passed as discrete values Windows
/// parses itself, so a path with spaces or quotes can't turn into extra arguments.
/// </summary>
public sealed class WindowsServiceControl
{
    public const string ServiceName = "MinecraftFirewall";
    private const string DisplayName = "MinecraftFirewall";

    private static readonly TimeSpan TransitionTimeout = TimeSpan.FromSeconds(30);

    public ServiceStatus GetStatus()
    {
        try
        {
            using var controller = new ServiceController(ServiceName);
            var state = controller.Status switch
            {
                ServiceControllerStatus.Running => ServiceState.Running,
                ServiceControllerStatus.Stopped => ServiceState.Stopped,
                ServiceControllerStatus.StartPending or ServiceControllerStatus.StopPending
                    or ServiceControllerStatus.ContinuePending or ServiceControllerStatus.PausePending => ServiceState.Pending,
                ServiceControllerStatus.Paused => ServiceState.Stopped,
                _ => ServiceState.Unknown,
            };

            var startMode = controller.StartType switch
            {
                System.ServiceProcess.ServiceStartMode.Automatic => ServiceStartMode.Automatic,
                System.ServiceProcess.ServiceStartMode.Manual => ServiceStartMode.Manual,
                System.ServiceProcess.ServiceStartMode.Disabled => ServiceStartMode.Disabled,
                _ => ServiceStartMode.Unknown,
            };

            return new ServiceStatus(state, startMode);
        }
        catch (InvalidOperationException)
        {
            // ServiceController throws this (wrapping a Win32 "service does not exist") rather than
            // returning anything queryable, so it is the normal not-installed path, not an error.
            return new ServiceStatus(ServiceState.NotInstalled, ServiceStartMode.Unknown);
        }
        catch (Exception ex)
        {
            return new ServiceStatus(ServiceState.Unknown, ServiceStartMode.Unknown, ex.Message);
        }
    }

    public async Task<(bool Success, string Message)> StartAsync()
    {
        try
        {
            using var controller = new ServiceController(ServiceName);
            if (controller.Status == ServiceControllerStatus.Running)
                return (true, "Already running.");

            controller.Start();
            await Task.Run(() => controller.WaitForStatus(ServiceControllerStatus.Running, TransitionTimeout)).ConfigureAwait(false);
            return (true, "Service started.");
        }
        catch (Exception ex)
        {
            return (false, Describe(ex));
        }
    }

    public async Task<(bool Success, string Message)> StopAsync()
    {
        try
        {
            using var controller = new ServiceController(ServiceName);
            if (controller.Status == ServiceControllerStatus.Stopped)
                return (true, "Already stopped.");

            controller.Stop();
            await Task.Run(() => controller.WaitForStatus(ServiceControllerStatus.Stopped, TransitionTimeout)).ConfigureAwait(false);
            return (true, "Service stopped.");
        }
        catch (Exception ex)
        {
            return (false, Describe(ex));
        }
    }

    /// <summary>Registers the service pointing at the proxy executable that shipped alongside this
    /// console. Defaults to Automatic start, because a firewall that only protects while someone
    /// happens to be logged in is the failure mode this whole design exists to avoid.</summary>
    public async Task<(bool Success, string Message)> InstallAsync()
    {
        string exePath = ProxyExecutablePath();
        if (!File.Exists(exePath))
            return (false, $"Could not find the service executable next to this app:\n{exePath}");

        // An upgrade reaches here with the service already registered, and `sc create` fails outright
        // on that. Treating the failure as fatal is how an upgrade ended up leaving the machine
        // unprotected: the installer stops the service, the create fails, nothing starts it again, and
        // the only sign is a status page nobody was looking at. Reconfiguring instead also handles the
        // case that makes it necessary — an install path that has changed since last time.
        if (GetStatus().State != ServiceState.NotInstalled)
            return await ReconfigureAsync(exePath).ConfigureAwait(false);

        var (code, output) = await RunScAsync(
            "create", ServiceName,
            // Quoted deliberately, and the quotes have to survive all the way into the registry.
            // sc.exe stores whatever it receives verbatim as the service's ImagePath, so passing a
            // bare path leaves Windows an unquoted ImagePath — and with the app installed under
            // "C:\Program Files\...", Windows would then also try C:\Program.exe first when starting
            // it. That is the classic unquoted-service-path privilege-escalation hole: anyone able to
            // drop a file at that name gets it executed as the service account. ArgumentList escapes
            // these quotes for the command line, so sc.exe receives them as part of the value.
            "binPath=", $"\"{exePath}\"",
            "start=", "auto",
            "DisplayName=", DisplayName).ConfigureAwait(false);

        if (code != 0)
            return (false, $"sc create failed:\n{output}");

        await RunScAsync("description", ServiceName,
            "Protects Minecraft servers running in offline mode: username verification, VPN blocking and firewall bans.").ConfigureAwait(false);

        return (true, "Service installed and set to start automatically with Windows.");
    }

    /// <summary>
    /// Points an already-registered service at this copy of the executable.
    ///
    /// The quoting matters here for exactly the reason it does in <see cref="InstallAsync"/>: sc.exe
    /// stores the argument verbatim as the ImagePath, and an unquoted path under "C:\Program Files"
    /// makes Windows try C:\Program.exe first. An upgrade must not quietly reintroduce the hole the
    /// original install avoided.
    /// </summary>
    private async Task<(bool Success, string Message)> ReconfigureAsync(string exePath)
    {
        var (code, output) = await RunScAsync(
            "config", ServiceName,
            "binPath=", $"\"{exePath}\"",
            "start=", "auto").ConfigureAwait(false);

        return code == 0
            ? (true, "Service updated to this version and set to start automatically with Windows.")
            : (false, $"sc config failed:\n{output}");
    }

    public async Task<(bool Success, string Message)> UninstallAsync()
    {
        await StopAsync().ConfigureAwait(false);
        var (code, output) = await RunScAsync("delete", ServiceName).ConfigureAwait(false);
        return code == 0 ? (true, "Service removed.") : (false, $"sc delete failed:\n{output}");
    }

    public async Task<(bool Success, string Message)> SetStartModeAsync(ServiceStartMode mode)
    {
        string value = mode switch
        {
            ServiceStartMode.Automatic => "auto",
            ServiceStartMode.Manual => "demand",
            ServiceStartMode.Disabled => "disabled",
            _ => throw new ArgumentOutOfRangeException(nameof(mode)),
        };

        var (code, output) = await RunScAsync("config", ServiceName, "start=", value).ConfigureAwait(false);
        return code == 0 ? (true, "Start mode updated.") : (false, $"sc config failed:\n{output}");
    }

    public static string ProxyExecutablePath() =>
        Path.Combine(AppContext.BaseDirectory, "MinecraftFirewall.Proxy.exe");

    private static string Describe(Exception ex) => ex switch
    {
        InvalidOperationException { InnerException: not null } io => io.InnerException!.Message,
        _ => ex.Message,
    };

    private static async Task<(int ExitCode, string Output)> RunScAsync(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo("sc.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        // Discrete arguments, never a formatted string — see the class comment.
        foreach (string argument in arguments)
            startInfo.ArgumentList.Add(argument);

        using var process = Process.Start(startInfo);
        if (process is null)
            return (-1, "Could not start sc.exe.");

        string stdout = await process.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
        await process.WaitForExitAsync().ConfigureAwait(false);

        return (process.ExitCode, (stdout + stderr).Trim());
    }
}
