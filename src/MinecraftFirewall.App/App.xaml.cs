using System.IO;
using System.Windows;
using System.Windows.Threading;
using MinecraftFirewall.App.Services;

namespace MinecraftFirewall.App;

public partial class App : Application
{
    /// <summary>Set by the login-startup entry (see LoginStartup) so the app can come back after a
    /// reboot without a window flashing up in the user's face.</summary>
    public static bool StartMinimisedToTray { get; private set; }

    private static readonly string CrashLogPath =
        Path.Combine(Path.GetTempPath(), "MinecraftFirewall-crash.log");

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // A WPF crash with no console attached leaves the user with a window that simply never
        // appears and nothing to report. Writing it somewhere findable turns "it doesn't open" into
        // something diagnosable.
        DispatcherUnhandledException += (_, args) =>
        {
            Report(args.Exception, "UI thread");
            args.Handled = false;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            Report(args.ExceptionObject as Exception, "background thread");

        // The installer drives service registration through these rather than reimplementing sc.exe's
        // quoting rules in Pascal. One implementation, already exercised by the console's own use of it.
        if (HasFlag(e.Args, "--install-service") || HasFlag(e.Args, "--uninstall-service"))
        {
            Environment.Exit(RunServiceSetup(install: HasFlag(e.Args, "--install-service")));
            return;
        }

        StartMinimisedToTray = HasFlag(e.Args, "--tray");

        var window = new MainWindow();
        MainWindow = window;

        // ShutdownMode is OnExplicitShutdown: closing the window hides it to the tray instead of
        // ending the process, so the app decides for itself when to actually exit.
        if (!StartMinimisedToTray)
            window.Show();
    }

    private static bool HasFlag(string[] args, string flag) =>
        args.Any(a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));

    /// <summary>Headless install/uninstall for the setup program. Returns a process exit code, so a
    /// failure surfaces as a failed installation step rather than a silent no-op — an installer that
    /// reports success while leaving no service registered is the worst of both outcomes.</summary>
    private static int RunServiceSetup(bool install)
    {
        var control = new WindowsServiceControl();

        try
        {
            var (success, message) = install
                ? control.InstallAsync().GetAwaiter().GetResult()
                : control.UninstallAsync().GetAwaiter().GetResult();

            if (!success)
            {
                Log($"service {(install ? "install" : "uninstall")}", message);
            }
            else if (install)
            {
                // Started here rather than left to the installer, and on the upgrade path as much as
                // the first install: the point of running setup is a machine that is protected when it
                // finishes, not one that will be after a reboot. An upgrade that leaves the service
                // stopped is the worst version of this, because everything looks like it worked.
                var (started, startMessage) = control.StartAsync().GetAwaiter().GetResult();
                if (!started)
                    Log("service start", startMessage);
            }

            return success ? 0 : 1;
        }
        catch (Exception ex)
        {
            Log(install ? "service install" : "service uninstall", ex.ToString());
            return 1;
        }
    }

    /// <summary>Appends to the crash log without the message box <see cref="Report"/> shows — during
    /// a silent install there is nobody at the screen to dismiss one.</summary>
    private static void Log(string where, string detail)
    {
        try
        {
            File.AppendAllText(CrashLogPath,
                $"=== {DateTimeOffset.Now:u} ({where}) ==={Environment.NewLine}{detail}{Environment.NewLine}{Environment.NewLine}");
        }
        catch
        {
            // Nothing useful left to do if even the log can't be written.
        }
    }

    private static void Report(Exception? exception, string where)
    {
        if (exception is null)
            return;

        try
        {
            File.AppendAllText(CrashLogPath,
                $"=== {DateTimeOffset.Now:u} ({where}) ==={Environment.NewLine}{exception}{Environment.NewLine}{Environment.NewLine}");
        }
        catch
        {
            // Nothing useful left to do if even the crash log can't be written.
        }

        MessageBox.Show(
            $"MinecraftFirewall hit an unexpected error and needs to close.\n\n{exception.Message}\n\nDetails were written to:\n{CrashLogPath}",
            "MinecraftFirewall", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}
