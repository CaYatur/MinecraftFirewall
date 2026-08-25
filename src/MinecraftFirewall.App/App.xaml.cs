using System.IO;
using System.Windows;
using System.Windows.Threading;

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

        StartMinimisedToTray = e.Args.Any(a => string.Equals(a, "--tray", StringComparison.OrdinalIgnoreCase));

        var window = new MainWindow();
        MainWindow = window;

        // ShutdownMode is OnExplicitShutdown: closing the window hides it to the tray instead of
        // ending the process, so the app decides for itself when to actually exit.
        if (!StartMinimisedToTray)
            window.Show();
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
