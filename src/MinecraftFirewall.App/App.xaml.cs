using System.Windows;

namespace MinecraftFirewall.App;

public partial class App : Application
{
    /// <summary>Set by the login-startup entry (see LoginStartup) so the app can come back after a
    /// reboot without a window flashing up in the user's face.</summary>
    public static bool StartMinimisedToTray { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        StartMinimisedToTray = e.Args.Any(a => string.Equals(a, "--tray", StringComparison.OrdinalIgnoreCase));

        var window = new MainWindow();
        MainWindow = window;

        // ShutdownMode is OnExplicitShutdown: closing the window hides it to the tray instead of
        // ending the process, so the app has to decide for itself when to actually exit.
        if (!StartMinimisedToTray)
            window.Show();
    }
}
