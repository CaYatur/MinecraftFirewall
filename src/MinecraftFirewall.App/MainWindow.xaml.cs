using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using MinecraftFirewall.App.Services;
using Forms = System.Windows.Forms;

namespace MinecraftFirewall.App;

public partial class MainWindow : Window
{
    private readonly WindowsServiceControl _service = new();
    private readonly AdminPipeClient _pipe = new();
    private readonly DispatcherTimer _poll;
    private readonly Forms.NotifyIcon _tray;

    private bool _reallyExiting;
    private bool _suppressSettingEvents;
    private ServiceState _lastState = ServiceState.Unknown;

    public MainWindow()
    {
        InitializeComponent();

        VersionText.Text = $"v{typeof(MainWindow).Assembly.GetName().Version?.ToString(3) ?? "1.1.0"}";

        _tray = BuildTrayIcon();

        // 2s rather than 1s: each tick opens a pipe connection and reads the log tail, and the
        // service's accept loop handles one connection at a time. Fast enough to feel live, slow
        // enough to stay out of the CLI's way.
        _poll = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _poll.Tick += async (_, _) => await RefreshAsync();
        _poll.Start();

        Loaded += async (_, _) =>
        {
            LoadPreferences();
            await RefreshAsync();
        };
    }

    // ---------------------------------------------------------------- tray

    private Forms.NotifyIcon BuildTrayIcon()
    {
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Open MinecraftFirewall", null, (_, _) => ShowFromTray());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Start protection", null, async (_, _) => await RunAsync(_service.StartAsync, "Start"));
        menu.Items.Add("Stop protection", null, async (_, _) => await RunAsync(_service.StopAsync, "Stop"));
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Exit control panel", null, (_, _) => ExitApplication());

        var icon = new Forms.NotifyIcon
        {
            Icon = LoadTrayIcon(),
            Visible = true,
            Text = "MinecraftFirewall",
            ContextMenuStrip = menu,
        };
        icon.DoubleClick += (_, _) => ShowFromTray();
        return icon;
    }

    private static System.Drawing.Icon LoadTrayIcon()
    {
        var stream = Application.GetResourceStream(new Uri("Assets/app.ico", UriKind.Relative))?.Stream;
        return stream is not null ? new System.Drawing.Icon(stream) : System.Drawing.SystemIcons.Shield;
    }

    private void ShowFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        // The service keeps running either way — this only decides whether the control panel stays
        // reachable from the notification area or the process actually ends.
        if (!_reallyExiting && ChkCloseToTray.IsChecked == true)
        {
            e.Cancel = true;
            Hide();
            _tray.ShowBalloonTip(3000, "MinecraftFirewall",
                "Still running here. Your server stays protected either way — the background service is separate from this window.",
                Forms.ToolTipIcon.Info);
            return;
        }

        base.OnClosing(e);
    }

    private void ExitApplication()
    {
        _reallyExiting = true;
        _poll.Stop();
        _tray.Visible = false;
        _tray.Dispose();
        Application.Current.Shutdown();
    }

    // ---------------------------------------------------------------- navigation

    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (PageStatus is null)
            return; // fires once during InitializeComponent, before the pages exist

        string page = (string)((RadioButton)sender).Tag;
        PageStatus.Visibility = page == "Status" ? Visibility.Visible : Visibility.Collapsed;
        PageBans.Visibility = page == "Bans" ? Visibility.Visible : Visibility.Collapsed;
        PageSettings.Visibility = page == "Settings" ? Visibility.Visible : Visibility.Collapsed;
        PageLog.Visibility = page == "Log" ? Visibility.Visible : Visibility.Collapsed;

        PageTitle.Text = page switch
        {
            "Bans" => "Blocked IPs",
            "Settings" => "Settings",
            "Log" => "Activity log",
            _ => "Status",
        };

        if (page == "Bans")
            _ = RefreshBansAsync();
    }

    // ---------------------------------------------------------------- polling

    private async Task RefreshAsync()
    {
        ServiceStatus status = _service.GetStatus();
        ApplyStatus(status);

        var lines = LogTailReader.ReadLastLines(200);
        MiniLogText.Text = string.Join(Environment.NewLine, lines.TakeLast(8));

        if (PageLog.Visibility == Visibility.Visible)
        {
            FullLogText.Text = string.Join(Environment.NewLine, lines);
            if (ChkAutoScroll.IsChecked == true)
                LogScroller.ScrollToEnd();
        }

        if (status.State == ServiceState.Running && _lastState != ServiceState.Running)
            await RefreshProfilesAsync();

        _lastState = status.State;
    }

    private void ApplyStatus(ServiceStatus status)
    {
        (string label, Brush colour, string detail) = status.State switch
        {
            ServiceState.Running => ("Protected", (Brush)FindResource("Good"), "The service is running."),
            ServiceState.Stopped => ("Not protecting", (Brush)FindResource("Bad"), "The service is installed but stopped."),
            ServiceState.Pending => ("Working…", (Brush)FindResource("Warn"), "Windows is starting or stopping the service."),
            ServiceState.NotInstalled => ("Not installed", (Brush)FindResource("Warn"), "Install the service to begin protecting your server."),
            _ => ("Unknown", (Brush)FindResource("TextMuted"), status.Detail ?? "Could not read the service state."),
        };

        StatusText.Text = label;
        StatusDot.Fill = colour;
        StatusDetail.Text = status.State == ServiceState.Running && status.StartMode == ServiceStartMode.Manual
            ? "Running, but set to manual — it will NOT come back after a reboot."
            : detail;

        _tray.Text = $"MinecraftFirewall — {label}";

        bool installed = status.State != ServiceState.NotInstalled;
        BtnStart.IsEnabled = installed && status.State != ServiceState.Running;
        BtnStop.IsEnabled = installed && status.State == ServiceState.Running;
        BtnInstall.IsEnabled = !installed;
        BtnUninstall.IsEnabled = installed;

        _suppressSettingEvents = true;
        StartAuto.IsChecked = status.StartMode == ServiceStartMode.Automatic;
        StartManual.IsChecked = status.StartMode is ServiceStartMode.Manual or ServiceStartMode.Disabled;
        StartAuto.IsEnabled = StartManual.IsEnabled = installed;
        _suppressSettingEvents = false;
    }

    private async Task RefreshProfilesAsync()
    {
        var response = await _pipe.ListProfilesAsync();
        ProfilesText.Text = response.Success
            ? response.Message
            : "Could not reach the service: " + response.Message;
    }

    private async Task RefreshBansAsync()
    {
        var response = await _pipe.ListBansAsync();
        BansText.Text = response.Success ? response.Message : "Could not reach the service: " + response.Message;
    }

    // ---------------------------------------------------------------- actions

    private async Task RunAsync(Func<Task<(bool, string)>> action, string what)
    {
        Toast($"{what}…", neutral: true);
        var (ok, message) = await action();
        Toast(message, neutral: ok);
        await RefreshAsync();
    }

    private async void BtnStart_Click(object sender, RoutedEventArgs e) => await RunAsync(_service.StartAsync, "Starting");

    private async void BtnStop_Click(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(this,
            "Stop protection?\n\nYour Minecraft server will accept connections without any of this app's checks until you start it again.",
            "MinecraftFirewall", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm == MessageBoxResult.Yes)
            await RunAsync(_service.StopAsync, "Stopping");
    }

    private async void BtnInstall_Click(object sender, RoutedEventArgs e)
    {
        await RunAsync(async () =>
        {
            var (ok, message) = await _service.InstallAsync();
            if (!ok)
                return (ok, message);

            var (started, startMessage) = await _service.StartAsync();
            return (started, message + " " + startMessage);
        }, "Installing");
    }

    private async void BtnUninstall_Click(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(this,
            "Remove the background service?\n\nYour server will no longer be protected, including after a reboot. Your configuration file and settings are kept.",
            "MinecraftFirewall", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm == MessageBoxResult.Yes)
            await RunAsync(_service.UninstallAsync, "Removing");
    }

    private async void BtnRefreshBans_Click(object sender, RoutedEventArgs e) => await RefreshBansAsync();

    private async void BtnUnban_Click(object sender, RoutedEventArgs e)
    {
        string ip = UnbanIpBox.Text.Trim();
        if (ip.Length == 0)
        {
            Toast("Type the IP address you want to unblock.", neutral: false);
            return;
        }

        var response = await _pipe.UnbanAsync(ip);
        Toast(response.Message, neutral: response.Success);
        UnbanIpBox.Clear();
        await RefreshBansAsync();
    }

    private async void BtnReloadLists_Click(object sender, RoutedEventArgs e)
    {
        Toast("Refreshing VPN/datacenter lists…", neutral: true);
        var response = await _pipe.ReloadIpListsAsync();
        Toast(response.Message, neutral: response.Success);
    }

    private void BtnEditConfig_Click(object sender, RoutedEventArgs e)
    {
        string config = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        if (!File.Exists(config))
        {
            Toast($"Configuration file not found at {config}", neutral: false);
            return;
        }

        OpenInShell(config);
        Toast("Changes take effect after the service restarts — use Stop then Start.", neutral: true);
    }

    private void BtnOpenLogs_Click(object sender, RoutedEventArgs e)
    {
        if (!Directory.Exists(LogTailReader.LogDirectory))
        {
            Toast("No log folder yet — start the service first.", neutral: false);
            return;
        }

        OpenInShell(LogTailReader.LogDirectory);
    }

    private static void OpenInShell(string path) =>
        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });

    // ---------------------------------------------------------------- settings

    private void LoadPreferences()
    {
        _suppressSettingEvents = true;
        ChkLoginStartup.IsChecked = LoginStartup.IsEnabled();
        ChkStartMinimised.IsChecked = App.StartMinimisedToTray;
        _suppressSettingEvents = false;
    }

    private async void StartMode_Changed(object sender, RoutedEventArgs e)
    {
        if (_suppressSettingEvents || !IsLoaded)
            return;

        var mode = StartAuto.IsChecked == true ? ServiceStartMode.Automatic : ServiceStartMode.Manual;
        var (ok, message) = await _service.SetStartModeAsync(mode);
        Toast(message, neutral: ok);
        await RefreshAsync();
    }

    private void StartupPreference_Changed(object sender, RoutedEventArgs e)
    {
        if (_suppressSettingEvents || !IsLoaded)
            return;

        var (ok, message) = LoginStartup.SetEnabled(
            ChkLoginStartup.IsChecked == true,
            ChkStartMinimised.IsChecked == true);

        Toast(message, neutral: ok);
    }

    // ---------------------------------------------------------------- toast

    private void Toast(string message, bool neutral)
    {
        ToastText.Text = message;
        ToastText.Foreground = neutral ? (Brush)FindResource("Text") : (Brush)FindResource("Bad");
        ToastBar.Visibility = Visibility.Visible;
    }
}
