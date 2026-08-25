using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using MinecraftFirewall.App.Localization;
using MinecraftFirewall.App.Services;
using MinecraftFirewall.Proxy.Admin;
using Forms = System.Windows.Forms;

namespace MinecraftFirewall.App;

public partial class MainWindow : Window
{
    private readonly WindowsServiceControl _service = new();
    private readonly AdminPipeClient _pipe = new();
    private readonly ServerConfigStore _config = new();
    private readonly ExposureCheck _exposure = new();
    private readonly DispatcherTimer _poll;
    private readonly Forms.NotifyIcon _tray;

    private readonly ObservableCollection<ServerRow> _servers = [];
    private readonly ObservableCollection<CheckRow> _checks = [];

    private bool _reallyExiting;
    private bool _suppressEvents;
    private bool _checkRunning;
    private List<CheckResult> _lastCheckResults = [];
    private ServiceState _lastState = ServiceState.Unknown;

    public MainWindow()
    {
        Strings.Current.SetLanguage(AppPreferences.Language);

        InitializeComponent();

        ServerList.ItemsSource = _servers;
        CheckResultList.ItemsSource = _checks;
        _tray = BuildTrayIcon();

        // 2s: each tick opens a pipe connection and reads the log tail, and the service handles one
        // pipe connection at a time. Live enough to feel responsive, calm enough to stay out of the
        // CLI's way.
        _poll = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _poll.Tick += async (_, _) => await RefreshAsync();
        _poll.Start();

        Loaded += async (_, _) =>
        {
            LoadPreferences();
            LoadServers();
            await RefreshAsync();
        };
    }

    // ------------------------------------------------------------------ tray

    private Forms.NotifyIcon BuildTrayIcon()
    {
        var icon = new Forms.NotifyIcon
        {
            Icon = LoadTrayIcon(),
            Visible = true,
            Text = "MinecraftFirewall",
        };
        icon.DoubleClick += (_, _) => ShowFromTray();
        RebuildTrayMenu(icon);
        return icon;
    }

    /// <summary>Rebuilt whenever the language changes — a WinForms menu holds plain strings and has no
    /// binding of its own, so it would otherwise stay in the old language until restart.</summary>
    private void RebuildTrayMenu(Forms.NotifyIcon icon)
    {
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add(Strings.Current["TrayOpen"], null, (_, _) => ShowFromTray());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(Strings.Current["TrayStart"], null, async (_, _) => await RunAsync(_service.StartAsync));
        menu.Items.Add(Strings.Current["TrayStop"], null, async (_, _) => await RunAsync(_service.StopAsync));
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(Strings.Current["TrayExit"], null, (_, _) => ExitApplication());

        icon.ContextMenuStrip?.Dispose();
        icon.ContextMenuStrip = menu;
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
        if (!_reallyExiting && ChkCloseToTray.IsChecked == true)
        {
            e.Cancel = true;
            Hide();
            _tray.ShowBalloonTip(3000, "MinecraftFirewall", Strings.Current["TrayStillRunning"], Forms.ToolTipIcon.Info);
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

    // ------------------------------------------------------------------ navigation

    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (PageStatus is null)
            return; // fires during InitializeComponent, before the pages exist

        string page = (string)((RadioButton)sender).Tag;
        PageStatus.Visibility = Show(page == "Status");
        PageServers.Visibility = Show(page == "Servers");
        PageSecurity.Visibility = Show(page == "Security");
        PageDefense.Visibility = Show(page == "Defense");
        PageBans.Visibility = Show(page == "Bans");
        PageLog.Visibility = Show(page == "Log");
        PageSettings.Visibility = Show(page == "Settings");

        PageTitle.Text = Strings.Current["Nav" + page];

        if (page == "Bans")
            _ = RefreshBansAsync();

        if (page == "Defense")
        {
            LoadDefenseSettings();
            _ = RefreshDefenseAsync();
        }

        static Visibility Show(bool visible) => visible ? Visibility.Visible : Visibility.Collapsed;
    }

    private void BtnGoServers_Click(object sender, RoutedEventArgs e) => NavServers.IsChecked = true;

    // ------------------------------------------------------------------ polling

    private async Task RefreshAsync()
    {
        ServiceStatus status = _service.GetStatus();
        ApplyStatus(status);

        var lines = LogTailReader.ReadLastLines(300);
        MiniLogText.Text = string.Join(Environment.NewLine, lines.TakeLast(8));

        if (PageLog.Visibility == Visibility.Visible)
        {
            FullLogText.Text = string.Join(Environment.NewLine, lines);
            if (ChkAutoScroll.IsChecked == true)
                LogScroller.ScrollToEnd();
        }

        if (PageDefense.Visibility == Visibility.Visible)
            await RefreshDefenseAsync();

        if (status.State != _lastState)
            await RefreshProfilesAsync(status.State == ServiceState.Running);

        _lastState = status.State;
    }

    private void ApplyStatus(ServiceStatus status)
    {
        var s = Strings.Current;
        (string label, Brush colour, string detail) = status.State switch
        {
            ServiceState.Running => (s["StateProtected"], (Brush)FindResource("Good"), s["StateRunningDetail"]),
            ServiceState.Stopped => (s["StateNotProtecting"], (Brush)FindResource("Bad"), s["StateStoppedDetail"]),
            ServiceState.Pending => (s["StateWorking"], (Brush)FindResource("Warn"), s["StatePendingDetail"]),
            ServiceState.NotInstalled => (s["StateNotInstalled"], (Brush)FindResource("Warn"), s["StateNotInstalledDetail"]),
            _ => (s["StateUnknown"], (Brush)FindResource("TextMuted"), status.Detail ?? ""),
        };

        StatusText.Text = label;
        StatusDot.Fill = colour;
        StatusDetail.Text = status is { State: ServiceState.Running, StartMode: ServiceStartMode.Manual }
            ? s["StateManualWarning"]
            : detail;

        _tray.Text = $"MinecraftFirewall — {label}";

        bool installed = status.State != ServiceState.NotInstalled;
        BtnStart.IsEnabled = installed && status.State != ServiceState.Running;
        BtnStop.IsEnabled = installed && status.State == ServiceState.Running;
        BtnInstall.IsEnabled = !installed;
        BtnUninstall.IsEnabled = installed;

        _suppressEvents = true;
        StartAuto.IsChecked = status.StartMode == ServiceStartMode.Automatic;
        StartManual.IsChecked = status.StartMode is ServiceStartMode.Manual or ServiceStartMode.Disabled;
        StartAuto.IsEnabled = StartManual.IsEnabled = installed;
        _suppressEvents = false;
    }

    /// <summary>
    /// Shows what is being protected — from the running service when there is one, and from the
    /// configuration file when there isn't.
    ///
    /// The fallback exists because the first thing someone does with this app is open it before
    /// anything is installed, and an empty box at that moment tells them nothing about whether their
    /// server was picked up. It is labelled as coming from the config so it can never be mistaken for
    /// evidence that protection is actually running.
    /// </summary>
    private async Task RefreshProfilesAsync(bool serviceRunning)
    {
        if (serviceRunning)
        {
            var response = await _pipe.ListProfilesAsync();
            if (response.Success)
            {
                ProfilesText.Text = response.Message;
                return;
            }
        }

        var (profiles, error) = _config.Load();
        if (error is not null || profiles.Count == 0)
        {
            ProfilesText.Text = Strings.Current["ProfilesUnavailable"];
            return;
        }

        ProfilesText.Text = Strings.Current["ProfilesFromConfig"] + Environment.NewLine + string.Join(
            Environment.NewLine,
            profiles.Select(p => $"  {p.Name}: :{p.PublicPort} -> {p.BackendHost}:{p.BackendPort}"
                              + (p.ProtectedUsernames.Count > 0 ? $"  ({p.ProtectedUsernames.Count} protected name(s))" : "")));
    }

    private async Task RefreshBansAsync()
    {
        var response = await _pipe.ListBansAsync();
        BansText.Text = response.Message;
    }

    // ------------------------------------------------------------------ servers

    private void LoadServers()
    {
        _servers.Clear();
        if (!_config.Exists)
        {
            Toast($"Configuration file not found: {_config.ConfigPath}", ok: false);
            return;
        }

        var (profiles, error) = _config.Load();
        if (error is not null)
        {
            Toast(error, ok: false);
            return;
        }

        foreach (ServerProfileEdit profile in profiles)
            _servers.Add(new ServerRow(profile));
    }

    private void BtnAddServer_Click(object sender, RoutedEventArgs e)
    {
        // Offset the ports from whatever is already configured, so adding a second server produces
        // something that works rather than something that collides with the first.
        int nextPublic = _servers.Count == 0 ? 25565 : _servers.Max(s => s.PublicPort) + 1;
        int nextBackend = _servers.Count == 0 ? 25566 : _servers.Max(s => s.BackendPort) + 1;

        _servers.Add(new ServerRow(new ServerProfileEdit
        {
            Name = $"Server{_servers.Count + 1}",
            PublicPort = nextPublic,
            BackendHost = "127.0.0.1",
            BackendPort = nextBackend,
        }));

        NavServers.IsChecked = true;
    }

    private void BtnRemoveServer_Click(object sender, RoutedEventArgs e)
    {
        if (((Button)sender).Tag is ServerRow row)
            _servers.Remove(row);
    }

    private async void BtnSaveServers_Click(object sender, RoutedEventArgs e)
    {
        var edits = _servers.Select(s => s.ToEdit()).ToList();

        if (edits.Any(p => p.Name.Length == 0))
        {
            Toast("Every server needs a name.", ok: false);
            return;
        }

        var duplicatePorts = edits.GroupBy(p => p.PublicPort).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        if (duplicatePorts.Count > 0)
        {
            Toast($"Two servers share the public port {duplicatePorts[0]}. Each needs its own.", ok: false);
            return;
        }

        var (saved, message) = _config.Save(edits);
        if (!saved)
        {
            Toast(message, ok: false);
            return;
        }

        // Restart rather than just saving: the service only reads this file at startup, so leaving it
        // stopped-then-not-started would mean the user believes a name is protected when it isn't.
        if (_service.GetStatus().State == ServiceState.Running)
        {
            Toast(Strings.Current["SaveNeedsRestart"], ok: true);
            await _service.StopAsync();
            var (started, startMessage) = await _service.StartAsync();
            Toast(started ? message : startMessage, ok: started);
        }
        else
        {
            Toast(message, ok: true);
        }

        await RefreshAsync();
        await RefreshProfilesAsync(_service.GetStatus().State == ServiceState.Running);
    }

    // ------------------------------------------------------------------ defence

    /// <summary>
    /// Reads the current defence switches out of appsettings.json.
    ///
    /// Every fallback here is the safe direction rather than the convenient one. A file that cannot be
    /// read must not leave a checkbox claiming a protection is on when nothing has confirmed it, and
    /// must not leave the two that ship deliberately off — the honeypot and movement kicking —
    /// looking enabled.
    /// </summary>
    private void LoadDefenseSettings()
    {
        _suppressEvents = true;
        try
        {
            ChkDdos.IsChecked = _config.GetBool(["DdosProtection", "Enabled"], false);
            ChkInspection.IsChecked = _config.GetBool(["DeepInspection", "Enabled"], false);
            ChkInjection.IsChecked = _config.GetBool(["DeepInspection", "ScanForInjectionPayloads"], false);
            ChkHoneypot.IsChecked = _config.GetBool(["Honeypot", "Enabled"], false);
            ChkMovement.IsChecked = _config.GetBool(["DeepInspection", "AnalyseMovement"], false);
            ChkMovementKick.IsChecked = _config.GetBool(["DeepInspection", "KickOnMovementAnomaly"], false);
            ChkAnomaly.IsChecked = _config.GetBool(["AnomalyDetection", "Enabled"], false);

            string action = _config.GetString(["BotDefense", "Action"], "LogOnly");
            BotDeny.IsChecked = string.Equals(action, "Deny", StringComparison.OrdinalIgnoreCase);
            BotLogOnly.IsChecked = !BotDeny.IsChecked!.Value;

            HoneypotPortsText.Text = Strings.Current.Format("HoneypotPorts", ReadHoneypotPorts());
        }
        finally
        {
            _suppressEvents = false;
        }
    }

    private string ReadHoneypotPorts()
    {
        try
        {
            using var document = System.Text.Json.JsonDocument.Parse(File.ReadAllText(_config.ConfigPath),
                new System.Text.Json.JsonDocumentOptions { CommentHandling = System.Text.Json.JsonCommentHandling.Skip, AllowTrailingCommas = true });

            if (document.RootElement.TryGetProperty("Honeypot", out var honeypot) &&
                honeypot.TryGetProperty("Ports", out var ports))
            {
                return string.Join(", ", ports.EnumerateArray().Select(p => p.GetInt32()));
            }
        }
        catch
        {
            // Cosmetic only — the ports are shown for information, and the service reads them itself.
        }

        return "—";
    }

    /// <summary>Writes one switch back. Every one of these needs the service restarted to take
    /// effect, which the page says rather than leaving the user to wonder.</summary>
    private async void DefenseToggle_Changed(object sender, RoutedEventArgs e)
    {
        if (_suppressEvents)
            return;

        var box = (CheckBox)sender;
        string[] path = ((string)box.Tag).Split('/');

        (bool success, string message) = _config.SetBool(path, box.IsChecked == true);
        Toast(success ? Strings.Current["SavedNeedsRestart"] : message, success);

        if (!success)
            LoadDefenseSettings();

        await Task.CompletedTask;
    }

    private void BotAction_Changed(object sender, RoutedEventArgs e)
    {
        if (_suppressEvents)
            return;

        string action = (string)((RadioButton)sender).Tag;
        (bool success, string message) = _config.SetString(["BotDefense", "Action"], action);
        Toast(success ? Strings.Current["SavedNeedsRestart"] : message, success);
    }

    private async Task RefreshDefenseAsync()
    {
        // The live counters only exist inside the running process, so there is no honest fallback for
        // them — saying the service is not running is the whole answer.
        AdminResponse status = await _pipe.DefenseStatusAsync();
        DefenseStatusText.Text = status.Success ? status.Message : Strings.Current["DefenseUnavailable"];

        AdminResponse threats = await _pipe.ListThreatsAsync();
        ThreatListText.Text = threats.Success ? threats.Message : ReadThreatsFromDisk();
    }

    /// <summary>
    /// Reads the honeypot's own record straight off disk when the service is not answering.
    ///
    /// Worth doing because this list is the one thing on the page that outlives the process: it is
    /// written in the same one-address-per-line format the imported feeds use, precisely so it can be
    /// read by something other than the service. Someone looking at this page after a restart wants to
    /// know what got caught, and "the service is not running" is a poor answer when the answer is
    /// sitting in a file.
    /// </summary>
    private static string ReadThreatsFromDisk()
    {
        try
        {
            string path = Path.Combine(LogTailReader.DataDirectory, "threats-observed.txt");
            if (!File.Exists(path))
                return Strings.Current["ThreatsNoneYet"];

            string[] entries = [.. File.ReadLines(path)
                .Where(line => line.Length > 0 && !line.StartsWith('#'))
                .Take(100)];

            return entries.Length == 0
                ? Strings.Current["ThreatsNoneYet"]
                : Strings.Current.Format("ThreatsFromFile", entries.Length) + Environment.NewLine + string.Join(Environment.NewLine, entries);
        }
        catch
        {
            return Strings.Current["ThreatsNoneYet"];
        }
    }

    private async void BtnRestartService_Click(object sender, RoutedEventArgs e)
    {
        await RunAsync(async () =>
        {
            (bool stopped, string stopMessage) = await _service.StopAsync();
            if (!stopped)
                return (false, stopMessage);

            return await _service.StartAsync();
        });

        LoadDefenseSettings();
    }

    // ------------------------------------------------------------------ security check

    private async void BtnRunCheck_Click(object sender, RoutedEventArgs e)
    {
        // Guarded because the check does real network I/O and takes a second or two. Two overlapping
        // runs both clear the list and then both append, which showed up as every finding listed
        // twice — the button is on two pages, so double-triggering is easy.
        if (_checkRunning)
            return;

        _checkRunning = true;
        try
        {
            NavSecurity.IsChecked = true;
            _checks.Clear();
            QuickCheckText.Text = Strings.Current["LeakRunning"];
            QuickCheckDot.Fill = (Brush)FindResource("TextMuted");

            var (profiles, _) = _config.Load();
            List<CheckResult> results = await _exposure.RunAsync(profiles);
            _lastCheckResults = results;

            _checks.Clear();
            foreach (CheckResult result in results)
                _checks.Add(new CheckRow(result));

            CheckVerdict worst =
                results.Any(r => r.Verdict == CheckVerdict.Danger) ? CheckVerdict.Danger :
                results.Any(r => r.Verdict == CheckVerdict.Warning) ? CheckVerdict.Warning :
                results.Any(r => r.Verdict == CheckVerdict.Unknown) ? CheckVerdict.Unknown : CheckVerdict.Safe;

            var summary = new CheckRow(new CheckResult("", worst, ""));
            QuickCheckText.Text = summary.VerdictLabel;
            QuickCheckText.Foreground = summary.VerdictBrush;
            QuickCheckDot.Fill = summary.VerdictBrush;
        }
        finally
        {
            _checkRunning = false;
        }
    }

    // ------------------------------------------------------------------ service actions

    private async Task RunAsync(Func<Task<(bool, string)>> action)
    {
        var (ok, message) = await action();
        Toast(message, ok);
        await RefreshAsync();
    }

    private async void BtnStart_Click(object sender, RoutedEventArgs e) => await RunAsync(_service.StartAsync);

    private async void BtnStop_Click(object sender, RoutedEventArgs e)
    {
        if (Confirm("ConfirmStopTitle", "ConfirmStopBody"))
            await RunAsync(_service.StopAsync);
    }

    private async void BtnInstall_Click(object sender, RoutedEventArgs e) =>
        await RunAsync(async () =>
        {
            var (ok, message) = await _service.InstallAsync();
            if (!ok)
                return (ok, message);

            var (started, startMessage) = await _service.StartAsync();
            return (started, message + " " + startMessage);
        });

    private async void BtnUninstall_Click(object sender, RoutedEventArgs e)
    {
        if (Confirm("ConfirmRemoveTitle", "ConfirmRemoveBody"))
            await RunAsync(_service.UninstallAsync);
    }

    private bool Confirm(string titleKey, string bodyKey) =>
        MessageBox.Show(this,
            Strings.Current[titleKey] + "\n\n" + Strings.Current[bodyKey],
            "MinecraftFirewall", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes;

    private async void BtnRefreshBans_Click(object sender, RoutedEventArgs e) => await RefreshBansAsync();

    private async void BtnUnban_Click(object sender, RoutedEventArgs e)
    {
        string ip = UnbanIpBox.Text.Trim();
        if (ip.Length == 0)
        {
            Toast(Strings.Current["UnbanNeedsIp"], ok: false);
            return;
        }

        var response = await _pipe.UnbanAsync(ip);
        Toast(response.Message, response.Success);
        UnbanIpBox.Clear();
        await RefreshBansAsync();
    }

    private async void BtnReloadLists_Click(object sender, RoutedEventArgs e)
    {
        var response = await _pipe.ReloadIpListsAsync();
        Toast(response.Message, response.Success);
    }

    private void BtnEditConfig_Click(object sender, RoutedEventArgs e)
    {
        if (!_config.Exists)
        {
            Toast($"Configuration file not found: {_config.ConfigPath}", ok: false);
            return;
        }

        OpenInShell(_config.ConfigPath);
        Toast(Strings.Current["ConfigRestartNote"], ok: true);
    }

    private void BtnOpenLogs_Click(object sender, RoutedEventArgs e)
    {
        if (!Directory.Exists(LogTailReader.LogDirectory))
        {
            Toast("No log folder yet — start the service first.", ok: false);
            return;
        }

        OpenInShell(LogTailReader.LogDirectory);
    }

    private static void OpenInShell(string path) =>
        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });

    // ------------------------------------------------------------------ settings

    private void LoadPreferences()
    {
        _suppressEvents = true;
        LangEn.IsChecked = Strings.Current.LanguageCode == "en";
        LangTr.IsChecked = Strings.Current.LanguageCode == "tr";
        ChkLoginStartup.IsChecked = LoginStartup.IsEnabled();
        ChkStartMinimised.IsChecked = App.StartMinimisedToTray;
        ChkAutoPremium.IsChecked = _config.Exists && _config.GetAutoPremium();
        _suppressEvents = false;

        PageTitle.Text = Strings.Current["NavStatus"];
    }

    private void Language_Changed(object sender, RoutedEventArgs e)
    {
        if (_suppressEvents || !IsLoaded)
            return;

        string code = (string)((RadioButton)sender).Tag;
        Strings.Current.SetLanguage(code);
        AppPreferences.Language = code;

        RebuildTrayMenu(_tray);
        PageTitle.Text = Strings.Current["Nav" + CurrentPageTag()];
        ApplyStatus(_service.GetStatus());

        // CheckRow resolves its text through Strings when a binding reads it, but the bindings
        // themselves are plain CLR properties with no change notification — so already-rendered
        // findings would keep the old language until the next run. Rebuild them from the stored
        // results instead of asking the user to re-run the check.
        if (_lastCheckResults.Count > 0)
        {
            _checks.Clear();
            foreach (CheckResult result in _lastCheckResults)
                _checks.Add(new CheckRow(result));
        }
    }

    private string CurrentPageTag() =>
        PageServers.Visibility == Visibility.Visible ? "Servers" :
        PageSecurity.Visibility == Visibility.Visible ? "Security" :
        PageBans.Visibility == Visibility.Visible ? "Bans" :
        PageLog.Visibility == Visibility.Visible ? "Log" :
        PageSettings.Visibility == Visibility.Visible ? "Settings" : "Status";

    private async void StartMode_Changed(object sender, RoutedEventArgs e)
    {
        if (_suppressEvents || !IsLoaded)
            return;

        var mode = StartAuto.IsChecked == true ? ServiceStartMode.Automatic : ServiceStartMode.Manual;
        var (ok, message) = await _service.SetStartModeAsync(mode);
        Toast(message, ok);
        await RefreshAsync();
    }

    private void StartupPreference_Changed(object sender, RoutedEventArgs e)
    {
        if (_suppressEvents || !IsLoaded)
            return;

        var (ok, message) = LoginStartup.SetEnabled(ChkLoginStartup.IsChecked == true, ChkStartMinimised.IsChecked == true);
        Toast(message, ok);
    }

    private async void AutoPremium_Changed(object sender, RoutedEventArgs e)
    {
        if (_suppressEvents || !IsLoaded)
            return;

        var (ok, message) = _config.SetAutoPremium(ChkAutoPremium.IsChecked == true);
        if (!ok)
        {
            Toast(message, ok: false);
            return;
        }

        if (_service.GetStatus().State == ServiceState.Running)
        {
            await _service.StopAsync();
            await _service.StartAsync();
        }

        Toast(message, ok: true);
    }

    // ------------------------------------------------------------------ toast

    private void Toast(string message, bool ok)
    {
        ToastText.Text = message;
        ToastRail.Fill = ok ? (Brush)FindResource("Good") : (Brush)FindResource("Bad");
        ToastBar.Visibility = Visibility.Visible;
    }
}
