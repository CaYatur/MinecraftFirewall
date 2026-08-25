using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Markup;

namespace MinecraftFirewall.App.Localization;

/// <summary>
/// Every user-visible string, in every supported language.
///
/// Exposed as an indexer on a singleton that raises <c>PropertyChanged</c> for "Item[]", so XAML
/// bindings re-evaluate the moment the language changes — the window relabels itself live instead of
/// asking the user to restart. English is the default and the fallback: an unknown key, or a key
/// missing from a translation, renders the English text rather than blanking the control.
/// </summary>
public sealed class Strings : INotifyPropertyChanged
{
    public static Strings Current { get; } = new();

    public event PropertyChangedEventHandler? PropertyChanged;

    private Dictionary<string, string> _active = English;

    public string LanguageCode { get; private set; } = "en";

    public string this[string key] =>
        _active.TryGetValue(key, out string? value) ? value
        : English.TryGetValue(key, out string? fallback) ? fallback
        : key;

    public void SetLanguage(string code)
    {
        LanguageCode = code == "tr" ? "tr" : "en";
        _active = LanguageCode == "tr" ? Turkish : English;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
    }

    /// <summary>Formats a localized string that contains {0}-style placeholders.</summary>
    public string Format(string key, params object[] args) => string.Format(this[key], args);

    /// <summary>
    /// Every key one language defines. Exposed so a test can assert the two dictionaries stay in step.
    ///
    /// Worth having because the lookup above falls back to English for a missing key, which is the
    /// right behaviour at runtime — an English label beats a blank one — and exactly what makes the
    /// omission invisible. With every new page adding twenty or thirty strings at a time, a forgotten
    /// translation is a matter of when rather than whether, and nothing else would ever notice.
    /// </summary>
    public static IReadOnlyCollection<string> KeysFor(string code) =>
        (code == "tr" ? Turkish : English).Keys;

    private static readonly Dictionary<string, string> English = new()
    {
        // Shell
        ["AppTagline"] = "Minecraft server protection",
        ["NavStatus"] = "Status",
        ["NavServers"] = "Servers",
        ["NavSecurity"] = "Security check",
        ["NavBans"] = "Blocked IPs",
        ["NavLog"] = "Activity log",
        ["NavSettings"] = "Settings",

        // Status states
        ["StateProtected"] = "Protected",
        ["StateNotProtecting"] = "Not protecting",
        ["StateWorking"] = "Working…",
        ["StateNotInstalled"] = "Not installed",
        ["StateUnknown"] = "Unknown",
        ["StateRunningDetail"] = "The protection service is running.",
        ["StateStoppedDetail"] = "The service is installed but stopped.",
        ["StatePendingDetail"] = "Windows is starting or stopping the service.",
        ["StateNotInstalledDetail"] = "Install the service to begin protecting your server.",
        ["StateManualWarning"] = "Running, but set to manual — it will NOT come back after a reboot.",

        // Status page
        ["ProtectionTitle"] = "Protection service",
        ["ProtectionBlurb"] = "The proxy runs as a Windows service, so it keeps protecting your server after a reboot even when nobody is logged in. This window is only its control panel — closing it does not stop protection.",
        ["BtnStart"] = "Start",
        ["BtnStop"] = "Stop",
        ["BtnInstall"] = "Install service",
        ["BtnUninstall"] = "Remove service",
        ["NavDefense"] = "Protection",
        ["UpgradeTitle"] = "Your configuration is missing some settings",
        ["UpgradeDetail"] = "This version added settings your appsettings.json does not have yet: {0}. Your file was left alone during the upgrade \u2014 which is right, since it holds your servers and protected usernames \u2014 but the switches below cannot be saved until the sections exist. Adding them copies the shipped defaults across, with their explanations, and changes nothing you have already set.",
        ["BtnAddSections"] = "Add the missing settings",
        ["FieldVpn"] = "VPN and hosting-provider connections",
        ["FieldVpnHint"] = "Free lists of known VPN exit points and datacentre ranges, refreshed daily.",
        ["VpnLogOnly"] = "Allow them, just note it in the log",
        ["VpnProtectedOnly"] = "Block them only for protected usernames (recommended)",
        ["VpnEveryone"] = "Block them for everyone",

        ["ChkMalformed"] =
            "Refuse packets a real client could not send (bad interaction types, impossible coordinates, " +
            "trailing bytes) — this is what PacketFixer-style plugins do, but before the server parses them",
        ["MessagesHeading"] = "Player messages",
        ["MessagesBlurb"] =
            "Your configuration file keeps the messages players see, and it is never overwritten when you " +
            "update — so improved wording and colour from a newer version do not reach an existing install. " +
            "This brings them up to date, and only touches messages you have not edited yourself.",
        ["BtnRefreshMessages"] = "Update messages to the latest defaults",
        ["BtnSetUpForwarding"] = "Set my server up for this",
        ["ForwardingSetupTitle"] = "Change your server's configuration?",
        ["ForwardingSetupFormat"] =
            "{0}\n\nYour Minecraft server must be restarted afterwards. The previous file is kept beside it. " +
            "Continue?",
        ["PluginHeading"] = "Server plugin (optional)",
        ["PluginBlurb"] =
            "A firewall in front of your server cannot stop a creeper: a player waiting at the login prompt is " +
            "really standing in your world, and only the server decides their health. This small plugin is the " +
            "part that is inside, so it can. It also makes /login, /register and /premium real commands, so they " +
            "show in blue and appear in /help. Everything works without it.",
        ["ChkUsePlugin"] = "Use the plugin when it is installed (harmless when it is not)",
        ["BtnCheckPlugin"] = "Check my server",
        ["BtnInstallPlugin"] = "Install into my server",
        ["BtnRemovePlugin"] = "Remove it",
        ["PluginNotChecked"] = "  Press \u201CCheck my server\u201D to see where this would go.",
        ["PluginConfirmTitle"] = "Install the plugin?",
        ["PluginConfirmFormat"] =
            "This will copy a file into your Minecraft server:\n\n{0}\n\nNothing else is changed, and your " +
            "server must be restarted before it loads. Continue?",
        ["PluginRemoveConfirmFormat"] = "Delete this file?\n\n{0}",
        ["NavPlayers"] = "Players",
        ["PlayersHeading"] = "Players this server knows",
        ["PlayersBlurb"] =
            "Everyone who has registered, been locked to a Minecraft account, or been named in your configuration. " +
            "Pick a server to see its own list. This reads from the running service, so it is live.",
        ["PlayersServer"] = "Server:",
        ["PlayersListHeading"] = "Accounts",
        ["PlayersEmpty"] =
            "Nobody yet. Names appear here once someone registers, proves a Minecraft account, or is listed under " +
            "that server's protected usernames.",
        ["ColPlayer"] = "Name",
        ["ColStatus"] = "Status",
        ["ColRegistered"] = "Registered",
        ["ColLastSeen"] = "Last seen",
        ["ColLastIp"] = "Last address",
        ["ColRisk"] = "Risk",
        ["PlayerSummaryFormat"] =
            "{0}  ·  registered {1}  ·  last seen {2}  ·  last address {3}  ·  {4} remembered address(es)",
        ["PlayerRiskHeading"] = "Why this address looks suspicious",
        ["PlayerRiskTotal"] = "total",
        ["PlayerNoRisk"] = "  Nothing recorded against this address.",
        ["PlayerHistoryHeading"] = "This player's history",
        ["PlayerNoHistory"] = "  Nothing recorded yet.",
        ["PlayerActionsHeading"] = "Actions",
        ["PlayerActionsHint"] =
            "These take effect immediately on the running service. Locking a name to a Minecraft account is the one " +
            "that does not survive a restart on its own — put it in the server's configuration too.",
        ["BtnRefresh"] = "Refresh",
        ["BtnForgetAddresses"] = "Forget remembered addresses",
        ["BtnResetPassword"] = "Reset password",
        ["BtnLockPremium"] = "Lock to Minecraft account",
        ["BtnUnlockPremium"] = "Unlock",
        ["BtnRemovePlayer"] = "Remove from this server",
        ["ConfirmTitle"] = "Are you sure?",
        ["ConfirmForgetAddresses"] =
            "Forget the addresses '{0}' is trusted from?\n\nThey will have to type their password again the next " +
            "time they join. Their password itself is not changed.",
        ["ConfirmResetPassword"] =
            "Clear the password for '{0}'?\n\nThey will be asked to register again on their next join, and their " +
            "remembered addresses are cleared too — otherwise the name would simply go to whoever connects next.",
        ["ConfirmRemovePlayer"] =
            "Remove everything this server has learned about '{0}'?\n\nTheir password, remembered addresses and " +
            "history are all forgotten. If the name is also in your configuration file, it comes back from there " +
            "on the next restart.",
        ["ConfirmLockPremium"] =
            "Lock '{0}' to its real Minecraft account?\n\nOnly that account will be able to use the name here, from " +
            "any address, and it will never be asked for a password. This does NOT survive a restart on its own — " +
            "add it to the server's configuration as well.",
        ["ConfirmUnlockPremium"] =
            "Unlock '{0}'?\n\nAnyone will be able to use the name again, subject to your other settings. If it is " +
            "set in your configuration file, remove it there too.",

        ["FieldIpForwarding"] = "Real player IP addresses",
        ["FieldIpForwardingHint"] =
            "Without this, every player in your server's log and in every plugin is 127.0.0.1, so banning " +
            "an IP there bans everyone. Your Minecraft server has to be set to expect the same option, and " +
            "its port must stay on 127.0.0.1 — the security check looks for that.",
        ["ForwardNone"] = "Off — the server sees this firewall's address",
        ["ForwardProxyProtocol"] = "PROXY protocol (Paper: proxies.proxy-protocol: true)",
        ["ForwardBungeeCord"] = "BungeeCord style (spigot.yml: bungeecord: true)",
        ["ChkDatacenter"] = "Also use the wider datacentre list (catches more, false-positives more)",
        ["DefAuthTitle"] = "Accounts and passwords (CaYaDev-Check)",
        ["DefAuthBlurb"] = "The AuthMe-style login system. Off, any player who types /register protects their own name and everyone else plays as before. On, nobody reaches your world until they have registered or logged in \u2014 they join, but cannot move, hit, place or open anything, and only chat gets through so they can type the command.",
        ["ChkRequireRegistration"] = "Require every player to register and log in",
        ["AuthNote"] = "Players with a premium-locked name skip this entirely. Their Microsoft account has already proved who they are, and asking for a password on top would mean making the real owner prove themselves twice \u2014 which is the one thing this firewall promises never to do.",
        ["AnomalyActionLabel"] = "When the same address keeps being flagged",
        ["AnomalyActionReport"] = "Just write it in the log (recommended to start with)",
        ["AnomalyActionScore"] = "Count it towards that address\u2019s bot score",
        ["AnomalyActionReauth"] = "Make them log in again next time they connect",
        ["AnomalyActionThrottle"] = "Tighten that address\u2019s connection limits for a while",
        ["AnomalyActionBan"] = "Ban the address for a while",
        ["ChkBackendTitle"] = "Your Minecraft server",
        ["ChkBackendUnknown"] = "Could not work out which server is on port {0}, so nothing can be said about its version. Harmless \u2014 it only means this panel could not read the server\u2019s own files.",
        ["ChkBackendPlain"] = "Running Minecraft {0} with {1} plugin(s). Players on that version get the full login system; anyone on an older client still connects and plays, they just cannot be asked for a password.",
        ["ChkBackendVia"] = "Running Minecraft {0} with {1}. That is why players on much older clients can join \u2014 and it is worth knowing that the login system can only prompt clients from 1.20.2 onwards.",
        ["ChkBackendViaFix"] = "Older clients are not blocked and never will be: they connect and play normally. What they cannot do is be held for a password, because reading their chat needs packet tables that do not exist for those versions. For names you actually care about, lock them to a Microsoft account instead \u2014 that works on every version.",
        ["DefLiveTitle"] = "Right now",
        ["DefLiveBlurb"] = "Live counters from the running service. Connections it is holding, addresses it is tracking, and how many it has turned away since it started.",
        ["DefenseUnavailable"] = "The service is not running, so there are no live figures to show.",
        ["ThreatsNoneYet"] = "Nothing has touched a decoy port yet. (Decoy ports ship switched off \u2014 turn them on above.)",
        ["ThreatsFromFile"] = "{0} address(es) caught here, read from the saved record:",
        ["DefFloodTitle"] = "Floods and malformed packets",
        ["DefFloodBlurb"] = "Turns away addresses opening far more connections than a player needs, and refuses packets no Minecraft client sends \u2014 impossible coordinates, oversized frames, and Log4j-style payloads in chat, usernames, signs and books.",
        ["ChkDdos"] = "Limit how many connections one address may open",
        ["ChkInspection"] = "Inspect what clients send after they are let in",
        ["ChkInjection"] = "Scan player text for injection payloads",
        ["DefBotTitle"] = "Automated players",
        ["DefBotBlurb"] = "Scores join behaviour that does not look like a person: logging in without ever asking for the server list, working through a list of usernames, reconnecting on a metronome. No single signal refuses anyone \u2014 it takes several at once.",
        ["BotLogOnly"] = "Only report them (recommended to start with)",
        ["BotDeny"] = "Refuse them",
        ["BotActionNote"] = "Leave this on \u201conly report\u201d for a few days first and watch the Activity log. If your own players never score highly, switching to \u201crefuse\u201d is safe. If they do, turn down whichever signal keeps firing in appsettings.json rather than switching the whole thing off.",
        ["DefHoneypotTitle"] = "Decoy ports",
        ["DefHoneypotBlurb"] = "Listens on ports nothing advertises. A player\u2019s client connects to the port you gave them and has no reason to try the one next door \u2014 so anything that does is scanning you, not playing.",
        ["ChkHoneypot"] = "Listen on decoy ports and record whoever connects",
        ["HoneypotPorts"] = "Ports: {0}. Any port one of your own servers already uses is skipped automatically. Edit the list in appsettings.json.",
        ["DefMovementTitle"] = "Movement",
        ["DefMovementBlurb"] = "Coordinates that are not numbers at all are always refused \u2014 they are crash inputs, not cheats. Moving faster than seems possible is a separate, much weaker claim.",
        ["ChkMovement"] = "Watch movement and report anything unusual",
        ["ChkMovementKick"] = "Also disconnect players for unusual movement",
        ["MovementKickWarning"] = "Leave this off unless you have watched the reports on your own server first. This firewall sees coordinates and nothing else \u2014 not ice, boats, elytra, riptide tridents, speed potions, or a plugin teleporting someone. All of those look exactly like a speed cheat from here. A server-side anti-cheat plugin can tell them apart; this cannot.",
        ["DefAnomalyTitle"] = "Learning what normal looks like",
        ["DefAnomalyBlurb"] = "Every other check here follows a rule somebody wrote down, and rules only catch what their author thought of. This one learns the shape of ordinary connections to your server and reports the ones that do not fit \u2014 including techniques nobody has seen before.",
        ["ChkAnomaly"] = "Learn a baseline and report connections that do not fit it",
        ["AnomalyNote"] = "This only ever reports \u2014 it never refuses anyone, and there is no setting to change that. What it detects is \u201cunlike your other connections\u201d, which is not the same as \u201cmalicious\u201d: a server whose players are all in one timezone will flag someone joining at an odd hour, correctly and unhelpfully. It also needs a few hundred connections before it says anything, and it learns from whoever is connecting \u2014 so switch it on at a quiet time, not during an attack.",
        ["DefRestartTitle"] = "Applying changes",
        ["DefRestartBlurb"] = "The service reads these settings when it starts, so a change here takes effect at the next restart.",
        ["BtnApplyRestart"] = "Restart the service now",
        ["SavedNeedsRestart"] = "Saved. Restart the service to apply it.",
        ["ServersTitle"] = "Servers being protected",
        ["ProfilesFromConfig"] = "From your configuration file (the service is not running, so this is what would be protected):",
        ["ProfilesUnavailable"] = "No servers configured yet. Open the Servers page to add one.",
        ["BtnManageServers"] = "Manage servers",
        ["BtnRefreshLists"] = "Refresh VPN lists now",
        ["RecentTitle"] = "Recent activity",
        ["QuickCheckTitle"] = "Security check",
        ["QuickCheckBlurb"] = "Confirms your real Minecraft server can't be reached directly, bypassing this firewall. This is the single most important thing to get right.",
        ["BtnRunCheck"] = "Run check now",

        // Servers page
        ["ServersHeading"] = "Your servers",
        ["ServersBlurb"] = "Each entry puts this firewall in front of one Minecraft server. Players connect to the public port; the firewall forwards approved connections to the real server.",
        ["BtnAddServer"] = "Add a server",
        ["BtnRemoveServer"] = "Remove",
        ["BtnSaveServers"] = "Save and apply",
        ["FieldName"] = "Name",
        ["FieldPublicPort"] = "Public port (players connect here)",
        ["FieldBackendHost"] = "Real server address",
        ["FieldBackendPort"] = "Real server port",
        ["FieldAllowedDomains"] = "Allowed domains (optional, one per line)",
        ["FieldProtectedNames"] = "Protected usernames",
        ["ProtectedNamesBlurb"] = "One per line. Add  |premium  after a name to lock it to its genuine Minecraft account, or  |ip=1.2.3.4  to allow it only from that address.",
        ["SaveNeedsRestart"] = "Saved. Restart the service to apply — press Stop then Start on the Status page.",
        ["BtnSaveAndRestart"] = "Save and restart service",

        // Security check page
        ["LeakHeading"] = "Is your real server exposed?",
        ["LeakBlurb"] = "This firewall only helps if players cannot reach your Minecraft server directly. This check looks for the ways it usually stays reachable by mistake.",
        ["LeakRunning"] = "Checking…",
        ["LeakSafe"] = "Looks correct",
        ["LeakWarn"] = "Needs attention",
        ["LeakDanger"] = "Exposed",
        ["LeakUnknown"] = "Could not determine",

        // Security check findings
        ["ChkNoServersTitle"] = "Servers configured",
        ["ChkNoServersDetail"] = "No servers are configured yet, so there is nothing to check.",
        ["ChkNoServersFix"] = "Add your Minecraft server on the Servers page.",
        ["ChkBindingTitle"] = "Real server binding",
        ["ChkBindingNoListener"] = "Nothing is listening on port {0} right now, so its binding can't be read.",
        ["ChkBindingNoListenerFix"] = "Start your Minecraft server, then run this check again.",
        ["ChkBindingWildcard"] = "Your Minecraft server ({0}) is listening on port {1} on ALL network interfaces. Anyone who can reach this machine can connect straight to it and bypass every check this firewall makes.",
        ["ChkBindingWildcardFix"] = "In that server's server.properties set  server-ip=127.0.0.1  and restart it.",
        ["ChkBindingLoopback"] = "Port {0} is bound to loopback only, so it can't be reached from another machine.",
        ["ChkBindingError"] = "Could not read listening sockets: {0}",
        ["ChkLanTitle"] = "Reachable from the network",
        ["ChkLanNoAddress"] = "No local network address was found, so this test could not run.",
        ["ChkLanReachable"] = "Connected to your real server at {0}:{1} using this machine's own network address. Every device on your network can do the same, and so can the internet if your router forwards that port.",
        ["ChkLanReachableFix"] = "Bind the server to 127.0.0.1 and remove any port-forward or firewall rule for that port.",
        ["ChkLanRefused"] = "Port {0} refused a connection over this machine's network address ({1}).",
        ["ChkPublicTitle"] = "Firewall is accepting players",
        ["ChkPublicListening"] = "Port {0} is accepting connections, so players can reach {1} through the firewall.",
        ["ChkPublicClosed"] = "Nothing is accepting connections on the public port {0}. Players cannot join at all right now.",
        ["ChkPublicClosedFix"] = "Start the protection service on the Status page.",
        ["ChkRulesTitle"] = "Windows Firewall rules",
        ["ChkRulesOffending"] = "These inbound firewall rules allow traffic straight to your real server's port: {0}",
        ["ChkRulesOffendingFix"] = "Remove or disable them in Windows Defender Firewall — only the public port needs to be reachable.",
        ["ChkRulesClean"] = "No inbound rule allows your real server's port. Note this cannot see your router — check there too if the server is on the internet.",
        ["ChkRulesError"] = "Could not read firewall rules: {0}",

        // Bans page
        ["BansHeading"] = "Currently blocked",
        ["BansBlurb"] = "IPs blocked after repeated failed logins, dangerous commands, or VPN policy. Each has an expiry and is lifted automatically. Loopback and your local network can never be blocked.",
        ["BtnUnban"] = "Unblock this IP",
        ["BtnRefresh"] = "Refresh",
        ["UnbanPlaceholder"] = "IP address",
        ["UnbanNeedsIp"] = "Type the IP address you want to unblock.",

        // Log page
        ["LogHeading"] = "Service log",
        ["BtnOpenLogFolder"] = "Open log folder",
        ["ChkFollow"] = "Follow new lines",

        // Settings page
        ["SettingsProtectionTitle"] = "Protection at startup",
        ["SettingsProtectionBlurb"] = "This is the setting that decides whether your server is protected. It applies to the background service and works with nobody logged in.",
        ["StartAuto"] = "Start automatically with Windows  (recommended)",
        ["StartManual"] = "Only start when I press Start",
        ["SettingsWindowTitle"] = "This window",
        ["SettingsWindowBlurb"] = "Convenience only — these do not affect whether your server is protected.",
        ["ChkLoginStartup"] = "Open this control panel when I log in",
        ["ChkStartMinimised"] = "Start minimised to the notification area",
        ["ChkCloseToTray"] = "Closing this window keeps it in the notification area",
        ["SettingsLanguageTitle"] = "Language",
        ["SettingsPremiumTitle"] = "Automatic premium lock",
        ["SettingsPremiumBlurb"] = "When someone joins with a genuine Minecraft account, permanently reserve that username for them. Names that fail are never marked — an offline player simply joins as usual, and the real owner can still claim the name later by connecting once.",
        ["ChkAutoPremium"] = "Claim usernames automatically for verified accounts",
        ["AutoPremiumWarning"] = "Leave this off unless you have tested it. It makes the server ask every new player's client to prove itself, and some non-original launchers handle that badly and may fail to connect.",
        ["SettingsFilesTitle"] = "Files",
        ["BtnOpenConfig"] = "Open configuration file",
        ["ConfigRestartNote"] = "Changes to the configuration file take effect when the service restarts.",

        // Tray / dialogs
        ["TrayOpen"] = "Open MinecraftFirewall",
        ["TrayStart"] = "Start protection",
        ["TrayStop"] = "Stop protection",
        ["TrayExit"] = "Exit control panel",
        ["TrayStillRunning"] = "Still running here. Your server stays protected either way — the background service is separate from this window.",
        ["ConfirmStopTitle"] = "Stop protection?",
        ["ConfirmStopBody"] = "Your Minecraft server will accept connections without any of this app's checks until you start it again.",
        ["ConfirmRemoveTitle"] = "Remove the background service?",
        ["ConfirmRemoveBody"] = "Your server will no longer be protected, including after a reboot. Your configuration file and settings are kept.",
    };

    private static readonly Dictionary<string, string> Turkish = new()
    {
        ["AppTagline"] = "Minecraft sunucu koruması",
        ["NavStatus"] = "Durum",
        ["NavServers"] = "Sunucular",
        ["NavSecurity"] = "Güvenlik kontrolü",
        ["NavBans"] = "Engellenen IP'ler",
        ["NavLog"] = "Etkinlik günlüğü",
        ["NavSettings"] = "Ayarlar",

        ["StateProtected"] = "Korunuyor",
        ["StateNotProtecting"] = "Korumuyor",
        ["StateWorking"] = "İşleniyor…",
        ["StateNotInstalled"] = "Kurulu değil",
        ["StateUnknown"] = "Bilinmiyor",
        ["StateRunningDetail"] = "Koruma servisi çalışıyor.",
        ["StateStoppedDetail"] = "Servis kurulu ama durdurulmuş.",
        ["StatePendingDetail"] = "Windows servisi başlatıyor veya durduruyor.",
        ["StateNotInstalledDetail"] = "Korumayı başlatmak için servisi kurun.",
        ["StateManualWarning"] = "Çalışıyor, ancak elle başlatmaya ayarlı — yeniden başlatmadan sonra AÇILMAZ.",

        ["ProtectionTitle"] = "Koruma servisi",
        ["ProtectionBlurb"] = "Proxy bir Windows servisi olarak çalışır; böylece bilgisayar yeniden başlasa ve kimse oturum açmasa bile sunucunuzu korumaya devam eder. Bu pencere yalnızca kontrol panelidir — kapatmanız korumayı durdurmaz.",
        ["BtnStart"] = "Başlat",
        ["BtnStop"] = "Durdur",
        ["BtnInstall"] = "Servisi kur",
        ["BtnUninstall"] = "Servisi kaldır",
        ["NavDefense"] = "Koruma",
        ["UpgradeTitle"] = "Ayar dosyanızda eksik bölümler var",
        ["UpgradeDetail"] = "Bu sürüm, appsettings.json dosyanızda henüz bulunmayan ayarlar ekledi: {0}. Yükseltme sırasında dosyanıza dokunulmadı \u2014 sunucularınızı ve korumalı kullanıcı adlarınızı tuttuğu için bu doğrudur \u2014 ancak bölümler oluşana kadar aşağıdaki anahtarlar kaydedilemez. Eklemek, varsayılanları açıklamalarıyla birlikte kopyalar ve daha önce yaptığınız hiçbir ayarı değiştirmez.",
        ["BtnAddSections"] = "Eksik ayarları ekle",
        ["FieldVpn"] = "VPN ve barındırma sağlayıcısı bağlantıları",
        ["FieldVpnHint"] = "Bilinen VPN çıkış noktalarının ve veri merkezi aralıklarının ücretsiz listeleri, her gün yenilenir.",
        ["VpnLogOnly"] = "İzin ver, sadece günlüğe not düş",
        ["VpnProtectedOnly"] = "Yalnızca korumalı kullanıcı adları için engelle (önerilir)",
        ["VpnEveryone"] = "Herkes için engelle",

        ["ChkMalformed"] =
            "Gerçek bir istemcinin gönderemeyeceği paketleri reddet (hatalı etkileşim türleri, imkânsız " +
            "koordinatlar, artık baytlar) — PacketFixer tarzı eklentilerin yaptığı iş, ama sunucu paketi " +
            "çözümlemeden önce",
        ["MessagesHeading"] = "Oyuncu mesajları",
        ["MessagesBlurb"] =
            "Oyuncuların gördüğü mesajlar yapılandırma dosyanızda tutulur ve güncellemede asla üzerine " +
            "yazılmaz — bu yüzden yeni sürümdeki iyileştirilmiş metinler ve renkler mevcut bir kuruluma " +
            "ulaşmaz. Bu düğme onları güncelleştirir ve yalnızca sizin düzenlemediğiniz mesajlara dokunur.",
        ["BtnRefreshMessages"] = "Mesajları en son varsayılanlara güncelle",
        ["BtnSetUpForwarding"] = "Sunucumu buna göre ayarla",
        ["ForwardingSetupTitle"] = "Sunucunuzun yapılandırması değiştirilsin mi?",
        ["ForwardingSetupFormat"] =
            "{0}\n\nArdından Minecraft sunucunuzu yeniden başlatmanız gerekir. Önceki dosya yanında saklanır. " +
            "Devam edilsin mi?",
        ["PluginHeading"] = "Sunucu eklentisi (isteğe bağlı)",
        ["PluginBlurb"] =
            "Sunucunun önündeki bir güvenlik duvarı creeper'ı durduramaz: giriş ekranında bekleyen oyuncu " +
            "gerçekten dünyanızda duruyordur ve canını yalnızca sunucu belirler. Bu küçük eklenti içeride " +
            "çalışan kısımdır, bu yüzden durdurabilir. Ayrıca /login, /register ve /premium komutlarını gerçek " +
            "komutlara dönüştürür; mavi görünürler ve /help içinde çıkarlar. Eklenti olmadan da her şey çalışır.",
        ["ChkUsePlugin"] = "Kuruluysa eklentiyi kullan (kurulu değilse zararsızdır)",
        ["BtnCheckPlugin"] = "Sunucumu denetle",
        ["BtnInstallPlugin"] = "Sunucuma kur",
        ["BtnRemovePlugin"] = "Kaldır",
        ["PluginNotChecked"] = "  Nereye kurulacağını görmek için \u201CSunucumu denetle\u201D düğmesine basın.",
        ["PluginConfirmTitle"] = "Eklenti kurulsun mu?",
        ["PluginConfirmFormat"] =
            "Minecraft sunucunuza bir dosya kopyalanacak:\n\n{0}\n\nBaşka hiçbir şey değişmez ve yüklenmesi " +
            "için sunucunuzu yeniden başlatmanız gerekir. Devam edilsin mi?",
        ["PluginRemoveConfirmFormat"] = "Bu dosya silinsin mi?\n\n{0}",
        ["NavPlayers"] = "Oyuncular",
        ["PlayersHeading"] = "Bu sunucunun tanıdığı oyuncular",
        ["PlayersBlurb"] =
            "Kayıt olmuş, Minecraft hesabına kilitlenmiş veya yapılandırmanızda adı geçen herkes. " +
            "Kendi listesini görmek için bir sunucu seçin. Bu bilgiler çalışan servisten canlı olarak okunur.",
        ["PlayersServer"] = "Sunucu:",
        ["PlayersListHeading"] = "Hesaplar",
        ["PlayersEmpty"] =
            "Henüz kimse yok. Biri kayıt olduğunda, bir Minecraft hesabını doğruladığında ya da o sunucunun korumalı " +
            "kullanıcı adlarında listelendiğinde adlar burada görünür.",
        ["ColPlayer"] = "Ad",
        ["ColStatus"] = "Durum",
        ["ColRegistered"] = "Kayıt",
        ["ColLastSeen"] = "Son görülme",
        ["ColLastIp"] = "Son adres",
        ["ColRisk"] = "Risk",
        ["PlayerSummaryFormat"] =
            "{0}  ·  kayıt {1}  ·  son görülme {2}  ·  son adres {3}  ·  {4} hatırlanan adres",
        ["PlayerRiskHeading"] = "Bu adres neden şüpheli görünüyor",
        ["PlayerRiskTotal"] = "toplam",
        ["PlayerNoRisk"] = "  Bu adrese dair kayıtlı bir şey yok.",
        ["PlayerHistoryHeading"] = "Bu oyuncunun geçmişi",
        ["PlayerNoHistory"] = "  Henüz kayıt yok.",
        ["PlayerActionsHeading"] = "İşlemler",
        ["PlayerActionsHint"] =
            "Bunlar çalışan serviste anında etkili olur. Bir adı Minecraft hesabına kilitlemek, tek başına yeniden " +
            "başlatmadan sağ çıkmayan tek işlemdir — sunucunun yapılandırmasına da ekleyin.",
        ["BtnRefresh"] = "Yenile",
        ["BtnForgetAddresses"] = "Hatırlanan adresleri unut",
        ["BtnResetPassword"] = "Şifreyi sıfırla",
        ["BtnLockPremium"] = "Minecraft hesabına kilitle",
        ["BtnUnlockPremium"] = "Kilidi kaldır",
        ["BtnRemovePlayer"] = "Bu sunucudan kaldır",
        ["ConfirmTitle"] = "Emin misiniz?",
        ["ConfirmForgetAddresses"] =
            "'{0}' oyuncusunun güvenilen adresleri unutulsun mu?\n\nBir sonraki girişinde şifresini yeniden yazması " +
            "gerekecek. Şifresi değiştirilmez.",
        ["ConfirmResetPassword"] =
            "'{0}' oyuncusunun şifresi silinsin mi?\n\nBir sonraki girişinde yeniden kayıt olması istenecek ve " +
            "hatırlanan adresleri de temizlenecek — aksi hâlde ad, sıradaki bağlanana kalırdı.",
        ["ConfirmRemovePlayer"] =
            "Bu sunucunun '{0}' hakkında öğrendiği her şey kaldırılsın mı?\n\nŞifresi, hatırlanan adresleri ve " +
            "geçmişi unutulur. Ad yapılandırma dosyanızda da varsa, yeniden başlatmada oradan geri gelir.",
        ["ConfirmLockPremium"] =
            "'{0}' gerçek Minecraft hesabına kilitlensin mi?\n\nBu adı burada yalnızca o hesap kullanabilir, hangi " +
            "adresten olursa olsun, ve asla şifre sorulmaz. Bu ayar tek başına yeniden başlatmadan sağ çıkmaz — " +
            "sunucunun yapılandırmasına da ekleyin.",
        ["ConfirmUnlockPremium"] =
            "'{0}' kilidi kaldırılsın mı?\n\nDiğer ayarlarınıza bağlı olarak adı yeniden herkes kullanabilir. " +
            "Yapılandırma dosyanızda ayarlıysa oradan da kaldırın.",

        ["FieldIpForwarding"] = "Oyuncuların gerçek IP adresleri",
        ["FieldIpForwardingHint"] =
            "Bu kapalıyken sunucu günlüğünde ve tüm eklentilerde her oyuncu 127.0.0.1 görünür; oradan bir IP " +
            "yasaklamak herkesi yasaklar. Minecraft sunucunuzun da aynı seçeneği bekleyecek şekilde ayarlanması " +
            "ve portunun 127.0.0.1 üzerinde kalması gerekir — güvenlik denetimi tam olarak buna bakar.",
        ["ForwardNone"] = "Kapalı — sunucu bu güvenlik duvarının adresini görür",
        ["ForwardProxyProtocol"] = "PROXY protokolü (Paper: proxies.proxy-protocol: true)",
        ["ForwardBungeeCord"] = "BungeeCord tarzı (spigot.yml: bungeecord: true)",
        ["ChkDatacenter"] = "Daha geniş veri merkezi listesini de kullan (daha çok yakalar, daha çok yanılır)",
        ["DefAuthTitle"] = "Hesaplar ve şifreler (CaYaDev-Check)",
        ["DefAuthBlurb"] = "AuthMe tarzı giriş sistemi. Kapalıyken /register yazan oyuncu kendi adını korur, diğerleri eskisi gibi oynar. Açıkken hiç kimse kayıt olmadan veya giriş yapmadan dünyanıza ulaşamaz \u2014 sunucuya girerler ama hareket edemez, vuramaz, blok koyamaz, hiçbir şey açamazlar; yalnızca sohbet geçer, böylece komutu yazabilirler.",
        ["ChkRequireRegistration"] = "Her oyuncunun kayıt olup giriş yapmasını zorunlu kıl",
        ["AuthNote"] = "Adı premium olarak kilitlenmiş oyuncular bunu tamamen atlar. Microsoft hesapları kim olduklarını zaten kanıtlamıştır ve üstüne bir de şifre istemek, gerçek sahibe kendini iki kez ispatlatmak olurdu \u2014 bu güvenlik duvarının asla yapmamaya söz verdiği tek şey de budur.",
        ["AnomalyActionLabel"] = "Aynı adres tekrar tekrar işaretlendiğinde",
        ["AnomalyActionReport"] = "Sadece günlüğe yaz (başlangıç için önerilir)",
        ["AnomalyActionScore"] = "O adresin bot puanına ekle",
        ["AnomalyActionReauth"] = "Bir sonraki bağlantısında tekrar giriş yapmasını iste",
        ["AnomalyActionThrottle"] = "O adresin bağlantı sınırlarını bir süre daralt",
        ["AnomalyActionBan"] = "Adresi bir süreliğine engelle",
        ["ChkBackendTitle"] = "Minecraft sunucunuz",
        ["ChkBackendUnknown"] = "{0} portundaki sunucu belirlenemedi, bu yüzden sürümü hakkında bir şey söylenemiyor. Zararsız \u2014 sadece bu panelin sunucunun dosyalarını okuyamadığı anlamına gelir.",
        ["ChkBackendPlain"] = "Minecraft {0} çalışıyor, {1} eklenti var. O sürümdeki oyuncular giriş sisteminin tamamını kullanır; daha eski istemcidekiler yine bağlanıp oynar, sadece onlardan şifre istenemez.",
        ["ChkBackendVia"] = "Minecraft {0} çalışıyor, {1} kurulu. Çok daha eski istemcilerin girebilmesinin sebebi bu \u2014 ve giriş sisteminin yalnızca 1.20.2 ve sonrasına soru sorabildiğini bilmekte fayda var.",
        ["ChkBackendViaFix"] = "Eski istemciler engellenmiyor ve engellenmeyecek: normal şekilde bağlanıp oynarlar. Yapamadıkları tek şey şifre için tutulmak, çünkü sohbetlerini okumak o sürümler için var olmayan paket tablolarını gerektiriyor. Gerçekten önemsediğiniz isimler için onları bir Microsoft hesabına kilitleyin \u2014 bu her sürümde çalışır.",
        ["DefLiveTitle"] = "Şu anda",
        ["DefLiveBlurb"] = "Çalışan hizmetten canlı sayaçlar. Açık tuttuğu bağlantılar, izlediği adresler ve başladığından beri geri çevirdikleri.",
        ["DefenseUnavailable"] = "Hizmet çalışmıyor, bu yüzden gösterilecek canlı veri yok.",
        ["ThreatsNoneYet"] = "Henüz hiçbir şey tuzak porta dokunmadı. (Tuzak portlar kapalı gelir \u2014 yukarıdan açabilirsiniz.)",
        ["ThreatsFromFile"] = "Burada yakalanan {0} adres, kayıtlı dosyadan okundu:",
        ["DefFloodTitle"] = "Saldırılar ve bozuk paketler",
        ["DefFloodBlurb"] = "Bir oyuncunun ihtiyaç duyduğundan çok daha fazla bağlantı açan adresleri geri çevirir ve hiçbir Minecraft istemcisinin göndermediği paketleri reddeder: imkânsız koordinatlar, aşırı büyük paketler ve sohbette, kullanıcı adlarında, tabelalarda ve kitaplarda Log4j tarzı yükler.",
        ["ChkDdos"] = "Bir adresin açabileceği bağlantı sayısını sınırla",
        ["ChkInspection"] = "İçeri alınan istemcilerin gönderdiklerini incele",
        ["ChkInjection"] = "Oyuncu metinlerini zararlı yük için tara",
        ["DefBotTitle"] = "Otomatik oyuncular",
        ["DefBotBlurb"] = "İnsana benzemeyen giriş davranışlarını puanlar: sunucu listesini hiç sormadan giriş yapmak, kullanıcı adı listesini tek tek denemek, metronom gibi düzenli aralıklarla yeniden bağlanmak. Tek bir sinyal kimseyi reddetmez; birkaçının aynı anda olması gerekir.",
        ["BotLogOnly"] = "Sadece bildir (başlangıç için önerilir)",
        ["BotDeny"] = "Reddet",
        ["BotActionNote"] = "Önce birkaç gün \u201csadece bildir\u201d modunda bırakın ve Etkinlik günlüğünü izleyin. Kendi oyuncularınız yüksek puan almıyorsa \u201creddet\u201d moduna geçmek güvenlidir. Alıyorlarsa, tüm özelliği kapatmak yerine appsettings.json içinden sürekli tetiklenen sinyalin ağırlığını düşürün.",
        ["DefHoneypotTitle"] = "Tuzak portlar",
        ["DefHoneypotBlurb"] = "Hiçbir yerde duyurulmayan portları dinler. Bir oyuncunun istemcisi ona verdiğiniz porta bağlanır ve yanındakini denemek için bir sebebi yoktur; deneyen şey oynamıyor, sizi tarıyordur.",
        ["ChkHoneypot"] = "Tuzak portları dinle ve bağlananları kaydet",
        ["HoneypotPorts"] = "Portlar: {0}. Kendi sunucularınızdan birinin kullandığı port otomatik olarak atlanır. Listeyi appsettings.json içinden düzenleyin.",
        ["DefMovementTitle"] = "Hareket",
        ["DefMovementBlurb"] = "Sayı bile olmayan koordinatlar her zaman reddedilir; bunlar hile değil, çökertme girişimidir. Mümkün görünenden hızlı hareket etmek ise çok daha zayıf, ayrı bir iddiadır.",
        ["ChkMovement"] = "Hareketi izle ve olağandışı olanı bildir",
        ["ChkMovementKick"] = "Olağandışı hareket için oyuncunun bağlantısını da kes",
        ["MovementKickWarning"] = "Kendi sunucunuzdaki bildirimleri bir süre izlemeden bunu açmayın. Bu güvenlik duvarı sadece koordinatları görür; buzu, tekneleri, elytrayı, riptide üç dişli mızrağını, hız iksirini veya bir eklentinin oyuncuyu ışınlamasını göremez. Buradan bakınca hepsi hız hilesine birebir benzer. Sunucu tarafındaki bir anti-cheat eklentisi bunları ayırt edebilir; bu edemez.",
        ["DefAnomalyTitle"] = "Normalin neye benzediğini öğrenme",
        ["DefAnomalyBlurb"] = "Buradaki diğer her kontrol birinin yazdığı bir kurala uyar ve kurallar yalnızca yazarının aklına geleni yakalar. Bu ise sunucunuza gelen sıradan bağlantıların şeklini öğrenir ve uymayanları bildirir \u2014 daha önce hiç görülmemiş yöntemler dahil.",
        ["ChkAnomaly"] = "Bir temel davranış öğren ve uymayan bağlantıları bildir",
        ["AnomalyNote"] = "Bu yalnızca bildirir \u2014 kimseyi reddetmez ve bunu değiştiren bir ayar yoktur. Tespit ettiği şey \u201cdiğer bağlantılarınıza benzemiyor\u201d demektir, \u201czararlı\u201d demek değil: oyuncularının hepsi aynı saat diliminde olan bir sunucu, tuhaf bir saatte giren birini doğru ama işe yaramaz biçimde işaretler. Ayrıca bir şey söylemeden önce birkaç yüz bağlantıya ihtiyaç duyar ve kim bağlanıyorsa ondan öğrenir \u2014 bu yüzden saldırı sırasında değil, sakin bir zamanda açın.",
        ["DefRestartTitle"] = "Değişiklikleri uygulama",
        ["DefRestartBlurb"] = "Hizmet bu ayarları başlarken okur, bu yüzden buradaki bir değişiklik bir sonraki yeniden başlatmada geçerli olur.",
        ["BtnApplyRestart"] = "Hizmeti şimdi yeniden başlat",
        ["SavedNeedsRestart"] = "Kaydedildi. Uygulamak için hizmeti yeniden başlatın.",
        ["ServersTitle"] = "Korunan sunucular",
        ["ProfilesFromConfig"] = "Ayar dosyanızdan (hizmet çalışmıyor, bu yüzden burada korunacak olanlar listeleniyor):",
        ["ProfilesUnavailable"] = "Henüz sunucu tanımlanmamış. Eklemek için Sunucular sayfasını açın.",
        ["BtnManageServers"] = "Sunucuları yönet",
        ["BtnRefreshLists"] = "VPN listelerini yenile",
        ["RecentTitle"] = "Son etkinlik",
        ["QuickCheckTitle"] = "Güvenlik kontrolü",
        ["QuickCheckBlurb"] = "Gerçek Minecraft sunucunuza bu güvenlik duvarını atlayarak doğrudan erişilemediğini doğrular. Doğru yapılması gereken en önemli şey budur.",
        ["BtnRunCheck"] = "Şimdi kontrol et",

        ["ServersHeading"] = "Sunucularınız",
        ["ServersBlurb"] = "Her kayıt, bu güvenlik duvarını bir Minecraft sunucusunun önüne koyar. Oyuncular genel porta bağlanır; güvenlik duvarı onaylanan bağlantıları gerçek sunucuya iletir.",
        ["BtnAddServer"] = "Sunucu ekle",
        ["BtnRemoveServer"] = "Kaldır",
        ["BtnSaveServers"] = "Kaydet ve uygula",
        ["FieldName"] = "Ad",
        ["FieldPublicPort"] = "Genel port (oyuncular buraya bağlanır)",
        ["FieldBackendHost"] = "Gerçek sunucu adresi",
        ["FieldBackendPort"] = "Gerçek sunucu portu",
        ["FieldAllowedDomains"] = "İzin verilen alan adları (isteğe bağlı, her satıra bir tane)",
        ["FieldProtectedNames"] = "Korunan kullanıcı adları",
        ["ProtectedNamesBlurb"] = "Her satıra bir tane. Bir adı gerçek Minecraft hesabına kilitlemek için sonuna  |premium  yazın; yalnızca belirli bir adresten izin vermek için  |ip=1.2.3.4  yazın.",
        ["SaveNeedsRestart"] = "Kaydedildi. Uygulanması için servisi yeniden başlatın — Durum sayfasında Durdur, sonra Başlat.",
        ["BtnSaveAndRestart"] = "Kaydet ve servisi yeniden başlat",

        ["LeakHeading"] = "Gerçek sunucunuz dışarıya açık mı?",
        ["LeakBlurb"] = "Bu güvenlik duvarı yalnızca oyuncular Minecraft sunucunuza doğrudan ulaşamıyorsa işe yarar. Bu kontrol, sunucunun yanlışlıkla erişilebilir kalmasının bilinen yollarını arar.",
        ["LeakRunning"] = "Kontrol ediliyor…",
        ["LeakSafe"] = "Doğru görünüyor",
        ["LeakWarn"] = "Dikkat gerekiyor",
        ["LeakDanger"] = "Dışarıya açık",
        ["LeakUnknown"] = "Belirlenemedi",

        ["ChkNoServersTitle"] = "Yapılandırılmış sunucular",
        ["ChkNoServersDetail"] = "Henüz hiç sunucu yapılandırılmadı, dolayısıyla kontrol edilecek bir şey yok.",
        ["ChkNoServersFix"] = "Minecraft sunucunuzu Sunucular sayfasından ekleyin.",
        ["ChkBindingTitle"] = "Gerçek sunucunun bağlanma adresi",
        ["ChkBindingNoListener"] = "Şu anda {0} portunu dinleyen bir şey yok, bu yüzden bağlanma adresi okunamıyor.",
        ["ChkBindingNoListenerFix"] = "Minecraft sunucunuzu başlatın, sonra bu kontrolü tekrar çalıştırın.",
        ["ChkBindingWildcard"] = "Minecraft sunucunuz ({0}) {1} portunu TÜM ağ arayüzlerinde dinliyor. Bu bilgisayara ulaşabilen herkes doğrudan ona bağlanabilir ve bu güvenlik duvarının yaptığı tüm kontrolleri atlayabilir.",
        ["ChkBindingWildcardFix"] = "O sunucunun server.properties dosyasında  server-ip=127.0.0.1  yapın ve sunucuyu yeniden başlatın.",
        ["ChkBindingLoopback"] = "{0} portu yalnızca yerel geri döngüye bağlı, yani başka bir bilgisayardan erişilemez.",
        ["ChkBindingError"] = "Dinlenen bağlantı noktaları okunamadı: {0}",
        ["ChkLanTitle"] = "Ağdan erişilebilirlik",
        ["ChkLanNoAddress"] = "Yerel ağ adresi bulunamadı, bu test çalıştırılamadı.",
        ["ChkLanReachable"] = "Bu bilgisayarın kendi ağ adresi kullanılarak gerçek sunucunuza {0}:{1} üzerinden bağlanıldı. Ağınızdaki her cihaz aynısını yapabilir; yönlendiriciniz o portu yönlendiriyorsa internet de yapabilir.",
        ["ChkLanReachableFix"] = "Sunucuyu 127.0.0.1'e bağlayın ve o port için tüm port yönlendirmelerini ve güvenlik duvarı kurallarını kaldırın.",
        ["ChkLanRefused"] = "{0} portu, bu bilgisayarın ağ adresi ({1}) üzerinden gelen bağlantıyı reddetti.",
        ["ChkPublicTitle"] = "Güvenlik duvarı oyuncuları kabul ediyor",
        ["ChkPublicListening"] = "{0} portu bağlantı kabul ediyor, yani oyuncular {1} sunucusuna güvenlik duvarı üzerinden ulaşabilir.",
        ["ChkPublicClosed"] = "{0} genel portunda bağlantı kabul eden bir şey yok. Oyuncular şu anda hiç giremez.",
        ["ChkPublicClosedFix"] = "Durum sayfasından koruma servisini başlatın.",
        ["ChkRulesTitle"] = "Windows Güvenlik Duvarı kuralları",
        ["ChkRulesOffending"] = "Şu gelen kuralları, trafiğin doğrudan gerçek sunucunuzun portuna ulaşmasına izin veriyor: {0}",
        ["ChkRulesOffendingFix"] = "Bunları Windows Defender Güvenlik Duvarı'ndan kaldırın veya devre dışı bırakın — yalnızca genel portun erişilebilir olması gerekir.",
        ["ChkRulesClean"] = "Hiçbir gelen kural gerçek sunucunuzun portuna izin vermiyor. Bunun yönlendiricinizi göremediğini unutmayın — sunucu internete açıksa orayı da kontrol edin.",
        ["ChkRulesError"] = "Güvenlik duvarı kuralları okunamadı: {0}",

        ["BansHeading"] = "Şu anda engellenenler",
        ["BansBlurb"] = "Tekrarlanan başarısız girişler, tehlikeli komutlar veya VPN politikası nedeniyle engellenen IP'ler. Her birinin bir süresi vardır ve otomatik olarak kaldırılır. Yerel ağınız ve bu bilgisayar asla engellenemez.",
        ["BtnUnban"] = "Bu IP'nin engelini kaldır",
        ["BtnRefresh"] = "Yenile",
        ["UnbanPlaceholder"] = "IP adresi",
        ["UnbanNeedsIp"] = "Engelini kaldırmak istediğiniz IP adresini yazın.",

        ["LogHeading"] = "Servis günlüğü",
        ["BtnOpenLogFolder"] = "Günlük klasörünü aç",
        ["ChkFollow"] = "Yeni satırları takip et",

        ["SettingsProtectionTitle"] = "Başlangıçta koruma",
        ["SettingsProtectionBlurb"] = "Sunucunuzun korunup korunmayacağını belirleyen ayar budur. Arka plan servisi için geçerlidir ve kimse oturum açmasa da çalışır.",
        ["StartAuto"] = "Windows ile birlikte otomatik başlat  (önerilir)",
        ["StartManual"] = "Yalnızca Başlat'a bastığımda çalışsın",
        ["SettingsWindowTitle"] = "Bu pencere",
        ["SettingsWindowBlurb"] = "Yalnızca kolaylık içindir — sunucunuzun korunmasını etkilemez.",
        ["ChkLoginStartup"] = "Oturum açtığımda bu kontrol panelini aç",
        ["ChkStartMinimised"] = "Bildirim alanına küçültülmüş olarak başlat",
        ["ChkCloseToTray"] = "Bu pencereyi kapatmak onu bildirim alanında tutar",
        ["SettingsLanguageTitle"] = "Dil",
        ["SettingsPremiumTitle"] = "Otomatik premium kilidi",
        ["SettingsPremiumBlurb"] = "Biri gerçek bir Minecraft hesabıyla katıldığında, o kullanıcı adını kalıcı olarak ona ayırır. Doğrulanamayan adlar asla işaretlenmez — orijinal olmayan bir oyuncu her zamanki gibi girer ve gerçek sahibi daha sonra bir kez bağlanarak adı yine sahiplenebilir.",
        ["ChkAutoPremium"] = "Doğrulanmış hesaplar için kullanıcı adlarını otomatik sahiplen",
        ["AutoPremiumWarning"] = "Test etmediyseniz bunu kapalı bırakın. Her yeni oyuncunun istemcisinden kendini doğrulamasını ister; bazı orijinal olmayan başlatıcılar bunu iyi karşılamaz ve bağlanamayabilir.",
        ["SettingsFilesTitle"] = "Dosyalar",
        ["BtnOpenConfig"] = "Yapılandırma dosyasını aç",
        ["ConfigRestartNote"] = "Yapılandırma dosyasındaki değişiklikler servis yeniden başlatıldığında geçerli olur.",

        ["TrayOpen"] = "MinecraftFirewall'ı aç",
        ["TrayStart"] = "Korumayı başlat",
        ["TrayStop"] = "Korumayı durdur",
        ["TrayExit"] = "Kontrol panelinden çık",
        ["TrayStillRunning"] = "Burada çalışmaya devam ediyor. Sunucunuz her durumda korunur — arka plan servisi bu pencereden bağımsızdır.",
        ["ConfirmStopTitle"] = "Koruma durdurulsun mu?",
        ["ConfirmStopBody"] = "Tekrar başlatana kadar Minecraft sunucunuz bu uygulamanın hiçbir kontrolü olmadan bağlantı kabul edecek.",
        ["ConfirmRemoveTitle"] = "Arka plan servisi kaldırılsın mı?",
        ["ConfirmRemoveBody"] = "Sunucunuz artık korunmayacak, yeniden başlatmadan sonra da. Yapılandırma dosyanız ve ayarlarınız korunur.",
    };
}

/// <summary>
/// XAML shorthand: <c>Text="{loc:T NavStatus}"</c>.
///
/// Returns a real binding rather than a plain string, which is what lets every label on screen
/// re-render the instant the language changes instead of needing the window rebuilt.
/// </summary>
public sealed class TExtension : MarkupExtension
{
    public TExtension() { }
    public TExtension(string key) => Key = key;

    public string Key { get; set; } = "";

    public override object ProvideValue(IServiceProvider serviceProvider) =>
        new Binding($"[{Key}]")
        {
            Source = Strings.Current,
            Mode = BindingMode.OneWay,
        }.ProvideValue(serviceProvider);
}
