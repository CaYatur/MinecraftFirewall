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
