; Inno Setup script for MinecraftFirewall.
;
; Build it with installer/build.ps1 rather than compiling this directly — the script publishes the
; three executables into publish\app first, which is where every [Files] entry below reads from.

#define AppName        "MinecraftFirewall"
; Guarded so build.ps1 can override it with /DAppVersion=... ; an unguarded #define would silently
; win over the command line and stamp the wrong version on the installer.
#ifndef AppVersion
  #define AppVersion   "1.3.0"
#endif
#define AppPublisher   "CaYaDev"
#define AppUrl         "https://github.com/CaYatur/MinecraftFirewall"
#define AppExe         "MinecraftFirewall.exe"
#define ServiceName    "MinecraftFirewall"
#define FirewallRule   "MinecraftFirewall (proxy)"
#define SourceDir      "..\publish\app"

[Setup]
AppId={{7F2B9C31-4E6A-4C58-9E1D-2B7A5F0D9C44}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}/issues
AppUpdatesURL={#AppUrl}/releases
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\publish
OutputBaseFilename=MinecraftFirewall-{#AppVersion}-setup
SetupIconFile=..\src\MinecraftFirewall.App\Assets\app.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Everything this installs needs elevation: a Windows service, a machine-wide firewall rule, and
; files under Program Files. Asking once, up front, beats failing halfway through.
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 10 1809 — the floor for the .NET 10 runtime bundled in the self-contained build.
MinVersion=10.0.17763

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "tr"; MessagesFile: "compiler:Languages\Turkish.isl"

[CustomMessages]
en.TaskDesktop=Create a desktop shortcut
en.TaskFirewall=Allow MinecraftFirewall through Windows Firewall (players cannot connect without this)
en.StatusService=Registering the Windows service...
en.StatusFirewall=Adding the Windows Firewall rule...
en.LaunchApp=Open the {#AppName} control panel
tr.TaskDesktop=Masaüstü kısayolu oluştur
tr.TaskFirewall=MinecraftFirewall'a Windows Güvenlik Duvarı izni ver (bu olmadan oyuncular bağlanamaz)
tr.StatusService=Windows hizmeti kaydediliyor...
tr.StatusFirewall=Windows Güvenlik Duvarı kuralı ekleniyor...
tr.LaunchApp={#AppName} kontrol panelini aç

[Tasks]
Name: "desktopicon"; Description: "{cm:TaskDesktop}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "firewallrule"; Description: "{cm:TaskFirewall}"

[Files]
; The user's own configuration. Never overwritten on upgrade and never removed on uninstall — it
; holds their server list, protected usernames and webhook, none of which this installer can
; regenerate. A pristine copy ships alongside it under a different name to compare against.
Source: "{#SourceDir}\appsettings.json"; DestDir: "{app}"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "{#SourceDir}\appsettings.json"; DestDir: "{app}"; DestName: "appsettings.default.json"; Flags: ignoreversion
Source: "{#SourceDir}\*"; DestDir: "{app}"; Excludes: "appsettings.json,appsettings.Development.json,*.pdb,*.xml"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
; Created up front so the service has somewhere to write from its very first start, rather than
; depending on it being able to create directories under ProgramData itself.
Name: "{commonappdata}\{#AppName}"
Name: "{commonappdata}\{#AppName}\logs"
Name: "{commonappdata}\{#AppName}\cache"

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Parameters: "--install-service"; StatusMsg: "{cm:StatusService}"; Flags: runhidden waituntilterminated
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""{#FirewallRule}"" dir=in action=allow program=""{app}\MinecraftFirewall.Proxy.exe"" enable=yes profile=any"; StatusMsg: "{cm:StatusFirewall}"; Flags: runhidden waituntilterminated; Tasks: firewallrule
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchApp}"; Flags: postinstall nowait skipifsilent

[UninstallRun]
; Ordered before the files are deleted, and RunOnceId keeps them from repeating if an uninstall is
; retried after a failure.
Filename: "{app}\{#AppExe}"; Parameters: "--uninstall-service"; RunOnceId: "RemoveService"; Flags: runhidden waituntilterminated
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#FirewallRule}"""; RunOnceId: "RemoveFirewallRule"; Flags: runhidden waituntilterminated

[Code]
// Files under the install directory cannot be replaced while the service or the tray app still holds
// them open, and an upgrade is by far the most common time both are running. Stopping them here turns
// a "file in use, retry?" dialog most people would cancel out of into an unremarkable upgrade.
procedure StopRunningComponents();
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}	askkill.exe'), '/IM {#AppExe} /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  // sc stop returns as soon as the stop is accepted, not once the process has exited and released its
  // file handles.
  Sleep(1500);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopRunningComponents();
  Result := '';
end;

function InitializeUninstall(): Boolean;
begin
  StopRunningComponents();
  Result := True;
end;
