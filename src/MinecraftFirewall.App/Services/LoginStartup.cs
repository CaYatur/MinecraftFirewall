using Microsoft.Win32;

namespace MinecraftFirewall.App.Services;

/// <summary>
/// Controls whether this console reopens when the user logs in.
///
/// Worth being precise about, because users conflate it with protection: this only decides whether
/// the *window* comes back. The proxy runs as a Windows service and starts with the machine
/// regardless — see <see cref="WindowsServiceControl.SetStartModeAsync"/> for the setting that
/// actually governs that. The UI labels them distinctly for the same reason.
///
/// HKCU rather than HKLM deliberately: this is a per-user preference, and writing a machine-wide Run
/// entry would launch an elevated window in every account on the box.
/// </summary>
public static class LoginStartup
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "MinecraftFirewall";

    public static bool IsEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: false);
            return key?.GetValue(ValueName) is string value && !string.IsNullOrWhiteSpace(value);
        }
        catch
        {
            return false;
        }
    }

    public static (bool Success, string Message) SetEnabled(bool enabled, bool startMinimised)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true)
                ?? Registry.CurrentUser.CreateSubKey(RunKeyPath);

            if (!enabled)
            {
                key.DeleteValue(ValueName, throwOnMissingValue: false);
                return (true, "Will no longer open at login.");
            }

            string exePath = Environment.ProcessPath ?? throw new InvalidOperationException("Could not determine this application's path.");
            string command = startMinimised ? $"\"{exePath}\" --tray" : $"\"{exePath}\"";
            key.SetValue(ValueName, command, RegistryValueKind.String);

            return (true, startMinimised ? "Will start minimised to the tray at login." : "Will open at login.");
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }
}
