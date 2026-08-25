using Microsoft.Win32;

namespace MinecraftFirewall.App.Services;

/// <summary>
/// The control panel's own preferences — language and the auto-premium toggle's UI state.
///
/// Kept in HKCU rather than beside the executable: the app lives in Program Files after install,
/// which is not writable without another elevation dance, and these are per-user choices anyway.
/// </summary>
public static class AppPreferences
{
    private const string KeyPath = @"Software\MinecraftFirewall";

    public static string Language
    {
        get => Read("Language") ?? "en";
        set => Write("Language", value);
    }

    private static string? Read(string name)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(KeyPath);
            return key?.GetValue(name) as string;
        }
        catch
        {
            return null;
        }
    }

    private static void Write(string name, string value)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(KeyPath);
            key?.SetValue(name, value, RegistryValueKind.String);
        }
        catch
        {
            // A preference that can't be saved is not worth interrupting the user over; it simply
            // reverts to the default next launch.
        }
    }
}
