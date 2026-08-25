using System.Windows;
using System.Windows.Media;
using MinecraftFirewall.App.Localization;
using MinecraftFirewall.App.Services;

namespace MinecraftFirewall.App;

/// <summary>
/// A server profile as the editor binds to it. Wraps <see cref="ServerProfileEdit"/> rather than
/// binding it directly, because the two list fields are edited as free text (one entry per line) —
/// which is far friendlier for a non-technical user than a nested grid of rows to add and delete.
/// </summary>
public sealed class ServerRow
{
    public ServerRow(ServerProfileEdit source)
    {
        Name = source.Name;
        PublicPort = source.PublicPort;
        BackendHost = source.BackendHost;
        BackendPort = source.BackendPort;
        AllowedHostnamesText = string.Join(Environment.NewLine, source.AllowedHostnames);
        ProtectedNamesText = string.Join(Environment.NewLine, source.ProtectedUsernames.Select(p => p.ToString()));
    }

    // No INotifyPropertyChanged on purpose: the editor only ever reads these back out of the controls
    // (view -> model), and the whole list is rebuilt from disk on load, so there is nothing for a
    // change notification to update.
    public string Name { get; set; }
    public int PublicPort { get; set; }
    public string BackendHost { get; set; }
    public int BackendPort { get; set; }
    public string AllowedHostnamesText { get; set; }
    public string ProtectedNamesText { get; set; }

    public ServerProfileEdit ToEdit() => new()
    {
        Name = Name.Trim(),
        PublicPort = PublicPort,
        BackendHost = BackendHost.Trim(),
        BackendPort = BackendPort,
        AllowedHostnames = [.. SplitLines(AllowedHostnamesText)],
        ProtectedUsernames = [.. SplitLines(ProtectedNamesText).Select(ProtectedNameEdit.Parse).OfType<ProtectedNameEdit>()],
    };

    private static IEnumerable<string> SplitLines(string text) =>
        text.Split(['\r', '\n'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
}

/// <summary>One security-check finding, with its colour and label resolved for binding.</summary>
public sealed class CheckRow(CheckResult result)
{
    // Resolved once, at construction: the list is rebuilt from scratch on every run and on a language
    // change, so there is nothing to gain from re-resolving on each binding read.
    public string Title => Strings.Current[result.TitleKey];

    public string Detail => result.DetailArgs is { Length: > 0 } args
        ? Strings.Current.Format(result.DetailKey, args)
        : Strings.Current[result.DetailKey];

    public string? Fix => result.FixKey is null ? null : Strings.Current[result.FixKey];

    public Visibility FixVisibility => result.FixKey is null ? Visibility.Collapsed : Visibility.Visible;

    public Brush VerdictBrush => result.Verdict switch
    {
        CheckVerdict.Safe => new SolidColorBrush(Color.FromRgb(0x3F, 0xBF, 0x6A)),
        CheckVerdict.Warning => new SolidColorBrush(Color.FromRgb(0xE0, 0xA0, 0x30)),
        CheckVerdict.Danger => new SolidColorBrush(Color.FromRgb(0xE1, 0x1D, 0x2A)),
        _ => new SolidColorBrush(Color.FromRgb(0x9A, 0x92, 0x9C)),
    };

    public string VerdictLabel => Strings.Current[result.Verdict switch
    {
        CheckVerdict.Safe => "LeakSafe",
        CheckVerdict.Warning => "LeakWarn",
        CheckVerdict.Danger => "LeakDanger",
        _ => "LeakUnknown",
    }];

    public CheckVerdict Verdict => result.Verdict;
}
