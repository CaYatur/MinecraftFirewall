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
        VpnPolicy = source.VpnPolicy;
        UseDatacenterList = source.UseDatacenterList;
        IpForwarding = source.IpForwarding;
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
    public string VpnPolicy { get; set; }
    public bool UseDatacenterList { get; set; }
    public string IpForwarding { get; set; }

    /// <summary>Index into the UI's three-item list, in the order the ComboBox declares them. A value
    /// the app does not recognise selects nothing rather than silently becoming the first option,
    /// which would change the policy behind the user's back.</summary>
    public int VpnPolicyIndex
    {
        get => VpnPolicy switch { "LogOnly" => 0, "BlockForProtectedUsernamesOnly" => 1, "BlockForEveryone" => 2, _ => -1 };
        set => VpnPolicy = value switch { 0 => "LogOnly", 2 => "BlockForEveryone", _ => "BlockForProtectedUsernamesOnly" };
    }

    /// <summary>Index into the forwarding ComboBox. Same rule as the VPN one above: a value this
    /// build does not recognise selects nothing rather than quietly becoming the first option, which
    /// here would mean turning forwarding off and putting every player back on 127.0.0.1.</summary>
    public int IpForwardingIndex
    {
        get => IpForwarding switch { "None" => 0, "ProxyProtocol" => 1, "BungeeCord" => 2, _ => -1 };
        set => IpForwarding = value switch { 1 => "ProxyProtocol", 2 => "BungeeCord", _ => "None" };
    }

    public ServerProfileEdit ToEdit() => new()
    {
        Name = Name.Trim(),
        PublicPort = PublicPort,
        BackendHost = BackendHost.Trim(),
        BackendPort = BackendPort,
        AllowedHostnames = [.. SplitLines(AllowedHostnamesText)],
        VpnPolicy = VpnPolicy,
        UseDatacenterList = UseDatacenterList,
        IpForwarding = IpForwarding,
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

/// <summary>
/// One player as the Players grid shows them.
///
/// Every field is already formatted for display. The grid binds directly to these, and pushing the
/// formatting down here keeps "what a null last-seen looks like" in one place rather than spread
/// across six column templates.
/// </summary>
public sealed class PlayerRow
{
    public required string Username { get; init; }
    public required string Status { get; init; }
    public required string Registered { get; init; }
    public required string LastSeen { get; init; }
    public required string LastAddress { get; init; }
    public required int Risk { get; init; }

    /// <summary>Blank rather than "0" when there is nothing against them. A zero in a risk column
    /// reads as a measurement; blank reads as "nothing to say", which is what it means.</summary>
    public string RiskLabel => Risk > 0 ? Risk.ToString() : "";

    public static string When(DateTimeOffset? value) =>
        value is { } at ? at.ToLocalTime().ToString("yyyy-MM-dd HH:mm") : "\u2014";
}
