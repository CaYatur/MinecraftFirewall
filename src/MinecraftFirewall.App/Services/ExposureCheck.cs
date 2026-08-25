using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace MinecraftFirewall.App.Services;

public enum CheckVerdict
{
    Safe,
    Warning,
    Danger,
    Unknown,
}

/// <summary>
/// A finding, carried as localization keys plus their arguments rather than finished sentences, so
/// the same result renders in whichever language the window is set to. Resolving it to text is the
/// view's job (see CheckRow) — this class never formats a user-facing string itself.
/// </summary>
public sealed record CheckResult(
    string TitleKey,
    CheckVerdict Verdict,
    string DetailKey,
    object[]? DetailArgs = null,
    string? FixKey = null);

/// <summary>
/// Looks for the mistake that makes this entire product pointless: the real Minecraft server still
/// being reachable directly, so players can simply bypass the firewall by using the backend port.
///
/// The honest limitation, stated in the results themselves rather than buried: nothing here can prove
/// what the *internet* can reach, because that requires something outside this machine to try. What it
/// can prove is the failure that actually happens in practice — the server bound to all interfaces
/// rather than loopback, which makes it reachable from every other machine on the network and from
/// the internet the moment a router forwards the port. That is checked by genuinely connecting to it
/// over this machine's LAN address, not by reading configuration and assuming.
/// </summary>
public sealed class ExposureCheck
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(2);

    public async Task<List<CheckResult>> RunAsync(IReadOnlyList<ServerProfileEdit> profiles)
    {
        var results = new List<CheckResult>();

        if (profiles.Count == 0)
        {
            results.Add(new CheckResult("ChkNoServersTitle", CheckVerdict.Warning, "ChkNoServersDetail", null, "ChkNoServersFix"));
            return results;
        }

        IPAddress[] localAddresses = LocalNetworkAddresses();

        foreach (ServerProfileEdit profile in profiles)
        {
            results.Add(CheckBackendIsLoopback(profile));
            results.Add(await CheckBackendReachableOverLanAsync(profile, localAddresses).ConfigureAwait(false));
            results.Add(await CheckPublicPortIsListeningAsync(profile).ConfigureAwait(false));
        }

        results.Add(CheckBackendPortFirewallRules(profiles));

        // Not an exposure question, but the same page is where somebody looks to understand their own
        // setup, and what this finds changes what the rest of the firewall can do for them.
        foreach (ServerProfileEdit profile in profiles)
            results.Add(DescribeBackendServer(profile));

        return results;
    }

    /// <summary>
    /// Works out what the server behind the proxy is, and says what that means for the login system.
    ///
    /// The version matters because reading chat needs that version's packet IDs, and ViaVersion
    /// matters because it lets far older clients join — clients whose chat this proxy cannot read.
    /// Both are knowable from the server's own files, and neither is something an admin would think to
    /// mention, so the panel finds out rather than asking.
    /// </summary>
    private static CheckResult DescribeBackendServer(ServerProfileEdit profile)
    {
        const string title = "ChkBackendTitle";

        BackendServerInfo info = new BackendServerInspector().Inspect(profile.BackendPort);

        if (info.Directory is null)
            return new CheckResult(title, CheckVerdict.Unknown, "ChkBackendUnknown", [profile.BackendPort]);

        string version = info.ServerVersion ?? "?";

        if (info.HasViaVersion || info.HasViaBackwards)
        {
            return new CheckResult(title, CheckVerdict.Warning, "ChkBackendVia",
                [version, info.HasViaBackwards ? "ViaVersion + ViaBackwards" : "ViaVersion"],
                "ChkBackendViaFix");
        }

        return new CheckResult(title, CheckVerdict.Safe, "ChkBackendPlain", [version, info.Plugins.Count]);
    }

    /// <summary>Reads what the backend port is actually bound to. Bound to 127.0.0.1 means only this
    /// machine can reach it; bound to 0.0.0.0 means every interface, which is the default in a fresh
    /// server.properties and the single most common way people leave themselves exposed.</summary>
    private static CheckResult CheckBackendIsLoopback(ServerProfileEdit profile)
    {
        const string title = "ChkBindingTitle";

        try
        {
            IPEndPoint[] listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
            IPEndPoint[] onBackendPort = [.. listeners.Where(l => l.Port == profile.BackendPort)];

            if (onBackendPort.Length == 0)
            {
                return new CheckResult(title, CheckVerdict.Unknown, "ChkBindingNoListener",
                    [profile.BackendPort], "ChkBindingNoListenerFix");
            }

            bool anyWildcard = onBackendPort.Any(l => l.Address.Equals(IPAddress.Any) || l.Address.Equals(IPAddress.IPv6Any));
            if (anyWildcard)
            {
                return new CheckResult(title, CheckVerdict.Danger, "ChkBindingWildcard",
                    [profile.Name, profile.BackendPort], "ChkBindingWildcardFix");
            }

            return new CheckResult(title, CheckVerdict.Safe, "ChkBindingLoopback", [profile.BackendPort]);
        }
        catch (Exception ex)
        {
            return new CheckResult(title, CheckVerdict.Unknown, "ChkBindingError", [ex.Message]);
        }
    }

    /// <summary>The empirical half: actually try to open the backend port using this machine's own LAN
    /// address. If that connects, every other device on the network can do exactly the same.</summary>
    private async Task<CheckResult> CheckBackendReachableOverLanAsync(ServerProfileEdit profile, IPAddress[] localAddresses)
    {
        const string title = "ChkLanTitle";

        if (localAddresses.Length == 0)
        {
            return new CheckResult(title, CheckVerdict.Unknown, "ChkLanNoAddress");
        }

        foreach (IPAddress address in localAddresses)
        {
            if (await CanConnectAsync(address, profile.BackendPort).ConfigureAwait(false))
            {
                return new CheckResult(title, CheckVerdict.Danger, "ChkLanReachable",
                    [address.ToString(), profile.BackendPort], "ChkLanReachableFix");
            }
        }

        return new CheckResult(title, CheckVerdict.Safe, "ChkLanRefused",
            [profile.BackendPort, string.Join(", ", localAddresses.Select(a => a.ToString()))]);
    }

    private async Task<CheckResult> CheckPublicPortIsListeningAsync(ServerProfileEdit profile)
    {
        const string title = "ChkPublicTitle";

        bool listening = await CanConnectAsync(IPAddress.Loopback, profile.PublicPort).ConfigureAwait(false);
        return listening
            ? new CheckResult(title, CheckVerdict.Safe, "ChkPublicListening", [profile.PublicPort, profile.Name])
            : new CheckResult(title, CheckVerdict.Warning, "ChkPublicClosed", [profile.PublicPort], "ChkPublicClosedFix");
    }

    /// <summary>Windows Firewall rules are only advisory here: a rule allowing the backend port is a
    /// strong smell, but its absence proves nothing, since the port may be exposed by a router
    /// port-forward this machine can't see.</summary>
    private static CheckResult CheckBackendPortFirewallRules(IReadOnlyList<ServerProfileEdit> profiles)
    {
        const string title = "ChkRulesTitle";

        try
        {
            var ports = profiles.Select(p => p.BackendPort).ToHashSet();
            var offending = new List<string>();

            foreach (var rule in WindowsFirewallHelper.FirewallManager.Instance.Rules)
            {
                if (rule.Direction != WindowsFirewallHelper.FirewallDirection.Inbound ||
                    rule.Action != WindowsFirewallHelper.FirewallAction.Allow ||
                    !rule.IsEnable)
                {
                    continue;
                }

                if (rule.LocalPorts is { Length: > 0 } localPorts && localPorts.Any(p => ports.Contains(p)))
                    offending.Add(rule.Name);
            }

            if (offending.Count > 0)
            {
                return new CheckResult(title, CheckVerdict.Warning, "ChkRulesOffending",
                    [string.Join(", ", offending.Take(5))], "ChkRulesOffendingFix");
            }

            return new CheckResult(title, CheckVerdict.Safe, "ChkRulesClean");
        }
        catch (Exception ex)
        {
            return new CheckResult(title, CheckVerdict.Unknown, "ChkRulesError", [ex.Message]);
        }
    }

    private static async Task<bool> CanConnectAsync(IPAddress address, int port)
    {
        try
        {
            using var client = new TcpClient(address.AddressFamily);
            using var cts = new CancellationTokenSource(ConnectTimeout);
            await client.ConnectAsync(address, port, cts.Token).ConfigureAwait(false);
            return client.Connected;
        }
        catch
        {
            return false;
        }
    }

    private static IPAddress[] LocalNetworkAddresses() =>
    [
        .. NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up
                     && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses)
            .Select(a => a.Address)
            .Where(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a))
            .Distinct()
    ];
}
