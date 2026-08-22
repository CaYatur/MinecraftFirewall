using System.Net;
using MinecraftFirewall.Proxy.Identity;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Enforcement;

public sealed class NeverBanOptions
{
    public const string SectionName = "NeverBan";

    /// <summary>Extra CIDR ranges/IPs the admin never wants auto-banned, beyond loopback and RFC1918.</summary>
    public List<string> ExtraAllowlist { get; set; } = [];
}

/// <summary>
/// Hardcoded protection for loopback, RFC1918 private ranges, and an admin-configured allowlist —
/// checked before every ban call so rate-limiting/heuristics can never lock out the LAN, the
/// machine itself, or addresses the admin explicitly trusts.
/// </summary>
public sealed class NeverBanList
{
    private static readonly CidrRange[] BuiltIn =
    [
        CidrRange.Parse("127.0.0.0/8"),
        CidrRange.Parse("::1/128"),
        CidrRange.Parse("10.0.0.0/8"),
        CidrRange.Parse("172.16.0.0/12"),
        CidrRange.Parse("192.168.0.0/16"),
    ];

    private readonly List<CidrRange> _extra;

    public NeverBanList(IOptions<NeverBanOptions> options)
    {
        _extra = options.Value.ExtraAllowlist.Select(CidrRange.Parse).ToList();
    }

    public bool IsProtected(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
            return true;

        foreach (var range in BuiltIn)
        {
            if (range.Contains(address))
                return true;
        }

        foreach (var range in _extra)
        {
            if (range.Contains(address))
                return true;
        }

        return false;
    }
}
