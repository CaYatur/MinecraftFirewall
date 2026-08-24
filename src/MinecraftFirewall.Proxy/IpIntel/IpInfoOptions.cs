namespace MinecraftFirewall.Proxy.IpIntel;

/// <summary>
/// Secondary, real-time VPN/hosting-provider signal via ipinfo.io — deliberately a different
/// provider and mechanism than the primary X4BNet CIDR lists (VpnIntelligence/IpListRefreshService),
/// which are periodic and disk-cached rather than queried per connection.
///
/// IMPORTANT — verified empirically (a live unauthenticated request to
/// https://api.ipinfo.io/lite/{ip} returns HTTP 403 "Unknown token"): ipinfo's free Lite tier still
/// requires a free account token, it is not keyless. Sign up at https://ipinfo.io/signup (no credit
/// card) and paste the token below. Leave it empty (default) to disable this signal entirely — the
/// primary X4BNet lists keep working either way, this is additive.
///
/// ALSO IMPORTANT: the Lite API returns ASN + organization/domain name, not a dedicated "is this a
/// VPN" flag — that flag is a separate paid ipinfo product. What this class does is match the
/// returned org/domain name against a configurable keyword list, which is a heuristic (false
/// positives and false negatives both possible), not a certainty — treated exactly like the X4BNet
/// datacenter list is already treated in this app: a signal that feeds the same VpnPolicy decision,
/// not a hard fact.
/// </summary>
public sealed class IpInfoOptions
{
    public const string SectionName = "IpInfo";

    /// <summary>Empty (default) disables this check entirely — no outbound requests are made.</summary>
    public string Token { get; set; } = "";

    /// <summary>When false (default), only connections for a protected/identity-gated username pay
    /// the real-time lookup cost. When true, every login attempt is checked (subject to the cache).</summary>
    public bool ApplyToAllConnections { get; set; }

    /// <summary>Case-insensitive substrings matched against the returned as_name/as_domain fields —
    /// a hit means "looks like a hosting/VPN provider," see the class-level heuristic note.</summary>
    public List<string> HostingKeywords { get; set; } =
    [
        "hosting", "vpn", "proxy", "cloud", "datacenter", "data center", "server",
        "digitalocean", "amazon", "aws", "google cloud", "azure", "ovh", "hetzner",
        "linode", "vultr", "leaseweb", "m247", "choopa", "contabo",
    ];

    /// <summary>Per-IP result cache — without this, a login flood becomes an outbound-request flood
    /// against ipinfo's rate limit.</summary>
    public TimeSpan CacheTtl { get; set; } = TimeSpan.FromHours(6);

    public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(3);
}
