namespace MinecraftFirewall.Proxy.IpIntel;

public sealed class VpnIntelOptions
{
    public const string SectionName = "VpnIntel";

    // MIT licensed, GitHub-Actions-updated — see the plan's Stage 1 source verification note.
    public string VpnListUrl { get; set; } = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt";
    public string DatacenterListUrl { get; set; } = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt";

    public string CacheDirectory { get; set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MinecraftFirewall", "cache");

    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromHours(24);
    public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(30);
}
