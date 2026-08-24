using System.Net;

namespace MinecraftFirewall.Proxy.IpIntel;

public sealed record IpInfoLookupResult(bool LooksLikeHostingProvider, string? AsName, string? Asn)
{
    public static readonly IpInfoLookupResult NoSignal = new(false, null, null);
}

/// <summary>Extracted purely so PolicyEngine's tests never make a real HTTP call — see FakeIpInfoClient.</summary>
public interface IIpInfoClient
{
    Task<IpInfoLookupResult> LookupAsync(IPAddress address, CancellationToken ct);
}
