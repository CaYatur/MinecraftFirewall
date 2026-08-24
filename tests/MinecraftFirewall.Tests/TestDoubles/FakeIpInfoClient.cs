using System.Collections.Concurrent;
using System.Net;
using MinecraftFirewall.Proxy.IpIntel;

namespace MinecraftFirewall.Tests.TestDoubles;

/// <summary>In-memory stand-in for IpInfoClient so tests never make a real HTTP call. Returns
/// NoSignal for any address that wasn't explicitly configured to flag as hosting-like.</summary>
public sealed class FakeIpInfoClient : IIpInfoClient
{
    private readonly ConcurrentDictionary<IPAddress, IpInfoLookupResult> _results = new();
    public int CallCount { get; private set; }

    public void SetResult(IPAddress address, IpInfoLookupResult result) => _results[address] = result;

    public void FlagAsHosting(IPAddress address, string asName = "Example Hosting LLC") =>
        SetResult(address, new IpInfoLookupResult(true, asName, "AS0"));

    public Task<IpInfoLookupResult> LookupAsync(IPAddress address, CancellationToken ct)
    {
        CallCount++;
        return Task.FromResult(_results.TryGetValue(address, out var result) ? result : IpInfoLookupResult.NoSignal);
    }
}
