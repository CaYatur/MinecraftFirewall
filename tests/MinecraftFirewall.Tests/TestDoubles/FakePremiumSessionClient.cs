using MinecraftFirewall.Proxy.Identity.Premium;

namespace MinecraftFirewall.Tests.TestDoubles;

/// <summary>In-memory stand-in for MojangSessionClient so PremiumVerifier tests never make a real
/// HTTP call. Defaults to NotJoined (fail-closed default) unless a result was explicitly set.</summary>
public sealed class FakePremiumSessionClient : IPremiumSessionClient
{
    private HasJoinedResult _result = HasJoinedResult.NotJoined;
    public int CallCount { get; private set; }
    public string? LastUsername { get; private set; }
    public string? LastServerIdHash { get; private set; }

    public void SetResult(HasJoinedResult result) => _result = result;

    public void SucceedWith(Guid uuid, string name) => _result = new HasJoinedResult(true, uuid, name);

    public Task<HasJoinedResult> HasJoinedAsync(string username, string serverIdHash, CancellationToken ct)
    {
        CallCount++;
        LastUsername = username;
        LastServerIdHash = serverIdHash;
        return Task.FromResult(_result);
    }
}
