using MinecraftFirewall.Proxy.Identity.Premium;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Tests.TestDoubles;

/// <summary>Builds a real PremiumLoginHandshake with only the Mojang HTTP call swapped out, so tests
/// exercise the genuine RSA/session-hash/pin logic rather than a stand-in for it.</summary>
public static class PremiumTestFactory
{
    public static PremiumLoginHandshake CreateHandshake(
        RsaServerKeyPair keyPair,
        IPremiumSessionClient? sessionClient = null,
        PremiumOptions? options = null) =>
        new(keyPair,
            new PremiumVerifier(sessionClient ?? new FakePremiumSessionClient(), NullLogger<PremiumVerifier>.Instance),
            Options.Create(options ?? new PremiumOptions()),
            NullLogger<PremiumLoginHandshake>.Instance);
}
