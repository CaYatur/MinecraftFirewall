using MinecraftFirewall.Proxy.Identity;
using Xunit;

namespace MinecraftFirewall.Tests;

public class IdentityEntryPinnedUuidTests
{
    [Fact]
    public void TryClaimOrMatchPinnedUuid_FirstCall_ClaimsThePin()
    {
        var entry = new IdentityEntry { Username = "Admin", PremiumRequired = true };
        var uuid = Guid.NewGuid();

        bool claimed = entry.TryClaimOrMatchPinnedUuid(uuid);

        Assert.True(claimed);
        Assert.Equal(uuid, entry.PinnedUuid);
    }

    [Fact]
    public void TryClaimOrMatchPinnedUuid_SameAccountAgain_Matches()
    {
        var entry = new IdentityEntry { Username = "Admin", PremiumRequired = true };
        var uuid = Guid.NewGuid();
        entry.TryClaimOrMatchPinnedUuid(uuid);

        Assert.True(entry.TryClaimOrMatchPinnedUuid(uuid));
        Assert.Equal(uuid, entry.PinnedUuid);
    }

    [Fact]
    public void TryClaimOrMatchPinnedUuid_DifferentAccount_IsRejectedAndLeavesThePinIntact()
    {
        var entry = new IdentityEntry { Username = "Admin", PremiumRequired = true };
        var owner = Guid.NewGuid();
        var impostor = Guid.NewGuid();
        entry.TryClaimOrMatchPinnedUuid(owner);

        Assert.False(entry.TryClaimOrMatchPinnedUuid(impostor));
        Assert.Equal(owner, entry.PinnedUuid); // the real owner keeps the name
    }

    [Fact]
    public async Task TryClaimOrMatchPinnedUuid_ConcurrentFirstClaims_ExactlyOneWins()
    {
        // The race the method exists to close: with a read-then-write from caller code, two
        // simultaneous connections could both observe a null pin and both write, letting the second
        // silently take a name the first had just claimed.
        for (int attempt = 0; attempt < 200; attempt++)
        {
            var entry = new IdentityEntry { Username = "Admin", PremiumRequired = true };
            var first = Guid.NewGuid();
            var second = Guid.NewGuid();

            bool[] results = new bool[2];
            using var barrier = new Barrier(2);

            var t1 = Task.Run(() => { barrier.SignalAndWait(); results[0] = entry.TryClaimOrMatchPinnedUuid(first); });
            var t2 = Task.Run(() => { barrier.SignalAndWait(); results[1] = entry.TryClaimOrMatchPinnedUuid(second); });
            await Task.WhenAll(t1, t2);

            Assert.Single(results, r => r); // exactly one claim succeeded
            Assert.Equal(results[0] ? first : second, entry.PinnedUuid);
        }
    }
}
