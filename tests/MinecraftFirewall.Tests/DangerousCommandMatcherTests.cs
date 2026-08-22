using MinecraftFirewall.Proxy.Policy;

namespace MinecraftFirewall.Tests;

public class DangerousCommandMatcherTests
{
    private static readonly string[] Dangerous = ["op", "ban", "stop", "whitelist"];

    [Theory]
    [InlineData("op Attacker")]
    [InlineData("OP Attacker")]
    [InlineData("/op Attacker")]
    [InlineData("minecraft:op Attacker")]
    [InlineData("MINECRAFT:OP Attacker")]
    [InlineData("op")]
    public void IsMatch_RecognizesVariants(string commandText)
    {
        Assert.True(DangerousCommandMatcher.IsMatch(commandText, Dangerous));
    }

    [Theory]
    [InlineData("gamemode creative")]
    [InlineData("tpa SomePlayer")]
    [InlineData("spawn")]
    [InlineData("helpop")] // must not fuzzy-match "op" as a substring of a different command
    public void IsMatch_DoesNotMatchUnrelatedCommands(string commandText)
    {
        Assert.False(DangerousCommandMatcher.IsMatch(commandText, Dangerous));
    }

    [Theory]
    [InlineData("op Attacker", "op")]
    [InlineData("/minecraft:BAN Attacker forever", "ban")]
    [InlineData("stop", "stop")]
    public void ExtractBaseCommand_NormalizesCorrectly(string commandText, string expected)
    {
        Assert.Equal(expected, DangerousCommandMatcher.ExtractBaseCommand(commandText));
    }
}
