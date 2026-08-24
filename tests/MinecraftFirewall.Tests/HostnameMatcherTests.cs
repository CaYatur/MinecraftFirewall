using MinecraftFirewall.Proxy.Policy;

namespace MinecraftFirewall.Tests;

public class HostnameMatcherTests
{
    [Fact]
    public void IsAllowed_EmptyAllowlist_AllowsAnyHostname()
    {
        Assert.True(HostnameMatcher.IsAllowed("anything.example", []));
        Assert.True(HostnameMatcher.IsAllowed("203.0.113.5", []));
    }

    [Fact]
    public void IsAllowed_ExactMatch_IsCaseInsensitive()
    {
        string[] allowlist = ["mc.example.com"];

        Assert.True(HostnameMatcher.IsAllowed("mc.example.com", allowlist));
        Assert.True(HostnameMatcher.IsAllowed("MC.EXAMPLE.COM", allowlist));
        Assert.False(HostnameMatcher.IsAllowed("other.example.com", allowlist));
    }

    [Fact]
    public void IsAllowed_RawIpAddress_IsRejectedWhenNotOnAllowlist()
    {
        // This is the entire point of the feature: a client that knows the server's IP and connects
        // directly (skipping the domain) sends the raw IP as the Handshake Server Address — must be
        // denied when an allowlist is configured, even though the IP itself is perfectly valid.
        string[] allowlist = ["mc.example.com"];

        Assert.False(HostnameMatcher.IsAllowed("203.0.113.5", allowlist));
    }

    [Fact]
    public void IsAllowed_WildcardSubdomain_MatchesSubdomainsOnly()
    {
        string[] allowlist = ["*.example.com"];

        Assert.True(HostnameMatcher.IsAllowed("mc.example.com", allowlist));
        Assert.True(HostnameMatcher.IsAllowed("play.mc.example.com", allowlist));
        Assert.False(HostnameMatcher.IsAllowed("example.com", allowlist)); // bare apex isn't a subdomain
        Assert.False(HostnameMatcher.IsAllowed("notexample.com", allowlist)); // no dot boundary
    }

    [Fact]
    public void IsAllowed_MultipleEntries_AnyMatchIsSufficient()
    {
        string[] allowlist = ["mc.example.com", "*.alt-domain.net"];

        Assert.True(HostnameMatcher.IsAllowed("mc.example.com", allowlist));
        Assert.True(HostnameMatcher.IsAllowed("play.alt-domain.net", allowlist));
        Assert.False(HostnameMatcher.IsAllowed("unrelated.org", allowlist));
    }

    [Fact]
    public void Normalize_StripsForgeFmlMarkerAndTrailingDot()
    {
        Assert.Equal("mc.example.com", HostnameMatcher.Normalize("mc.example.com\0FML3\0"));
        Assert.Equal("mc.example.com", HostnameMatcher.Normalize("mc.example.com."));
        Assert.Equal("mc.example.com", HostnameMatcher.Normalize("MC.Example.Com"));
    }

    [Fact]
    public void IsAllowed_ForgeMarkerAndTrailingDot_StillMatchByHostname()
    {
        string[] allowlist = ["mc.example.com"];

        Assert.True(HostnameMatcher.IsAllowed("mc.example.com\0FML3\0", allowlist));
        Assert.True(HostnameMatcher.IsAllowed("mc.example.com.", allowlist));
    }

    [Fact]
    public void TruncateForLogging_LongHostname_IsBounded()
    {
        string longHost = new string('a', 200) + ".example.com";

        string truncated = HostnameMatcher.TruncateForLogging(longHost, maxLength: 64);

        Assert.True(truncated.Length <= 65); // 64 chars + the ellipsis marker
    }

    [Fact]
    public void TruncateForLogging_ShortHostname_IsUnchanged()
    {
        Assert.Equal("mc.example.com", HostnameMatcher.TruncateForLogging("mc.example.com", maxLength: 64));
    }
}
