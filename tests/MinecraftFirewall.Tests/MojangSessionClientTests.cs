using System.Net;
using MinecraftFirewall.Proxy.Identity.Premium;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Every test here asserts the fail-CLOSED contract from IPremiumSessionClient's doc comment: a
/// timeout, a non-success status, or a malformed body must all come back as NotJoined, never throw,
/// and never be treated as "couldn't check, so allow" — that would defeat PremiumRequired entirely.
/// </summary>
public class MojangSessionClientTests
{
    private static MojangSessionClient CreateClient(FakeHttpMessageHandler handler, TimeSpan? timeout = null) =>
        new(new FakeHttpClientFactory(handler), Options.Create(new PremiumOptions { HttpTimeout = timeout ?? TimeSpan.FromSeconds(5) }), NullLogger<MojangSessionClient>.Instance);

    [Fact]
    public async Task HasJoinedAsync_SuccessResponse_ReturnsParsedUuidAndName()
    {
        var handler = new FakeHttpMessageHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""{"id":"069a79f444e94726a5befca90e38aaf5","name":"Notch"}"""),
        }));
        var client = CreateClient(handler);

        var result = await client.HasJoinedAsync("Notch", "somehash", CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("Notch", result.Name);
        // 32-char compact id gets dashes inserted at the standard UUID positions.
        Assert.Equal(Guid.Parse("069a79f4-44e9-4726-a5be-fca90e38aaf5"), result.Uuid);
    }

    [Fact]
    public async Task HasJoinedAsync_NoContent_ReturnsNotJoined()
    {
        // Mojang's real "no such session" response is 204 No Content.
        var handler = new FakeHttpMessageHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent)));
        var client = CreateClient(handler);

        var result = await client.HasJoinedAsync("CrackedUser", "somehash", CancellationToken.None);

        Assert.False(result.Success);
    }

    [Fact]
    public async Task HasJoinedAsync_ServerError_ReturnsNotJoined_NotAnException()
    {
        var handler = new FakeHttpMessageHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError)));
        var client = CreateClient(handler);

        var result = await client.HasJoinedAsync("SomeUser", "somehash", CancellationToken.None);

        Assert.False(result.Success);
    }

    [Fact]
    public async Task HasJoinedAsync_MalformedJsonBody_ReturnsNotJoined_NotAnException()
    {
        var handler = new FakeHttpMessageHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("this is not json"),
        }));
        var client = CreateClient(handler);

        var result = await client.HasJoinedAsync("SomeUser", "somehash", CancellationToken.None);

        Assert.False(result.Success);
    }

    [Fact]
    public async Task HasJoinedAsync_UnparseableUuid_ReturnsNotJoined_NotAnException()
    {
        var handler = new FakeHttpMessageHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""{"id":"not-a-real-uuid","name":"Notch"}"""),
        }));
        var client = CreateClient(handler);

        var result = await client.HasJoinedAsync("Notch", "somehash", CancellationToken.None);

        Assert.False(result.Success);
    }

    [Fact]
    public async Task HasJoinedAsync_TimesOut_ReturnsNotJoined_NotAnException()
    {
        var handler = new FakeHttpMessageHandler(async (_, ct) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(30), ct); // never legitimately completes within the test timeout below
            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        var client = CreateClient(handler, timeout: TimeSpan.FromMilliseconds(50));

        var result = await client.HasJoinedAsync("SomeUser", "somehash", CancellationToken.None);

        Assert.False(result.Success);
    }

    [Fact]
    public async Task HasJoinedAsync_RequestUrl_IncludesUsernameAndServerIdHash()
    {
        HttpRequestMessage? capturedRequest = null;
        var handler = new FakeHttpMessageHandler((request, _) =>
        {
            capturedRequest = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent));
        });
        var client = CreateClient(handler);

        await client.HasJoinedAsync("Some User", "-abc123", CancellationToken.None);

        Assert.NotNull(capturedRequest);
        // AbsoluteUri (not ToString(), which unescapes spaces back for display) — need to see the
        // actual percent-encoded bytes that go on the wire.
        string url = capturedRequest!.RequestUri!.AbsoluteUri;
        Assert.Contains("sessionserver.mojang.com/session/minecraft/hasJoined", url);
        Assert.Contains("username=Some%20User", url);
        Assert.Contains("serverId=-abc123", url);
    }
}
