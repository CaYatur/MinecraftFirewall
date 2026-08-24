namespace MinecraftFirewall.Tests.TestDoubles;

/// <summary>Minimal HttpMessageHandler stand-in — routes every request through a caller-supplied
/// async responder, so tests can simulate specific status codes, bodies, or a hang (for timeout
/// tests) without a real network call.</summary>
public sealed class FakeHttpMessageHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        respond(request, cancellationToken);
}

public sealed class FakeHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
{
    public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
}
