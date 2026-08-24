using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using MinecraftFirewall.Proxy.Identity.Premium;
using Xunit;

namespace MinecraftFirewall.Tests;

/// <summary>
/// The cipher itself is verified against NIST vectors in Cfb8CipherTests; these cover what wrapping
/// it in a Stream adds — that the two directions really are independent, that arbitrary chunk
/// boundaries don't shift the stream, and that concurrent read/write (which is exactly how
/// ClientConnection's relay drives this) doesn't corrupt either direction.
/// </summary>
public class AesCfb8StreamTests
{
    private static byte[] NewSecret() => RandomNumberGenerator.GetBytes(16);

    [Fact]
    public async Task WriteThenRead_RoundTripsThroughTwoIndependentStreamInstances()
    {
        byte[] secret = NewSecret();
        byte[] payload = RandomNumberGenerator.GetBytes(2048);

        var wire = new MemoryStream();
        await using (var writer = new AesCfb8Stream(wire, secret, leaveInnerOpen: true))
            await writer.WriteAsync(payload);

        byte[] onTheWire = wire.ToArray();
        Assert.NotEqual(payload, onTheWire); // actually encrypted, not passed through
        Assert.Equal(payload.Length, onTheWire.Length); // CFB8 is a stream cipher — no padding growth

        var readBack = new MemoryStream(onTheWire);
        await using var reader = new AesCfb8Stream(readBack, secret, leaveInnerOpen: true);
        byte[] decrypted = new byte[payload.Length];
        await reader.ReadExactlyAsync(decrypted);

        Assert.Equal(payload, decrypted);
    }

    [Fact]
    public async Task WriteAsync_DoesNotMutateTheCallersBuffer()
    {
        // Stream.CopyToAsync reuses one rented buffer for every chunk, so encrypting in place here
        // would silently corrupt the source of a relay.
        byte[] secret = NewSecret();
        byte[] payload = RandomNumberGenerator.GetBytes(256);
        byte[] original = (byte[])payload.Clone();

        await using var stream = new AesCfb8Stream(new MemoryStream(), secret);
        await stream.WriteAsync(payload);

        Assert.Equal(original, payload);
    }

    [Fact]
    public async Task RaggedWriteSizes_ProduceTheSameCiphertextAsOneBigWrite()
    {
        byte[] secret = NewSecret();
        byte[] payload = RandomNumberGenerator.GetBytes(500);

        var bulkWire = new MemoryStream();
        await using (var bulk = new AesCfb8Stream(bulkWire, secret, leaveInnerOpen: true))
            await bulk.WriteAsync(payload);

        var chunkedWire = new MemoryStream();
        await using (var chunked = new AesCfb8Stream(chunkedWire, secret, leaveInnerOpen: true))
        {
            int[] sizes = [1, 17, 3, 100, 7, 255, 117];
            int offset = 0;
            foreach (int size in sizes)
            {
                await chunked.WriteAsync(payload.AsMemory(offset, size));
                offset += size;
            }
            Assert.Equal(payload.Length, offset);
        }

        Assert.Equal(bulkWire.ToArray(), chunkedWire.ToArray());
    }

    [Fact]
    public async Task ReadInSmallPieces_DecryptsIdenticallyToOneLargeRead()
    {
        byte[] secret = NewSecret();
        byte[] payload = RandomNumberGenerator.GetBytes(300);

        var wire = new MemoryStream();
        await using (var writer = new AesCfb8Stream(wire, secret, leaveInnerOpen: true))
            await writer.WriteAsync(payload);
        byte[] ciphertext = wire.ToArray();

        await using var reader = new AesCfb8Stream(new MemoryStream(ciphertext), secret, leaveInnerOpen: true);
        byte[] decrypted = new byte[payload.Length];
        for (int i = 0; i < payload.Length; i++)
            await reader.ReadExactlyAsync(decrypted.AsMemory(i, 1));

        Assert.Equal(payload, decrypted);
    }

    [Fact]
    public async Task ConcurrentReadAndWrite_OverARealSocketPair_DoNotCorruptEitherDirection()
    {
        // The real failure mode this guards: the two directions sharing one feedback register or one
        // ICryptoTransform. That only shows up when both run at once, which is exactly how
        // ClientConnection drives this (backend->client pump writing while the inspector reads).
        byte[] secret = NewSecret();
        byte[] aToB = RandomNumberGenerator.GetBytes(64 * 1024);
        byte[] bToA = RandomNumberGenerator.GetBytes(64 * 1024);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var clientA = new TcpClient();
        var acceptTask = listener.AcceptTcpClientAsync();
        await clientA.ConnectAsync(IPAddress.Loopback, port);
        using TcpClient clientB = await acceptTask;
        listener.Stop();

        await using var streamA = new AesCfb8Stream(clientA.GetStream(), secret, leaveInnerOpen: true);
        await using var streamB = new AesCfb8Stream(clientB.GetStream(), secret, leaveInnerOpen: true);

        byte[] receivedAtB = new byte[aToB.Length];
        byte[] receivedAtA = new byte[bToA.Length];

        await Task.WhenAll(
            streamA.WriteAsync(aToB).AsTask(),
            streamB.WriteAsync(bToA).AsTask(),
            streamB.ReadExactlyAsync(receivedAtB).AsTask(),
            streamA.ReadExactlyAsync(receivedAtA).AsTask());

        Assert.Equal(aToB, receivedAtB);
        Assert.Equal(bToA, receivedAtA);
    }

    [Fact]
    public async Task LeaveInnerOpenFalse_DisposesTheInnerStream()
    {
        var inner = new MemoryStream();
        var stream = new AesCfb8Stream(inner, NewSecret(), leaveInnerOpen: false);

        await stream.DisposeAsync();

        Assert.Throws<ObjectDisposedException>(() => inner.WriteByte(1));
    }

    [Fact]
    public async Task LeaveInnerOpenTrue_KeepsTheInnerStreamUsable()
    {
        // ClientConnection relies on this: the raw socket stream outlives the cipher wrapper so the
        // TcpClient's own `using` still owns the socket's lifetime.
        var inner = new MemoryStream();
        var stream = new AesCfb8Stream(inner, NewSecret(), leaveInnerOpen: true);

        await stream.DisposeAsync();

        inner.WriteByte(1); // must not throw
        Assert.Equal(1, inner.Length);
    }
}
