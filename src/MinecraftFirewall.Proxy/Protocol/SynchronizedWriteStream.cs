namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>
/// Serializes writes to a stream that two things need to write to at once.
///
/// The client socket has exactly one writer for almost all of a connection's life: the pump copying
/// the backend's replies out to the player. The premium self-lock flow adds a second — the proxy
/// itself, saying something to the player without ending their connection.
///
/// Two concurrent writers on a raw socket stream is not a theoretical problem. Minecraft's wire format
/// is a stream of length-prefixed frames, so a write that interleaves with another produces a frame
/// whose declared length does not match its contents, and the client disconnects with a decode error
/// it cannot explain. It would happen rarely — the proxy speaks perhaps twice in a player's lifetime —
/// which makes it the worst kind of bug: reproducible only under load, and indistinguishable from a
/// network fault when it happens.
///
/// Reads are deliberately not synchronized. There is only ever one reader, and adding a lock the read
/// path does not need would put a semaphore on the hot path of every packet.
/// </summary>
public sealed class SynchronizedWriteStream(Stream inner, bool leaveInnerOpen = true) : Stream
{
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public override bool CanRead => inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => inner.CanWrite;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) =>
        inner.ReadAsync(buffer, ct);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        inner.ReadAsync(buffer, offset, count, ct);

    public override void Write(byte[] buffer, int offset, int count)
    {
        _writeLock.Wait();
        try
        {
            inner.Write(buffer, offset, count);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await inner.WriteAsync(buffer, ct).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();

    public override void Flush() => inner.Flush();

    public override Task FlushAsync(CancellationToken ct) => inner.FlushAsync(ct);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _writeLock.Dispose();
            if (!leaveInnerOpen)
                inner.Dispose();
        }

        base.Dispose(disposing);
    }
}
