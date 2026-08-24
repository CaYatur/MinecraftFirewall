using System.Buffers;

namespace MinecraftFirewall.Proxy.Identity.Premium;

/// <summary>
/// Wraps the client-side socket of a verified premium connection: reads decrypt, writes encrypt,
/// AES-CFB8, using the shared secret negotiated during the Encryption Request/Response exchange
/// (see <see cref="PremiumLoginHandshake"/>). Everything above this — frame reading, PlayStateInspector,
/// the byte pump — is unchanged and unaware the connection is encrypted, which is what keeps Stage 4b
/// to "wrap the stream, then run the existing relay" instead of a second parallel relay
/// implementation.
///
/// The two directions have completely independent cipher state (see <see cref="Cfb8Cipher"/>), which
/// matters because ClientConnection's relay reads and writes this stream from two different tasks at
/// the same time. Writes are additionally serialized by a semaphore: encrypting and writing must stay
/// one atomic step, since two writers interleaving between "encrypt" and "write" would emit
/// correctly-encrypted bytes in an order the client's own single cipher state cannot follow.
/// </summary>
public sealed class AesCfb8Stream : Stream
{
    private readonly Stream _inner;
    private readonly bool _leaveInnerOpen;
    private readonly Cfb8Cipher _decryptor;
    private readonly Cfb8Cipher _encryptor;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private bool _disposed;

    public AesCfb8Stream(Stream inner, byte[] sharedSecret, bool leaveInnerOpen = false)
    {
        _inner = inner;
        _leaveInnerOpen = leaveInnerOpen;
        _decryptor = new Cfb8Cipher(sharedSecret, sharedSecret);
        _encryptor = new Cfb8Cipher(sharedSecret, sharedSecret);
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanWrite => _inner.CanWrite;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        int read = await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (read > 0)
            _decryptor.Decrypt(buffer.Span[..read], buffer.Span[..read]);
        return read;
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        int read = _inner.Read(buffer, offset, count);
        if (read > 0)
            _decryptor.Decrypt(buffer.AsSpan(offset, read), buffer.AsSpan(offset, read));
        return read;
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        // Encrypt into scratch space rather than in place: the caller owns `buffer` and may well
        // reuse it (Stream.CopyToAsync does exactly that).
        byte[] scratch = ArrayPool<byte>.Shared.Rent(buffer.Length);
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _encryptor.Encrypt(buffer.Span, scratch.AsSpan(0, buffer.Length));
            await _inner.WriteAsync(scratch.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
            ArrayPool<byte>.Shared.Return(scratch);
        }
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        byte[] scratch = ArrayPool<byte>.Shared.Rent(count);
        _writeLock.Wait();
        try
        {
            _encryptor.Encrypt(buffer.AsSpan(offset, count), scratch.AsSpan(0, count));
            _inner.Write(scratch, 0, count);
        }
        finally
        {
            _writeLock.Release();
            ArrayPool<byte>.Shared.Return(scratch);
        }
    }

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            _decryptor.Dispose();
            _encryptor.Dispose();
            _writeLock.Dispose();
            if (!_leaveInnerOpen)
                _inner.Dispose();
        }

        base.Dispose(disposing);
    }
}
