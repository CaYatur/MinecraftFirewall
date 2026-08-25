namespace MinecraftFirewall.Tests.TestDoubles;

/// <summary>
/// Reads from one buffer and writes to another, the way a socket does.
///
/// A <see cref="MemoryStream"/> built from a byte array looks like a usable stand-in for a client
/// connection right up until something writes to it: reads and writes share one cursor and one buffer,
/// so anything the proxy says to the player lands on top of the packets it has not read yet. That is
/// not a hypothetical — the inspector sends a prompt the moment a player needs to authenticate, and
/// against a MemoryStream that prompt silently overwrote the very command the test was about to feed
/// it. The failure looked like the registration logic not working.
/// </summary>
public sealed class DuplexTestStream(byte[] toRead) : Stream
{
    private readonly MemoryStream _input = new(toRead, writable: false);
    private readonly MemoryStream _output = new();

    /// <summary>Everything the code under test sent back to the client.</summary>
    public byte[] Written => _output.ToArray();

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => _input.Read(buffer, offset, count);

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) =>
        _input.ReadAsync(buffer, ct);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        _input.ReadAsync(buffer, offset, count, ct);

    public override void Write(byte[] buffer, int offset, int count) => _output.Write(buffer, offset, count);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) =>
        _output.WriteAsync(buffer, ct);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        _output.WriteAsync(buffer, offset, count, ct);

    public override void Flush() => _output.Flush();

    public override Task FlushAsync(CancellationToken ct) => _output.FlushAsync(ct);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _input.Dispose();
            _output.Dispose();
        }

        base.Dispose(disposing);
    }
}
