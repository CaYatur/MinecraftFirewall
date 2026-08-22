namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>
/// Minecraft's VarInt encoding: 7 data bits per byte, high bit set means "more bytes follow",
/// little-endian group order, at most 5 bytes for a 32-bit value.
/// </summary>
public static class VarInt
{
    public const int MaxBytes = 5;

    /// <summary>Reads a VarInt from a stream, one byte at a time. Throws InvalidDataException if malformed.</summary>
    public static async Task<int> ReadAsync(Stream stream, CancellationToken ct)
    {
        int value = 0;
        int position = 0;
        var single = new byte[1];

        while (true)
        {
            await stream.ReadExactlyAsync(single, 0, 1, ct).ConfigureAwait(false);
            byte b = single[0];

            value |= (b & 0x7F) << position;

            if ((b & 0x80) == 0)
                break;

            position += 7;
            if (position >= 32)
                throw new InvalidDataException("VarInt is too large (exceeds 5 bytes).");
        }

        return value;
    }

    /// <summary>
    /// Decodes a VarInt from the start of an in-memory buffer that is known to already contain a complete VarInt.
    /// </summary>
    public static int Decode(ReadOnlySpan<byte> buffer, out int bytesRead)
    {
        int value = 0;
        int position = 0;
        bytesRead = 0;

        foreach (byte b in buffer)
        {
            bytesRead++;
            value |= (b & 0x7F) << position;

            if ((b & 0x80) == 0)
                return value;

            position += 7;
            if (position >= 32)
                throw new InvalidDataException("VarInt is too large (exceeds 5 bytes).");
        }

        throw new InvalidDataException("Buffer ended before VarInt was complete.");
    }

    /// <summary>Number of bytes required to encode the given value as a VarInt.</summary>
    public static int GetSize(int value)
    {
        uint u = unchecked((uint)value);
        int size = 1;
        while ((u & ~0x7Fu) != 0)
        {
            u >>= 7;
            size++;
        }
        return size;
    }

    /// <summary>Encodes a VarInt into the given buffer (must be at least GetSize(value) bytes). Returns bytes written.</summary>
    public static int Encode(int value, Span<byte> destination)
    {
        uint u = unchecked((uint)value);
        int i = 0;
        do
        {
            byte b = (byte)(u & 0x7F);
            u >>= 7;
            if (u != 0)
                b |= 0x80;
            destination[i++] = b;
        } while (u != 0);
        return i;
    }

    public static byte[] Encode(int value)
    {
        var buffer = new byte[GetSize(value)];
        Encode(value, buffer);
        return buffer;
    }
}
