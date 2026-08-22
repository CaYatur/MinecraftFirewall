using System.Text;

namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>Read helpers for the handful of Minecraft protocol primitives this app needs to inspect.</summary>
public static class MinecraftPrimitives
{
    // Real Minecraft strings (server address, chat, commands) are capped at 32767 chars by the
    // protocol itself; enforcing the same cap here rejects malformed/hostile length prefixes early.
    public const int MaxStringBytes = 32767 * 4;

    public static string ReadString(ReadOnlySpan<byte> buffer, out int bytesRead)
    {
        int length = VarInt.Decode(buffer, out int prefixLen);
        if (length < 0 || length > MaxStringBytes)
            throw new InvalidDataException($"String length {length} is out of range.");
        if (prefixLen + length > buffer.Length)
            throw new InvalidDataException("String length exceeds remaining buffer.");

        var text = Encoding.UTF8.GetString(buffer.Slice(prefixLen, length));
        bytesRead = prefixLen + length;
        return text;
    }

    public static ushort ReadUShort(ReadOnlySpan<byte> buffer, out int bytesRead)
    {
        if (buffer.Length < 2)
            throw new InvalidDataException("Buffer too short for a UShort field.");
        bytesRead = 2;
        return (ushort)((buffer[0] << 8) | buffer[1]);
    }
}
