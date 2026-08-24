using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Proxy.Identity.Premium;

public sealed record EncryptionResponseFields(byte[] EncryptedSharedSecret, byte[] EncryptedVerifyToken);

/// <summary>
/// Parses the Login-state serverbound Encryption Response packet (packet ID 0x01) — just two
/// Prefixed Array of Byte fields. No message-signing fields: that mechanism existed briefly
/// (1.19–1.19.2) and was removed in 1.19.3; confirmed empirically absent for protocol 774 too — see
/// EncryptionRequestPacket's doc comment for how the surrounding field layout was verified live.
/// </summary>
public static class EncryptionResponsePacket
{
    public const int PacketId = 0x01;

    // RSA-1024-encrypted fields never exceed 128 bytes; this cap only guards against a hostile or
    // corrupt length prefix before the real amount of buffered data is known.
    private const int MaxFieldLength = 4096;

    public static EncryptionResponseFields Parse(ReadOnlySpan<byte> fields)
    {
        byte[] encryptedSharedSecret = ReadPrefixedBytes(fields, out int bytesRead);
        byte[] encryptedVerifyToken = ReadPrefixedBytes(fields[bytesRead..], out _);
        return new EncryptionResponseFields(encryptedSharedSecret, encryptedVerifyToken);
    }

    private static byte[] ReadPrefixedBytes(ReadOnlySpan<byte> buffer, out int bytesRead)
    {
        int length = VarInt.Decode(buffer, out int prefixLen);
        if (length < 0 || length > MaxFieldLength)
            throw new InvalidDataException($"Encryption Response byte-array field length {length} is out of range.");
        if (prefixLen + length > buffer.Length)
            throw new InvalidDataException("Encryption Response byte-array field exceeds remaining buffer.");

        byte[] result = buffer.Slice(prefixLen, length).ToArray();
        bytesRead = prefixLen + length;
        return result;
    }
}
