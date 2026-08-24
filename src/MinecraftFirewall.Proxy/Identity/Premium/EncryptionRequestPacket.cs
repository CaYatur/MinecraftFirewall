using System.Security.Cryptography;
using System.Text;
using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Proxy.Identity.Premium;

/// <summary>
/// Builds the Login-state clientbound Encryption Request packet (packet ID 0x01). Field layout
/// verified against a real Paper 1.21.11 server (protocol 774) — see
/// tools/MinecraftFirewall.ProtocolSpike's "encryption-probe" mode and docs/plan.md's Stage 4 note.
/// Field order: String Server ID (always empty — Notchian-derived servers haven't used this for
/// anything since the session API moved to serverId hashing), Prefixed Array of Byte Public Key
/// (X.509 SubjectPublicKeyInfo DER), Prefixed Array of Byte Verify Token, Boolean Should
/// Authenticate. This proxy always sends Should Authenticate = true — it always wants Mojang to
/// actually verify the session; there is no code path that skips verification.
/// </summary>
public static class EncryptionRequestPacket
{
    public const int PacketId = 0x01;
    private const int VerifyTokenLength = 4;

    public static byte[] GenerateVerifyToken() => RandomNumberGenerator.GetBytes(VerifyTokenLength);

    public static byte[] BuildFields(byte[] publicKeyDer, byte[] verifyToken)
    {
        byte[] serverId = WriteString("");
        byte[] publicKeyField = WritePrefixedBytes(publicKeyDer);
        byte[] verifyTokenField = WritePrefixedBytes(verifyToken);

        return [.. serverId, .. publicKeyField, .. verifyTokenField, 1 /* Should Authenticate = true */];
    }

    private static byte[] WriteString(string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        return [.. VarInt.Encode(bytes.Length), .. bytes];
    }

    private static byte[] WritePrefixedBytes(byte[] data) => [.. VarInt.Encode(data.Length), .. data];
}
