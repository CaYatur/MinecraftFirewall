using System.Security.Cryptography;

namespace MinecraftFirewall.Proxy.Identity.Premium;

/// <summary>
/// One RSA keypair generated at proxy startup and reused for every PremiumRequired connection —
/// matches real Notchian/Paper server behavior (confirmed empirically: a real Paper 1.21.11 server
/// logs "Generating keypair" exactly once at startup, not per-connection). 1024-bit, matching the
/// key size observed live against that same server (its Encryption Request carried a 162-byte
/// SubjectPublicKeyInfo DER, which is exactly a 1024-bit RSA key's DER encoding — see
/// tools/MinecraftFirewall.ProtocolSpike's "encryption-probe" mode and docs/plan.md's Stage 4 note).
/// </summary>
public sealed class RsaServerKeyPair : IDisposable
{
    private readonly RSA _rsa = RSA.Create(1024);

    public RsaServerKeyPair()
    {
        PublicKeyDer = _rsa.ExportSubjectPublicKeyInfo();
    }

    public byte[] PublicKeyDer { get; }

    public byte[] Decrypt(byte[] data) => _rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);

    public void Dispose() => _rsa.Dispose();
}
