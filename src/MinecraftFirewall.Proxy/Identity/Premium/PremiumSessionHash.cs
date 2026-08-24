using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace MinecraftFirewall.Proxy.Identity.Premium;

/// <summary>
/// Computes the Mojang session-server hash used for the hasJoined check: SHA-1 over
/// serverId + sharedSecret + the server's DER-encoded RSA public key, formatted the way Java's
/// `new BigInteger(digest).toString(16)` formats it — signed, two's-complement, no leading-zero
/// padding, which can (and, for roughly half of all inputs, does) produce a leading '-'.
///
/// This is NOT a plain hex-encode of the raw digest bytes, and .NET's own BigInteger.ToString("x")
/// does not match Java's format either: .NET pads with a leading zero nibble to disambiguate sign on
/// positive values, and represents negative values in two's-complement hex rather than as a literal
/// minus sign in front of the magnitude. Getting this wrong is silent — a round-trip test of this
/// code against itself would still pass. See PremiumSessionHashTests for the published known-answer
/// vectors (SHA1("Notch"/"jeb_"/"simon") run through this exact formatting rule) this was verified
/// against instead.
/// </summary>
public static class PremiumSessionHash
{
    public static string Compute(string serverId, byte[] sharedSecret, byte[] publicKeyDer)
    {
        byte[] serverIdBytes = Encoding.ASCII.GetBytes(serverId);
        byte[] buffer = new byte[serverIdBytes.Length + sharedSecret.Length + publicKeyDer.Length];

        int offset = 0;
        serverIdBytes.CopyTo(buffer, offset); offset += serverIdBytes.Length;
        sharedSecret.CopyTo(buffer, offset); offset += sharedSecret.Length;
        publicKeyDer.CopyTo(buffer, offset);

        byte[] digest = SHA1.HashData(buffer);
        return ToJavaHexBigInteger(digest);
    }

    internal static string ToJavaHexBigInteger(byte[] digest)
    {
        var value = new BigInteger(digest, isUnsigned: false, isBigEndian: true);
        bool negative = value.Sign < 0;
        BigInteger magnitude = negative ? -value : value;

        byte[] magnitudeBytes = magnitude.ToByteArray(isUnsigned: true, isBigEndian: true);
        string hex = Convert.ToHexString(magnitudeBytes).ToLowerInvariant().TrimStart('0');
        if (hex.Length == 0) hex = "0";

        return negative ? "-" + hex : hex;
    }
}
