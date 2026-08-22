using System.Security.Cryptography;

namespace MinecraftFirewall.Proxy.Identity;

/// <summary>PBKDF2 password hashing for self-registered CaYaDev-Check identities — passwords are
/// never stored or logged in plaintext (see PlayStateInspector for where chat text gets redacted).</summary>
public static class PasswordHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int Iterations = 210_000; // OWASP 2023+ minimum recommendation for PBKDF2-HMAC-SHA256

    public static string Hash(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, HashSize);
        return $"{Iterations}:{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string password, string encoded)
    {
        try
        {
            string[] parts = encoded.Split(':', 3);
            if (parts.Length != 3 || !int.TryParse(parts[0], out int iterations))
                return false;

            byte[] salt = Convert.FromBase64String(parts[1]);
            byte[] expectedHash = Convert.FromBase64String(parts[2]);
            byte[] actualHash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expectedHash.Length);

            return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
        }
        catch (FormatException)
        {
            // Malformed stored hash (corrupted config, hand-edited file, etc.) — never a real password
            // match, so fail closed rather than let a decode error propagate as an unhandled exception.
            return false;
        }
    }
}
