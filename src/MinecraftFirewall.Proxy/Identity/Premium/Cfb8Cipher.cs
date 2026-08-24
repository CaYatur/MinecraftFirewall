using System.Security.Cryptography;

namespace MinecraftFirewall.Proxy.Identity.Premium;

/// <summary>
/// AES in CFB8 (8-bit cipher feedback) mode — the cipher Minecraft uses for the encrypted half of a
/// premium connection. Minecraft uses the 16-byte shared secret as both the AES key and the initial IV.
///
/// Hand-rolled rather than driven through <c>CipherMode.CFB</c> + <c>ICryptoTransform</c>: CFB8
/// through that API is a stateful, partial-block-sensitive path where a subtle misuse produces
/// plausible-looking-but-wrong bytes, and the algorithm itself is four lines. Note that BOTH
/// directions AES-*encrypt* the IV (the AES inverse cipher is never used, not even for decryption)
/// and BOTH shift the *ciphertext* byte into the IV — a decrypt path that shifts in the plaintext
/// byte instead still round-trips against its own encrypt path, which is exactly why
/// Cfb8CipherTests checks against NIST SP 800-38A's published vectors rather than a round-trip.
///
/// One instance carries the state for exactly ONE direction of ONE connection and is NOT
/// thread-safe. <see cref="AesCfb8Stream"/> creates two, precisely because read and write run
/// concurrently on separate tasks in ClientConnection's relay — sharing one instance, or one IV
/// buffer, between the two directions produces intermittent corruption that presents as a framing bug.
/// </summary>
internal sealed class Cfb8Cipher : IDisposable
{
    private const int BlockSize = 16;

    private readonly Aes _aes;
    private readonly ICryptoTransform _blockEncryptor;
    private readonly byte[] _iv = new byte[BlockSize];
    private readonly byte[] _keystreamBlock = new byte[BlockSize];

    public Cfb8Cipher(byte[] key, byte[] iv)
    {
        if (iv.Length != BlockSize)
            throw new ArgumentException($"CFB8 IV must be exactly {BlockSize} bytes.", nameof(iv));

        _aes = Aes.Create();
        _aes.Key = key;
        _aes.Mode = CipherMode.ECB;      // the raw block cipher; CFB8 chaining is done below by hand
        _aes.Padding = PaddingMode.None;
        _blockEncryptor = _aes.CreateEncryptor();

        // Own copy — never alias the caller's array, which is the shared secret and is handed to a
        // second Cfb8Cipher for the opposite direction.
        iv.CopyTo(_iv, 0);
    }

    /// <summary>Safe to call with <paramref name="input"/> and <paramref name="output"/> referring to
    /// the same memory: each byte is read before its output position is written.</summary>
    public void Encrypt(ReadOnlySpan<byte> input, Span<byte> output)
    {
        for (int i = 0; i < input.Length; i++)
        {
            byte cipherByte = (byte)(input[i] ^ NextKeystreamByte());
            ShiftIn(cipherByte);
            output[i] = cipherByte;
        }
    }

    /// <summary>Safe to call in-place, same as <see cref="Encrypt"/>.</summary>
    public void Decrypt(ReadOnlySpan<byte> input, Span<byte> output)
    {
        for (int i = 0; i < input.Length; i++)
        {
            byte cipherByte = input[i];
            output[i] = (byte)(cipherByte ^ NextKeystreamByte());
            ShiftIn(cipherByte);
        }
    }

    private byte NextKeystreamByte()
    {
        _blockEncryptor.TransformBlock(_iv, 0, BlockSize, _keystreamBlock, 0);
        return _keystreamBlock[0];
    }

    private void ShiftIn(byte cipherByte)
    {
        Array.Copy(_iv, 1, _iv, 0, BlockSize - 1);
        _iv[BlockSize - 1] = cipherByte;
    }

    public void Dispose()
    {
        _blockEncryptor.Dispose();
        _aes.Dispose();
    }
}
