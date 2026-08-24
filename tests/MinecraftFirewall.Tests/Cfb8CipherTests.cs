using MinecraftFirewall.Proxy.Identity.Premium;
using Xunit;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Known-answer tests against NIST SP 800-38A's published CFB8 vectors (F.3.7 / F.3.9 / F.3.11 —
/// AES-128, AES-192, AES-256, same IV and plaintext for all three). These are deliberately NOT
/// round-trip tests: a CFB8 implementation that shifts the wrong byte into the feedback register, or
/// runs the AES inverse cipher on the decrypt path, still round-trips perfectly against itself. Only
/// fixed published outputs catch that, and matching all three key sizes is not something a subtly
/// broken implementation does by chance.
///
/// Also worth recording, since it justifies hand-rolling CFB8 at all: .NET's own
/// <c>CipherMode.CFB</c> + <c>FeedbackSize = 8</c> path rejects the 18-byte NIST plaintext outright
/// ("TransformBlock may only process bytes in block sized increments"), so it cannot be fed the
/// arbitrary-length chunks a socket actually delivers without an additional buffering layer of its own.
/// </summary>
public class Cfb8CipherTests
{
    private const string Aes128Key = "2b7e151628aed2a6abf7158809cf4f3c";
    private const string Aes192Key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    private const string Aes256Key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    private const string Iv = "000102030405060708090a0b0c0d0e0f";
    private const string Plaintext = "6bc1bee22e409f96e93d7e117393172aae2d";

    [Theory]
    [InlineData(Aes128Key, "3b79424c9c0dd436bace9e0ed4586a4f32b9")]
    [InlineData(Aes192Key, "cda2521ef0a905ca44cd057cbf0d47a0678a")]
    [InlineData(Aes256Key, "dc1f1a8520a64db55fcc8ac554844e889700")]
    public void Encrypt_MatchesNistSp800_38A_Cfb8Vectors(string keyHex, string expectedCiphertextHex)
    {
        using var cipher = new Cfb8Cipher(Convert.FromHexString(keyHex), Convert.FromHexString(Iv));
        byte[] plaintext = Convert.FromHexString(Plaintext);
        byte[] output = new byte[plaintext.Length];

        cipher.Encrypt(plaintext, output);

        Assert.Equal(expectedCiphertextHex, Convert.ToHexString(output).ToLowerInvariant());
    }

    [Theory]
    [InlineData(Aes128Key, "3b79424c9c0dd436bace9e0ed4586a4f32b9")]
    [InlineData(Aes192Key, "cda2521ef0a905ca44cd057cbf0d47a0678a")]
    [InlineData(Aes256Key, "dc1f1a8520a64db55fcc8ac554844e889700")]
    public void Decrypt_MatchesNistSp800_38A_Cfb8Vectors(string keyHex, string ciphertextHex)
    {
        using var cipher = new Cfb8Cipher(Convert.FromHexString(keyHex), Convert.FromHexString(Iv));
        byte[] ciphertext = Convert.FromHexString(ciphertextHex);
        byte[] output = new byte[ciphertext.Length];

        cipher.Decrypt(ciphertext, output);

        Assert.Equal(Plaintext, Convert.ToHexString(output).ToLowerInvariant());
    }

    [Fact]
    public void Encrypt_ByteAtATime_ProducesTheSameStreamAsOneBulkCall()
    {
        // This is the property a socket actually depends on: TCP hands over arbitrary chunk
        // boundaries, and the cipher state must carry across them exactly as if it were one call.
        byte[] key = Convert.FromHexString(Aes128Key);
        byte[] iv = Convert.FromHexString(Iv);
        byte[] plaintext = new byte[512];
        Random.Shared.NextBytes(plaintext);

        using var bulkCipher = new Cfb8Cipher(key, iv);
        byte[] bulk = new byte[plaintext.Length];
        bulkCipher.Encrypt(plaintext, bulk);

        using var streamingCipher = new Cfb8Cipher(key, iv);
        byte[] streaming = new byte[plaintext.Length];
        for (int i = 0; i < plaintext.Length; i++)
            streamingCipher.Encrypt(plaintext.AsSpan(i, 1), streaming.AsSpan(i, 1));

        Assert.Equal(bulk, streaming);
    }

    [Fact]
    public void Encrypt_RaggedChunkBoundaries_ProduceTheSameStreamAsOneBulkCall()
    {
        byte[] key = Convert.FromHexString(Aes128Key);
        byte[] iv = Convert.FromHexString(Iv);
        byte[] plaintext = new byte[500];
        Random.Shared.NextBytes(plaintext);

        using var bulkCipher = new Cfb8Cipher(key, iv);
        byte[] bulk = new byte[plaintext.Length];
        bulkCipher.Encrypt(plaintext, bulk);

        // Deliberately not multiples of the AES block size — a chunking bug that only shows up on
        // non-16-byte boundaries is exactly what a tidy test would miss.
        int[] chunkSizes = [1, 17, 3, 100, 7, 255, 117];
        using var chunkedCipher = new Cfb8Cipher(key, iv);
        byte[] chunked = new byte[plaintext.Length];
        int offset = 0;
        foreach (int size in chunkSizes)
        {
            chunkedCipher.Encrypt(plaintext.AsSpan(offset, size), chunked.AsSpan(offset, size));
            offset += size;
        }

        Assert.Equal(plaintext.Length, offset); // the chunk sizes must exactly cover the input
        Assert.Equal(bulk, chunked);
    }

    [Fact]
    public void Encrypt_InPlace_ProducesTheSameOutputAsIntoASeparateBuffer()
    {
        byte[] key = Convert.FromHexString(Aes128Key);
        byte[] iv = Convert.FromHexString(Iv);
        byte[] plaintext = Convert.FromHexString(Plaintext);

        using var separateCipher = new Cfb8Cipher(key, iv);
        byte[] separate = new byte[plaintext.Length];
        separateCipher.Encrypt(plaintext, separate);

        using var inPlaceCipher = new Cfb8Cipher(key, iv);
        byte[] inPlace = (byte[])plaintext.Clone();
        inPlaceCipher.Encrypt(inPlace, inPlace);

        Assert.Equal(separate, inPlace);
    }

    [Fact]
    public void Constructor_TakesItsOwnCopyOfTheIv_SoTwoCiphersCanShareOneSharedSecretArray()
    {
        // AesCfb8Stream hands the very same shared-secret array to both directions' ciphers. If
        // either aliased it instead of copying, the two would corrupt each other's feedback register.
        byte[] sharedSecret = Convert.FromHexString(Iv);
        byte[] key = Convert.FromHexString(Aes128Key);
        byte[] plaintext = Convert.FromHexString(Plaintext);

        using var first = new Cfb8Cipher(key, sharedSecret);
        using var second = new Cfb8Cipher(key, sharedSecret);

        byte[] firstOut = new byte[plaintext.Length];
        first.Encrypt(plaintext, firstOut);

        // The second cipher has not been used yet, so it must still start from the pristine IV and
        // produce the identical result — which it can't if the first mutated a shared array.
        byte[] secondOut = new byte[plaintext.Length];
        second.Encrypt(plaintext, secondOut);

        Assert.Equal(firstOut, secondOut);
        Assert.Equal(Iv, Convert.ToHexString(sharedSecret).ToLowerInvariant()); // caller's array untouched
    }
}
