using MinecraftFirewall.Proxy.Messages;
using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Encoding a packet the proxy composed itself for the compression this connection negotiated.
///
/// This exists because it was got wrong, in a shipped release, on a live server. Every packet the
/// proxy originated was sent with a declared length of zero — meaning uncompressed — on the stated
/// belief that the frame format allowed that whatever the threshold was. It does not. Minecraft's
/// rule is exact and enforced at both ends: a payload at or above the threshold must be compressed,
/// one below it must not be, and a client that receives the wrong one disconnects with a decoder
/// error rather than tolerating it.
///
/// The cost was that asking what locking your name means kicked you for asking: the explanation is
/// 312 bytes and the default threshold is 256.
/// </summary>
public class CompressionThresholdTests
{
    private const int VanillaDefault = 256;

    /// <summary>Reads a frame the way the client does, returning what it declares and what it holds.
    /// Throws the same way a client would refuse it.</summary>
    private static (int Declared, DecodedPacket Packet) ReadAsClient(byte[] frame, int threshold)
    {
        int frameLength = VarInt.Decode(frame, out int prefix);
        Assert.Equal(frame.Length - prefix, frameLength);

        ReadOnlySpan<byte> payload = frame.AsSpan(prefix);
        int declared = VarInt.Decode(payload, out _);

        // The two checks a real client applies, in the order it applies them.
        if (declared == 0)
        {
            int actual = frameLength - VarInt.Encode(0).Length;
            Assert.True(actual < threshold,
                $"Actual uncompressed size {actual} is greater than threshold {threshold} — the client refuses this.");
        }
        else
        {
            Assert.True(declared >= threshold,
                $"Badly compressed packet - size of {declared} is below server threshold of {threshold}.");
        }

        return (declared, CompressedPacketReader.Decode(ToFrame(frame)));
    }

    private static Frame ToFrame(byte[] raw)
    {
        _ = VarInt.Decode(raw, out int prefix);
        return new Frame { Raw = raw, PayloadOffset = prefix, PayloadLength = raw.Length - prefix };
    }

    [Fact]
    public void TheMessageThatKickedPeopleForAskingIsNowSentCompressed()
    {
        // The exact case, from the exact default message, against the exact default threshold. The
        // client reported "Actual uncompressed size 312 is greater than threshold 256".
        string explanation = new MessagesOptions().PremiumLockExplain;

        byte[] frame = FrameWriter.WriteSystemChatFrame(0x72, explanation, VanillaDefault);
        (int declared, DecodedPacket packet) = ReadAsClient(frame, VanillaDefault);

        Assert.True(declared >= VanillaDefault, "a payload over the threshold has to be compressed");
        Assert.Equal(0x72, packet.PacketId);
    }

    [Fact]
    public void ASmallMessageIsStillSentUncompressed()
    {
        // The other half of the same rule, and just as enforced: compressing something below the
        // threshold is refused too, with "below server threshold".
        byte[] frame = FrameWriter.WriteSystemChatFrame(0x72, "Authenticated. Have fun.", VanillaDefault);
        (int declared, DecodedPacket packet) = ReadAsClient(frame, VanillaDefault);

        Assert.Equal(0, declared);
        Assert.Equal(0x72, packet.PacketId);
    }

    [Fact]
    public void APayloadOfExactlyTheThresholdIsCompressed()
    {
        // The boundary, which is inclusive. A payload of exactly the threshold is legal compressed and
        // illegal uncompressed, so this is the one value where an off-by-one would disconnect somebody
        // and never be noticed.
        const int threshold = 64;

        // One packet-id byte, so the fields are one short of the threshold.
        byte[] fields = new byte[threshold - 1];
        byte[] frame = FrameWriter.WritePlayFrame(0x01, fields, threshold);

        (int declared, _) = ReadAsClient(frame, threshold);
        Assert.Equal(threshold, declared);
    }

    [Fact]
    public void OneByteBelowTheThresholdIsNot()
    {
        const int threshold = 64;

        byte[] frame = FrameWriter.WritePlayFrame(0x01, new byte[threshold - 2], threshold);

        (int declared, _) = ReadAsClient(frame, threshold);
        Assert.Equal(0, declared);
    }

    [Fact]
    public void WithCompressionOffTheFrameCarriesNoDeclaredLengthAtAll()
    {
        // A third encoding, not a variation on the other two: before Set Compression, and on a server
        // that never sends it, frames are simply [length][packet id][fields].
        byte[] frame = FrameWriter.WritePlayFrame(0x2B, [0xAA, 0xBB], ConnectionCompression.NotCompressed);

        int length = VarInt.Decode(frame, out int prefix);
        Assert.Equal(3, length);
        Assert.Equal(0x2B, frame[prefix]);
        Assert.Equal(new byte[] { 0xAA, 0xBB }, frame[(prefix + 1)..]);
    }

    [Fact]
    public void EveryShippedMessageSurvivesTheDefaultThreshold()
    {
        // A guard on the configuration itself rather than on the code. These strings are meant to be
        // edited, and an admin writing a longer one — or translating into a language that runs longer —
        // must not be able to produce a message that disconnects the player reading it.
        var messages = new MessagesOptions();

        foreach (System.Reflection.PropertyInfo property in typeof(MessagesOptions).GetProperties())
        {
            if (property.PropertyType != typeof(string) || property.GetValue(messages) is not string text)
                continue;

            byte[] frame = FrameWriter.WriteSystemChatFrame(0x72, text, VanillaDefault);

            // Throws with the client's own wording if this one would have been refused.
            ReadAsClient(frame, VanillaDefault);
        }
    }

    [Fact]
    public void ColouredMessagesSurviveItToo()
    {
        // Colour is what makes this urgent rather than theoretical: every styled run adds around forty
        // bytes of NBT, so a message that fitted in plain text can stop fitting the moment somebody
        // colours three words of it.
        string colourful = "&c" + new string('a', 100) + "&e" + new string('b', 100) + "&a" + new string('c', 100);

        byte[] frame = FrameWriter.WriteSystemChatFrame(0x72, colourful, VanillaDefault);
        (int declared, _) = ReadAsClient(frame, VanillaDefault);

        Assert.True(declared >= VanillaDefault);
    }
}
