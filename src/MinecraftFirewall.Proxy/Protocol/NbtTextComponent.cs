using System.Text;

namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>
/// Builds a minimal NBT-encoded literal text component (`{text: "..."}`), the field type used by
/// Configuration/Play-state Disconnect packets since 1.20.2 — confirmed empirically against a real
/// server during the Stage 2 spike (a Configuration Disconnect packet's payload decoded exactly as an
/// unnamed root TAG_Compound, unlike file NBT's named root). Login-state Disconnect is unrelated and
/// still uses a plain JSON string (see LoginDisconnect.cs) — the two states never share this encoding.
/// </summary>
public static class NbtTextComponent
{
    private const byte TagCompound = 0x0A;
    private const byte TagString = 0x08;
    private const byte TagEnd = 0x00;

    public static byte[] BuildLiteral(string text)
    {
        byte[] textBytes = Encoding.UTF8.GetBytes(text);
        if (textBytes.Length > ushort.MaxValue)
            throw new ArgumentException("Text component is too long to encode.", nameof(text));

        using var ms = new MemoryStream();
        ms.WriteByte(TagCompound); // root compound, unnamed (network NBT convention)

        ms.WriteByte(TagString);
        WriteUShortBigEndian(ms, 4);
        ms.Write("text"u8);
        WriteUShortBigEndian(ms, (ushort)textBytes.Length);
        ms.Write(textBytes);

        ms.WriteByte(TagEnd);
        return ms.ToArray();
    }

    private static void WriteUShortBigEndian(Stream stream, ushort value)
    {
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)(value & 0xFF));
    }
}
