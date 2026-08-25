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
    private const byte TagByte = 0x01;
    private const byte TagInt = 0x03;
    private const byte TagString = 0x08;
    private const byte TagList = 0x09;
    private const byte TagCompound = 0x0A;
    private const byte TagEnd = 0x00;

    /// <summary>
    /// Builds a text component, applying any Minecraft formatting codes the text carries.
    ///
    /// Text with no codes in it produces exactly the flat component this class always produced — the
    /// cheaper encoding, and the one every existing caller was already getting. Only text that
    /// actually asks for colour pays for the tree.
    /// </summary>
    public static byte[] Build(string text) =>
        TextColour.HasCodes(text) ? BuildStyled(TextColour.Split(text)) : BuildLiteral(text);

    /// <summary>
    /// Encodes styled runs as a component with an empty parent and one child per run.
    ///
    /// The parent is deliberately empty and unstyled. Children inherit from it, so anything set here
    /// would apply to every run that did not explicitly override it — and each run already states its
    /// own appearance in full, precisely so that no run can be coloured by accident.
    /// </summary>
    private static byte[] BuildStyled(List<TextRun> runs)
    {
        if (runs.Count == 0)
            return BuildLiteral("");

        // One run with no styling is just a literal; skipping the list keeps the frame small.
        if (runs.Count == 1 && runs[0].IsPlain)
            return BuildLiteral(runs[0].Text);

        using var ms = new MemoryStream();
        ms.WriteByte(TagCompound); // root compound, unnamed (network NBT convention)

        WriteStringField(ms, "text", "");

        ms.WriteByte(TagList);
        WriteUShortBigEndian(ms, 5);
        ms.Write("extra"u8);
        ms.WriteByte(TagCompound);       // every element is a compound
        WriteIntBigEndian(ms, runs.Count);

        foreach (TextRun run in runs)
        {
            // List elements carry their body only: no tag byte, no name, but still their own TAG_End.
            WriteStringField(ms, "text", run.Text);

            if (run.Colour is { } colour)
                WriteStringField(ms, "color", colour);

            WriteBoolField(ms, "bold", run.Bold);
            WriteBoolField(ms, "italic", run.Italic);
            WriteBoolField(ms, "underlined", run.Underlined);
            WriteBoolField(ms, "strikethrough", run.Strikethrough);
            WriteBoolField(ms, "obfuscated", run.Obfuscated);

            ms.WriteByte(TagEnd);
        }

        ms.WriteByte(TagEnd);
        return ms.ToArray();
    }

    private static void WriteStringField(Stream stream, string name, string value)
    {
        byte[] nameBytes = Encoding.UTF8.GetBytes(name);
        byte[] valueBytes = Encoding.UTF8.GetBytes(value);

        if (valueBytes.Length > ushort.MaxValue)
            throw new ArgumentException("Text component is too long to encode.", nameof(value));

        stream.WriteByte(TagString);
        WriteUShortBigEndian(stream, (ushort)nameBytes.Length);
        stream.Write(nameBytes);
        WriteUShortBigEndian(stream, (ushort)valueBytes.Length);
        stream.Write(valueBytes);
    }

    /// <summary>Written only when true. A false is the default everywhere, and leaving it out keeps
    /// the component small enough to stay well inside a frame.</summary>
    private static void WriteBoolField(Stream stream, string name, bool value)
    {
        if (!value)
            return;

        byte[] nameBytes = Encoding.UTF8.GetBytes(name);

        stream.WriteByte(TagByte);
        WriteUShortBigEndian(stream, (ushort)nameBytes.Length);
        stream.Write(nameBytes);
        stream.WriteByte(1);
    }

    private static void WriteIntBigEndian(Stream stream, int value)
    {
        stream.WriteByte((byte)(value >> 24));
        stream.WriteByte((byte)(value >> 16));
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }

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
