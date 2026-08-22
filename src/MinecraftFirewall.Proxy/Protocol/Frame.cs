namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>
/// One length-prefixed Minecraft packet frame, captured as raw bytes (VarInt length + payload)
/// so it can be forwarded to the backend byte-for-byte without re-serialization.
/// </summary>
public sealed class Frame
{
    public required byte[] Raw { get; init; }
    public required int PayloadOffset { get; init; }
    public required int PayloadLength { get; init; }

    public ReadOnlySpan<byte> Payload => Raw.AsSpan(PayloadOffset, PayloadLength);
}
