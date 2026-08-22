namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>
/// Encodes the small number of packets this proxy ever originates itself (kick/disconnect messages).
/// Never used for anything the proxy is merely forwarding — those go out as the exact bytes that were
/// read in. Outbound synthetic packets here are always small, so they're sent uncompressed
/// (dataLength=0), which the compressed-frame format permits regardless of the negotiated threshold.
/// </summary>
public static class FrameWriter
{
    /// <summary>Encodes a packet for the pre-compression phase (Login, before Set Compression) — just [length][packetId][fields].</summary>
    public static byte[] WriteUncompressed(int packetId, byte[] fields)
    {
        byte[] payload = [.. VarInt.Encode(packetId), .. fields];
        return [.. VarInt.Encode(payload.Length), .. payload];
    }

    /// <summary>Encodes a packet for the post-compression phase (Configuration/Play) as an uncompressed (dataLength=0) frame.</summary>
    public static byte[] WriteCompressedFrameUncompressedPayload(int packetId, byte[] fields)
    {
        byte[] inner = [.. VarInt.Encode(packetId), .. fields];
        byte[] payload = [.. VarInt.Encode(0), .. inner];
        return [.. VarInt.Encode(payload.Length), .. payload];
    }
}
