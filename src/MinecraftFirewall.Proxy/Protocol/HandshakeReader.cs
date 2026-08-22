namespace MinecraftFirewall.Proxy.Protocol;

public enum HandshakeNextState
{
    Status = 1,
    Login = 2,
}

public sealed record HandshakeInfo(int ProtocolVersion, string ServerAddress, ushort ServerPort, HandshakeNextState NextState);

/// <summary>
/// Parses the two pre-login packets this app ever needs to understand: Handshake and Login Start.
/// Both are stable across Minecraft versions (unlike Play-state packets), which is why they're
/// always parsed regardless of protocol version, while Play-state inspection (Stage 3) is gated
/// per-version.
/// </summary>
public static class HandshakeReader
{
    public static HandshakeInfo ParseHandshake(ReadOnlySpan<byte> payload)
    {
        int offset = 0;

        int packetId = VarInt.Decode(payload[offset..], out int idLen);
        offset += idLen;
        if (packetId != 0x00)
            throw new InvalidDataException($"Expected Handshake packet ID 0x00, got 0x{packetId:X2}.");

        int protocolVersion = VarInt.Decode(payload[offset..], out int pvLen);
        offset += pvLen;

        string serverAddress = MinecraftPrimitives.ReadString(payload[offset..], out int addrLen);
        offset += addrLen;

        ushort serverPort = MinecraftPrimitives.ReadUShort(payload[offset..], out int portLen);
        offset += portLen;

        int nextState = VarInt.Decode(payload[offset..], out _);

        if (nextState is not (1 or 2))
            throw new InvalidDataException($"Unexpected Handshake next_state {nextState} (expected 1=status or 2=login).");

        return new HandshakeInfo(protocolVersion, serverAddress, serverPort, (HandshakeNextState)nextState);
    }

    public static string ParseLoginStartUsername(ReadOnlySpan<byte> payload)
    {
        int offset = 0;

        int packetId = VarInt.Decode(payload[offset..], out int idLen);
        offset += idLen;
        if (packetId != 0x00)
            throw new InvalidDataException($"Expected Login Start packet ID 0x00, got 0x{packetId:X2}.");

        // Username is the first field; UUID/other fields that follow (version-dependent) are never
        // needed here because Stage 1 forwards the already-captured raw frame bytes verbatim.
        string username = MinecraftPrimitives.ReadString(payload[offset..], out _);
        return username;
    }
}
