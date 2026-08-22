using System.Text;
using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Tests.TestDoubles;

/// <summary>Builds raw, length-prefixed Handshake/Login Start frames for driving the proxy in integration tests.</summary>
public static class MinecraftPacketBuilder
{
    public static byte[] BuildHandshakeFrame(int protocolVersion, string serverAddress, ushort serverPort, int nextState)
    {
        byte[] payload =
        [
            .. VarInt.Encode(0x00),
            .. VarInt.Encode(protocolVersion),
            .. EncodeString(serverAddress),
            (byte)(serverPort >> 8),
            (byte)(serverPort & 0xFF),
            .. VarInt.Encode(nextState),
        ];
        return WrapFrame(payload);
    }

    public static byte[] BuildLoginStartFrame(string username)
    {
        byte[] payload = [.. VarInt.Encode(0x00), .. EncodeString(username)];
        return WrapFrame(payload);
    }

    private static byte[] WrapFrame(byte[] payload) => [.. VarInt.Encode(payload.Length), .. payload];

    private static byte[] EncodeString(string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        return [.. VarInt.Encode(bytes.Length), .. bytes];
    }
}
