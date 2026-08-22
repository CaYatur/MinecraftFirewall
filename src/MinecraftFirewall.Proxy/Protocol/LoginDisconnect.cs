using System.Text;
using System.Text.Json;

namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>
/// Builds a Login-state clientbound Disconnect packet (ID 0x00, a JSON chat-component string field).
/// This packet's shape has been stable for a very long time — like Handshake/Login Start, it's part
/// of the simple pre-login protocol, not the version-churning Play state — so it's safe to hardcode
/// without a per-version table.
/// </summary>
public static class LoginDisconnect
{
    public static byte[] BuildPacket(string reasonText)
    {
        string json = JsonSerializer.Serialize(new { text = reasonText });
        byte[] jsonBytes = Encoding.UTF8.GetBytes(json);

        byte[] idBytes = VarInt.Encode(0x00);
        byte[] jsonLenBytes = VarInt.Encode(jsonBytes.Length);

        int payloadLength = idBytes.Length + jsonLenBytes.Length + jsonBytes.Length;
        byte[] frameLenBytes = VarInt.Encode(payloadLength);

        var result = new byte[frameLenBytes.Length + payloadLength];
        int offset = 0;
        frameLenBytes.CopyTo(result, offset); offset += frameLenBytes.Length;
        idBytes.CopyTo(result, offset); offset += idBytes.Length;
        jsonLenBytes.CopyTo(result, offset); offset += jsonLenBytes.Length;
        jsonBytes.CopyTo(result, offset);

        return result;
    }
}
