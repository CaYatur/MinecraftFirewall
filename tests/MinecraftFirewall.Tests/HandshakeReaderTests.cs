using System.Text;
using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Tests;

public class HandshakeReaderTests
{
    [Theory]
    [InlineData(1, HandshakeNextState.Status)]
    [InlineData(2, HandshakeNextState.Login)]
    public void ParseHandshake_ReadsAllFields(int nextStateValue, HandshakeNextState expected)
    {
        byte[] payload = BuildHandshakePayload(protocolVersion: 767, serverAddress: "play.example.com", serverPort: 25565, nextState: nextStateValue);

        var handshake = HandshakeReader.ParseHandshake(payload);

        Assert.Equal(767, handshake.ProtocolVersion);
        Assert.Equal("play.example.com", handshake.ServerAddress);
        Assert.Equal((ushort)25565, handshake.ServerPort);
        Assert.Equal(expected, handshake.NextState);
    }

    [Fact]
    public void ParseHandshake_WrongPacketId_Throws()
    {
        byte[] payload = [.. VarInt.Encode(0x05), .. VarInt.Encode(767)];

        Assert.Throws<InvalidDataException>(() => HandshakeReader.ParseHandshake(payload));
    }

    [Fact]
    public void ParseHandshake_InvalidNextState_Throws()
    {
        byte[] payload = BuildHandshakePayload(767, "host", 25565, nextState: 99);

        Assert.Throws<InvalidDataException>(() => HandshakeReader.ParseHandshake(payload));
    }

    [Fact]
    public void ParseLoginStartUsername_ReadsName()
    {
        byte[] payload = [.. VarInt.Encode(0x00), .. EncodeString("Admin")];

        string username = HandshakeReader.ParseLoginStartUsername(payload);

        Assert.Equal("Admin", username);
    }

    [Fact]
    public void ParseLoginStartUsername_IgnoresTrailingFields()
    {
        // Newer protocol versions append a UUID field after the username; parsing must not choke on it.
        byte[] trailingUuidBytes = new byte[16];
        byte[] payload = [.. VarInt.Encode(0x00), .. EncodeString("Admin"), 0x01, .. trailingUuidBytes];

        string username = HandshakeReader.ParseLoginStartUsername(payload);

        Assert.Equal("Admin", username);
    }

    private static byte[] BuildHandshakePayload(int protocolVersion, string serverAddress, ushort serverPort, int nextState)
    {
        List<byte> bytes =
        [
            .. VarInt.Encode(0x00),
            .. VarInt.Encode(protocolVersion),
            .. EncodeString(serverAddress),
            (byte)(serverPort >> 8),
            (byte)(serverPort & 0xFF),
            .. VarInt.Encode(nextState),
        ];
        return [.. bytes];
    }

    private static byte[] EncodeString(string text)
    {
        byte[] textBytes = Encoding.UTF8.GetBytes(text);
        return [.. VarInt.Encode(textBytes.Length), .. textBytes];
    }
}
