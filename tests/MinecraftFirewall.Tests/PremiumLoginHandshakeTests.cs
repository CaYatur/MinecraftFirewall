using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Identity.Premium;
using MinecraftFirewall.Proxy.Protocol;
using MinecraftFirewall.Tests.TestDoubles;
using Xunit;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Drives the real handshake over a real socket pair, with a test-side "client" that parses the
/// Encryption Request exactly as a Minecraft client would and answers with a genuine RSA-encrypted
/// Encryption Response. Only the Mojang HTTP call is faked — the RSA, the packet framing, the
/// session hash and the UUID pin are all the production implementations.
/// </summary>
public class PremiumLoginHandshakeTests : IDisposable
{
    private readonly RsaServerKeyPair _serverKey = new();
    private readonly TcpListener _listener;
    private readonly TcpClient _proxySide;
    private readonly TcpClient _clientSide;

    public PremiumLoginHandshakeTests()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        int port = ((IPEndPoint)_listener.LocalEndpoint).Port;

        _clientSide = new TcpClient();
        var accept = _listener.AcceptTcpClientAsync();
        _clientSide.Connect(IPAddress.Loopback, port);
        _proxySide = accept.GetAwaiter().GetResult();
        _listener.Stop();
    }

    public void Dispose()
    {
        _proxySide.Dispose();
        _clientSide.Dispose();
        _serverKey.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>Acts as the client half: reads the Encryption Request, then answers with a real
    /// Encryption Response. <paramref name="corruptVerifyToken"/> simulates a client that fails the
    /// token round-trip; <paramml name="wrongPacketId"/> a client that answers with the wrong packet.</summary>
    private async Task<byte[]> RespondAsClientAsync(bool corruptVerifyToken = false, int? overridePacketId = null)
    {
        NetworkStream stream = _clientSide.GetStream();
        Frame frame = await FrameReader.ReadFrameAsync(stream, FrameReader.MaxPreLoginFrameSize, CancellationToken.None);

        ReadOnlySpan<byte> payload = frame.Payload;
        int packetId = VarInt.Decode(payload, out int idLength);
        Assert.Equal(EncryptionRequestPacket.PacketId, packetId);

        ReadOnlySpan<byte> fields = payload[idLength..];
        int offset = 0;
        string serverId = MinecraftPrimitives.ReadString(fields, out int serverIdLength);
        offset += serverIdLength;
        Assert.Equal("", serverId);

        int publicKeyLength = VarInt.Decode(fields[offset..], out int publicKeyLengthSize);
        offset += publicKeyLengthSize;
        byte[] publicKeyDer = fields.Slice(offset, publicKeyLength).ToArray();
        offset += publicKeyLength;

        int tokenLength = VarInt.Decode(fields[offset..], out int tokenLengthSize);
        offset += tokenLengthSize;
        byte[] verifyToken = fields.Slice(offset, tokenLength).ToArray();
        offset += tokenLength;

        Assert.Equal(1, fields[offset]);              // Should Authenticate
        Assert.Equal(fields.Length, offset + 1);      // and nothing after it

        if (corruptVerifyToken)
            verifyToken[0] ^= 0xFF;

        using RSA clientRsa = RSA.Create();
        clientRsa.ImportSubjectPublicKeyInfo(publicKeyDer, out _);
        byte[] sharedSecret = RandomNumberGenerator.GetBytes(16);

        byte[] response = FrameWriter.WriteUncompressed(
            overridePacketId ?? EncryptionResponsePacket.PacketId,
            [
                .. VarInt.Encode(128), .. clientRsa.Encrypt(sharedSecret, RSAEncryptionPadding.Pkcs1),
                .. VarInt.Encode(128), .. clientRsa.Encrypt(verifyToken, RSAEncryptionPadding.Pkcs1),
            ]);
        await stream.WriteAsync(response);
        return sharedSecret;
    }

    private PremiumLoginHandshake CreateHandshake(FakePremiumSessionClient sessionClient) =>
        PremiumTestFactory.CreateHandshake(_serverKey, sessionClient);

    [Fact]
    public async Task ValidClient_WithSuccessfulHasJoined_SucceedsAndClaimsThePin()
    {
        var entry = new IdentityEntry { Username = "RealOwner", PremiumRequired = true };
        var uuid = Guid.NewGuid();
        var sessionClient = new FakePremiumSessionClient();
        sessionClient.SucceedWith(uuid, "RealOwner");

        Task<byte[]> clientTask = RespondAsClientAsync();
        PremiumLoginOutcome outcome = await CreateHandshake(sessionClient)
            .RunAsync(_proxySide.GetStream(), entry, "RealOwner", CancellationToken.None);
        byte[] clientSecret = await clientTask;

        Assert.True(outcome.Success);
        Assert.Equal(uuid, entry.PinnedUuid);
        // Both sides must have agreed on the same key, or the cipher wrapper would produce garbage.
        Assert.Equal(clientSecret, outcome.SharedSecret);
    }

    [Fact]
    public async Task ValidClient_ButHasJoinedFails_DeniesAndStillReturnsTheSecretForAnEncryptedKick()
    {
        var entry = new IdentityEntry { Username = "RealOwner", PremiumRequired = true };
        var sessionClient = new FakePremiumSessionClient(); // defaults to NotJoined

        Task<byte[]> clientTask = RespondAsClientAsync();
        PremiumLoginOutcome outcome = await CreateHandshake(sessionClient)
            .RunAsync(_proxySide.GetStream(), entry, "RealOwner", CancellationToken.None);
        byte[] clientSecret = await clientTask;

        Assert.False(outcome.Success);
        Assert.False(outcome.PinnedToDifferentAccount); // an outage looks exactly like this — not fast-tracked
        Assert.Null(entry.PinnedUuid);                  // a failed check must never claim the name
        Assert.Equal(clientSecret, outcome.SharedSecret);
    }

    [Fact]
    public async Task ClientCorruptsTheVerifyToken_DeniesWithNoSecret()
    {
        var entry = new IdentityEntry { Username = "RealOwner", PremiumRequired = true };
        var sessionClient = new FakePremiumSessionClient();
        sessionClient.SucceedWith(Guid.NewGuid(), "RealOwner");

        Task<byte[]> clientTask = RespondAsClientAsync(corruptVerifyToken: true);
        PremiumLoginOutcome outcome = await CreateHandshake(sessionClient)
            .RunAsync(_proxySide.GetStream(), entry, "RealOwner", CancellationToken.None);
        await clientTask;

        Assert.False(outcome.Success);
        Assert.Null(outcome.SharedSecret); // no agreed key — nothing readable could be sent back
        Assert.Equal(0, sessionClient.CallCount); // never reached Mojang
        Assert.Null(entry.PinnedUuid);
    }

    [Fact]
    public async Task ClientAnswersWithTheWrongPacket_DeniesWithNoSecret()
    {
        var entry = new IdentityEntry { Username = "RealOwner", PremiumRequired = true };
        var sessionClient = new FakePremiumSessionClient();

        Task<byte[]> clientTask = RespondAsClientAsync(overridePacketId: 0x00);
        PremiumLoginOutcome outcome = await CreateHandshake(sessionClient)
            .RunAsync(_proxySide.GetStream(), entry, "RealOwner", CancellationToken.None);
        await clientTask;

        Assert.False(outcome.Success);
        Assert.Null(outcome.SharedSecret);
        Assert.Equal(0, sessionClient.CallCount);
    }

    [Fact]
    public async Task AlreadyPinnedToAnotherAccount_DeniesAndFlagsItAsImpersonation()
    {
        var owner = Guid.NewGuid();
        var entry = new IdentityEntry { Username = "RealOwner", PremiumRequired = true };
        entry.TryClaimOrMatchPinnedUuid(owner);

        // A genuine, verifiable Mojang account — just not the one this name belongs to.
        var sessionClient = new FakePremiumSessionClient();
        sessionClient.SucceedWith(Guid.NewGuid(), "RealOwner");

        Task<byte[]> clientTask = RespondAsClientAsync();
        PremiumLoginOutcome outcome = await CreateHandshake(sessionClient)
            .RunAsync(_proxySide.GetStream(), entry, "RealOwner", CancellationToken.None);
        await clientTask;

        Assert.False(outcome.Success);
        Assert.True(outcome.PinnedToDifferentAccount); // unambiguous — this one IS fast-tracked
        Assert.Equal(owner, entry.PinnedUuid);         // the real owner keeps the name
    }

    [Fact]
    public async Task SecondConnectionFromTheSameAccount_MatchesTheExistingPin()
    {
        var uuid = Guid.NewGuid();
        var entry = new IdentityEntry { Username = "RealOwner", PremiumRequired = true };
        entry.TryClaimOrMatchPinnedUuid(uuid);

        var sessionClient = new FakePremiumSessionClient();
        sessionClient.SucceedWith(uuid, "RealOwner");

        Task<byte[]> clientTask = RespondAsClientAsync();
        PremiumLoginOutcome outcome = await CreateHandshake(sessionClient)
            .RunAsync(_proxySide.GetStream(), entry, "RealOwner", CancellationToken.None);
        await clientTask;

        Assert.True(outcome.Success);
        Assert.Equal(uuid, entry.PinnedUuid);
    }

    [Fact]
    public async Task SharedSecretFromASuccessfulHandshake_ActuallyDecryptsWhatTheClientEncrypts()
    {
        // The end-to-end point of the whole exchange: both sides must derive a key that really works
        // for the AES-CFB8 relay that follows.
        var entry = new IdentityEntry { Username = "RealOwner", PremiumRequired = true };
        var sessionClient = new FakePremiumSessionClient();
        sessionClient.SucceedWith(Guid.NewGuid(), "RealOwner");

        Task<byte[]> clientTask = RespondAsClientAsync();
        PremiumLoginOutcome outcome = await CreateHandshake(sessionClient)
            .RunAsync(_proxySide.GetStream(), entry, "RealOwner", CancellationToken.None);
        byte[] clientSecret = await clientTask;

        Assert.True(outcome.Success);

        byte[] message = "hello from the client"u8.ToArray();
        await using var clientCipher = new AesCfb8Stream(_clientSide.GetStream(), clientSecret, leaveInnerOpen: true);
        await using var proxyCipher = new AesCfb8Stream(_proxySide.GetStream(), outcome.SharedSecret!, leaveInnerOpen: true);

        await clientCipher.WriteAsync(message);
        byte[] received = new byte[message.Length];
        await proxyCipher.ReadExactlyAsync(received);

        Assert.Equal(message, received);
    }
}
