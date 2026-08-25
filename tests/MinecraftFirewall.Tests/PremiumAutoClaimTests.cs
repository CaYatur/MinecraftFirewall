using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Identity.Premium;
using MinecraftFirewall.Proxy.Protocol;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Options;
using Xunit;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Auto-claim lets an undeclared username be locked to whoever proves they own the genuine Mojang
/// account. The whole safety of the feature rests on one asymmetry, which is what these tests pin:
/// it only ever writes a POSITIVE.
///
/// The design that was rejected during planning recorded the *result* of probing a new name, so a
/// cracked client connecting first marked that name "offline-eligible" permanently — handing every
/// valuable username to whoever got there first, which is precisely the attack the feature exists to
/// prevent. A failed claim here must therefore leave absolutely no trace: no premium flag, no pin,
/// nothing that could stop the real owner claiming the name later.
/// </summary>
public class PremiumAutoClaimTests : IDisposable
{
    private readonly RsaServerKeyPair _serverKey = new();
    private readonly TcpListener _listener;
    private readonly TcpClient _proxySide;
    private readonly TcpClient _clientSide;

    public PremiumAutoClaimTests()
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

    private PremiumLoginHandshake CreateHandshake(IPremiumSessionClient session, bool autoClaim = true) =>
        PremiumTestFactory.CreateHandshake(_serverKey, session,
            new PremiumOptions { Enabled = true, AutoClaimOnVerifiedLogin = autoClaim });

    /// <summary>Answers the Encryption Request the way any client would — genuine or cracked. Both
    /// can complete the crypto; only a genuine one passes Mojang's session check.</summary>
    private async Task RespondAsClientAsync()
    {
        NetworkStream stream = _clientSide.GetStream();
        Frame frame = await FrameReader.ReadFrameAsync(stream, FrameReader.MaxPreLoginFrameSize, CancellationToken.None);

        ReadOnlySpan<byte> payload = frame.Payload;
        VarInt.Decode(payload, out int idLength);
        ReadOnlySpan<byte> fields = payload[idLength..];

        int offset = 0;
        MinecraftPrimitives.ReadString(fields, out int serverIdLength);
        offset += serverIdLength;

        int publicKeyLength = VarInt.Decode(fields[offset..], out int publicKeyLengthSize);
        offset += publicKeyLengthSize;
        byte[] publicKeyDer = fields.Slice(offset, publicKeyLength).ToArray();
        offset += publicKeyLength;

        int tokenLength = VarInt.Decode(fields[offset..], out int tokenLengthSize);
        offset += tokenLengthSize;
        byte[] verifyToken = fields.Slice(offset, tokenLength).ToArray();

        using RSA clientRsa = RSA.Create();
        clientRsa.ImportSubjectPublicKeyInfo(publicKeyDer, out _);

        byte[] response = FrameWriter.WriteUncompressed(EncryptionResponsePacket.PacketId,
        [
            .. VarInt.Encode(128), .. clientRsa.Encrypt(RandomNumberGenerator.GetBytes(16), RSAEncryptionPadding.Pkcs1),
            .. VarInt.Encode(128), .. clientRsa.Encrypt(verifyToken, RSAEncryptionPadding.Pkcs1),
        ]);
        await stream.WriteAsync(response);
    }

    [Fact]
    public async Task GenuineAccount_ClaimsTheNamePermanently()
    {
        var entry = new IdentityEntry { Username = "Notch" };
        var uuid = Guid.NewGuid();
        var session = new FakePremiumSessionClient();
        session.SucceedWith(uuid, "Notch");

        Task client = RespondAsClientAsync();
        PremiumLoginOutcome outcome = await CreateHandshake(session)
            .TryAutoClaimAsync(_proxySide.GetStream(), entry, "Notch", CancellationToken.None);
        await client;

        Assert.True(outcome.Success);
        Assert.True(entry.PremiumRequired);   // the name is now locked...
        Assert.Equal(uuid, entry.PinnedUuid); // ...to this specific account

        // Locked at runtime, so it survives a restart. Without this the promise made to the player —
        // that only their account can ever use this name — lasted until the service came back up, and
        // then failed OPEN.
        Assert.True(entry.PremiumLockedAtRuntime);

        // And this is the moment the name joined the server. Only the password path used to record it,
        // so anybody taking the premium route showed a dash where their join date belonged — which
        // reads as missing data rather than as a different kind of account.
        Assert.NotNull(entry.RegisteredAt);
        Assert.Contains(entry.Events, e => e.Kind == PlayerEventKind.PremiumVerified);
    }

    [Fact]
    public async Task CrackedClient_RecordsNothingAtAll()
    {
        // The property the rejected design got backwards. A cracked client connecting first must not
        // be able to mark this name as anything — otherwise connecting early would be an attack.
        var entry = new IdentityEntry { Username = "Notch" };
        var session = new FakePremiumSessionClient(); // defaults to NotJoined

        Task client = RespondAsClientAsync();
        PremiumLoginOutcome outcome = await CreateHandshake(session)
            .TryAutoClaimAsync(_proxySide.GetStream(), entry, "Notch", CancellationToken.None);
        await client;

        Assert.False(outcome.Success);
        Assert.False(entry.PremiumRequired);
        Assert.Null(entry.PinnedUuid);
    }

    [Fact]
    public async Task RealOwner_CanStillClaimTheNameAfterACrackedClientUsedIt()
    {
        // The end-to-end consequence, stated as behaviour: getting there first buys an impostor
        // nothing permanent.
        var entry = new IdentityEntry { Username = "Notch" };

        var crackedSession = new FakePremiumSessionClient();
        Task cracked = RespondAsClientAsync();
        await CreateHandshake(crackedSession).TryAutoClaimAsync(_proxySide.GetStream(), entry, "Notch", CancellationToken.None);
        await cracked;

        Assert.False(entry.PremiumRequired);

        // Later, on a fresh connection, the genuine owner turns up.
        using var second = new PremiumAutoClaimTests();
        var ownerUuid = Guid.NewGuid();
        var ownerSession = new FakePremiumSessionClient();
        ownerSession.SucceedWith(ownerUuid, "Notch");

        Task owner = second.RespondAsClientAsync();
        PremiumLoginOutcome outcome = await second.CreateHandshake(ownerSession)
            .TryAutoClaimAsync(second._proxySide.GetStream(), entry, "Notch", CancellationToken.None);
        await owner;

        Assert.True(outcome.Success);
        Assert.True(entry.PremiumRequired);
        Assert.Equal(ownerUuid, entry.PinnedUuid);
    }

    [Fact]
    public async Task FailedClaim_StillReturnsTheSharedSecret_SoTheConnectionCanContinueEncrypted()
    {
        // Once the client has sent its Encryption Response it has switched its own cipher on, so the
        // caller needs the key to keep talking to it — the player is being let through, not kicked.
        var entry = new IdentityEntry { Username = "Notch" };
        var session = new FakePremiumSessionClient();

        Task client = RespondAsClientAsync();
        PremiumLoginOutcome outcome = await CreateHandshake(session)
            .TryAutoClaimAsync(_proxySide.GetStream(), entry, "Notch", CancellationToken.None);
        await client;

        Assert.False(outcome.Success);
        Assert.NotNull(outcome.SharedSecret);
    }

    [Fact]
    public void AutoClaim_IsOffByDefault()
    {
        // It changes the login handshake for every player on the server, so it must never switch
        // itself on — the operator has to choose it and test it.
        Assert.False(new PremiumOptions().AutoClaimOnVerifiedLogin);

        var handshake = PremiumTestFactory.CreateHandshake(_serverKey, new FakePremiumSessionClient(), new PremiumOptions());
        Assert.False(handshake.AutoClaimEnabled);
    }

    [Fact]
    public void AutoClaim_IsAlsoOff_WhenPremiumVerificationItselfIsDisabled()
    {
        var handshake = PremiumTestFactory.CreateHandshake(_serverKey, new FakePremiumSessionClient(),
            new PremiumOptions { Enabled = false, AutoClaimOnVerifiedLogin = true });

        Assert.False(handshake.AutoClaimEnabled);
    }

    [Fact]
    public async Task AlreadyPinnedName_IsNotStolenByADifferentVerifiedAccount()
    {
        var owner = Guid.NewGuid();
        var entry = new IdentityEntry { Username = "Notch" };
        entry.TryClaimOrMatchPinnedUuid(owner);

        var session = new FakePremiumSessionClient();
        session.SucceedWith(Guid.NewGuid(), "Notch"); // genuine, but a different account

        Task client = RespondAsClientAsync();
        PremiumLoginOutcome outcome = await CreateHandshake(session)
            .TryAutoClaimAsync(_proxySide.GetStream(), entry, "Notch", CancellationToken.None);
        await client;

        Assert.False(outcome.Success);
        Assert.True(outcome.PinnedToDifferentAccount);
        Assert.Equal(owner, entry.PinnedUuid);
    }
}
