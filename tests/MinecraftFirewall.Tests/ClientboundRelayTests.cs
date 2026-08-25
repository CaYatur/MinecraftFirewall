using MinecraftFirewall.Proxy.Protocol;
using MinecraftFirewall.Tests.TestDoubles;

namespace MinecraftFirewall.Tests;

/// <summary>
/// The backend's half of a connection.
///
/// This is the only place in the project that reads the server's side of a live session, and it is
/// carrying every byte the player receives while it does. That makes the failure mode unusually
/// unpleasant: a mistake here does not refuse a connection, it corrupts one mid-session, and the
/// player sees a decode error nobody can explain. So what is asserted throughout is not "the right
/// things were noticed" but "everything arrived, byte for byte, in order" — noticing is secondary.
///
/// The login phase gets as much attention as the rest, because the compression threshold it carries
/// decides how every packet the proxy composes is encoded. Getting that wrong is not a degraded
/// message, it is a disconnected player.
/// </summary>
public class ClientboundRelayTests
{
    private static PlayStatePacketIds Ids()
    {
        Assert.True(ProtocolVersionRegistry.TryGet(774, out PlayStatePacketIds ids));
        return ids;
    }

    private sealed record Result(byte[] Delivered, List<PlayerPosition> Positions, List<float> Health, ConnectionCompression Compression);

    private static async Task<Result> RunAsync(byte[] fromBackend, AuthHold? hold = null, int maxFrameBytes = 8 * 1024 * 1024)
    {
        var positions = new List<PlayerPosition>();
        var health = new List<float>();
        var compression = new ConnectionCompression();

        var relay = new ClientboundRelay(Ids(), compression, hold, positions.Add, health.Add, maxFrameBytes);

        using var backend = new MemoryStream(fromBackend, writable: false);
        using var client = new MemoryStream();

        try
        {
            await relay.RunAsync(backend, client, CancellationToken.None);
        }
        catch (EndOfStreamException)
        {
            // Running out of input is how these end.
        }

        return new Result(client.ToArray(), positions, health, compression);
    }

    // ---- the login phase ---------------------------------------------------------------------------

    [Fact]
    public async Task TheCompressionThresholdIsReadFromTheBackendRatherThanAssumed()
    {
        // The whole reason this phase is parsed. Every packet the proxy composes has to be encoded for
        // this number, and both a too-large uncompressed frame and a too-small compressed one are
        // refused by the client with a decoder error rather than being tolerated.
        Result result = await RunAsync([.. SetCompression(256), .. CompressedLoginSuccess()]);

        Assert.True(result.Compression.Established);
        Assert.Equal(256, result.Compression.Threshold);
    }

    [Fact]
    public async Task ABackendThatNeverEnablesCompressionSaysSoByFinishingTheLogin()
    {
        // "Off" has to be established rather than assumed too: with compression off, frames carry no
        // declared-length field at all, so the encoding is different again.
        Result result = await RunAsync(UncompressedLoginSuccess());

        Assert.True(result.Compression.Established);
        Assert.Equal(ConnectionCompression.NotCompressed, result.Compression.Threshold);
    }

    [Fact]
    public async Task NothingIsClaimedAboutCompressionBeforeTheBackendHasSaid()
    {
        // The proxy stays silent until this flips. A message held back for a moment is strictly better
        // than one encoded for a guess.
        Result result = await RunAsync(SetCompression(256));

        Assert.Equal(256, result.Compression.Threshold);

        Result nothing = await RunAsync([]);
        Assert.False(nothing.Compression.Established);
    }

    [Fact]
    public async Task ThresholdZeroOrBelowMeansCompressionIsOff()
    {
        // A server can disable compression by announcing a threshold of zero or less, and that is not
        // the same as "compress everything".
        Result result = await RunAsync([.. SetCompression(0), .. UncompressedLoginSuccess()]);

        Assert.Equal(ConnectionCompression.NotCompressed, result.Compression.Threshold);
    }

    // ---- carrying the traffic ----------------------------------------------------------------------

    [Fact]
    public async Task EveryByteTheBackendSendsReachesThePlayerUnchanged()
    {
        // The property that matters more than any detection this class performs.
        byte[] traffic =
        [
            .. SetCompression(256),
            .. CompressedLoginSuccess(),
            .. Position(1000, 70, -2000),
            .. Health(20f),
            .. MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(0x27), // keep-alive, ignored
            .. Health(11.5f),
        ];

        Result result = await RunAsync(traffic, new AuthHold());

        Assert.Equal(traffic, result.Delivered);
    }

    [Fact]
    public async Task ThePlayersPositionIsPickedOutAndRemembered()
    {
        var hold = new AuthHold();

        Result result = await RunAsync([.. SetCompression(256), .. CompressedLoginSuccess(), .. Position(1000, 70, -2000)], hold);

        PlayerPosition seen = Assert.Single(result.Positions);
        Assert.Equal(1000, seen.X);
        Assert.Equal(70, seen.Y);
        Assert.Equal(-2000, seen.Z);

        // Remembered on the hold as well, because it is the inspector — on the other thread — that
        // has to put the player back there once they log in.
        Assert.True(hold.HasBackendPosition);
        Assert.Equal(1000, hold.BackendPosition!.Value.X);
    }

    [Fact]
    public async Task HealthIsReportedInTheOrderItArrives()
    {
        Result result = await RunAsync(
            [.. SetCompression(256), .. CompressedLoginSuccess(), .. Health(20f), .. Health(14f)], new AuthHold());

        Assert.Equal([20f, 14f], result.Health);
    }

    [Fact]
    public async Task ALargeFrameIsCarriedWithoutBeingOpened()
    {
        // Chunk data runs to hundreds of kilobytes, and inflating every one of them to look for a
        // forty-byte position packet would make joining a server measurably slower for no benefit.
        // The frame still has to arrive intact, which is what this actually checks.
        byte[] big = FrameWriter.WriteCompressedFrameUncompressedPayload(0x28, new byte[16384]);

        byte[] traffic = [.. SetCompression(256), .. CompressedLoginSuccess(), .. big, .. Position(5, 6, 7)];
        Result result = await RunAsync(traffic, new AuthHold());

        Assert.Equal(traffic, result.Delivered);
        Assert.Single(result.Positions);
    }

    [Fact]
    public async Task WithNobodyHeldThePlayPhaseIsNotDecodedAtAll()
    {
        // An authenticated player's session must not pay for a login feature. Once the login phase is
        // over and there is no hold, this becomes a plain copy.
        byte[] traffic = [.. SetCompression(256), .. CompressedLoginSuccess(), .. Position(1, 2, 3), .. Health(3f)];

        Result result = await RunAsync(traffic, hold: null);

        Assert.Equal(traffic, result.Delivered);
        Assert.Empty(result.Positions);
        Assert.Empty(result.Health);
    }

    [Fact]
    public async Task OnceTheHoldIsReleasedTheRestOfTheStreamIsCopiedStraightThrough()
    {
        // The seam worth testing. Watching stops the moment a player authenticates, and the same
        // socket carries on being read by a plain copy — so anything left buffered, or a frame read
        // half-way, would corrupt the session rather than fail it. Nothing is buffered: frames are
        // read byte-exact from the stream, which is what makes the handover safe at any point.
        var hold = new AuthHold();
        var compression = new ConnectionCompression();

        byte[] prologue = [.. SetCompression(256), .. CompressedLoginSuccess()];
        byte[] beforeRelease = Position(1, 2, 3);
        byte[] afterRelease = [.. Health(20f), .. new byte[] { 0xAB, 0xCD, 0xEF }];

        var positions = new List<PlayerPosition>();
        var health = new List<float>();
        var relay = new ClientboundRelay(Ids(), compression, hold,
            _ =>
            {
                positions.Add(default);
                hold.Released = true; // the player authenticated, on the other thread
            },
            health.Add, 8 * 1024 * 1024);

        using var backend = new MemoryStream([.. prologue, .. beforeRelease, .. afterRelease], writable: false);
        using var client = new MemoryStream();

        await relay.RunAsync(backend, client, CancellationToken.None);

        Assert.Equal<byte>([.. prologue, .. beforeRelease, .. afterRelease], client.ToArray());
        Assert.Single(positions);
        Assert.Empty(health);
    }

    [Fact]
    public async Task AFrameTooLargeToReadEndsTheRelayRatherThanBeingGuessedAt()
    {
        // The ceiling is deliberately far above anything real, so reaching it means the stream is not
        // what this thinks it is. Stopping is the honest response; carrying on would mean writing
        // bytes to the player out of frame.
        await Assert.ThrowsAsync<InvalidDataException>(() => RunAsync(Position(1, 2, 3), new AuthHold(), maxFrameBytes: 16));
    }

    [Fact]
    public async Task AnUnreadableFrameIsStillDeliveredToThePlayer()
    {
        // This side is observed, never filtered. A packet the proxy cannot make sense of is still a
        // packet the client is entitled to receive — and the client, unlike the proxy, may well know
        // exactly what it is.
        byte[] payload = [.. VarInt.Encode(64), 0x01, 0x02, 0x03];
        byte[] nonsense = [.. VarInt.Encode(payload.Length), .. payload];

        byte[] traffic = [.. SetCompression(256), .. CompressedLoginSuccess(), .. nonsense];
        Result result = await RunAsync(traffic, new AuthHold());

        Assert.Equal(traffic, result.Delivered);
    }

    // ---- frame builders -----------------------------------------------------------------------------

    /// <summary>Login-state Set Compression: no declared-length field, because it is itself what turns
    /// that field on.</summary>
    private static byte[] SetCompression(int threshold)
    {
        byte[] inner = [.. VarInt.Encode(0x03), .. VarInt.Encode(threshold)];
        return [.. VarInt.Encode(inner.Length), .. inner];
    }

    private static byte[] UncompressedLoginSuccess()
    {
        byte[] inner = [.. VarInt.Encode(0x02)];
        return [.. VarInt.Encode(inner.Length), .. inner];
    }

    private static byte[] CompressedLoginSuccess() =>
        FrameWriter.WriteCompressedFrameUncompressedPayload(0x02, []);

    private static byte[] Position(double x, double y, double z) =>
        FrameWriter.WritePlayerPositionFrame(
            Ids().PlayPlayerPositionClientbound, Ids().PositionLayout, x, y, z, 0f, 0f,
            teleportId: 1, compressionThreshold: 256);

    private static byte[] Health(float health)
    {
        var fields = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteSingleBigEndian(fields, health);
        return FrameWriter.WriteCompressedFrameUncompressedPayload(Ids().PlaySetHealthClientbound, fields);
    }
}
