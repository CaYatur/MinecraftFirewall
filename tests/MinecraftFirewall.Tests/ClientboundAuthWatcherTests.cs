using MinecraftFirewall.Proxy.Protocol;
using MinecraftFirewall.Tests.TestDoubles;

namespace MinecraftFirewall.Tests;

/// <summary>
/// The backend's half of a held connection.
///
/// This is the only place in the project that reads the server's side of a live session, and it is
/// carrying every byte the player receives while it does. That makes the failure mode unusually
/// unpleasant: a mistake here does not refuse a connection, it corrupts one mid-session, and the
/// player sees a decode error nobody can explain. So what is asserted throughout is not "the right
/// things were noticed" but "everything arrived, byte for byte, in order" — noticing is secondary.
/// </summary>
public class ClientboundAuthWatcherTests
{
    private static PlayStatePacketIds Ids()
    {
        Assert.True(ProtocolVersionRegistry.TryGet(774, out PlayStatePacketIds ids));
        return ids;
    }

    private static async Task<(byte[] Delivered, List<PlayerPosition> Positions, List<float> Health)> RunAsync(
        AuthHold hold, byte[] fromBackend, int maxFrameBytes = 8 * 1024 * 1024)
    {
        var positions = new List<PlayerPosition>();
        var health = new List<float>();

        var watcher = new ClientboundAuthWatcher(Ids(), hold, positions.Add, health.Add, maxFrameBytes);

        using var backend = new MemoryStream(fromBackend, writable: false);
        using var client = new MemoryStream();

        try
        {
            await watcher.RunAsync(backend, client, CancellationToken.None);
        }
        catch (EndOfStreamException)
        {
            // Running out of input is how these end.
        }

        return (client.ToArray(), positions, health);
    }

    [Fact]
    public async Task EveryByteTheBackendSendsReachesThePlayerUnchanged()
    {
        // The property that matters more than any detection this class performs.
        var hold = new AuthHold();
        byte[] traffic =
        [
            .. Position(1000, 70, -2000),
            .. Health(20f),
            .. MinecraftPacketBuilder.BuildCompressedEmptyPacketFrame(0x27), // keep-alive, ignored
            .. Health(11.5f),
        ];

        (byte[] delivered, _, _) = await RunAsync(hold, traffic);

        Assert.Equal(traffic, delivered);
    }

    [Fact]
    public async Task ThePlayersPositionIsPickedOutAndRemembered()
    {
        var hold = new AuthHold();

        (_, List<PlayerPosition> positions, _) = await RunAsync(hold, Position(1000, 70, -2000));

        PlayerPosition seen = Assert.Single(positions);
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
        var hold = new AuthHold();

        (_, _, List<float> health) = await RunAsync(hold, [.. Health(20f), .. Health(14f)]);

        Assert.Equal([20f, 14f], health);
    }

    [Fact]
    public async Task ALargeFrameIsCarriedWithoutBeingOpened()
    {
        // Chunk data runs to hundreds of kilobytes, and inflating every one of them to look for a
        // forty-byte position packet would make joining a server measurably slower for no benefit.
        // The frame still has to arrive intact, which is what this actually checks.
        var hold = new AuthHold();
        byte[] big = FrameWriter.WriteCompressedFrameUncompressedPayload(0x28, new byte[16384]);

        byte[] traffic = [.. big, .. Position(5, 6, 7)];
        (byte[] delivered, List<PlayerPosition> positions, _) = await RunAsync(hold, traffic);

        Assert.Equal(traffic, delivered);
        Assert.Single(positions);
    }

    [Fact]
    public async Task OnceTheHoldIsReleasedTheRestOfTheStreamIsCopiedStraightThrough()
    {
        // The seam worth testing. Watching stops the moment a player authenticates, and the same
        // socket carries on being read by a plain copy — so anything left buffered, or a frame read
        // half-way, would corrupt the session rather than fail it. Nothing is buffered: frames are
        // read byte-exact from the stream, which is what makes the handover safe at any point.
        var hold = new AuthHold();

        byte[] beforeRelease = Position(1, 2, 3);
        byte[] afterRelease = [.. Health(20f), .. new byte[] { 0xAB, 0xCD, 0xEF }];

        var positions = new List<PlayerPosition>();
        var health = new List<float>();
        var watcher = new ClientboundAuthWatcher(Ids(), hold,
            _ =>
            {
                positions.Add(default);
                hold.Released = true; // the player authenticated, on the other thread
            },
            health.Add, 8 * 1024 * 1024);

        using var backend = new MemoryStream([.. beforeRelease, .. afterRelease], writable: false);
        using var client = new MemoryStream();

        await watcher.RunAsync(backend, client, CancellationToken.None);

        // Everything arrived, in order, and the tail went through untouched rather than being decoded.
        Assert.Equal<byte>([.. beforeRelease, .. afterRelease], client.ToArray());
        Assert.Single(positions);
        Assert.Empty(health);
    }

    [Fact]
    public async Task AFrameTooLargeToReadEndsTheWatchRatherThanBeingGuessedAt()
    {
        // The ceiling is deliberately far above anything real, so reaching it means the stream is not
        // what this thinks it is. Stopping is the honest response; carrying on would mean writing
        // bytes to the player out of frame.
        var hold = new AuthHold();

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
        {
            var watcher = new ClientboundAuthWatcher(Ids(), hold, _ => { }, _ => { }, maxFrameBytes: 16);
            using var backend = new MemoryStream(Position(1, 2, 3), writable: false);
            using var client = new MemoryStream();
            await watcher.RunAsync(backend, client, CancellationToken.None);
        });
    }

    [Fact]
    public async Task AnUnreadableFrameIsStillDeliveredToThePlayer()
    {
        // This side is observed, never filtered. A packet the proxy cannot make sense of is still a
        // packet the client is entitled to receive — and the client, unlike the proxy, may well know
        // exactly what it is.
        var hold = new AuthHold();

        // Claims to be compressed, but the payload is not valid deflate.
        byte[] payload = [.. VarInt.Encode(64), 0x01, 0x02, 0x03];
        byte[] nonsense = [.. VarInt.Encode(payload.Length), .. payload];

        (byte[] delivered, _, _) = await RunAsync(hold, nonsense);

        Assert.Equal(nonsense, delivered);
    }

    private static byte[] Position(double x, double y, double z) =>
        FrameWriter.WritePlayerPositionFrame(
            Ids().PlayPlayerPositionClientbound, Ids().PositionLayout, x, y, z, 0f, 0f, teleportId: 1);

    private static byte[] Health(float health)
    {
        var fields = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteSingleBigEndian(fields, health);
        return FrameWriter.WriteCompressedFrameUncompressedPayload(Ids().PlaySetHealthClientbound, fields);
    }
}
