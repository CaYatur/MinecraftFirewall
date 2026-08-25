using System.Buffers.Binary;

namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>Where the backend believes a player is: the position it last synchronised to their
/// client. Recorded so the hold can be undone exactly, putting them back where they actually are
/// rather than somewhere approximated.</summary>
public readonly record struct PlayerPosition(double X, double Y, double Z, float Yaw, float Pitch);

/// <summary>
/// The state shared between the two halves of a held connection.
///
/// A player waiting at the login prompt is held by two pieces of code running at once: the inspector
/// reading what they send, and the pump carrying what the backend sends back. Pinning them in place
/// needs both — the pump is the only side that ever learns where the backend thinks they are, and the
/// inspector is the only side that knows when they have authenticated. This is the small amount of
/// state that has to cross between them, and every field on it is touched from both.
/// </summary>
public sealed class AuthHold
{
    /// <summary>
    /// The first teleport id the proxy issues for itself.
    ///
    /// Deliberately far above anything a server produces: Minecraft's own teleport ids start at zero
    /// and increment once per teleport, so a server would have to teleport a single player a billion
    /// times to reach this. Ids have to be distinguishable because the client answers every teleport
    /// with a confirmation, and forwarding a confirmation for a teleport the backend never sent would
    /// desynchronise it — while swallowing one it did send would leave the player unable to move.
    /// </summary>
    private const int FirstProxyTeleportId = 0x4000_0000;

    private readonly Lock _lock = new();
    private readonly HashSet<int> _proxyTeleportIds = [];
    private int _nextTeleportId = FirstProxyTeleportId;
    private PlayerPosition? _backendPosition;

    /// <summary>Set once the player authenticates, or once the hold ends for any other reason. The
    /// clientbound pump watches this to know when it can stop decoding packets and go back to being a
    /// plain byte copy.</summary>
    public volatile bool Released;

    /// <summary>True once the backend has told us where the player is. Until then there is nothing to
    /// pin them back to, so the hold does not move them at all.</summary>
    public bool HasBackendPosition
    {
        get { lock (_lock) return _backendPosition is not null; }
    }

    public PlayerPosition? BackendPosition
    {
        get { lock (_lock) return _backendPosition; }
    }

    public void RecordBackendPosition(PlayerPosition position)
    {
        lock (_lock) _backendPosition = position;
    }

    /// <summary>Reserves a teleport id for a teleport the proxy is about to send itself.</summary>
    public int NextProxyTeleportId()
    {
        lock (_lock)
        {
            int id = _nextTeleportId++;
            _proxyTeleportIds.Add(id);

            // A held player is re-pinned several times a second, so the set would otherwise grow for
            // as long as they sit there. Only the most recent ids can still be in flight.
            if (_proxyTeleportIds.Count > 64)
            {
                foreach (int stale in _proxyTeleportIds.Where(existing => existing < id - 64).ToArray())
                    _proxyTeleportIds.Remove(stale);
            }

            return id;
        }
    }

    /// <summary>True when this confirmation answers a teleport the proxy invented, which means it must
    /// be swallowed rather than passed to a backend that knows nothing about it.</summary>
    public bool IsProxyTeleport(int teleportId)
    {
        lock (_lock) return _proxyTeleportIds.Contains(teleportId);
    }
}

/// <summary>
/// Reads the backend's half of a held connection, one packet at a time, for as long as the player is
/// waiting to authenticate.
///
/// This exists for exactly two things the proxy cannot learn any other way: where the backend has
/// placed the player, and whether they are being hurt while they stand there unable to defend
/// themselves. Once the hold is released it stops decoding entirely and the caller goes back to a
/// plain byte copy — an authenticated player's connection should not pay for a login feature.
///
/// Large frames are forwarded without being decoded at all. Chunk data runs to hundreds of kilobytes
/// and inflating every one of them to look for a forty-byte position packet would make joining a
/// server measurably slower for no benefit.
/// </summary>
public sealed class ClientboundAuthWatcher(
    PlayStatePacketIds packetIds,
    AuthHold hold,
    Action<PlayerPosition> onPosition,
    Action<float> onHealth,
    int maxFrameBytes)
{
    /// <summary>Frames larger than this are passed through unopened. Everything this watcher looks
    /// for is a few dozen bytes; anything big is chunk, entity or inventory data.</summary>
    private const int DecodeCeiling = 4096;

    public async Task RunAsync(Stream backendStream, Stream clientStream, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && !hold.Released)
        {
            Frame frame = await FrameReader.ReadFrameAsync(backendStream, maxFrameBytes, ct).ConfigureAwait(false);
            await clientStream.WriteAsync(frame.Raw, ct).ConfigureAwait(false);

            if (frame.Raw.Length > DecodeCeiling)
                continue;

            Inspect(frame);
        }

        // Whatever is left is somebody else's to carry. Nothing is buffered here — every frame is read
        // byte-exact from the socket — so handing the stream on is safe at any point.
        if (!ct.IsCancellationRequested)
            await backendStream.CopyToAsync(clientStream, 81920, ct).ConfigureAwait(false);
    }

    private void Inspect(Frame frame)
    {
        DecodedPacket packet;
        try
        {
            packet = CompressedPacketReader.Decode(frame);
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            // Already forwarded verbatim. Failing to read something the proxy only wants to observe is
            // never a reason to interfere with a connection that is otherwise working.
            return;
        }

        try
        {
            if (packet.PacketId == packetIds.PlayPlayerPositionClientbound &&
                TryReadPosition(packet.Fields, packetIds.PositionLayout) is { } position)
            {
                hold.RecordBackendPosition(position);
                onPosition(position);
            }
            else if (packet.PacketId == packetIds.PlaySetHealthClientbound && packet.Fields.Length >= 4)
            {
                onHealth(BinaryPrimitives.ReadSingleBigEndian(packet.Fields));
            }
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            // Same reasoning: observation only.
        }
    }

    /// <summary>
    /// Reads the position out of a Synchronize Player Position packet, in whichever of the two field
    /// orders this version uses.
    ///
    /// Relative teleports are ignored rather than guessed at. A relative move is an offset from
    /// wherever the client currently is, and while the hold is on that is the origin rather than the
    /// player's real position — so applying one would record a location the backend never meant.
    /// </summary>
    internal static PlayerPosition? TryReadPosition(ReadOnlySpan<byte> fields, PositionLayout layout)
    {
        if (layout == PositionLayout.TeleportIdFirst)
        {
            // teleport id, x, y, z, delta x/y/z, yaw, pitch, 32-bit relative flags.
            _ = VarInt.Decode(fields, out int idLength);
            ReadOnlySpan<byte> rest = fields[idLength..];
            if (rest.Length < (8 * 6) + (4 * 2) + 4)
                return null;

            if (BinaryPrimitives.ReadInt32BigEndian(rest[((8 * 6) + (4 * 2))..]) != 0)
                return null;

            return new PlayerPosition(
                BinaryPrimitives.ReadDoubleBigEndian(rest),
                BinaryPrimitives.ReadDoubleBigEndian(rest[8..]),
                BinaryPrimitives.ReadDoubleBigEndian(rest[16..]),
                BinaryPrimitives.ReadSingleBigEndian(rest[48..]),
                BinaryPrimitives.ReadSingleBigEndian(rest[52..]));
        }

        // x, y, z, yaw, pitch, one flags byte, then the teleport id.
        if (fields.Length < (8 * 3) + (4 * 2) + 1)
            return null;

        if (fields[(8 * 3) + (4 * 2)] != 0)
            return null;

        return new PlayerPosition(
            BinaryPrimitives.ReadDoubleBigEndian(fields),
            BinaryPrimitives.ReadDoubleBigEndian(fields[8..]),
            BinaryPrimitives.ReadDoubleBigEndian(fields[16..]),
            BinaryPrimitives.ReadSingleBigEndian(fields[24..]),
            BinaryPrimitives.ReadSingleBigEndian(fields[28..]));
    }
}
