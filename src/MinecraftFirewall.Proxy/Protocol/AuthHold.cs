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
/// Carries the backend's half of a connection, reading only as much of it as the proxy actually needs.
///
/// It needs two things, and they are needed at different times. First, always: the compression
/// threshold the backend chooses during login, because every packet the proxy composes has to be
/// encoded for it and getting that wrong disconnects the player rather than being ignored. Second,
/// only while somebody is waiting at the login prompt: where the backend has placed them, and whether
/// something is hurting them while they stand there.
///
/// Three phases, and the phase decides how a frame is read — explicitly, rather than by trying one
/// format and catching the failure. Login frames carry no declared-length field at all; frames after
/// Set Compression do. Reading one as the other does not fail loudly, it silently misreads, and this
/// class is forwarding every byte the player receives while it works.
///
/// Once there is nothing left to learn it stops decoding entirely and becomes a plain copy. An
/// authenticated player's session should not pay for a login feature.
/// </summary>
public sealed class ClientboundRelay(
    PlayStatePacketIds packetIds,
    ConnectionCompression compression,
    AuthHold? hold,
    Action<PlayerPosition> onPosition,
    Action<float> onHealth,
    int maxFrameBytes)
{
    /// <summary>Frames larger than this are passed through unopened. Everything this looks for is a
    /// few dozen bytes; anything big is chunk, entity or inventory data, and inflating it to look for
    /// a forty-byte position packet would make joining measurably slower for no benefit.</summary>
    private const int DecodeCeiling = 4096;

    // Login-state clientbound ids. Part of the fixed pre-play protocol, unchanged for many years,
    // which is why they are named here rather than looked up per version.
    private const int LoginSuccess = 0x02;
    private const int SetCompression = 0x03;

    public async Task RunAsync(Stream backendStream, Stream clientStream, CancellationToken ct)
    {
        bool inLoginPhase = true;

        while (!ct.IsCancellationRequested)
        {
            if (!inLoginPhase && (hold is null || hold.Released))
                break;

            Frame frame = await FrameReader.ReadFrameAsync(backendStream, maxFrameBytes, ct).ConfigureAwait(false);
            await clientStream.WriteAsync(frame.Raw, ct).ConfigureAwait(false);

            if (inLoginPhase)
            {
                inLoginPhase = !ReadLoginFrame(frame);
                continue;
            }

            if (frame.Raw.Length <= DecodeCeiling)
                InspectPlayFrame(frame);
        }

        // Whatever is left is somebody else's to carry. Nothing is buffered here — every frame is read
        // byte-exact from the socket — so handing the stream on is safe at any point.
        if (!ct.IsCancellationRequested)
            await backendStream.CopyToAsync(clientStream, 81920, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads one login-phase frame. Returns true once the login phase is over.
    ///
    /// Set Compression is the packet worth waiting for, and Login Success is the one that ends the
    /// phase. A backend that never sends the first still sends the second, which is how "compression
    /// is off" gets established rather than assumed.
    /// </summary>
    private bool ReadLoginFrame(Frame frame)
    {
        try
        {
            // Before Set Compression the frame is [length][packetId][fields] with no declared length;
            // after it, the compressed form applies. The flag decides which, rather than a guess.
            if (compression.Established)
            {
                DecodedPacket decoded = CompressedPacketReader.Decode(frame);
                return decoded.PacketId == LoginSuccess;
            }

            ReadOnlySpan<byte> payload = frame.Payload;
            int packetId = VarInt.Decode(payload, out int idLength);

            if (packetId == SetCompression)
            {
                int threshold = VarInt.Decode(payload[idLength..], out _);
                compression.UseThreshold(threshold);
                return false; // Login Success still follows, now compressed
            }

            if (packetId == LoginSuccess)
            {
                compression.UseNoCompression();
                return true;
            }

            return false;
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            // Already forwarded verbatim. A login frame this cannot read is not a reason to interfere
            // with a connection that is otherwise working — it only means the proxy stays quiet, since
            // nothing is sent until the threshold is known.
            return false;
        }
    }

    private void InspectPlayFrame(Frame frame)
    {
        if (hold is null)
            return;

        DecodedPacket packet;
        try
        {
            packet = CompressedPacketReader.Decode(frame);
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            // Already forwarded. Failing to read something the proxy only wants to observe is never a
            // reason to interfere with a working connection.
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
