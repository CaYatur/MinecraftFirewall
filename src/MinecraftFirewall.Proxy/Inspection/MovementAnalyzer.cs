using System.Buffers.Binary;

namespace MinecraftFirewall.Proxy.Inspection;

/// <summary>How seriously a movement finding should be taken.</summary>
public enum MovementSeverity
{
    /// <summary>Nothing wrong.</summary>
    None,

    /// <summary>The player moved in a way that looks impossible, which is a claim this proxy is not
    /// well placed to make — see <see cref="MovementAnalyzer"/>. Reported, never enforced by default.</summary>
    Suspicious,

    /// <summary>The packet is not something a Minecraft client produces: NaN, infinity, or a
    /// coordinate outside the absolute world limit. Enforced by default, because there is no
    /// legitimate reading of it.</summary>
    Invalid,
}

public readonly record struct MovementFinding(MovementSeverity Severity, string Detail)
{
    public static readonly MovementFinding None = new(MovementSeverity.None, "");
}

/// <summary>
/// Watches a connection's movement packets.
///
/// Two very different jobs live here and the code keeps them apart on purpose.
///
/// The first is rejecting coordinates that are not numbers. NaN and infinity in a position packet are
/// a long-standing way to upset a server's physics and chunk maths, and a coordinate past ±3.2e7 is
/// outside anything the world can address. No client produces these by playing, so they are refused
/// with no hesitation and no configuration.
///
/// The second is noticing that someone moved further than seems possible — and here the honest
/// position is that a proxy is a bad place to judge. This code sees coordinates and timestamps.
/// It does not know whether the player is on ice, in a boat or minecart, wearing an elytra, using a
/// riptide trident, holding a speed potion, standing in a bubble column, being launched by a slime
/// block, or has just been teleported by a plugin — all of which produce exactly the readings a
/// speed cheat produces. A server-side anti-cheat has the world state to tell those apart. This does
/// not, and so what it produces is a report, not a verdict, unless someone explicitly turns
/// enforcement on after watching their own server's numbers.
///
/// Layout handling is deliberately conservative. Field sizes are only interpreted when they match
/// exactly what protocol 774 defines; anything else is left alone and forwarded rather than guessed
/// at, and a connection whose packets never match is dropped from analysis with a single log line.
/// The cost of a wrong guess here would be paid by every legitimate player at once.
/// </summary>
public sealed class MovementAnalyzer(InspectionOptions options)
{
    /// <summary>Minecraft's absolute coordinate limit — the point past which the server's own
    /// position handling stops being meaningful.</summary>
    private const double AbsoluteCoordinateLimit = 3.2e7;

    // Field layouts for protocol 774. Since 1.21.2 the movement packets end in a flags byte rather
    // than a bare on-ground boolean, which is why these are 25/33 rather than 25/33 minus one.
    private const int MovePosFieldBytes = 8 + 8 + 8 + 1;              // x, y, z, flags
    private const int MovePosRotFieldBytes = 8 + 8 + 8 + 4 + 4 + 1;   // x, y, z, yaw, pitch, flags

    private double _lastX, _lastY, _lastZ;
    private DateTimeOffset _lastMove;
    private bool _havePrevious;
    private int _consecutiveAnomalies;
    private int _layoutMismatches;
    private int _layoutMatches;

    /// <summary>Set once when this connection's packets never matched the expected layout, so the
    /// caller can say so exactly once instead of on every packet.</summary>
    public bool LayoutUnrecognised { get; private set; }

    public int TotalAnomalies { get; private set; }

    public double PeakBlocksPerSecond { get; private set; }

    public MovementFinding Inspect(ReadOnlySpan<byte> fields, DateTimeOffset now)
    {
        if (!TryReadPosition(fields, out double x, out double y, out double z))
            return MovementFinding.None;

        if (options.BlockImpossibleCoordinates)
        {
            MovementFinding invalid = CheckCoordinatesAreReal(x, y, z);
            if (invalid.Severity != MovementSeverity.None)
                return invalid;
        }

        if (!options.AnalyseMovement)
            return MovementFinding.None;

        return CheckSpeed(x, y, z, now);
    }

    /// <summary>Rotation-only and status-only packets carry no coordinates, so there is nothing to
    /// check — but they do mean time has passed without a position, which would otherwise make the
    /// next position look like a huge jump. Resetting the clock is what stops that.</summary>
    public void NoteNonPositionalMovement() => _havePrevious = false;

    private bool TryReadPosition(ReadOnlySpan<byte> fields, out double x, out double y, out double z)
    {
        x = y = z = 0;

        if (fields.Length is not (MovePosFieldBytes or MovePosRotFieldBytes))
        {
            // Not the layout this version is documented to use. Rather than guess at an offset — which
            // would mean reading someone's rotation as their position — this stays out of the way.
            if (++_layoutMismatches >= 8 && _layoutMatches == 0)
                LayoutUnrecognised = true;

            return false;
        }

        _layoutMatches++;

        // Minecraft is big-endian on the wire, which is the opposite of x86, so these cannot be read
        // as a plain reinterpret cast.
        x = BinaryPrimitives.ReadDoubleBigEndian(fields[..8]);
        y = BinaryPrimitives.ReadDoubleBigEndian(fields[8..16]);
        z = BinaryPrimitives.ReadDoubleBigEndian(fields[16..24]);
        return true;
    }

    private static MovementFinding CheckCoordinatesAreReal(double x, double y, double z)
    {
        if (double.IsNaN(x) || double.IsNaN(y) || double.IsNaN(z))
            return new MovementFinding(MovementSeverity.Invalid, "position contained NaN");

        if (double.IsInfinity(x) || double.IsInfinity(y) || double.IsInfinity(z))
            return new MovementFinding(MovementSeverity.Invalid, "position contained infinity");

        if (Math.Abs(x) > AbsoluteCoordinateLimit || Math.Abs(z) > AbsoluteCoordinateLimit || Math.Abs(y) > AbsoluteCoordinateLimit)
        {
            return new MovementFinding(MovementSeverity.Invalid,
                $"position ({x:0.#}, {y:0.#}, {z:0.#}) is outside the world limit");
        }

        return MovementFinding.None;
    }

    private MovementFinding CheckSpeed(double x, double y, double z, DateTimeOffset now)
    {
        if (!_havePrevious)
        {
            Remember(x, y, z, now);
            return MovementFinding.None;
        }

        double seconds = (now - _lastMove).TotalSeconds;

        // Two packets in the same instant give no usable rate, and a long gap means the connection
        // stalled — treating a lag spike as a speed reading is the single easiest way to produce a
        // false accusation.
        if (seconds is < 0.02 or > 2.0)
        {
            Remember(x, y, z, now);
            return MovementFinding.None;
        }

        double horizontal = Math.Sqrt(((x - _lastX) * (x - _lastX)) + ((z - _lastZ) * (z - _lastZ))) / seconds;
        double vertical = (y - _lastY) / seconds;

        Remember(x, y, z, now);

        if (horizontal > PeakBlocksPerSecond)
            PeakBlocksPerSecond = horizontal;

        bool tooFast = horizontal > options.MaxHorizontalBlocksPerSecond;
        bool tooHigh = vertical > options.MaxVerticalBlocksPerSecond;

        if (!tooFast && !tooHigh)
        {
            _consecutiveAnomalies = 0;
            return MovementFinding.None;
        }

        // Counted consecutively rather than cumulatively. A teleport, a lag spike or a boat ride
        // produces isolated readings; a movement cheat produces a run of them, and only the run is
        // worth reporting.
        if (++_consecutiveAnomalies < options.MovementAnomaliesBeforeReport)
            return MovementFinding.None;

        _consecutiveAnomalies = 0;
        TotalAnomalies++;

        return new MovementFinding(MovementSeverity.Suspicious, tooFast
            ? $"moved {horizontal:0.#} blocks/second horizontally over {options.MovementAnomaliesBeforeReport} consecutive updates"
            : $"climbed {vertical:0.#} blocks/second over {options.MovementAnomaliesBeforeReport} consecutive updates");
    }

    private void Remember(double x, double y, double z, DateTimeOffset now)
    {
        _lastX = x;
        _lastY = y;
        _lastZ = z;
        _lastMove = now;
        _havePrevious = true;
    }
}
