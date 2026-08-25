using System.Buffers.Binary;
using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Proxy.Inspection;

/// <summary>
/// Refuses serverbound packets that are structurally impossible, before a server has to decide what
/// to do with them.
///
/// This is what plugins like PacketFixer are for, and the reason a firewall is a better place for it
/// than a plugin is order: a plugin runs after the server has already parsed the packet, which is
/// where the damage is done. A malformed enum, a negative array length or a coordinate that is not a
/// number reaches the server's own decoder first, and "the plugin then rejected it" is no comfort if
/// the decoder threw.
///
/// The discipline is the same one the rest of this project follows and is worth restating, because it
/// is what separates this from a filter that breaks ordinary play: **only layouts that come out of the
/// generated tables are opened, and only fields whose meaning is fixed are judged.** Nothing here
/// guesses. A packet whose fields do not decode cleanly is forwarded untouched rather than refused —
/// an unverified field offset is never worth a wrong refusal, and a mod inventing its own traffic is
/// far likelier than an attack.
///
/// What is judged, then, is a short list where a real client has exactly one possible answer:
///
///   * An interaction type outside the three that exist. A client sends 0, 1 or 2; anything else is a
///     value the server will look up in a table that has three entries.
///   * A hand that is neither of the two hands.
///   * A negative entity id, which no entity has.
///   * Coordinates on an interaction that are NaN, infinite, or further away than the world is wide —
///     the same rule movement already applies, extended to the other packet that carries a position.
///   * Trailing bytes on a packet whose length is fixed. A real client sends the fields and stops.
///
/// Every one of these is a certainty rather than a judgement, which is why they are refused outright
/// rather than scored. The heuristics live elsewhere, and they only ever report.
/// </summary>
public static class PacketSanitiser
{
    /// <summary>The three interaction kinds: interact, attack, interact-at. A fourth value does not
    /// mean anything.</summary>
    private const int MaxInteractionType = 2;

    /// <summary>Main hand and off hand.</summary>
    private const int MaxHand = 1;

    /// <summary>
    /// How far from the origin an interaction coordinate may be.
    ///
    /// Matches the world border's own maximum. This is not a reach check — the offset in an
    /// interact-at is relative to the entity and tiny — it is a check that the number is a number at
    /// all. Anything at this scale is either a corrupted field or a deliberately absurd one.
    /// </summary>
    private const float CoordinateLimit = 3.0E7f;

    /// <summary>Checks one interaction packet: which entity, what kind of interaction, and where.</summary>
    public static PayloadFinding? InspectInteract(ReadOnlySpan<byte> fields)
    {
        int target, type;
        ReadOnlySpan<byte> rest;

        try
        {
            target = VarInt.Decode(fields, out int targetLength);
            rest = fields[targetLength..];
            type = VarInt.Decode(rest, out int typeLength);
            rest = rest[typeLength..];
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            // Two VarInts is the one part of this packet's shape that has never varied. A packet that
            // cannot produce them is not one this can reason about at all.
            return new PayloadFinding("unreadable-interact",
                "an interact packet whose target and type could not be read", PayloadSeverity.ProtocolViolation);
        }

        if (target < 0)
        {
            return new PayloadFinding("negative-entity-id",
                $"interact aimed at entity id {target}, which cannot exist", PayloadSeverity.ProtocolViolation);
        }

        if (type is < 0 or > MaxInteractionType)
        {
            return new PayloadFinding("invalid-interaction-type",
                $"interaction type {type}, outside the {MaxInteractionType + 1} kinds that exist",
                PayloadSeverity.ProtocolViolation);
        }

        // The three coordinates are only present on interact-at, which is what the type field selects.
        if (type == MaxInteractionType)
        {
            if (rest.Length < 12)
            {
                return new PayloadFinding("truncated-interact",
                    "an interact-at packet without its coordinates", PayloadSeverity.ProtocolViolation);
            }

            for (int offset = 0; offset < 12; offset += 4)
            {
                float value = BinaryPrimitives.ReadSingleBigEndian(rest[offset..]);
                if (!float.IsFinite(value) || Math.Abs(value) > CoordinateLimit)
                {
                    return new PayloadFinding("impossible-interact-position",
                        $"interact-at carried the coordinate {value}", PayloadSeverity.ProtocolViolation);
                }
            }

            rest = rest[12..];
        }

        // A hand follows on everything except a plain attack.
        if (type == 1)
            return null;

        try
        {
            int hand = VarInt.Decode(rest, out _);
            if (hand is < 0 or > MaxHand)
            {
                return new PayloadFinding("invalid-hand",
                    $"interact used hand {hand}, and there are two hands", PayloadSeverity.ProtocolViolation);
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            // Forwarded. The hand is the last field before a trailing boolean whose presence has
            // shifted between versions, and a wrong refusal here would cost more than it saves.
            return null;
        }

        return null;
    }

    /// <summary>Checks a swing packet, which is one field long and has been for every version this
    /// project covers.</summary>
    public static PayloadFinding? InspectSwing(ReadOnlySpan<byte> fields)
    {
        int hand;
        int handLength;

        try
        {
            hand = VarInt.Decode(fields, out handLength);
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            return new PayloadFinding("unreadable-swing",
                "a swing packet with no readable hand", PayloadSeverity.ProtocolViolation);
        }

        if (hand is < 0 or > MaxHand)
        {
            return new PayloadFinding("invalid-hand",
                $"swing used hand {hand}, and there are two hands", PayloadSeverity.ProtocolViolation);
        }

        // Nothing follows the hand in any version covered here. Extra bytes on a fixed-length packet
        // are the shape of a client trying to make a decoder read past what it expected.
        if (fields.Length > handLength)
        {
            return new PayloadFinding("trailing-bytes",
                $"a swing packet with {fields.Length - handLength} unexpected byte(s) after its only field",
                PayloadSeverity.ProtocolViolation);
        }

        return null;
    }
}
