using System.Buffers.Binary;
using MinecraftFirewall.Proxy.Inspection;
using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Refusing packets a real client could not have sent.
///
/// Half of these assert that something is refused. The other half matter more: they assert that
/// ordinary play is not. A filter in front of a server that rejects one legitimate packet in a
/// thousand is worse than no filter at all, because the symptom is a game that intermittently
/// misbehaves and the cause is invisible from inside it.
/// </summary>
public class PacketSanitiserTests
{
    // ---- interact --------------------------------------------------------------------------------

    private static byte[] Interact(int target, int type, float[]? at = null, int? hand = null)
    {
        var bytes = new List<byte>();
        bytes.AddRange(VarInt.Encode(target));
        bytes.AddRange(VarInt.Encode(type));

        foreach (float value in at ?? [])
        {
            var buffer = new byte[4];
            BinaryPrimitives.WriteSingleBigEndian(buffer, value);
            bytes.AddRange(buffer);
        }

        if (hand is { } h)
            bytes.AddRange(VarInt.Encode(h));

        bytes.Add(0x00); // sneaking
        return [.. bytes];
    }

    [Fact]
    public void AnOrdinaryAttackIsLeftAlone()
    {
        Assert.Null(PacketSanitiser.InspectInteract(Interact(target: 412, type: 1)));
    }

    [Fact]
    public void AnOrdinaryRightClickIsLeftAlone()
    {
        Assert.Null(PacketSanitiser.InspectInteract(Interact(target: 412, type: 0, hand: 0)));
        Assert.Null(PacketSanitiser.InspectInteract(Interact(target: 412, type: 0, hand: 1)));
    }

    [Fact]
    public void AnOrdinaryInteractAtIsLeftAlone()
    {
        // The offset is relative to the entity, so it is always small — a fraction of a block.
        Assert.Null(PacketSanitiser.InspectInteract(
            Interact(target: 412, type: 2, at: [0.13f, 1.62f, -0.44f], hand: 0)));
    }

    [Fact]
    public void AnInteractionTypeThatDoesNotExistIsRefused()
    {
        // The server looks this up in a table with three entries. A fourth value is not a gesture it
        // does not recognise, it is an index it does not have.
        PayloadFinding? finding = PacketSanitiser.InspectInteract(Interact(target: 1, type: 7));

        Assert.NotNull(finding);
        Assert.Equal("invalid-interaction-type", finding.Rule);
        Assert.Equal(PayloadSeverity.ProtocolViolation, finding.Severity);
    }

    [Fact]
    public void ANegativeEntityIdIsRefused()
    {
        PayloadFinding? finding = PacketSanitiser.InspectInteract(Interact(target: -5, type: 1));

        Assert.NotNull(finding);
        Assert.Equal("negative-entity-id", finding.Rule);
    }

    [Theory]
    [InlineData(float.NaN)]
    [InlineData(float.PositiveInfinity)]
    [InlineData(float.NegativeInfinity)]
    [InlineData(9.0E9f)]
    public void ACoordinateThatIsNotANumberIsRefused(float bad)
    {
        // The same rule movement already applies, extended to the other packet carrying a position.
        PayloadFinding? finding = PacketSanitiser.InspectInteract(
            Interact(target: 1, type: 2, at: [bad, 1f, 1f], hand: 0));

        Assert.NotNull(finding);
        Assert.Equal("impossible-interact-position", finding.Rule);
    }

    [Fact]
    public void AHandThatIsNeitherHandIsRefused()
    {
        PayloadFinding? finding = PacketSanitiser.InspectInteract(Interact(target: 1, type: 0, hand: 9));

        Assert.NotNull(finding);
        Assert.Equal("invalid-hand", finding.Rule);
    }

    [Fact]
    public void AnInteractAtWithoutItsCoordinatesIsRefused()
    {
        PayloadFinding? finding = PacketSanitiser.InspectInteract([.. VarInt.Encode(1), .. VarInt.Encode(2)]);

        Assert.NotNull(finding);
        Assert.Equal("truncated-interact", finding.Rule);
    }

    [Fact]
    public void AnInteractWithNothingReadableInItIsRefused()
    {
        Assert.NotNull(PacketSanitiser.InspectInteract([]));
    }

    // ---- swing -----------------------------------------------------------------------------------

    [Fact]
    public void AnOrdinarySwingIsLeftAlone()
    {
        Assert.Null(PacketSanitiser.InspectSwing([.. VarInt.Encode(0)]));
        Assert.Null(PacketSanitiser.InspectSwing([.. VarInt.Encode(1)]));
    }

    [Fact]
    public void ASwingWithAThirdHandIsRefused()
    {
        PayloadFinding? finding = PacketSanitiser.InspectSwing([.. VarInt.Encode(2)]);

        Assert.NotNull(finding);
        Assert.Equal("invalid-hand", finding.Rule);
    }

    [Fact]
    public void ASwingWithBytesAfterItsOnlyFieldIsRefused()
    {
        // A fixed-length packet with more in it is the shape of a client trying to make a decoder read
        // past what it expected.
        PayloadFinding? finding = PacketSanitiser.InspectSwing([.. VarInt.Encode(0), 0xFF, 0xFF, 0xFF]);

        Assert.NotNull(finding);
        Assert.Equal("trailing-bytes", finding.Rule);
    }

    [Fact]
    public void AnEmptySwingIsRefused()
    {
        Assert.NotNull(PacketSanitiser.InspectSwing([]));
    }

    // ---- the rule the whole thing rests on --------------------------------------------------------

    [Fact]
    public void EverythingRefusedHereIsACertaintyRatherThanAJudgement()
    {
        // The severity decides whether a refusal counts towards a ban. Anything this file rejects is
        // something no client produces by playing, so all of it is unambiguous — and if a heuristic
        // ever wandered in here, it would start banning people for a guess.
        PayloadFinding?[] findings =
        [
            PacketSanitiser.InspectInteract(Interact(target: -1, type: 1)),
            PacketSanitiser.InspectInteract(Interact(target: 1, type: 99)),
            PacketSanitiser.InspectInteract(Interact(target: 1, type: 0, hand: 4)),
            PacketSanitiser.InspectSwing([.. VarInt.Encode(6)]),
            PacketSanitiser.InspectSwing([.. VarInt.Encode(0), 0x00]),
        ];

        foreach (PayloadFinding? finding in findings)
        {
            Assert.NotNull(finding);
            Assert.Equal(PayloadSeverity.ProtocolViolation, finding.Severity);
        }
    }
}
