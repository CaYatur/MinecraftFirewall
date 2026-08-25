using System.Net;
using MinecraftFirewall.Proxy.Network;
using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Telling the backend who is really connecting.
///
/// Without this every player on the server is 127.0.0.1: in the log, in a ban, and to every plugin
/// that reads an address. A moderator banning an IP bans the proxy, which is everyone. It showed up
/// as a one-line observation from somebody running the thing — every join in their server log had the
/// same address — and it is the sort of bug that only ever surfaces that way, because the firewall's
/// own log had the real addresses all along.
/// </summary>
public class IpForwardingTests
{
    // ---- PROXY protocol v2 ---------------------------------------------------------------------

    private static readonly byte[] Signature =
        [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

    [Fact]
    public void TheHeaderStartsWithSomethingNoMinecraftPacketCouldBe()
    {
        // This is what makes enabling it on only one side fail loudly instead of quietly. A server
        // that is not expecting a header cannot mistake this for a handshake: the first byte is a
        // frame length of 13, and what follows is not a packet.
        byte[] header = ProxyProtocolHeader.Build(
            new IPEndPoint(IPAddress.Parse("159.146.99.204"), 55798),
            new IPEndPoint(IPAddress.Loopback, 25565));

        Assert.Equal(Signature, header[..12]);
        Assert.Equal(0x21, header[12]); // version 2, command PROXY
        Assert.Equal(0x11, header[13]); // IPv4 over STREAM
    }

    [Fact]
    public void TheAddressAndPortsSurviveIntact()
    {
        byte[] header = ProxyProtocolHeader.Build(
            new IPEndPoint(IPAddress.Parse("159.146.99.204"), 55798),
            new IPEndPoint(IPAddress.Parse("192.168.1.10"), 25565));

        Assert.Equal(new byte[] { 159, 146, 99, 204 }, header[16..20]);
        Assert.Equal(new byte[] { 192, 168, 1, 10 }, header[20..24]);
        Assert.Equal(55798, (header[24] << 8) | header[25]);
        Assert.Equal(25565, (header[26] << 8) | header[27]);
        Assert.Equal(12, (header[14] << 8) | header[15]); // declared payload length
        Assert.Equal(28, header.Length);
    }

    [Fact]
    public void AnIpv4PlayerArrivingThroughADualStackSocketIsStillAnIpv4Player()
    {
        // Windows accepts IPv4 connections on an IPv6 socket as ::ffff:a.b.c.d. Passing that through
        // unchanged would put an address in the server's log that no operator would recognise as the
        // one they are looking for, and that no IPv4 ban would ever match.
        byte[] header = ProxyProtocolHeader.Build(
            new IPEndPoint(IPAddress.Parse("::ffff:159.146.99.204"), 55798),
            new IPEndPoint(IPAddress.Parse("::ffff:127.0.0.1"), 25565));

        Assert.Equal(0x11, header[13]); // IPv4, not IPv6
        Assert.Equal(new byte[] { 159, 146, 99, 204 }, header[16..20]);
    }

    [Fact]
    public void AGenuineIpv6PlayerIsSentAsIpv6()
    {
        byte[] header = ProxyProtocolHeader.Build(
            new IPEndPoint(IPAddress.Parse("2001:db8::1"), 55798),
            new IPEndPoint(IPAddress.IPv6Loopback, 25565));

        Assert.Equal(0x21, header[13]); // IPv6 over STREAM
        Assert.Equal(36, (header[14] << 8) | header[15]);
        Assert.Equal(52, header.Length);
    }

    [Fact]
    public void MismatchedFamiliesBendTheDestinationRatherThanTheSource()
    {
        // Both ends of a header have to be the same family. The source is the entire reason the header
        // exists, so when something has to give it is never that one.
        byte[] header = ProxyProtocolHeader.Build(
            new IPEndPoint(IPAddress.Parse("2001:db8::1"), 55798),
            new IPEndPoint(IPAddress.Loopback, 25565));

        Assert.Equal(0x21, header[13]);
        Assert.Equal(IPAddress.Parse("2001:db8::1").GetAddressBytes(), header[16..32]);
    }

    // ---- BungeeCord forwarding -------------------------------------------------------------------

    [Theory]
    [InlineData("CaYatur", "a4d612be-0690-3eb4-ad07-784b2492f7c3")]
    [InlineData("Im_Pikachu", "8fac8282-8f37-3ffa-beb5-3fe3926de0a3")]
    public void TheOfflineUuidMatchesWhatTheServerWouldHaveWorkedOutItself(string username, string expected)
    {
        // Taken from a real offline-mode server's own log, because getting this wrong would not look
        // like a bug. The UUID is the player's identity: their inventory, their home, their
        // permissions. A different one is indistinguishable from everyone's account being wiped.
        Assert.Equal(Guid.Parse(expected), BungeeCordHandshake.OfflineUuid(username));
    }

    [Fact]
    public void TheRewrittenHandshakeCarriesTheAddressTheHostnameAndTheUuid()
    {
        var handshake = new HandshakeInfo(774, "play.example.com", 25565, HandshakeNextState.Login);

        byte[] frame = BungeeCordHandshake.Rewrite(handshake, IPAddress.Parse("159.146.99.204"), "CaYatur");

        HandshakeInfo parsed = HandshakeReader.ParseHandshake(Payload(frame));
        string[] parts = parsed.ServerAddress.Split('\0');

        Assert.Equal(4, parts.Length);
        Assert.Equal("play.example.com", parts[0]);
        Assert.Equal("159.146.99.204", parts[1]);
        Assert.Equal(BungeeCordHandshake.OfflineUuid("CaYatur").ToString("N"), parts[2]);
        Assert.Equal("[]", parts[3]);
    }

    [Fact]
    public void EverythingElseAboutTheHandshakeIsLeftAlone()
    {
        var handshake = new HandshakeInfo(764, "play.example.com", 25577, HandshakeNextState.Login);

        HandshakeInfo parsed = HandshakeReader.ParseHandshake(
            Payload(BungeeCordHandshake.Rewrite(handshake, IPAddress.Loopback, "Steve")));

        Assert.Equal(764, parsed.ProtocolVersion);
        Assert.Equal(25577, parsed.ServerPort);
        Assert.Equal(HandshakeNextState.Login, parsed.NextState);
    }

    [Fact]
    public void AForgeClientsOwnMarkerIsDroppedRatherThanForwardedAlongside()
    {
        // Forge puts its own marker in the same field. Both sets of extra parts at once is not
        // something the receiving end can parse, and the forwarding fields are the ones that matter
        // here — the hostname itself is kept, because a server may well be routing on it.
        var handshake = new HandshakeInfo(774, "play.example.com\0FML3\0", 25565, HandshakeNextState.Login);

        HandshakeInfo parsed = HandshakeReader.ParseHandshake(
            Payload(BungeeCordHandshake.Rewrite(handshake, IPAddress.Parse("203.0.113.5"), "Steve")));
        string[] parts = parsed.ServerAddress.Split('\0');

        Assert.Equal(4, parts.Length);
        Assert.Equal("play.example.com", parts[0]);
        Assert.Equal("203.0.113.5", parts[1]);
    }

    /// <summary>Strips the frame's length prefix, leaving what the handshake parser expects.</summary>
    private static byte[] Payload(byte[] frame)
    {
        _ = VarInt.Decode(frame, out int prefix);
        return frame[prefix..];
    }
}
