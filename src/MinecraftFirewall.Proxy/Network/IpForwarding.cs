using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Proxy.Network;

/// <summary>
/// How the backend is told who is really connecting.
///
/// Without one of these, every player on the server is 127.0.0.1. That is not cosmetic: it is the
/// address in the server log, the address a ban lands on, and the address every plugin that does
/// anything per-player reads. A moderator banning an IP bans the proxy, which is everyone.
///
/// Both options need the backend configured to expect them, and neither is safe to enable without
/// that — a server told to read a forwarded address will believe whoever it is talking to, so the
/// backend port must not be reachable from anywhere but this machine. That is already how this
/// project tells people to run it, and the control panel checks it.
/// </summary>
public enum IpForwardingMode
{
    /// <summary>Forward nothing. The backend sees the proxy's own address, which is what it saw
    /// before this existed.</summary>
    None,

    /// <summary>
    /// HAProxy's PROXY protocol v2: a small binary header before the first Minecraft byte.
    ///
    /// The better choice where the server supports it. It knows nothing about Minecraft, so it does
    /// not change with the game's protocol, works for the server-list ping as well as for joining,
    /// and cannot interact with anything else in the handshake. Paper enables it with
    /// proxies.proxy-protocol in config/paper-global.yml; Velocity and Waterfall have their own
    /// equivalents.
    /// </summary>
    ProxyProtocol,

    /// <summary>
    /// BungeeCord-style forwarding: the handshake's server-address field is replaced with the address,
    /// the real client IP, the player's UUID and their profile properties, separated by nulls.
    ///
    /// Here because a great many servers are already set up for it — it is what spigot.yml's
    /// bungeecord option reads. It only applies when somebody actually logs in, since a server-list
    /// ping has no player to describe, and it only makes sense on an offline-mode server, which is
    /// the only kind this firewall is for.
    /// </summary>
    BungeeCord,
}

/// <summary>
/// Builds the PROXY protocol v2 header that tells the backend which address a connection really came
/// from.
///
/// The format is deliberately unmistakable: a twelve-byte signature no Minecraft packet can begin
/// with, so a server that is not expecting one rejects it loudly instead of misreading it as a
/// handshake. That is the reason this is safer than it looks — a mismatch between the proxy and the
/// backend fails immediately and visibly rather than quietly corrupting the first packet.
/// </summary>
public static class ProxyProtocolHeader
{
    /// <summary>The signature every v2 header starts with, from the specification.</summary>
    private static readonly byte[] Signature =
        [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

    /// <summary>Builds the header describing one connection.</summary>
    /// <param name="client">Where the player is connecting from.</param>
    /// <param name="destination">The address on this machine they reached, as the backend should see it.</param>
    public static byte[] Build(IPEndPoint client, IPEndPoint destination)
    {
        // A v4 client reaching a v6 socket arrives as ::ffff:a.b.c.d. Sending that as an IPv6 address
        // would give the backend something no operator would recognise as the address in their logs.
        IPAddress source = Normalise(client.Address);
        IPAddress target = Normalise(destination.Address);

        // Both ends of a header have to be the same family. When they are not — a v6 player reaching a
        // v4-bound backend, say — the destination is the one to bend, because the source address is
        // the entire point of sending this.
        if (source.AddressFamily != target.AddressFamily)
        {
            target = source.AddressFamily == AddressFamily.InterNetworkV6
                ? IPAddress.IPv6Loopback
                : IPAddress.Loopback;
        }

        bool isIpv6 = source.AddressFamily == AddressFamily.InterNetworkV6;
        int addressBytes = isIpv6 ? 16 : 4;
        int payloadLength = (addressBytes * 2) + 4;

        var header = new byte[Signature.Length + 4 + payloadLength];
        Signature.CopyTo(header, 0);

        header[12] = 0x21;                       // version 2, command PROXY (not LOCAL)
        header[13] = (byte)(isIpv6 ? 0x21 : 0x11); // address family + STREAM
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(14), (ushort)payloadLength);

        int offset = 16;
        source.GetAddressBytes().CopyTo(header, offset);
        offset += addressBytes;
        target.GetAddressBytes().CopyTo(header, offset);
        offset += addressBytes;

        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(offset), (ushort)client.Port);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(offset + 2), (ushort)destination.Port);

        return header;
    }

    /// <summary>Unwraps an IPv4 address that arrived through a dual-stack socket.</summary>
    private static IPAddress Normalise(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}

/// <summary>
/// Rewrites a Handshake packet the BungeeCord way, so a server reading spigot.yml's bungeecord option
/// learns who is really connecting.
///
/// The server address field becomes four null-separated parts: the address the client asked for, the
/// player's real IP, their UUID, and their profile properties as JSON. On an offline-mode server —
/// the only kind this firewall fronts — the UUID is the one the server would have derived from the
/// name itself, so sending it changes nothing about who the player is. It only tells the truth about
/// where they are.
/// </summary>
public static class BungeeCordHandshake
{
    /// <summary>Empty rather than fabricated. Properties are where a skin and its Mojang signature
    /// live, and inventing either would be claiming something about an account this proxy has not
    /// verified.</summary>
    private const string NoProperties = "[]";

    /// <summary>
    /// Rebuilds the handshake frame with the forwarding fields spliced into its address.
    ///
    /// Anything already in that field beyond the hostname is dropped — a Forge client puts its own
    /// marker there, and passing both through at once is not something the receiving end can parse.
    /// The hostname the client asked for is kept, because a server may well be routing on it.
    /// </summary>
    public static byte[] Rewrite(HandshakeInfo handshake, IPAddress clientAddress, string username)
    {
        string hostname = handshake.ServerAddress.Split('\0')[0];
        string forwarded = string.Join('\0',
            hostname,
            clientAddress.ToString(),
            OfflineUuid(username).ToString("N"),
            NoProperties);

        byte[] fields =
        [
            .. VarInt.Encode(handshake.ProtocolVersion),
            .. EncodeString(forwarded),
            (byte)(handshake.ServerPort >> 8), (byte)(handshake.ServerPort & 0xFF),
            .. VarInt.Encode((int)handshake.NextState),
        ];

        return FrameWriter.WriteUncompressed(0x00, fields);
    }

    /// <summary>
    /// The UUID an offline-mode server derives from a username: a version 3 UUID over the bytes of
    /// "OfflinePlayer:&lt;name&gt;".
    ///
    /// Reproduced rather than invented, so the player keeps the same identity — and the same
    /// inventory, home and permissions — they had before forwarding was switched on. Getting this
    /// wrong would not look like a bug, it would look like everyone's account being wiped.
    /// </summary>
    public static Guid OfflineUuid(string username)
    {
        byte[] hash = MD5.HashData(Encoding.UTF8.GetBytes("OfflinePlayer:" + username));

        hash[6] = (byte)((hash[6] & 0x0F) | 0x30); // version 3
        hash[8] = (byte)((hash[8] & 0x3F) | 0x80); // IETF variant

        // Java writes the two halves big-endian; .NET's Guid reads its first three fields as
        // little-endian on every platform, so those bytes are reversed to compensate.
        Array.Reverse(hash, 0, 4);
        Array.Reverse(hash, 4, 2);
        Array.Reverse(hash, 6, 2);

        return new Guid(hash);
    }

    private static byte[] EncodeString(string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        return [.. VarInt.Encode(bytes.Length), .. bytes];
    }
}
