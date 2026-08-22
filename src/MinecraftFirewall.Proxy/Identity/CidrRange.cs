using System.Net;
using System.Net.Sockets;

namespace MinecraftFirewall.Proxy.Identity;

/// <summary>An IPv4 or IPv6 CIDR range (or a single address, treated as a /32 or /128).</summary>
public sealed class CidrRange
{
    private readonly AddressFamily _family;
    private readonly byte[] _networkBytes;
    private readonly int _prefixLength;

    private CidrRange(AddressFamily family, byte[] networkBytes, int prefixLength)
    {
        _family = family;
        _networkBytes = networkBytes;
        _prefixLength = prefixLength;
    }

    public static CidrRange Parse(string text)
    {
        string[] parts = text.Split('/', 2);
        var address = IPAddress.Parse(parts[0].Trim());
        int maxPrefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        int prefixLength = parts.Length == 2 ? int.Parse(parts[1].Trim()) : maxPrefix;

        if (prefixLength < 0 || prefixLength > maxPrefix)
            throw new FormatException($"Invalid CIDR prefix length in '{text}'.");

        return new CidrRange(address.AddressFamily, address.GetAddressBytes(), prefixLength);
    }

    public bool Contains(IPAddress address)
    {
        if (address.AddressFamily != _family)
            return false;

        byte[] candidate = address.GetAddressBytes();
        int fullBytes = _prefixLength / 8;
        int remainingBits = _prefixLength % 8;

        for (int i = 0; i < fullBytes; i++)
        {
            if (candidate[i] != _networkBytes[i])
                return false;
        }

        if (remainingBits > 0)
        {
            int mask = 0xFF << (8 - remainingBits) & 0xFF;
            if ((candidate[fullBytes] & mask) != (_networkBytes[fullBytes] & mask))
                return false;
        }

        return true;
    }

    public override string ToString() => $"{new IPAddress(_networkBytes)}/{_prefixLength}";
}
