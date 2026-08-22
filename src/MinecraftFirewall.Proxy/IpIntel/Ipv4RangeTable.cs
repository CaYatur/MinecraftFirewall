using System.Net;
using System.Net.Sockets;

namespace MinecraftFirewall.Proxy.IpIntel;

/// <summary>
/// Sorted, non-overlapping (start,end) IPv4 ranges with binary-search lookup. Built from plain-CIDR
/// text (one CIDR per line, '#' comments allowed) — the format X4BNet/lists_vpn ships. No IPv6
/// support: no usable free IPv6 VPN/datacenter list was found, so IPv6 connections simply never
/// match this table (see IdentityGate/PolicyEngine for how that's handled for protected usernames).
/// </summary>
public sealed class Ipv4RangeTable
{
    private readonly (uint Start, uint End)[] _ranges;

    private Ipv4RangeTable((uint Start, uint End)[] ranges) => _ranges = ranges;

    public static readonly Ipv4RangeTable Empty = new([]);

    public int RangeCount => _ranges.Length;

    public static Ipv4RangeTable Parse(IEnumerable<string> cidrLines)
    {
        var parsed = new List<(uint Start, uint End)>();

        foreach (var rawLine in cidrLines)
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;

            if (!TryParseCidr(line, out uint start, out uint end))
                continue; // skip malformed/IPv6 lines rather than fail the whole refresh

            parsed.Add((start, end));
        }

        parsed.Sort((a, b) => a.Start.CompareTo(b.Start));

        var merged = new List<(uint Start, uint End)>(parsed.Count);
        foreach (var range in parsed)
        {
            if (merged.Count > 0 && range.Start <= merged[^1].End + 1)
            {
                var last = merged[^1];
                if (range.End > last.End)
                    merged[^1] = (last.Start, range.End);
            }
            else
            {
                merged.Add(range);
            }
        }

        return new Ipv4RangeTable(merged.ToArray());
    }

    public bool Contains(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
            return false;

        uint value = ToUInt32(address);

        int lo = 0, hi = _ranges.Length - 1, candidate = -1;
        while (lo <= hi)
        {
            int mid = lo + (hi - lo) / 2;
            if (_ranges[mid].Start <= value)
            {
                candidate = mid;
                lo = mid + 1;
            }
            else
            {
                hi = mid - 1;
            }
        }

        return candidate >= 0 && value <= _ranges[candidate].End;
    }

    private static bool TryParseCidr(string text, out uint start, out uint end)
    {
        start = end = 0;
        string[] parts = text.Split('/', 2);

        if (!IPAddress.TryParse(parts[0].Trim(), out var address) ||
            address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        int prefixLength = 32;
        if (parts.Length == 2 && !int.TryParse(parts[1].Trim(), out prefixLength))
            return false;

        if (prefixLength is < 0 or > 32)
            return false;

        uint baseValue = ToUInt32(address);
        // C#'s >> on a 32-bit operand masks the shift count to 5 bits, so ">> 32" silently behaves
        // like ">> 0" instead of yielding 0 — a bare /32 entry would otherwise become a match-everything
        // range. Handle that boundary explicitly rather than relying on the shift.
        uint hostMask = prefixLength == 32 ? 0u : uint.MaxValue >> prefixLength;

        start = baseValue & ~hostMask;
        end = start | hostMask;
        return true;
    }

    private static uint ToUInt32(IPAddress address)
    {
        byte[] bytes = address.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }
}
