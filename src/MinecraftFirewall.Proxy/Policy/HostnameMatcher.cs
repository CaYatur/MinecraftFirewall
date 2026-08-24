namespace MinecraftFirewall.Proxy.Policy;

/// <summary>
/// Matches the Handshake packet's Server Address field against a per-profile allowlist of domains.
///
/// IMPORTANT — this is NOT a cryptographic boundary. The Server Address field is whatever string the
/// client chose to send; it is not bound to how the TCP connection was actually made. A stock
/// Minecraft client that was pointed at a raw IP (Direct Connect, or a scanner/bot probing IPs) sends
/// that IP as the Server Address and will correctly be rejected here. A custom/scripted client that
/// deliberately fakes this field to match an allowed domain, while still connecting straight to the
/// server's IP, is NOT stopped by this check alone. Making the restriction a hard guarantee requires
/// an OS-level firewall rule that only permits inbound traffic from a fronting proxy's IP ranges (see
/// docs/plan.md). This check is real defense-in-depth against the bulk of IP-scanning bots and casual
/// direct-IP joins, not a substitute for that firewall rule.
/// </summary>
public static class HostnameMatcher
{
    public static string Normalize(string serverAddress)
    {
        // Forge/FML clients append a null-byte-separated marker (e.g. "\0FML3\0", or
        // BungeeCord-style "\0<real-ip>\0<uuid>\0<props>") to the Server Address field. Strip
        // everything from the first embedded null onward before comparing the hostname itself.
        int nullIndex = serverAddress.IndexOf('\0');
        string host = nullIndex >= 0 ? serverAddress[..nullIndex] : serverAddress;
        host = host.TrimEnd('.'); // FQDN trailing dot
        return host.ToLowerInvariant();
    }

    public static bool IsAllowed(string serverAddress, IReadOnlyCollection<string> allowedHostnames)
    {
        if (allowedHostnames.Count == 0)
            return true; // no restriction configured — matches vanilla behavior

        string host = Normalize(serverAddress);

        foreach (string allowed in allowedHostnames)
        {
            string pattern = allowed.Trim().ToLowerInvariant();

            if (pattern.StartsWith("*.", StringComparison.Ordinal))
            {
                string suffix = pattern[1..]; // ".example.com" — includes the leading dot
                if (host.Length > suffix.Length && host.EndsWith(suffix, StringComparison.Ordinal))
                    return true;
            }
            else if (host == pattern)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Bounds a client-controlled hostname before it's interpolated into a log line or
    /// PolicyDecision reason — the field's only size limit otherwise is the pre-login frame cap.</summary>
    public static string TruncateForLogging(string serverAddress, int maxLength = 64)
    {
        if (serverAddress.Length <= maxLength)
            return serverAddress;

        return string.Concat(serverAddress.AsSpan(0, maxLength), "…");
    }
}
