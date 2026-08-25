namespace MinecraftFirewall.Proxy.Defense;

/// <summary>
/// Decoy ports that exist only to be touched by something that should not be touching them.
///
/// The value of a honeypot is that it has no false positives worth arguing about. A player's client
/// connects to the one port you gave them; it has no reason to try the port next door, and no reason
/// to try the RCON port. Anything that does is enumerating, and enumeration is the step before an
/// attack rather than a part of playing.
///
/// Off by default. Binding extra ports is a visible change to someone's machine — it can collide with
/// a service they actually run, and it puts new listening sockets on a box whose owner did not ask
/// for them. Ports are pre-filled with the ones scanners reach for first, so switching it on is one
/// click rather than a research project.
/// </summary>
public sealed class HoneypotOptions
{
    public const string SectionName = "Honeypot";

    public bool Enabled { get; set; }

    /// <summary>
    /// Ports to listen on as decoys.
    ///
    /// These are the neighbours of the default Minecraft port plus the default RCON port, which is
    /// what a Minecraft-aware scanner probes after finding 25565 open — RCON especially, since a
    /// reachable one with a weak password is a remote console. Any port already used by a configured
    /// server profile is dropped at startup with a warning rather than fought over.
    /// </summary>
    public List<int> Ports { get; set; } = [25567, 25570, 25575];

    /// <summary>
    /// Strikes added when an address touches a decoy. Defaults to the full ban threshold, so a single
    /// hit is enough — unlike every other signal in this firewall, there is no innocent reading of a
    /// connection to a port nothing advertises.
    ///
    /// The allowlist still applies. A honeypot hit routes through exactly the same ban path as
    /// everything else, which means loopback, the local network and anything in NeverBan are never
    /// banned by one — an admin scanning their own machine with nmap must not lock themselves out,
    /// and neither must the genuine owner of a premium-locked username whose ISP shares an address.
    /// </summary>
    public int StrikeWeight { get; set; } = 5;

    /// <summary>Whether a hit is added to this installation's own threat list, which can be published
    /// as a feed for other installations.</summary>
    public bool RecordToThreatList { get; set; } = true;

    /// <summary>
    /// Bytes read from a decoy connection before it is dropped.
    ///
    /// Reading a little is worth it: what a scanner sends first identifies what it thinks it found,
    /// which is the difference between "a Minecraft bot" and "a generic port sweep" in the log. Reading
    /// a lot would make the decoy itself a place to send traffic at, so the cap is small and the read
    /// deadline short.
    /// </summary>
    public int ProbeBytesToRead { get; set; } = 64;

    public TimeSpan ProbeReadTimeout { get; set; } = TimeSpan.FromSeconds(2);
}
