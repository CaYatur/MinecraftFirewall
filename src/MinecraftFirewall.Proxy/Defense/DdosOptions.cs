namespace MinecraftFirewall.Proxy.Defense;

/// <summary>
/// Admission control applied the instant a TCP connection is accepted, before a single byte is read.
///
/// The defaults are set so that a household or small community never notices them, which is the only
/// way a limit like this survives contact with a real server: a cap tight enough to be tripped by six
/// friends behind one router gets switched off, and then it protects nothing. Every value here is
/// generous compared to what a legitimate client does, and restrictive compared to what a flood does.
/// </summary>
public sealed class DdosOptions
{
    public const string SectionName = "DdosProtection";

    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Connections held open at once from one address. A player uses one, plus a brief second one
    /// while their client refreshes the server list, so this leaves room for roughly a dozen people
    /// sharing a single home or campus NAT before anyone is turned away.
    /// </summary>
    public int MaxConcurrentPerIp { get; set; } = 16;

    /// <summary>
    /// The same limit widened to the /24 (or /64 for IPv6) the address sits in. Botnets are usually
    /// spread across neighbouring addresses in a handful of hosting ranges, so the subnet is where a
    /// distributed flood becomes visible while a per-address cap still sees nothing unusual.
    /// </summary>
    public int MaxConcurrentPerSubnet { get; set; } = 64;

    /// <summary>A ceiling on everything in flight, so the process cannot be pushed past what it can
    /// actually serve no matter how well distributed the source addresses are.</summary>
    public int MaxConcurrentTotal { get; set; } = 1000;

    /// <summary>New connections per minute from one address. Reconnecting after a kick, retrying a
    /// laggy join, and a client refreshing the server list all land well under this.</summary>
    public int MaxNewConnectionsPerIpPerMinute { get; set; } = 60;

    public int MaxNewConnectionsPerSubnetPerMinute { get; set; } = 300;

    /// <summary>
    /// Accepts per second across all profiles that mean this is no longer ordinary traffic. Crossing
    /// it puts the governor into a defensive mode for <see cref="UnderAttackCooldown"/>, where the
    /// per-address limits above are multiplied by <see cref="UnderAttackTightening"/>.
    ///
    /// The point of the mode, rather than simply setting the limits lower permanently, is that the
    /// tighter limits do cost legitimate players something — a laggy reconnect loop can trip them —
    /// and that cost is only worth paying while something is actually happening.
    /// </summary>
    public int AcceptsPerSecondBeforeDefensiveMode { get; set; } = 150;

    public double UnderAttackTightening { get; set; } = 0.35;

    public TimeSpan UnderAttackCooldown { get; set; } = TimeSpan.FromSeconds(45);

    /// <summary>
    /// Strikes added when an address is turned away for flooding. At the default ban threshold this
    /// means a sustained flood earns a real firewall ban within a few seconds, while one refusal
    /// during a burst does not.
    ///
    /// Deliberately not an immediate ban: source addresses in a flood are frequently spoofed or
    /// shared, and the addresses that reach this code are the ones that completed a TCP handshake, so
    /// they are real — but they may still be a NAT gateway with innocent people behind it.
    /// </summary>
    public int StrikeWeightOnFlood { get; set; } = 1;

    /// <summary>How long a connection may stay open having sent nothing at all. Slowloris in its
    /// simplest form is a socket that connects and then waits; the pre-login read deadline already
    /// bounds that, and this is the belt to its braces for anything that slips past.</summary>
    public TimeSpan IdleHandshakeTimeout { get; set; } = TimeSpan.FromSeconds(10);
}
