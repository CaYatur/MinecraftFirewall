namespace MinecraftFirewall.Proxy.Enforcement;

public sealed class FirewallBanOptions
{
    public const string SectionName = "FirewallBan";

    /// <summary>How long a first ban lasts. Later bans of the same address get longer — see
    /// <see cref="EscalateRepeatOffenders"/>.</summary>
    public TimeSpan DefaultBanDuration { get; set; } = TimeSpan.FromHours(6);

    /// <summary>
    /// Whether each new ban of an address that has been banned before lasts twice as long as the last.
    ///
    /// Without this, a flat six hours is not a deterrent to anything automated — it is a schedule. A
    /// bot that comes back every evening pays the same price every evening and never runs out of
    /// evenings, while the doubling turns "keep trying" into a strategy that costs more each time:
    /// 6 hours, 12, a day, two days, four, and so on to the cap.
    ///
    /// It also stays gentle on the case that matters. Someone who trips a limit once, and again next
    /// month, is nowhere near the interesting part of that curve — and the count decays, so a single
    /// bad evening does not follow an address around forever.
    /// </summary>
    public bool EscalateRepeatOffenders { get; set; } = true;

    /// <summary>
    /// Ceiling on an escalated ban.
    ///
    /// A cap rather than unbounded growth because addresses are reassigned: today's persistent
    /// attacker is somebody's home connection next year, and a ban measured in decades would outlive
    /// any connection between the address and the behaviour.
    /// </summary>
    public TimeSpan MaxBanDuration { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// How long an address's previous bans keep counting towards the next one.
    ///
    /// Measured from the last ban, not the first, so a steady trickle of offences keeps the count
    /// alive while a genuine one-off falls out of it.
    /// </summary>
    public TimeSpan RepeatOffenceMemory { get; set; } = TimeSpan.FromDays(14);

    /// <summary>Consecutive rate-limit violations from one IP before a firewall-level ban is issued.</summary>
    public int StrikesBeforeBan { get; set; } = 5;

    public TimeSpan CleanupInterval { get; set; } = TimeSpan.FromMinutes(1);
}
