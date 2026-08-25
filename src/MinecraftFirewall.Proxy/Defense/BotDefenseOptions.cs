namespace MinecraftFirewall.Proxy.Defense;

/// <summary>What the bot score is allowed to do to a connection.</summary>
public enum BotAction
{
    /// <summary>Score it, record it, report it — never refuse anyone. The safe way to find out what
    /// your own server's normal traffic scores before letting the score decide anything.</summary>
    LogOnly,

    /// <summary>Refuse connections at or above the deny threshold.</summary>
    Deny,
}

/// <summary>
/// Scoring for join behaviour that does not look like a person.
///
/// None of these signals is proof on its own, and the design takes that seriously: they are weighted
/// and summed rather than checked one at a time, because every individual signal has a legitimate
/// explanation. A player on a flaky connection reconnects repeatedly. Someone's username genuinely is
/// "Player4821". A launcher can skip the server-list ping. What no real player does is trip several
/// of them at once.
/// </summary>
public sealed class BotDefenseOptions
{
    public const string SectionName = "BotDefense";

    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Starts at <see cref="BotAction.LogOnly"/> on purpose. Turning a heuristic loose on a live
    /// server before anyone has seen what it scores is how a firewall ends up refusing the owner.
    /// The control panel shows the scores as they happen, so the decision to switch this to Deny can
    /// be made from evidence rather than hope.
    /// </summary>
    public BotAction Action { get; set; } = BotAction.LogOnly;

    /// <summary>
    /// Score at or above which a connection is refused when <see cref="Action"/> is Deny.
    ///
    /// Worth showing the arithmetic, because a threshold nobody has checked is a threshold that either
    /// never fires or fires on everyone. With the default weights below:
    ///
    ///   no ping + several usernames                     35 + 55 = 90       refused
    ///   pings first, several usernames, looping              55 + 45 = 100      refused
    ///   no ping + generated name + on a threat list     35 + 20 + 45 = 100      refused
    ///   no ping + generated name                        35 + 20 = 55       allowed
    ///   looping alone                                             45       allowed
    ///   a threat-list hit alone                                   45       allowed
    ///
    /// So it takes two independent strong signals, and no single signal can refuse anyone by itself —
    /// including an imported list, which is somebody else's judgement about traffic that never came
    /// here.
    ///
    /// A bot author who adds one status ping before each login defeats the highest-weighted signal for
    /// a one-line change. That is expected and is why the others exist: they still have to use one
    /// username and reconnect like a person, and doing both is much more work than adding a ping.
    /// </summary>
    public int DenyScore { get; set; } = 90;

    /// <summary>Score at or above which the connection is reported even though it is allowed through.</summary>
    public int ReportScore { get; set; } = 60;

    /// <summary>Strikes added when a connection is refused as a bot. Low by design — the score is a
    /// judgement call, and a judgement call should not ban an address by itself.</summary>
    public int StrikeWeightOnDeny { get; set; } = 1;

    // ---- individual signal weights -------------------------------------------------------------
    // Exposed so a server with unusual-but-legitimate traffic can turn down whichever signal it keeps
    // tripping, instead of having to switch the whole feature off.

    /// <summary>A login from an address that has not asked for the server list recently. Real clients
    /// ping before they join — from the multiplayer list, and from Direct Connect too, which pings as
    /// soon as the address is typed. Moderate rather than high: a launcher is free not to.</summary>
    public int WeightNoRecentPing { get; set; } = 35;

    /// <summary>How recently a ping counts. Long enough to cover a player who pings, wanders off to
    /// make tea, and comes back to join.</summary>
    public TimeSpan PingMemory { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Distinct usernames from one address inside <see cref="UsernameMemory"/> before this
    /// counts against it. Household NATs and shared connections make small numbers unremarkable;
    /// working through a list of names is what this is looking for.</summary>
    public int DistinctUsernamesBeforeSuspicion { get; set; } = 6;

    public int WeightManyUsernames { get; set; } = 55;

    public TimeSpan UsernameMemory { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>Reconnects spaced so evenly that a human hand is not involved. Needs at least
    /// <see cref="CadenceSamples"/> connections before it will say anything at all.</summary>
    public int WeightMechanicalCadence { get; set; } = 45;

    public int CadenceSamples { get; set; } = 5;

    /// <summary>Coefficient of variation below which timing counts as mechanical. A person retrying a
    /// join produces gaps that vary by tens of percent; a loop produces gaps that vary by almost
    /// nothing.</summary>
    public double MechanicalCadenceThreshold { get; set; } = 0.12;

    /// <summary>The username looks generated rather than chosen. Weak on purpose — plenty of real
    /// players have names a generator could plausibly have produced.</summary>
    public int WeightGeneratedUsername { get; set; } = 20;

    /// <summary>Connected claiming a hostname this profile does not serve. Already a refusal in its
    /// own right when allowed domains are configured; this makes it count towards the address's
    /// reputation as well, which is the part that outlives the single connection.</summary>
    public int WeightHostnameMismatch { get; set; } = 40;

    /// <summary>Connected, completed the handshake, and left without doing anything — the shape of a
    /// port scan rather than a player.</summary>
    public int WeightScannerBehaviour { get; set; } = 30;

    // ---- server-indexing crawlers ----------------------------------------------------------------
    // These only apply to a profile that declares AllowedHostnames, since without a list nothing is a
    // mismatch. A crawler sweeping address ranges has no address to put in the Handshake packet, so it
    // sends its own domain — its brand, in the field meant for the server's name. That is a far
    // cleaner signal than anything else here, and it comes from the crawler itself.

    /// <summary>
    /// Foreign domains an address may announce before it is banned as a crawler.
    ///
    /// Counts distinct names inside <see cref="ScannerMemory"/>, not attempts, and only names that are
    /// not IP addresses. A raw IP in that field is what the admin's own test connection looks like and
    /// never escalates — it earns an ordinary strike like any other refusal.
    /// </summary>
    public int ScannerMismatchesBeforeBan { get; set; } = 3;

    /// <summary>
    /// How long a recognised crawler is banned for.
    ///
    /// Much longer than an ordinary ban, because the behaviour is not a mistake somebody might stop
    /// making: an indexing service is on a schedule and will be back next week regardless. Long enough
    /// to be worth the crawler dropping the entry, short enough that a wrongly-classified address is
    /// not blocked forever.
    /// </summary>
    public TimeSpan ScannerBanDuration { get; set; } = TimeSpan.FromDays(30);

    /// <summary>Window over which the distinct names are counted.</summary>
    public TimeSpan ScannerMemory { get; set; } = TimeSpan.FromDays(7);

    /// <summary>A protocol version no released Minecraft client uses. Custom clients do exist, so
    /// this is a nudge rather than a verdict.</summary>
    public int WeightImplausibleProtocol { get; set; } = 25;
}
