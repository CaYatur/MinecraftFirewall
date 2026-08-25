namespace MinecraftFirewall.Proxy.Defense;

/// <summary>What an address appearing on an imported threat list is allowed to cause.</summary>
public enum ThreatListAction
{
    /// <summary>Note it and let the connection through. The default, because the evidence is somebody
    /// else's and this server has no way to check it.</summary>
    LogOnly,

    /// <summary>Count it towards the address's bot score, so it can tip a connection that was already
    /// behaving oddly without being able to refuse one on its own.</summary>
    Score,

    /// <summary>Refuse the connection outright.</summary>
    Block,
}

/// <summary>
/// Shared threat intelligence: addresses seen attacking somewhere, imported from public lists, plus
/// the ones this installation has caught itself.
///
/// Worth being plain about what is and isn't here. There is no central MinecraftFirewall service
/// collecting honeypot hits from every installation and pushing them back out — building one would
/// mean running infrastructure, and a blocklist that anyone can write to by tripping a honeypot is a
/// denial-of-service tool aimed at whoever spoofs their way onto it. What this does instead is read
/// any list served over HTTP as one address or CIDR per line, which is the format every public feed
/// already uses, and write its own findings out in that same format. A community that wants a shared
/// feed can host the file; nothing here depends on one existing.
///
/// The two kinds of evidence are deliberately not pooled. What this server watched happen is
/// first-hand and acted on; what a list says is second-hand and, by default, only noted.
/// </summary>
public sealed class ThreatIntelOptions
{
    public const string SectionName = "ThreatIntel";

    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Lists to import, one address or CIDR per line. Comments (#) and a trailing count column are
    /// both tolerated.
    ///
    /// The shipped default is IPsum's level-3 file: addresses that appear on at least three
    /// independent public blacklists, rebuilt daily, MIT-licensed, and delivered from the same
    /// raw.githubusercontent host the VPN lists already come from. Three-list agreement is strict
    /// enough that a residential address rarely lands on it by accident — but "rarely" is why the
    /// default action only scores.
    ///
    /// That default lives in appsettings.json and this list starts empty, which is not a stylistic
    /// split: .NET configuration binding *appends* to a list that already has items rather than
    /// replacing it. A URL named in both places would be fetched twice and could never be removed by
    /// editing the file. Caught by a live run reporting two sources for one configured URL.
    /// </summary>
    public List<string> FeedUrls { get; set; } = [];

    /// <summary>Starts at Score, not Block. These addresses were judged by someone else, against
    /// traffic that was not aimed at this server, and a shared list is exactly the wrong place to
    /// discover a false positive by having a player unable to join.</summary>
    public ThreatListAction Action { get; set; } = ThreatListAction.Score;

    /// <summary>Bot-score contribution when <see cref="Action"/> is Score.</summary>
    public int ScoreWeight { get; set; } = 45;

    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromDays(1);

    public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(30);

    public string CacheDirectory { get; set; } = @"C:\ProgramData\MinecraftFirewall\cache";

    /// <summary>Where this installation's own catches are kept, in the same one-per-line format the
    /// feeds use — so it can be served as a feed to other installations without conversion.</summary>
    public string LocalThreatLogPath { get; set; } = @"C:\ProgramData\MinecraftFirewall\threats-observed.txt";

    /// <summary>How long an address this server caught itself stays on its local list.</summary>
    public TimeSpan LocalRetention { get; set; } = TimeSpan.FromDays(30);

    /// <summary>Cap on locally-recorded addresses. Reached, the oldest are dropped first — the file
    /// must not be allowed to grow without bound just because someone keeps scanning.</summary>
    public int MaxLocalRecords { get; set; } = 20000;
}
