namespace MinecraftFirewall.Proxy.Anomaly;

/// <summary>
/// The numbers describing one finished connection, in the order the model expects them.
///
/// Choosing what to measure is most of the work in a detector like this, and the rule followed here is
/// that a feature has to be something an attacker cannot trivially set to whatever they like. Declared
/// values — the protocol version, the username, the claimed hostname — are excluded for that reason:
/// they are free to fake and would teach the model nothing except what the attacker wanted it to
/// learn. What is left is the shape of the conversation, which costs real effort to disguise because
/// disguising it means behaving like a player.
///
/// Everything is scaled to a roughly comparable range before it reaches the forest. Isolation forests
/// split on raw values, so a feature measured in bytes would dominate one measured in seconds purely
/// because its numbers are larger.
/// </summary>
public readonly record struct ConnectionFeatures(
    double DurationSeconds,
    int PacketsFromClient,
    long BytesFromClient,
    double PeakPacketsPerSecond,
    int DistinctPacketKinds,
    double SecondsToFirstPacket,
    int ChatMessages,
    int MovementPackets)
{
    /// <summary>Feature vector, log-scaled where the raw range spans orders of magnitude. Log scaling
    /// matters more than it looks: without it, one very long session would set a range so wide that
    /// random split points almost never fall among the ordinary values.</summary>
    public double[] ToVector() =>
    [
        Math.Log10(1 + DurationSeconds),
        Math.Log10(1 + PacketsFromClient),
        Math.Log10(1 + BytesFromClient),
        Math.Log10(1 + PeakPacketsPerSecond),
        DistinctPacketKinds,
        Math.Log10(1 + Math.Max(0, SecondsToFirstPacket)),
        Math.Log10(1 + ChatMessages),
        Math.Log10(1 + MovementPackets),

        // Ratios, which carry information none of the absolute figures do. A session that sent a
        // thousand packets in ten minutes and one that sent a thousand in ten seconds look identical
        // by packet count and completely different here.
        DurationSeconds > 0.01 ? Math.Log10(1 + (PacketsFromClient / DurationSeconds)) : 0,
        PacketsFromClient > 0 ? Math.Log10(1 + ((double)BytesFromClient / PacketsFromClient)) : 0,
    ];

    /// <summary>A human-readable summary for the report. The score alone tells nobody what was odd
    /// about the connection, and a number with no explanation attached gets ignored.</summary>
    public string Describe() =>
        $"{DurationSeconds:0.#}s, {PacketsFromClient} packets ({BytesFromClient / 1024.0:0.#} KB), " +
        $"peak {PeakPacketsPerSecond:0} pkt/s, {DistinctPacketKinds} packet kinds, " +
        $"{ChatMessages} chat, {MovementPackets} movement";
}
