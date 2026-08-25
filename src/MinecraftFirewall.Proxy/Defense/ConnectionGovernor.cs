using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Defense;

/// <summary>Why a connection was turned away, or <see cref="Admitted"/> if it wasn't.</summary>
public enum AdmissionVerdict
{
    Admitted,
    TooManyFromAddress,
    TooManyFromSubnet,
    ServerAtCapacity,
    ConnectingTooFast,
    SubnetConnectingTooFast,
}

/// <summary>
/// A slot held for the lifetime of one connection. Disposing it is what returns the slot, so it has
/// to be disposed on every exit path — including the ones that look like they cannot fail.
/// </summary>
public sealed class ConnectionLease : IDisposable
{
    private readonly ConnectionGovernor _governor;
    private readonly string _ipKey;
    private readonly string _subnetKey;
    private int _released;

    internal ConnectionLease(ConnectionGovernor governor, string ipKey, string subnetKey)
    {
        _governor = governor;
        _ipKey = ipKey;
        _subnetKey = subnetKey;
    }

    public void Dispose()
    {
        // Guarded because releasing twice would give back a slot this connection never held, which
        // surfaces much later as a server refusing connections it has the capacity to serve.
        if (Interlocked.Exchange(ref _released, 1) == 0)
            _governor.Release(_ipKey, _subnetKey);
    }
}

public readonly record struct AdmissionResult(AdmissionVerdict Verdict, ConnectionLease? Lease, string Detail)
{
    public bool Admitted => Verdict == AdmissionVerdict.Admitted;
}

/// <summary>
/// Decides whether an accepted socket is allowed to become a connection at all.
///
/// This runs before the stream is touched, which is the whole point. Every check further in — the
/// handshake parser, the policy engine, the identity gate — costs a task, a buffer and at least one
/// read, and a flood is an attempt to make the server pay those costs faster than it can afford them.
/// The cheapest possible refusal is the only one that helps.
///
/// Four shapes of abuse are separated because they need different answers. One address opening many
/// sockets is capped per address. A botnet spread across neighbouring addresses is capped per /24,
/// which is where it becomes visible. Reconnect storms are capped by rate rather than by count, since
/// a socket that closes immediately never appears in a concurrency figure. And a flood distributed
/// widely enough to slip under all three still meets a global ceiling.
/// </summary>
public sealed class ConnectionGovernor : IDisposable
{
    private readonly DdosOptions _options;
    private readonly ILogger<ConnectionGovernor> _logger;

    private readonly ConcurrentDictionary<string, int> _perIp = new();
    private readonly ConcurrentDictionary<string, int> _perSubnet = new();
    private readonly SlidingCounter _ipRate;
    private readonly SlidingCounter _subnetRate;
    private readonly SlidingCounter _acceptRate;
    private readonly Timer _pruneTimer;

    private int _total;
    private long _defensiveUntilTicks;
    private long _refusals;

    /// <summary>
    /// Asked, per address, whether that address is currently under a tightened allowance.
    ///
    /// A delegate rather than a reference to the anomaly detector, because the governor runs on the
    /// accept path and has no business knowing what a model is. Anything that can answer "should this
    /// address get less room" can supply it.
    /// </summary>
    public Func<IPAddress, bool>? IsAddressThrottled { get; set; }

    public ConnectionGovernor(IOptions<DdosOptions> options, ILogger<ConnectionGovernor> logger)
    {
        _options = options.Value;
        _logger = logger;

        _ipRate = new SlidingCounter(TimeSpan.FromMinutes(1), Math.Max(8, _options.MaxNewConnectionsPerIpPerMinute + 1));
        _subnetRate = new SlidingCounter(TimeSpan.FromMinutes(1), Math.Max(16, _options.MaxNewConnectionsPerSubnetPerMinute + 1));
        _acceptRate = new SlidingCounter(TimeSpan.FromSeconds(1), Math.Max(32, _options.AcceptsPerSecondBeforeDefensiveMode + 1));

        _pruneTimer = new Timer(_ => Prune(), null, TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(2));
    }

    public bool DefensiveMode => Interlocked.Read(ref _defensiveUntilTicks) > DateTimeOffset.UtcNow.Ticks;

    public int CurrentConnections => Volatile.Read(ref _total);

    public long TotalRefusals => Interlocked.Read(ref _refusals);

    public int TrackedAddresses => _perIp.Count;

    public AdmissionResult TryAdmit(IPAddress address)
    {
        if (!_options.Enabled)
            return Exempt();

        // The machine itself is exempt. The admin CLI, the control panel's probes and the security
        // check all originate here, and throttling those would mean the tools for diagnosing an
        // attack stop working exactly when one is under way.
        if (IPAddress.IsLoopback(address))
            return Exempt();

        DateTimeOffset now = DateTimeOffset.UtcNow;
        string ipKey = address.ToString();
        string subnetKey = SubnetKey(address);

        int accepts = _acceptRate.Record("*", now);
        if (accepts > _options.AcceptsPerSecondBeforeDefensiveMode)
            EnterDefensiveMode(accepts, now);

        // Either a server-wide flood or an individual address that has been flagged tightens the
        // same limits, so they share one path — an address under both is not punished twice.
        bool defensive = DefensiveMode || IsAddressThrottled?.Invoke(address) == true;
        int maxPerIp = Tighten(_options.MaxConcurrentPerIp, defensive);
        int maxPerSubnet = Tighten(_options.MaxConcurrentPerSubnet, defensive);
        int maxIpRate = Tighten(_options.MaxNewConnectionsPerIpPerMinute, defensive);
        int maxSubnetRate = Tighten(_options.MaxNewConnectionsPerSubnetPerMinute, defensive);

        int ipConnectRate = _ipRate.Record(ipKey, now);
        if (ipConnectRate > maxIpRate)
            return Refuse(AdmissionVerdict.ConnectingTooFast, $"{ipConnectRate} connections in the last minute (limit {maxIpRate})");

        int subnetConnectRate = _subnetRate.Record(subnetKey, now);
        if (subnetConnectRate > maxSubnetRate)
            return Refuse(AdmissionVerdict.SubnetConnectingTooFast, $"{subnetConnectRate} from {subnetKey} in the last minute (limit {maxSubnetRate})");

        // Counted before the per-address checks so the global ceiling stays authoritative: it is the
        // one that corresponds to what this process can actually serve.
        int total = Interlocked.Increment(ref _total);
        if (total > _options.MaxConcurrentTotal)
        {
            Interlocked.Decrement(ref _total);
            return Refuse(AdmissionVerdict.ServerAtCapacity, $"{total - 1} connections already open (limit {_options.MaxConcurrentTotal})");
        }

        int perIp = _perIp.AddOrUpdate(ipKey, 1, static (_, current) => current + 1);
        if (perIp > maxPerIp)
        {
            Decrement(_perIp, ipKey);
            Interlocked.Decrement(ref _total);
            return Refuse(AdmissionVerdict.TooManyFromAddress, $"{perIp - 1} already open from this address (limit {maxPerIp})");
        }

        int perSubnet = _perSubnet.AddOrUpdate(subnetKey, 1, static (_, current) => current + 1);
        if (perSubnet > maxPerSubnet)
        {
            Decrement(_perSubnet, subnetKey);
            Decrement(_perIp, ipKey);
            Interlocked.Decrement(ref _total);
            return Refuse(AdmissionVerdict.TooManyFromSubnet, $"{perSubnet - 1} already open from {subnetKey} (limit {maxPerSubnet})");
        }

        return new AdmissionResult(AdmissionVerdict.Admitted, new ConnectionLease(this, ipKey, subnetKey), "");
    }

    internal void Release(string ipKey, string subnetKey)
    {
        if (ipKey.Length == 0)
            return; // exempt connection — nothing was counted for it in the first place

        Decrement(_perIp, ipKey);
        Decrement(_perSubnet, subnetKey);
        Interlocked.Decrement(ref _total);
    }

    /// <summary>
    /// The /24 an IPv4 address sits in, or the /64 for IPv6.
    ///
    /// Both are the smallest block normally allocated as a unit, which is what makes them the right
    /// granularity: addresses inside one are far more likely to share an operator than to share
    /// nothing. For IPv6 especially, treating single addresses as the unit would be useless — one
    /// host is routinely handed more addresses than a botnet needs.
    /// </summary>
    public static string SubnetKey(IPAddress address)
    {
        byte[] bytes = address.GetAddressBytes();

        if (address.AddressFamily == AddressFamily.InterNetwork)
            return $"{bytes[0]}.{bytes[1]}.{bytes[2]}.0/24";

        return string.Concat(Convert.ToHexString(bytes.AsSpan(0, 8)), "::/64");
    }

    private AdmissionResult Exempt() =>
        new(AdmissionVerdict.Admitted, new ConnectionLease(this, "", ""), "");

    private int Tighten(int limit, bool defensive) =>
        defensive ? Math.Max(1, (int)(limit * _options.UnderAttackTightening)) : limit;

    private void EnterDefensiveMode(int accepts, DateTimeOffset now)
    {
        long until = (now + _options.UnderAttackCooldown).Ticks;
        long previous = Interlocked.Exchange(ref _defensiveUntilTicks, until);

        // Logged only on the transition in. Under a sustained flood this method runs on every accept,
        // and a warning per accepted socket would turn the log itself into the outage.
        if (previous <= now.Ticks)
        {
            _logger.LogWarning(
                "Defensive mode ON: {Accepts} connections accepted in the last second (threshold {Threshold}). " +
                "Per-address limits tightened to {Percent}% for {Cooldown}.",
                accepts, _options.AcceptsPerSecondBeforeDefensiveMode,
                (int)(_options.UnderAttackTightening * 100), _options.UnderAttackCooldown);
        }
    }

    private AdmissionResult Refuse(AdmissionVerdict verdict, string detail)
    {
        Interlocked.Increment(ref _refusals);
        return new AdmissionResult(verdict, null, detail);
    }

    private static void Decrement(ConcurrentDictionary<string, int> counters, string key)
    {
        // Removed at zero rather than left behind, so a flood spread over many addresses does not
        // leave one dictionary entry per address for the lifetime of the process.
        while (counters.TryGetValue(key, out int current))
        {
            if (current <= 1)
            {
                if (counters.TryRemove(new KeyValuePair<string, int>(key, current)))
                    return;
            }
            else if (counters.TryUpdate(key, current - 1, current))
            {
                return;
            }
        }
    }

    private void Prune()
    {
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            _ipRate.Prune(now);
            _subnetRate.Prune(now);
            _acceptRate.Prune(now);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Connection governor prune failed.");
        }
    }

    public void Dispose() => _pruneTimer.Dispose();
}
