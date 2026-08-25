namespace MinecraftFirewall.Proxy.Network;

/// <summary>
/// Watches whether IP forwarding is actually working on one server, and turns it off by itself when
/// it plainly is not.
///
/// Both forwarding modes need the backend configured to expect the same thing, and a backend that is
/// not does not fail politely: it reads the forwarding data as the first Minecraft packet, cannot
/// decode it, and drops the connection the instant it arrives. Every time, for every player. The
/// server becomes unjoinable, and the only clue is a decoder error in a log nobody is watching.
///
/// That is a setting mismatch, not an attack and not bad luck, and it has a signature no other
/// failure has: the backend hangs up before it has said a single word of Minecraft to us. A backend
/// restarting under load, a player closing the game, a flaky network — all of those either speak
/// first or fail later. So the trigger is deliberately narrow: consecutive connections that died
/// before the backend spoke, with no working session in between.
///
/// <para>
/// Nothing here is written to disk, and that is deliberate. The next restart tries forwarding again,
/// because the administrator may have fixed the server's configuration in the meantime — and a
/// feature that silently disabled itself permanently would be worse than the fault it is working
/// around.
/// </para>
/// </summary>
public sealed class IpForwardingHealth
{
    /// <summary>
    /// How many connections may die before the backend speaks, before forwarding is suspended.
    ///
    /// Small, because when this is the cause it is the cause every single time: the third failure in
    /// a row carries no more information than the second. Large enough not to trip on a server that
    /// happened to be restarting when the first player of the day tried to join.
    /// </summary>
    private const int FailuresBeforeSuspending = 3;

    private readonly Lock _lock = new();
    private int _consecutiveEarlyFailures;
    private bool _suspended;

    /// <summary>True while forwarding is being skipped because it appeared to be breaking every
    /// connection.</summary>
    public bool Suspended
    {
        get { lock (_lock) return _suspended; }
    }

    /// <summary>
    /// Records a session where the backend spoke Minecraft to us, which is proof it accepted whatever
    /// we sent ahead of it.
    ///
    /// Clears the count rather than decrementing it: the failures being counted are the ones that
    /// happen before a single successful session, and one success means they were something else.
    /// </summary>
    public void RecordWorkingSession()
    {
        lock (_lock)
        {
            _consecutiveEarlyFailures = 0;
            _suspended = false;
        }
    }

    /// <summary>
    /// Records a connection that failed before the backend said anything. Returns true if this is the
    /// failure that suspends forwarding, so the caller can say so once rather than on every attempt.
    /// </summary>
    public bool RecordFailureBeforeBackendSpoke()
    {
        lock (_lock)
        {
            if (_suspended)
                return false;

            _consecutiveEarlyFailures++;

            if (_consecutiveEarlyFailures < FailuresBeforeSuspending)
                return false;

            _suspended = true;
            return true;
        }
    }
}
