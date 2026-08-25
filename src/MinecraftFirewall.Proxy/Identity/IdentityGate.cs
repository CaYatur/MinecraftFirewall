using System.Net;

namespace MinecraftFirewall.Proxy.Identity;

public enum IdentityOutcome
{
    /// <summary>No identity record exists for this username — behaves like vanilla offline mode.</summary>
    NotProtected,
    Allow,
    Deny,

    /// <summary>
    /// The connection may proceed, but ClientConnection/PlayStateInspector must enforce that the very
    /// first Play-state chat message is a correct `/login &lt;password&gt;` — anything else (wrong
    /// password, any other message, or a timeout) must disconnect and fast-track a ban strike. This
    /// only applies to self-registered CaYaDev-Check names (a password set, no static allowlist entry
    /// matched); admin-declared protected names with only a static allowlist get a strict Deny instead
    /// — see the comment below for why the two cases aren't treated the same way.
    /// </summary>
    AllowPendingGraceAuthentication,

    /// <summary>
    /// The username is admin-declared <c>PremiumRequired</c>: the connection must pass a real Mojang
    /// encryption challenge + <c>hasJoined</c> session check (and match the recorded UUID pin, once
    /// one exists) before it reaches the backend at all. Unlike
    /// <see cref="AllowPendingGraceAuthentication"/>, nothing is forwarded on the strength of this
    /// outcome alone — ClientConnection runs the challenge during Login, before it so much as opens a
    /// backend connection, and a failure is always a denial with no fallback to any weaker check.
    /// </summary>
    PremiumVerificationRequired,

    /// <summary>
    /// Server-wide registration is switched on and this username has no password yet. The player joins
    /// but is held still until they register — see PlayStateInspector, which refuses every packet that
    /// would let them act on the world while they are in this state.
    /// </summary>
    RegistrationRequired,
}

public sealed record IdentityDecision(IdentityOutcome Outcome, string Reason);

/// <summary>
/// The single gate every identity check goes through. Precedence is fixed and must not be
/// improvised per-call: PremiumRequired (Stage 4) always wins over password/IP (Stage 1/3) so a
/// weaker mechanism can never bypass the stronger one once an admin has declared a name premium-only.
/// </summary>
public static class IdentityGate
{
    /// <param name="requireRegistration">Server-wide AuthMe-style registration, from
    /// IdentityOptions.RequireRegistrationForEveryone. It is checked *after* the premium branch, never
    /// before: a name proven to belong to a real Microsoft account has already been authenticated by
    /// something stronger than a stored password, and must never be asked for one.</param>
    public static IdentityDecision Evaluate(IdentityEntry? entry, IPAddress remoteAddress, bool requireRegistration = false)
    {
        if (entry is null)
        {
            return requireRegistration
                ? new IdentityDecision(IdentityOutcome.RegistrationRequired, "Server requires every player to register.")
                : new IdentityDecision(IdentityOutcome.NotProtected, "No identity record for this username.");
        }

        if (entry.PremiumRequired)
        {
            // The precedence rule, and the single most important line in this method: PremiumRequired
            // always wins and returns immediately. Everything below — static allowlist, learned IPs,
            // password — is deliberately never consulted for such a name, in BOTH directions. A
            // weaker mechanism must never be able to satisfy the stronger requirement (an attacker
            // who somehow learned the password can't bypass the Mojang check), and equally the
            // genuine owner must never be dropped into the password path (docs/plan.md's explicit
            // guarantee that a real premium account is never shown a password prompt, from any IP).
            return new IdentityDecision(IdentityOutcome.PremiumVerificationRequired,
                "Username is marked PremiumRequired — must pass Mojang session verification.");
        }

        bool hasAnyProtection = entry.StaticAllowlist.Count > 0 || entry.LearnedIps.Count > 0 || entry.PasswordHash is not null;
        if (!hasAnyProtection)
        {
            return requireRegistration
                ? new IdentityDecision(IdentityOutcome.RegistrationRequired, "Server requires every player to register.")
                : new IdentityDecision(IdentityOutcome.NotProtected, "Identity record has no active protection configured.");
        }

        if (entry.IsIpRecognized(remoteAddress))
            return new IdentityDecision(IdentityOutcome.Allow, "IP matched static allowlist or a learned IP.");

        if (entry.PasswordHash is not null)
        {
            // Self-registered (CaYaDev-Check) name, unrecognized IP. There is no protocol-safe way to
            // hold the connection open before Play state and prompt for a password (see docs/plan.md
            // Stage 2 — no real client was available to verify a held connection is tolerated), so the
            // grace-authentication window happens *inside* Play state instead: the player does join,
            // but must send the correct password as literally their first message or get kicked.
            return new IdentityDecision(IdentityOutcome.AllowPendingGraceAuthentication,
                "Registered username, unrecognized IP — first Play-state message must be a correct /login.");
        }

        // Admin-declared protected name (static allowlist only, no self-service password) and the IP
        // didn't match — strict deny, no grace window. This is deliberately stricter than the
        // self-registration case above: these are the names (OP/admin accounts) the whole project
        // exists to protect, so there's no acceptable window where an unverified connection is "in"
        // even briefly.
        return new IdentityDecision(IdentityOutcome.Deny, "IP not in the static allowlist for this protected username.");
    }
}
