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
}

public sealed record IdentityDecision(IdentityOutcome Outcome, string Reason);

/// <summary>
/// The single gate every identity check goes through. Precedence is fixed and must not be
/// improvised per-call: PremiumRequired (Stage 4) always wins over password/IP (Stage 1/3) so a
/// weaker mechanism can never bypass the stronger one once an admin has declared a name premium-only.
/// </summary>
public static class IdentityGate
{
    public static IdentityDecision Evaluate(IdentityEntry? entry, IPAddress remoteAddress)
    {
        if (entry is null)
            return new IdentityDecision(IdentityOutcome.NotProtected, "No identity record for this username.");

        if (entry.PremiumRequired)
        {
            // Stage 4 (real Mojang encryption + hasJoined verification) isn't implemented yet.
            // Fail closed rather than silently ignoring a premium requirement the admin declared.
            return new IdentityDecision(IdentityOutcome.Deny,
                "Username is marked PremiumRequired but premium verification (Stage 4) is not yet implemented.");
        }

        bool hasAnyProtection = entry.StaticAllowlist.Count > 0 || entry.LearnedIps.Count > 0 || entry.PasswordHash is not null;
        if (!hasAnyProtection)
            return new IdentityDecision(IdentityOutcome.NotProtected, "Identity record has no active protection configured.");

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
