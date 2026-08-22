using System.Net;

namespace MinecraftFirewall.Proxy.Identity;

public enum IdentityOutcome
{
    /// <summary>No identity record exists for this username — behaves like vanilla offline mode.</summary>
    NotProtected,
    Allow,
    Deny,
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

        if (entry.StaticAllowlist.Count > 0 || entry.LearnedIps.Count > 0)
        {
            if (entry.IsIpRecognized(remoteAddress))
                return new IdentityDecision(IdentityOutcome.Allow, "IP matched static allowlist or a learned IP.");

            if (entry.PasswordHash is not null)
            {
                // Stage 3's chat-based password gate isn't implemented yet; fail closed rather than
                // silently allowing an unrecognized IP through.
                return new IdentityDecision(IdentityOutcome.Deny,
                    "IP not recognized and the password gate (Stage 3) is not yet implemented.");
            }

            return new IdentityDecision(IdentityOutcome.Deny, "IP not in the static allowlist for this protected username.");
        }

        if (entry.PasswordHash is not null)
        {
            return new IdentityDecision(IdentityOutcome.Deny,
                "Username is registered but the password gate (Stage 3) is not yet implemented.");
        }

        // An entry exists (e.g. pre-created via CLI) but has no allowlist, password, or premium
        // requirement configured yet — treat as not-yet-protected rather than denying everyone.
        return new IdentityDecision(IdentityOutcome.NotProtected, "Identity record has no active protection configured.");
    }
}
