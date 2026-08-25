namespace MinecraftFirewall.Proxy.Identity;

/// <summary>
/// A player's own request to lock their username to their real Microsoft account.
///
/// This is the missing middle between the two ways a name could previously become premium-locked. An
/// admin could declare one in appsettings.json, which does not scale past the handful of names an
/// admin knows about; or auto-claim could offer the challenge to *everyone*, which asks every new
/// player's client to answer an encryption request and is switched off for exactly that reason. What
/// neither covers is the ordinary case: one player who cares about their own name and wants it locked,
/// on a server where the owner has not turned auto-claim on.
///
/// The safety argument is the same one that makes auto-claim safe, and it rests entirely on how
/// Mojang's check works. The challenge asks Mojang whether *this username* has an active session, so
/// the only account that can ever answer for a name is the account that owns it. Someone squatting a
/// name with a cracked client can arm this all they like: the challenge they then have to pass is one
/// only the genuine owner can pass, and a failure records nothing at all. There is no way to use it to
/// pin a name to an account that does not own it.
///
/// Two steps rather than one, and a short life. Locking a name is permanent and the player is about to
/// be asked to reconnect, so it asks for confirmation first — and if they wander off, the armed
/// request lapses rather than surprising them on a reconnect an hour later.
/// </summary>
public sealed record PremiumClaimRequest(DateTimeOffset ArmedAt)
{
    /// <summary>
    /// How long an armed request stays live.
    ///
    /// Long enough to close Minecraft, reopen it with the genuine account, and rejoin — which is what
    /// the player has just been told to do. Short enough that an abandoned request is not still
    /// waiting when somebody else connects with that name later.
    /// </summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    public bool IsLive(DateTimeOffset now) => now - ArmedAt < Lifetime;
}
