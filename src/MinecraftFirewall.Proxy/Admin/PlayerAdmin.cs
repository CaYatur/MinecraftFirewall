using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Identity;

namespace MinecraftFirewall.Proxy.Admin;

/// <summary>One player as the control panel's list shows them.</summary>
public sealed record PlayerSummary(
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("registeredAt")] DateTimeOffset? RegisteredAt,
    [property: JsonPropertyName("lastSeenAt")] DateTimeOffset? LastSeenAt,
    [property: JsonPropertyName("lastIp")] string? LastAddress,
    [property: JsonPropertyName("learnedIps")] int LearnedIpCount,
    [property: JsonPropertyName("risk")] int Risk);

/// <summary>One weighted reason an address looks suspicious, as the panel displays it.</summary>
public sealed record RiskFactor(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("weight")] int Weight,
    [property: JsonPropertyName("detail")] string Detail);

/// <summary>Everything the panel shows when one player is opened.</summary>
public sealed record PlayerDetail(
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("hasPassword")] bool HasPassword,
    [property: JsonPropertyName("premiumRequired")] bool PremiumRequired,
    [property: JsonPropertyName("pinnedUuid")] string? PinnedUuid,
    [property: JsonPropertyName("registeredAt")] DateTimeOffset? RegisteredAt,
    [property: JsonPropertyName("lastSeenAt")] DateTimeOffset? LastSeenAt,
    [property: JsonPropertyName("lastIp")] string? LastAddress,
    [property: JsonPropertyName("staticAllowlist")] List<string> StaticAllowlist,
    [property: JsonPropertyName("learnedIps")] List<string> LearnedIps,
    [property: JsonPropertyName("riskTotal")] int RiskTotal,
    [property: JsonPropertyName("riskScope")] string RiskScope,
    [property: JsonPropertyName("risks")] List<RiskFactor> Risks,
    [property: JsonPropertyName("events")] List<PersistedEventLine> Events);

public sealed record PersistedEventLine(
    [property: JsonPropertyName("at")] DateTimeOffset When,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("ip")] string? Address,
    [property: JsonPropertyName("detail")] string Detail);

/// <summary>
/// The per-player half of the admin surface: who this server knows, what happened to them, and the
/// handful of things an administrator can do about it.
///
/// Replies are JSON in the response's message field rather than the prose the other commands use.
/// That is not elegant, but the alternative is a second transport, and the pipe contract is one line
/// of JSON each way already. Prose is right for a person reading a terminal; a list a panel has to
/// sort and filter is not prose.
///
/// One thing this is deliberately careful about. The risk figures come from the bot detector, which
/// scores an *address*, not a person — the same address in this project's own testing carried two
/// different names. So the score is reported against the last address the player connected from and
/// labelled as such. Presenting an address's score as a player's would be quietly implying an
/// alt-account correlation that has not been built.
/// </summary>
public sealed class PlayerAdmin(IReadOnlyList<ServerProfile> profiles, BotDetector botDetector)
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    public AdminResponse List(string[] args)
    {
        if (args.Length != 1)
            return new AdminResponse(false, "Usage: list-players <profile>");

        if (!TryFindProfile(args[0], out ServerProfile profile, out string? error))
            return new AdminResponse(false, error!);

        List<PlayerSummary> summaries =
        [
            .. profile.IdentityStore.All()
                .OrderByDescending(e => e.LastSeenAt ?? DateTimeOffset.MinValue)
                .ThenBy(e => e.Username, StringComparer.OrdinalIgnoreCase)
                .Select(entry => new PlayerSummary(
                    entry.Username,
                    Describe(entry),
                    entry.RegisteredAt,
                    entry.LastSeenAt,
                    entry.LastAddress,
                    entry.LearnedIps.Count,
                    RiskOf(entry).Sum(r => r.Weight))),
        ];

        return new AdminResponse(true, JsonSerializer.Serialize(summaries, Json));
    }

    public AdminResponse Info(string[] args)
    {
        if (args.Length != 2)
            return new AdminResponse(false, "Usage: player-info <profile> <username>");

        if (!TryFindProfile(args[0], out ServerProfile profile, out string? error))
            return new AdminResponse(false, error!);

        IdentityEntry? entry = profile.IdentityStore.Find(args[1]);
        if (entry is null)
            return new AdminResponse(false, $"'{args[1]}' is not a name this server knows.");

        List<RiskFactor> risks = RiskOf(entry);

        var detail = new PlayerDetail(
            entry.Username,
            Describe(entry),
            entry.PasswordHash is not null,
            entry.PremiumRequired,
            entry.PinnedUuid?.ToString(),
            entry.RegisteredAt,
            entry.LastSeenAt,
            entry.LastAddress,
            [.. entry.StaticAllowlist.Select(c => c.ToString())],
            [.. entry.LearnedIps.Select(ip => ip.Address.ToString())],
            risks.Sum(r => r.Weight),
            entry.LastAddress is { } address
                ? $"scored for the address {address}, not for the person — one address can carry several names"
                : "no address seen yet",
            risks,
            [.. entry.Events.OrderByDescending(e => e.When)
                .Select(e => new PersistedEventLine(e.When, e.Kind.ToString(), e.Address, e.Detail))]);

        return new AdminResponse(true, JsonSerializer.Serialize(detail, Json));
    }

    /// <summary>
    /// Clears a password so the player registers again on their next join.
    ///
    /// A reset rather than a new password. An administrator setting one would have to transmit it to
    /// the player somehow, and every way of doing that ends with the password sitting in a chat log
    /// or a message somewhere. Clearing it means the next person to use the name chooses it — which
    /// is why the learned addresses go too, so it is not simply handed to whoever is nearby.
    /// </summary>
    public AdminResponse ResetPassword(string[] args)
    {
        if (args.Length != 2)
            return new AdminResponse(false, "Usage: reset-password <profile> <username>");

        if (!TryFindProfile(args[0], out ServerProfile profile, out string? error))
            return new AdminResponse(false, error!);

        IdentityEntry? entry = profile.IdentityStore.Find(args[1]);
        if (entry is null)
            return new AdminResponse(false, $"'{args[1]}' is not a name this server knows.");

        entry.PasswordHash = null;
        entry.ForgetLearnedIps();
        entry.RegisteredAt = null;
        entry.Record(PlayerEventKind.PasswordReset, null, "an administrator cleared the password", DateTimeOffset.UtcNow);

        return new AdminResponse(true,
            $"'{entry.Username}' has no password now and will be asked to register on their next join. " +
            "Their remembered addresses were cleared too, so the name is not simply handed to whoever connects next.");
    }

    /// <summary>Forgets the addresses this name is trusted from, so the next connection has to prove
    /// the password again. The gentler half of a reset.</summary>
    public AdminResponse ForgetAddresses(string[] args)
    {
        if (args.Length != 2)
            return new AdminResponse(false, "Usage: forget-addresses <profile> <username>");

        if (!TryFindProfile(args[0], out ServerProfile profile, out string? error))
            return new AdminResponse(false, error!);

        IdentityEntry? entry = profile.IdentityStore.Find(args[1]);
        if (entry is null)
            return new AdminResponse(false, $"'{args[1]}' is not a name this server knows.");

        int forgotten = entry.LearnedIps.Count;
        entry.ForgetLearnedIps();
        entry.Record(PlayerEventKind.Denied, null, "an administrator cleared the remembered addresses", DateTimeOffset.UtcNow);

        return new AdminResponse(true,
            $"Forgot {forgotten} remembered address(es) for '{entry.Username}'. Their next connection has to log in.");
    }

    /// <summary>
    /// Removes everything this server has learned about a name.
    ///
    /// Everything learned, which is not everything: a name declared in appsettings.json comes back
    /// from configuration on the next restart, and the reply says so rather than letting somebody
    /// discover it later. The alternative — writing to the config file from here — would mean this
    /// process editing the file the administrator edits, and those two would eventually disagree.
    /// </summary>
    public AdminResponse Remove(string[] args)
    {
        if (args.Length != 2)
            return new AdminResponse(false, "Usage: remove-player <profile> <username>");

        if (!TryFindProfile(args[0], out ServerProfile profile, out string? error))
            return new AdminResponse(false, error!);

        IdentityEntry? entry = profile.IdentityStore.Find(args[1]);
        if (entry is null)
            return new AdminResponse(false, $"'{args[1]}' is not a name this server knows.");

        bool declaredInConfig = entry.StaticAllowlist.Count > 0 || entry.PremiumRequired;
        profile.IdentityStore.Remove(entry.Username);

        return new AdminResponse(true, declaredInConfig
            ? $"Removed everything learned about '{entry.Username}'. It is also declared in appsettings.json, " +
              "so it will come back from there on the next restart — remove it from that file too if you want it gone."
            : $"Removed '{entry.Username}'. They will be treated as a new player on their next join.");
    }

    /// <summary>Locks a name to a verified Minecraft account, or unlocks it. See the warning in the
    /// reply: this one field is deliberately not persisted, because appsettings.json owns it.</summary>
    public AdminResponse SetPremium(string[] args)
    {
        if (args.Length != 3 || !bool.TryParse(args[2], out bool required))
            return new AdminResponse(false, "Usage: set-premium <profile> <username> <true|false>");

        if (!TryFindProfile(args[0], out ServerProfile profile, out string? error))
            return new AdminResponse(false, error!);

        IdentityEntry entry = profile.IdentityStore.GetOrCreate(args[1]);
        entry.PremiumRequired = required;
        entry.Record(required ? PlayerEventKind.PremiumVerified : PlayerEventKind.Denied, null,
            required ? "an administrator locked this name to its Minecraft account"
                     : "an administrator unlocked this name", DateTimeOffset.UtcNow);

        return new AdminResponse(true, required
            ? $"'{entry.Username}' now requires a verified Minecraft account. This is the one setting that does NOT " +
              "survive a restart: add \"RequirePremium\": true under that profile's ProtectedUsernames in " +
              "appsettings.json, or the name silently becomes usable by anyone again on the next restart."
            : $"'{entry.Username}' no longer requires a verified Minecraft account. If it is set in appsettings.json, " +
              "remove it there too — otherwise the next restart puts it back.");
    }

    /// <summary>
    /// What the bot detector currently thinks of the address this player last used.
    ///
    /// Empty for a player with no address on record. Nothing is invented here: these are the same
    /// signals the login path scores, surfaced rather than recomputed, which is why the weights add up
    /// to the same number the log prints when a connection is assessed.
    /// </summary>
    private List<RiskFactor> RiskOf(IdentityEntry entry)
    {
        if (entry.LastAddress is null || !IPAddress.TryParse(entry.LastAddress, out IPAddress? address))
            return [];

        return
        [
            .. botDetector.Explain(address)
                .Select(signal => new RiskFactor(signal.Name, signal.Weight, signal.Detail)),
        ];
    }

    private static string Describe(IdentityEntry entry)
    {
        if (entry.PremiumRequired)
            return entry.PinnedUuid is null ? "premium-locked (awaiting first verification)" : "premium-locked";

        if (entry.PasswordHash is not null)
            return "registered";

        return entry.StaticAllowlist.Count > 0 ? "allowlisted in config" : "known, no password";
    }

    private bool TryFindProfile(string name, out ServerProfile profile, out string? error)
    {
        ServerProfile? found = profiles.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
        if (found is null)
        {
            profile = null!;
            error = $"No server profile named '{name}'. Known profiles: {string.Join(", ", profiles.Select(p => p.Name))}";
            return false;
        }

        profile = found;
        error = null;
        return true;
    }
}
