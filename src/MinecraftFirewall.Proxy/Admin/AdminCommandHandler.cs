using System.Net;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.IpIntel;

namespace MinecraftFirewall.Proxy.Admin;

/// <summary>
/// The actual logic behind every Admin CLI command — deliberately separate from AdminPipeServer's
/// transport/ACL concerns so it's unit-testable without a real named pipe. Every mutation here is
/// in-memory only (see docs/plan.md's Admin CLI note): IdentityStore has no on-disk persistence, so a
/// whitelist-add-me or require-premium survives until the next service restart and no longer. Every
/// response for a mutating command says so explicitly — this is a correctness/security property to
/// preserve, not wording to trim.
/// </summary>
public sealed class AdminCommandHandler(
    IReadOnlyList<ServerProfile> profiles,
    FirewallBanService banService,
    IpListRefreshService ipListRefreshService,
    ILogger<AdminCommandHandler> logger)
{
    private const string NotPersistedNote =
        "NOTE: this change is in-memory only and will NOT survive a service restart. " +
        "To make it permanent, add it under that profile's ProtectedUsernames in appsettings.json.";

    /// <summary>
    /// require-premium needs a blunter warning than <see cref="NotPersistedNote"/> alone, because it
    /// is the one command whose loss on restart fails OPEN rather than closed. whitelist-add-me
    /// lapsing just means someone gets denied — annoying, safe. This lapsing means a name the admin
    /// believed was locked to its real owner is silently open to anyone again. Worse, it looks fine
    /// in the meantime: if the genuine owner connects before the config edit, their UUID pin IS
    /// written to the identity store, but the pin is only ever consulted for a name that is currently
    /// PremiumRequired — so after a restart it sits there doing nothing.
    /// </summary>
    private const string PremiumNotPersistedWarning =
        "WARNING: unlike the other commands, losing this one on restart fails OPEN — the name becomes " +
        "usable by anyone again, rather than simply being denied. Add \"RequirePremium\": true under that " +
        "profile's ProtectedUsernames in appsettings.json NOW. Until you do, even a successful " +
        "verification by the real owner does not make this stick: the UUID pin is recorded, but it is " +
        "only consulted while the name is marked premium, so a restart leaves the name unprotected.";

    public async Task<AdminResponse> HandleAsync(AdminRequest request, CancellationToken ct)
    {
        try
        {
            return request.Command.ToLowerInvariant() switch
            {
                "whitelist-add-me" => WhitelistAdd(request.Args),
                "list-bans" => ListBans(),
                "unban" => Unban(request.Args),
                "require-premium" => RequirePremium(request.Args),
                "reload" => await ReloadAsync(ct).ConfigureAwait(false),
                "list-profiles" => ListProfiles(),
                "help" or "" => Help(),
                _ => new AdminResponse(false, $"Unknown command '{request.Command}'. " + Help().Message),
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Admin command '{Command}' failed unexpectedly.", request.Command);
            return new AdminResponse(false, $"Internal error: {ex.Message}");
        }
    }

    private AdminResponse WhitelistAdd(string[] args)
    {
        // Named "whitelist-add-me" for continuity with the original design note, but it cannot
        // actually detect "your" IP: the admin pipe is loopback-only by design (see AdminPipeServer),
        // so the only IP a connection to it could ever reveal is 127.0.0.1 — useless for allowlisting
        // a remote admin's real address. It takes an explicit IP/CIDR instead of guessing.
        if (args.Length != 3)
            return new AdminResponse(false, "Usage: whitelist-add-me <profile> <username> <ip-or-cidr>");

        if (!TryFindProfile(args[0], out var profile, out var error))
            return new AdminResponse(false, error!);

        CidrRange cidr;
        try
        {
            cidr = CidrRange.Parse(args[2]);
        }
        catch (FormatException)
        {
            return new AdminResponse(false, $"'{args[2]}' is not a valid IP address or CIDR range.");
        }

        var entry = profile.IdentityStore.GetOrCreate(args[1]);
        entry.StaticAllowlist.Add(cidr);

        logger.LogWarning("Admin CLI: added '{Ip}' to the static allowlist for '{Username}' on profile '{Profile}'.",
            args[2], args[1], profile.Name);

        return new AdminResponse(true, $"Added {args[2]} to the allowlist for '{args[1]}' on profile '{profile.Name}'. {NotPersistedNote}");
    }

    private AdminResponse ListBans()
    {
        var bans = banService.ListActiveBans();
        if (bans.Count == 0)
            return new AdminResponse(true, "No active bans.");

        var lines = bans
            .OrderBy(b => b.ExpiresAt)
            .Select(b => $"{b.Address}  expires {b.ExpiresAt:u}");
        return new AdminResponse(true, string.Join('\n', lines));
    }

    private AdminResponse Unban(string[] args)
    {
        if (args.Length != 1 || !IPAddress.TryParse(args[0], out var address))
            return new AdminResponse(false, "Usage: unban <ip>");

        bool wasBanned = banService.IsBanned(address);
        banService.Unban(address);

        logger.LogWarning("Admin CLI: unbanned {Ip} (was banned: {WasBanned}).", address, wasBanned);

        return new AdminResponse(true, wasBanned ? $"Unbanned {address}." : $"{address} was not currently banned (no-op).");
    }

    private AdminResponse RequirePremium(string[] args)
    {
        if (args.Length != 2)
            return new AdminResponse(false, "Usage: require-premium <profile> <username>");

        if (!TryFindProfile(args[0], out var profile, out var error))
            return new AdminResponse(false, error!);

        var entry = profile.IdentityStore.GetOrCreate(args[1]);
        entry.PremiumRequired = true;

        logger.LogWarning("Admin CLI: marked '{Username}' on profile '{Profile}' as PremiumRequired.", args[1], profile.Name);

        return new AdminResponse(true,
            $"'{args[1]}' on profile '{profile.Name}' now requires a verified premium (Microsoft/Mojang) account to join — " +
            $"any other login attempt for that name will be denied outright, with no password fallback. {PremiumNotPersistedWarning}");
    }

    private async Task<AdminResponse> ReloadAsync(CancellationToken ct)
    {
        // Scope is deliberately narrow: this refreshes the X4BNet VPN/datacenter CIDR lists on demand
        // instead of waiting for the daily timer. It does NOT re-read ServerProfiles, protected
        // usernames, ports, or any other appsettings.json section — those require a service restart.
        await ipListRefreshService.RefreshNowAsync(ct).ConfigureAwait(false);
        return new AdminResponse(true, "VPN/datacenter IP lists refreshed. (This does not reload ServerProfiles or other config — restart the service for that.)");
    }

    private AdminResponse ListProfiles()
    {
        if (profiles.Count == 0)
            return new AdminResponse(true, "No server profiles configured.");

        var lines = profiles.Select(p =>
            $"{p.Name}: public port {p.PublicPort} -> {p.BackendHost}:{p.BackendPort}, VpnPolicy={p.VpnPolicy}" +
            (p.AllowedHostnames.Count > 0 ? $", AllowedHostnames=[{string.Join(", ", p.AllowedHostnames)}]" : ""));
        return new AdminResponse(true, string.Join('\n', lines));
    }

    private static AdminResponse Help() => new(true,
        "Commands:\n" +
        "  whitelist-add-me <profile> <username> <ip-or-cidr>  Add an IP/CIDR to a username's static allowlist\n" +
        "  list-bans                                           List active firewall bans\n" +
        "  unban <ip>                                          Remove a firewall ban\n" +
        "  require-premium <profile> <username>                Require a verified Mojang account for this username\n" +
        "  reload                                               Refresh the VPN/datacenter IP lists now\n" +
        "  list-profiles                                       List configured server profiles");

    private bool TryFindProfile(string name, out ServerProfile profile, out string? error)
    {
        var found = profiles.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
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
