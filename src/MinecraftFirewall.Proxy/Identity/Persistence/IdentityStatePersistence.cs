using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MinecraftFirewall.Proxy.Identity.Persistence;

public sealed record PersistedLearnedIp(
    [property: JsonPropertyName("ip")] string Ip,
    [property: JsonPropertyName("expiresAt")] long ExpiresAtUnixSeconds);

public sealed record PersistedIdentityEntry(
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("passwordHash")] string? PasswordHash,
    [property: JsonPropertyName("pinnedUuid")] Guid? PinnedUuid,
    [property: JsonPropertyName("learnedIps")] List<PersistedLearnedIp> LearnedIps);

public sealed record PersistedProfile(
    [property: JsonPropertyName("profile")] string ProfileName,
    [property: JsonPropertyName("entries")] List<PersistedIdentityEntry> Entries);

public sealed record PersistedIdentityState(
    [property: JsonPropertyName("version")] int Version,
    [property: JsonPropertyName("profiles")] List<PersistedProfile> Profiles);

/// <summary>
/// Reads and writes the runtime-learned half of every profile's IdentityStore.
///
/// **Only runtime-learned state is persisted**: self-registered CaYaDev-Check password hashes,
/// learned IPs, and premium UUID pins. Admin-declared fields — the static IP allowlist and the
/// PremiumRequired flag — are deliberately NOT persisted, because appsettings.json is their single
/// source of truth. Persisting them would mean an admin removing a name from config no longer
/// actually removes it, with a stale file quietly overriding the file the admin edited. It also
/// keeps the Admin CLI's "this does not survive a restart" warnings truthful: `whitelist-add-me`
/// and `require-premium` both write exactly those config-domain fields.
/// </summary>
public sealed class IdentityStatePersistence(ILogger<IdentityStatePersistence> logger)
{
    private const int CurrentVersion = 1;

    private static readonly JsonSerializerOptions SerializerOptions = new() { WriteIndented = true };

    public string Serialize(IReadOnlyList<ServerProfile> profiles)
    {
        var state = new PersistedIdentityState(CurrentVersion, [.. profiles.Select(SnapshotProfile)]);
        return JsonSerializer.Serialize(state, SerializerOptions);
    }

    private static PersistedProfile SnapshotProfile(ServerProfile profile)
    {
        var entries = profile.IdentityStore.All()
            // Nothing learned yet — persisting it would just be a config echo.
            .Where(entry => entry.PasswordHash is not null || entry.PinnedUuid is not null || entry.LearnedIps.Count > 0)
            .OrderBy(entry => entry.Username, StringComparer.OrdinalIgnoreCase)
            .Select(entry => new PersistedIdentityEntry(
                entry.Username,
                entry.PasswordHash,
                entry.PinnedUuid,
                [.. entry.LearnedIps
                    .OrderBy(ip => ip.Address.ToString(), StringComparer.Ordinal)
                    .Select(ip => new PersistedLearnedIp(ip.Address.ToString(), ip.ExpiresAtUnixSeconds))]))
            .ToList();

        return new PersistedProfile(profile.Name, entries);
    }

    /// <summary>Merges persisted runtime state onto the already-config-built profiles. Never throws:
    /// a missing, unreadable, or corrupt file means "start with config only", which is the same state
    /// a first run has — degraded, but never a crash loop at startup over a cache file.</summary>
    public void Load(IReadOnlyList<ServerProfile> profiles, string filePath)
    {
        if (!File.Exists(filePath))
        {
            logger.LogInformation("No persisted identity store at {Path} — starting from configuration only.", filePath);
            return;
        }

        PersistedIdentityState? state;
        try
        {
            state = JsonSerializer.Deserialize<PersistedIdentityState>(File.ReadAllText(filePath));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            logger.LogError(ex, "Could not read the persisted identity store at {Path} — continuing with configuration only. Self-registered passwords, learned IPs and premium UUID pins from previous runs are NOT loaded.", filePath);
            return;
        }

        if (state is null)
            return;

        if (state.Version != CurrentVersion)
        {
            logger.LogWarning("Persisted identity store at {Path} has version {Found}, expected {Expected} — ignoring it rather than guessing at its shape.", filePath, state.Version, CurrentVersion);
            return;
        }

        int restored = 0;
        foreach (var persistedProfile in state.Profiles)
        {
            var profile = profiles.FirstOrDefault(p => string.Equals(p.Name, persistedProfile.ProfileName, StringComparison.OrdinalIgnoreCase));
            if (profile is null)
            {
                logger.LogInformation("Persisted identity state for profile '{Profile}' has no matching configured profile — skipping it (the profile may have been renamed or removed).", persistedProfile.ProfileName);
                continue;
            }

            foreach (var persistedEntry in persistedProfile.Entries)
            {
                var entry = profile.IdentityStore.GetOrCreate(persistedEntry.Username);
                entry.PasswordHash ??= persistedEntry.PasswordHash;

                if (persistedEntry.PinnedUuid is { } pinned)
                    entry.TryClaimOrMatchPinnedUuid(pinned);

                foreach (var learned in persistedEntry.LearnedIps)
                {
                    if (IPAddress.TryParse(learned.Ip, out var address))
                        entry.RestoreLearnedIp(address, learned.ExpiresAtUnixSeconds);
                }

                restored++;
            }
        }

        logger.LogInformation("Restored {Count} identity record(s) from {Path}.", restored, filePath);
    }

    /// <summary>Writes via a temp file + atomic replace, so a crash or a full disk mid-write can
    /// never leave a half-written store behind — the previous good file survives instead.</summary>
    public void Save(string content, string filePath)
    {
        string? directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(directory))
            EnsureRestrictedDirectory(directory);

        string tempPath = filePath + ".tmp";
        File.WriteAllText(tempPath, content);
        RestrictToAdministrators(tempPath);
        File.Move(tempPath, filePath, overwrite: true);
    }

    private void EnsureRestrictedDirectory(string directory)
    {
        if (Directory.Exists(directory))
            return;

        Directory.CreateDirectory(directory);
        try
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            AddOwnerRules(security);
            new DirectoryInfo(directory).SetAccessControl(security);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or PlatformNotSupportedException or IOException)
        {
            logger.LogWarning(ex, "Could not restrict permissions on {Directory}. The identity store will still be written, but verify its ACLs yourself — it holds password hashes.", directory);
        }
    }

    /// <summary>
    /// This file holds PBKDF2 password hashes and premium UUID pins. C:\ProgramData is readable by
    /// every local user by default, so inheritance is switched off and access is narrowed — otherwise
    /// any local account could copy the hashes off the box and grind them offline at its leisure.
    /// Failing to apply the ACL is logged loudly but does not stop the save: losing all learned state
    /// would be the worse outcome, and the warning tells the operator exactly what to check.
    /// </summary>
    private void RestrictToAdministrators(string filePath)
    {
        try
        {
            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            AddOwnerRules(security);
            new FileInfo(filePath).SetAccessControl(security);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or PlatformNotSupportedException or IOException)
        {
            logger.LogWarning(ex, "Could not restrict permissions on {Path}. It contains password hashes — check its ACLs manually.", filePath);
        }
    }

    /// <summary>
    /// Administrators, SYSTEM, and the identity the service is actually running as — and nothing else.
    ///
    /// That third entry is not optional padding. README explicitly supports running this proxy
    /// unelevated (firewall bans degrade to in-process, everything else still works), and an
    /// Administrators+SYSTEM-only DACL locks such a service out of its own data file the moment it
    /// writes one — the store silently stops persisting from then on. Including the running account
    /// keeps the intended property intact either way: elevated, this resolves to administrators only;
    /// unelevated, it is the service's own account plus administrators, and still no other local user.
    /// </summary>
    private static void AddOwnerRules(FileSystemSecurity security)
    {
        var sids = new List<IdentityReference>
        {
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
        };

        using var current = WindowsIdentity.GetCurrent();
        if (current.User is not null && !sids.Contains(current.User))
            sids.Add(current.User);

        foreach (var sid in sids)
        {
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        }
    }
}
