using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Proxy.Identity.Persistence;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace MinecraftFirewall.Tests;

public class IdentityStatePersistenceTests : IDisposable
{
    private readonly string _tempDirectory = Path.Combine(Path.GetTempPath(), "mcfw-persist-" + Guid.NewGuid().ToString("N"));
    private readonly IdentityStatePersistence _persistence = new(NullLogger<IdentityStatePersistence>.Instance);

    private string FilePath => Path.Combine(_tempDirectory, "identity-store.json");

    public void Dispose()
    {
        if (Directory.Exists(_tempDirectory))
            Directory.Delete(_tempDirectory, recursive: true);
        GC.SuppressFinalize(this);
    }

    private static ServerProfile NewProfile(string name = "TestServer") =>
        new() { Name = name, PublicPort = 25565, BackendHost = "127.0.0.1", BackendPort = 25566 };

    private void SaveAndReload(IReadOnlyList<ServerProfile> from, IReadOnlyList<ServerProfile> into)
    {
        _persistence.Save(_persistence.Serialize(from), FilePath);
        _persistence.Load(into, FilePath);
    }

    [Fact]
    public void RoundTrip_RestoresPasswordHashPinnedUuidAndLearnedIps()
    {
        var original = NewProfile();
        var entry = original.IdentityStore.GetOrCreate("Player1");
        entry.PasswordHash = "pbkdf2-hash-value";
        entry.LearnIp(IPAddress.Parse("203.0.113.7"), TimeSpan.FromDays(30), maxLearnedIps: 5);
        var uuid = Guid.NewGuid();
        entry.TryClaimOrMatchPinnedUuid(uuid);

        var restored = NewProfile();
        SaveAndReload([original], [restored]);

        var loaded = restored.IdentityStore.Find("Player1");
        Assert.NotNull(loaded);
        Assert.Equal("pbkdf2-hash-value", loaded!.PasswordHash);
        Assert.Equal(uuid, loaded.PinnedUuid);
        Assert.True(loaded.IsIpRecognized(IPAddress.Parse("203.0.113.7")));
    }

    [Fact]
    public void RoundTrip_PreservesTheOriginalLearnedIpExpiry_RatherThanRenewingIt()
    {
        // The trap RestoreLearnedIp exists to avoid: if loading went through LearnIp, every restart
        // would reset each learned IP's TTL from "now", quietly turning a bounded 30-day trust window
        // into a permanent one for anyone who restarts the service regularly.
        var original = NewProfile();
        var entry = original.IdentityStore.GetOrCreate("Player1");
        entry.LearnIp(IPAddress.Parse("203.0.113.7"), TimeSpan.FromSeconds(90), maxLearnedIps: 5);
        long originalExpiry = entry.LearnedIps.Single().ExpiresAtUnixSeconds;

        var restored = NewProfile();
        SaveAndReload([original], [restored]);

        Assert.Equal(originalExpiry, restored.IdentityStore.Find("Player1")!.LearnedIps.Single().ExpiresAtUnixSeconds);
    }

    [Fact]
    public void Load_DropsLearnedIpsThatAlreadyExpired()
    {
        var original = NewProfile();
        var entry = original.IdentityStore.GetOrCreate("Player1");
        entry.PasswordHash = "hash";
        entry.LearnIp(IPAddress.Parse("203.0.113.7"), TimeSpan.FromDays(-1), maxLearnedIps: 5);

        var restored = NewProfile();
        SaveAndReload([original], [restored]);

        Assert.Empty(restored.IdentityStore.Find("Player1")!.LearnedIps);
    }

    [Fact]
    public void Serialize_OmitsAdminDeclaredFields_SoConfigStaysTheSourceOfTruth()
    {
        // PremiumRequired and the static allowlist come from appsettings.json. Persisting them would
        // mean removing a name from config no longer removes it — a stale file silently overriding
        // the file the admin actually edited.
        var profile = NewProfile();
        var entry = new IdentityEntry { Username = "Admin", PremiumRequired = true };
        entry.StaticAllowlist.Add(CidrRange.Parse("203.0.113.7/32"));
        entry.PasswordHash = "hash"; // so the entry is persisted at all
        profile.IdentityStore.AddOrReplace(entry);

        string json = _persistence.Serialize([profile]);

        Assert.DoesNotContain("PremiumRequired", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("allowlist", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("203.0.113.7", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_DoesNotResurrectPremiumRequiredForANameTheAdminRemovedFromConfig()
    {
        // The practical consequence of the rule above, stated as behaviour: a name that was premium
        // and had claimed a pin must not still be premium-gated after the admin removes the flag.
        var original = NewProfile();
        var entry = new IdentityEntry { Username = "Admin", PremiumRequired = true };
        entry.TryClaimOrMatchPinnedUuid(Guid.NewGuid());
        original.IdentityStore.AddOrReplace(entry);

        var restored = NewProfile(); // config no longer declares RequirePremium for this name
        SaveAndReload([original], [restored]);

        Assert.False(restored.IdentityStore.Find("Admin")!.PremiumRequired);
    }

    [Fact]
    public void Serialize_SkipsEntriesWithNothingLearned()
    {
        var profile = NewProfile();
        var configOnly = new IdentityEntry { Username = "Admin" };
        configOnly.StaticAllowlist.Add(CidrRange.Parse("203.0.113.7/32"));
        profile.IdentityStore.AddOrReplace(configOnly);

        string json = _persistence.Serialize([profile]);

        Assert.DoesNotContain("Admin", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Serialize_IsStable_ForUnchangedState()
    {
        // IdentityPersistenceService detects changes by comparing serialized output, so an unstable
        // ordering would rewrite the file (and its restrictive ACL) every single tick.
        var profile = NewProfile();
        var entry = profile.IdentityStore.GetOrCreate("Player1");
        entry.PasswordHash = "hash";
        entry.LearnIp(IPAddress.Parse("203.0.113.7"), TimeSpan.FromDays(30), 5);
        entry.LearnIp(IPAddress.Parse("198.51.100.4"), TimeSpan.FromDays(30), 5);
        profile.IdentityStore.GetOrCreate("Player2").PasswordHash = "hash2";

        Assert.Equal(_persistence.Serialize([profile]), _persistence.Serialize([profile]));
    }

    [Fact]
    public void Load_MissingFile_LeavesProfilesUntouchedAndDoesNotThrow()
    {
        var profile = NewProfile();

        _persistence.Load([profile], Path.Combine(_tempDirectory, "does-not-exist.json"));

        Assert.Null(profile.IdentityStore.Find("Player1"));
    }

    [Fact]
    public void Load_CorruptFile_DoesNotThrow_AndLeavesConfigStateIntact()
    {
        // A cache file must never be able to stop the service from starting.
        Directory.CreateDirectory(_tempDirectory);
        File.WriteAllText(FilePath, "{ this is not valid json");

        var profile = NewProfile();
        var entry = new IdentityEntry { Username = "Admin", PremiumRequired = true };
        profile.IdentityStore.AddOrReplace(entry);

        _persistence.Load([profile], FilePath);

        Assert.True(profile.IdentityStore.Find("Admin")!.PremiumRequired);
    }

    [Fact]
    public void Load_UnknownProfileName_IsSkippedWithoutAffectingOthers()
    {
        var original = NewProfile("RenamedAway");
        original.IdentityStore.GetOrCreate("Player1").PasswordHash = "hash";

        var restored = NewProfile("DifferentName");
        SaveAndReload([original], [restored]);

        Assert.Null(restored.IdentityStore.Find("Player1"));
    }

    [Fact]
    public void Save_WritesAFileReadableOnlyByAdministratorsSystemAndTheServiceAccount()
    {
        // The file holds PBKDF2 password hashes; C:\ProgramData is world-readable by default, so
        // inheritance must be off and the DACL narrow. The service's own account has to be on it too,
        // or an unelevated service (a deployment the README explicitly supports) silently loses write
        // access to its own store after the very first save.
        var profile = NewProfile();
        profile.IdentityStore.GetOrCreate("Player1").PasswordHash = "hash";
        _persistence.Save(_persistence.Serialize([profile]), FilePath);

        var security = new FileInfo(FilePath).GetAccessControl();
        Assert.True(security.AreAccessRulesProtected); // inheritance from ProgramData switched off

        var granted = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Where(rule => rule.AccessControlType == AccessControlType.Allow)
            .Select(rule => (SecurityIdentifier)rule.IdentityReference)
            .ToList();

        using var currentUser = WindowsIdentity.GetCurrent();
        Assert.Contains(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), granted);
        Assert.Contains(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), granted);
        Assert.Contains(currentUser.User!, granted);

        foreach (var forbidden in new[] { WellKnownSidType.WorldSid, WellKnownSidType.AuthenticatedUserSid, WellKnownSidType.BuiltinUsersSid })
            Assert.DoesNotContain(new SecurityIdentifier(forbidden, null), granted);
    }

    [Fact]
    public void Save_ThenLoad_WorksAsTheSameAccountThatWroteIt()
    {
        // The regression guard for the ACL trap above: writing must not lock this process out of
        // re-reading, re-writing, or replacing its own store on the next save.
        var profile = NewProfile();
        profile.IdentityStore.GetOrCreate("Player1").PasswordHash = "first";
        _persistence.Save(_persistence.Serialize([profile]), FilePath);

        profile.IdentityStore.Find("Player1")!.PasswordHash = "second";
        _persistence.Save(_persistence.Serialize([profile]), FilePath);

        var reloaded = NewProfile();
        _persistence.Load([reloaded], FilePath);
        Assert.Equal("second", reloaded.IdentityStore.Find("Player1")!.PasswordHash);
    }

    [Fact]
    public void Save_ReplacesAnExistingFileAtomically_LeavingNoTempFileBehind()
    {
        var profile = NewProfile();
        profile.IdentityStore.GetOrCreate("Player1").PasswordHash = "first";
        _persistence.Save(_persistence.Serialize([profile]), FilePath);

        profile.IdentityStore.Find("Player1")!.PasswordHash = "second";
        _persistence.Save(_persistence.Serialize([profile]), FilePath);

        Assert.Contains("second", File.ReadAllText(FilePath), StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(_tempDirectory, "*.tmp"));
    }
}
