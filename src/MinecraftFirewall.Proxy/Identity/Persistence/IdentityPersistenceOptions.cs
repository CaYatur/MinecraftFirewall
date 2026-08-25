namespace MinecraftFirewall.Proxy.Identity.Persistence;

public sealed class IdentityPersistenceOptions
{
    public const string SectionName = "IdentityPersistence";

    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Where the store is written. Defaults alongside the log directory. The file contains PBKDF2
    /// password hashes and premium UUID pins, so <see cref="IdentityStatePersistence"/> restricts it
    /// to Administrators + SYSTEM on creation — see the note there.
    /// </summary>
    public string FilePath { get; set; } = @"C:\ProgramData\MinecraftFirewall\identity-store.json";

    /// <summary>How often the store is checked for changes and written if any. Bounds how much
    /// runtime-learned state a hard crash can lose; a graceful stop always saves immediately.</summary>
    public TimeSpan SaveInterval { get; set; } = TimeSpan.FromSeconds(30);
}
