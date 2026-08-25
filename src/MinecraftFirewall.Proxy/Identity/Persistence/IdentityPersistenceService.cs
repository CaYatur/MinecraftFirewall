using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Proxy.Identity.Persistence;

/// <summary>
/// Loads the persisted identity store at startup, then re-saves it whenever it has actually changed,
/// and once more on graceful shutdown.
///
/// Change detection is by comparing the freshly serialized document to the last one written, rather
/// than by a dirty flag threaded through every mutation site (IdentityEntry.LearnIp, the password
/// setter, the UUID pin claim, GetOrCreate...). Serializing a few hundred records every 30 seconds
/// costs nothing measurable, and it cannot silently miss a mutation the way a hand-maintained flag
/// can — which matters here, because the thing that would go missing is exactly the state that
/// protects a username.
/// </summary>
public sealed class IdentityPersistenceService(
    IReadOnlyList<ServerProfile> profiles,
    IdentityStatePersistence persistence,
    IOptions<IdentityPersistenceOptions> options,
    ILogger<IdentityPersistenceService> logger) : BackgroundService
{
    private readonly IdentityPersistenceOptions _options = options.Value;
    private string? _lastWritten;

    public override Task StartAsync(CancellationToken cancellationToken)
    {
        if (!_options.Enabled)
        {
            logger.LogWarning("Identity persistence is disabled. Self-registered passwords, learned IPs and premium UUID pins will be lost on restart.");
            return base.StartAsync(cancellationToken);
        }

        persistence.Load(profiles, _options.FilePath);
        // Seed the baseline from what was just loaded, so an unchanged store isn't rewritten on the
        // very first tick purely because nothing had been written yet in this process.
        _lastWritten = SafeSerialize();
        return base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
            return;

        using var timer = new PeriodicTimer(_options.SaveInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
                SaveIfChanged();
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        // Runs after ExecuteAsync has been cancelled, so anything learned since the last tick is
        // still captured on a graceful stop — only a hard kill can lose up to SaveInterval.
        if (_options.Enabled)
            SaveIfChanged();

        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    private void SaveIfChanged()
    {
        string? current = SafeSerialize();
        if (current is null || current == _lastWritten)
            return;

        try
        {
            persistence.Save(current, _options.FilePath);
            _lastWritten = current;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Deliberately not fatal: the proxy protecting connections matters more than the store
            // being current, and _lastWritten is left alone so the next tick retries.
            logger.LogError(ex, "Could not write the identity store to {Path}. Runtime-learned state is not being persisted right now.", _options.FilePath);
        }
    }

    private string? SafeSerialize()
    {
        try
        {
            return persistence.Serialize(profiles);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Could not serialize the identity store.");
            return null;
        }
    }
}
