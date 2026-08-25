namespace MinecraftFirewall.Proxy.Alerts;

public enum AlertKind
{
    Ban,
    NewTrustedIp,
    PremiumVerificationFailure,
    DangerousCommand,
}

/// <summary>
/// Fire-and-forget notification sink. Implementations MUST NOT block the caller and MUST NOT throw:
/// every call site is on a live connection's path, and an alerting outage must never be able to
/// break, delay, or deny a player's connection. Same fail-open philosophy as IIpInfoClient, and the
/// opposite of IPremiumSessionClient — this is observability, not a security gate.
/// </summary>
public interface IAlertSender
{
    void Send(AlertKind kind, string message);
}

/// <summary>Used when alerting is switched off, so call sites never need a null check.</summary>
public sealed class NullAlertSender : IAlertSender
{
    public void Send(AlertKind kind, string message) { }
}
