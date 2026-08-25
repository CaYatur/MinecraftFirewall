using System.Collections.Concurrent;
using MinecraftFirewall.Proxy.Alerts;

namespace MinecraftFirewall.Tests.TestDoubles;

/// <summary>Captures alerts in memory instead of posting them, so tests can assert both that the
/// right events alert and — just as important — that alert text never carries anything it shouldn't.</summary>
public sealed class RecordingAlertSender : IAlertSender
{
    private readonly ConcurrentQueue<(AlertKind Kind, string Message)> _sent = new();

    public IReadOnlyList<(AlertKind Kind, string Message)> Sent => [.. _sent];

    public void Send(AlertKind kind, string message) => _sent.Enqueue((kind, message));
}
