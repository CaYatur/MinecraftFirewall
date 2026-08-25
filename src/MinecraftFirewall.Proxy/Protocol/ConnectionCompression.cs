namespace MinecraftFirewall.Proxy.Protocol;

/// <summary>
/// The compression threshold this connection negotiated, shared between the pump that learns it and
/// everything that writes to the player.
///
/// It has to be known, and it cannot be assumed. Minecraft's compressed frame format carries a
/// declared uncompressed length, and both ends enforce a rule about it that is easy to miss: a packet
/// at or above the threshold **must** be compressed, and one below it must **not** be. Get either
/// wrong and the client does not shrug — it disconnects with a decoder error.
///
/// This exists because that was got wrong. Every packet the proxy composed itself was sent with a
/// declared length of zero, meaning uncompressed, on the belief that the format allowed it whatever
/// the threshold was. It does not. Any message longer than the threshold — the explanation of what
/// locking your name does is 312 bytes against a default of 256 — disconnected the player it was
/// being explained to.
/// </summary>
public sealed class ConnectionCompression
{
    /// <summary>Payloads this size or larger must be compressed. Negative means the backend never
    /// turned compression on, and frames carry no length field at all.</summary>
    public volatile int Threshold = NotCompressed;

    public const int NotCompressed = -1;

    /// <summary>
    /// True once the backend has said which it is.
    ///
    /// Nothing the proxy originates is sent before this. It costs nothing to wait: every message it
    /// composes belongs to Play state, and Play state is strictly after the backend has finished
    /// deciding — so there is no case where waiting loses a message that could otherwise have been
    /// delivered, and guessing would mean a coin flip on disconnecting the player.
    /// </summary>
    public volatile bool Established;

    public void UseThreshold(int threshold)
    {
        Threshold = threshold > 0 ? threshold : NotCompressed;
        Established = true;
    }

    public void UseNoCompression()
    {
        Threshold = NotCompressed;
        Established = true;
    }
}
