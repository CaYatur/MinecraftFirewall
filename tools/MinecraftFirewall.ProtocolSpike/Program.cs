using System.Net.Sockets;
using MinecraftFirewall.Proxy.Protocol;

// Stage 2 empirical spike: connect to a real local server exactly like the proxy would forward a
// real client's bytes, and observe raw wire behavior instead of assuming it. Specifically:
//   - When does Set Compression arrive, and what does the frame format look like immediately after?
//   - What do real packet IDs/frame shapes look like during Login -> Configuration -> Play?
// This is a manual diagnostic tool, not part of the automated test suite — it needs a real server
// listening on 127.0.0.1:25566 (see test-server/ and README "Stage 2 spike" notes).

string host = args.Length > 0 ? args[0] : "127.0.0.1";
int port = args.Length > 1 ? int.Parse(args[1]) : 25566;

Console.WriteLine($"Discovering protocol version via a Status handshake against {host}:{port} ...");
int discoveredProtocolVersion = await DiscoverProtocolVersionAsync(host, port);
Console.WriteLine($"Server reports protocol version {discoveredProtocolVersion}. Using it for the Login handshake below (guessing here would risk a version-mismatch kick).\n");

Console.WriteLine($"Connecting to {host}:{port} ...");
using var client = new TcpClient();
await client.ConnectAsync(host, port);
var stream = client.GetStream();

byte[] handshake = BuildHandshakeFrame(protocolVersion: discoveredProtocolVersion, serverAddress: host, serverPort: (ushort)port, nextState: 2);
byte[] loginStart = BuildLoginStartFrame("SpikeTestUser");

await stream.WriteAsync(handshake);
await stream.WriteAsync(loginStart);
Console.WriteLine("Sent Handshake (next_state=login) + Login Start. Reading raw frames for 5 seconds...\n");

using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
int frameIndex = 0;
long compressionThreshold = -1; // -1 = not yet observed
bool sentLoginAcknowledged = false;
bool sentKnownPacks = false;
bool enteredPlayState = false;
byte[]? knownPacksEcho = null;

try
{
    while (true)
    {
        Frame frame;
        try
        {
            frame = await FrameReader.ReadFrameAsync(stream, maxFrameSize: 2 * 1024 * 1024, cts.Token);
        }
        catch (OperationCanceledException)
        {
            break;
        }

        frameIndex++;
        byte[] raw = frame.Raw;
        ReadOnlySpan<byte> payload = frame.Payload;

        if (compressionThreshold < 0)
        {
            // Pre-compression: payload = VarInt packetId + fields, exactly as Stage 1 assumes.
            int packetId = VarInt.Decode(payload, out int idLen);
            Console.WriteLine($"[frame {frameIndex}] RAW len={raw.Length} packetId=0x{packetId:X2} payload={ToHex(payload)}");

            // Login-state Set Compression packet: packet id 0x03 in every protocol version this
            // project targets (stable since its introduction), payload = packetId + one VarInt threshold.
            if (packetId == 0x03)
            {
                int threshold = VarInt.Decode(payload[idLen..], out _);
                compressionThreshold = threshold;
                Console.WriteLine($"  -> Interpreted as Set Compression, threshold={threshold}. Switching to compressed-frame parsing for subsequent frames.");
            }
        }
        else
        {
            // Post-compression: payload = VarInt dataLength + (possibly zlib-compressed) rest.
            int dataLength = VarInt.Decode(payload, out int dataLenPrefixLen);
            ReadOnlySpan<byte> rest = payload[dataLenPrefixLen..];
            int packetId;
            byte[] logicalPayload;

            if (dataLength == 0)
            {
                packetId = VarInt.Decode(rest, out int idLen3);
                logicalPayload = rest[idLen3..].ToArray();
                Console.WriteLine($"[frame {frameIndex}] RAW len={raw.Length} dataLength=0 (uncompressed) packetId=0x{packetId:X2} payload={ToHex(rest)}");
            }
            else
            {
                byte[] inflated = Inflate(rest.ToArray(), dataLength);
                packetId = VarInt.Decode(inflated, out int idLen2);
                logicalPayload = inflated[idLen2..];
                Console.WriteLine($"[frame {frameIndex}] RAW len={raw.Length} dataLength={dataLength} (compressed, inflated ok={inflated.Length == dataLength}) packetId=0x{packetId:X2} inflatedPayload={ToHex(inflated)}");
            }

            if (packetId == 0x02 && !sentLoginAcknowledged)
            {
                // This is Login Success (confirmed by structure: 16-byte UUID + String username + ...).
                // Real clients must reply with Login Acknowledged (serverbound, packet id 0x03, empty
                // payload) to move the connection into the Configuration state, then immediately send
                // Client Information (serverbound Configuration 0x00, per the current minecraft.wiki
                // field list) — a real client sends this proactively, not in response to a prompt.
                await stream.WriteAsync(WrapCompressedFrame([.. VarInt.Encode(0x03)]), cts.Token);
                sentLoginAcknowledged = true;
                Console.WriteLine("  -> Looks like Login Success. Sent Login Acknowledged (serverbound 0x03) to enter Configuration state.");

                byte[] clientInfo =
                [
                    .. VarInt.Encode(0x00),
                    .. EncodeString("en_US"),
                    10, // view distance
                    .. VarInt.Encode(0), // chat mode: enabled
                    1,  // chat colors: true
                    0x7F, // displayed skin parts: all
                    .. VarInt.Encode(1), // main hand: right
                    0,  // text filtering: false
                    1,  // allow server listings: true
                    .. VarInt.Encode(0), // particle status (added ~1.21.2): 0 = all
                ];
                await stream.WriteAsync(WrapCompressedFrame(clientInfo), cts.Token);
                Console.WriteLine("  -> Sent Client Information (serverbound Configuration 0x00).");
            }
            else if (sentLoginAcknowledged && !sentKnownPacks && packetId == 0x0E)
            {
                // Clientbound Known Packs — echo the same list back verbatim (packet id swapped to
                // the serverbound one, 0x07 per the wiki) rather than guess our own pack list.
                knownPacksEcho = [.. VarInt.Encode(0x07), .. logicalPayload];
                await stream.WriteAsync(WrapCompressedFrame(knownPacksEcho), cts.Token);
                sentKnownPacks = true;
                Console.WriteLine("  -> Echoed back serverbound Known Packs (Configuration 0x07).");
            }
            else if (sentLoginAcknowledged && packetId == 0x03)
            {
                Console.WriteLine("  -> Looks like Finish Configuration. Sending Acknowledge Finish Configuration (serverbound Configuration 0x03) to enter Play state.");
                await stream.WriteAsync(WrapCompressedFrame([.. VarInt.Encode(0x03)]), cts.Token);
                enteredPlayState = true;
            }
            else if (enteredPlayState)
            {
                Console.WriteLine("  -> (Play state packet)");
            }
        }
    }
}
catch (Exception ex)
{
    Console.WriteLine($"Stopped reading: {ex.GetType().Name}: {ex.Message}");
}

Console.WriteLine($"\nDone. Observed {frameIndex} frames. Compression threshold observed: {(compressionThreshold < 0 ? "never sent" : compressionThreshold.ToString())}.");

static string ToHex(ReadOnlySpan<byte> data)
{
    int max = Math.Min(data.Length, 64);
    return Convert.ToHexString(data[..max]) + (data.Length > max ? $"...(+{data.Length - max}B)" : "");
}

static byte[] Inflate(byte[] zlibCompressed, int expectedLength)
{
    using var input = new MemoryStream(zlibCompressed);
    using var zlib = new System.IO.Compression.ZLibStream(input, System.IO.Compression.CompressionMode.Decompress);
    using var output = new MemoryStream();
    zlib.CopyTo(output);
    return output.ToArray();
}

static byte[] BuildHandshakeFrame(int protocolVersion, string serverAddress, ushort serverPort, int nextState)
{
    byte[] payload =
    [
        .. VarInt.Encode(0x00),
        .. VarInt.Encode(protocolVersion),
        .. EncodeString(serverAddress),
        (byte)(serverPort >> 8),
        (byte)(serverPort & 0xFF),
        .. VarInt.Encode(nextState),
    ];
    return WrapFrame(payload);
}

static byte[] BuildLoginStartFrame(string username)
{
    // Modern Login Start also carries a UUID field after the username; the server tolerates
    // an all-zero UUID for an offline-mode connection (it computes its own OfflinePlayer UUID anyway).
    byte[] payload = [.. VarInt.Encode(0x00), .. EncodeString(username), .. new byte[16]];
    return WrapFrame(payload);
}

static byte[] WrapFrame(byte[] payload) => [.. VarInt.Encode(payload.Length), .. payload];

// Once compression is active, every frame (including ones we send) needs the dataLength prefix —
// dataLength=0 for payloads under the threshold, sent uncompressed after that VarInt.
static byte[] WrapCompressedFrame(byte[] payload)
{
    byte[] inner = [.. VarInt.Encode(0), .. payload];
    return WrapFrame(inner);
}

static async Task<int> DiscoverProtocolVersionAsync(string host, int port)
{
    using var client = new TcpClient();
    await client.ConnectAsync(host, port);
    var stream = client.GetStream();

    // protocolVersion=-1 is legal in a Status handshake — the server doesn't validate it for status.
    byte[] handshake = BuildHandshakeFrame(protocolVersion: -1, serverAddress: host, serverPort: (ushort)port, nextState: 1);
    byte[] statusRequest = WrapFrame([.. VarInt.Encode(0x00)]);
    await stream.WriteAsync(handshake);
    await stream.WriteAsync(statusRequest);

    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
    var frame = await FrameReader.ReadFrameAsync(stream, maxFrameSize: 1024 * 1024, cts.Token);
    ReadOnlySpan<byte> payload = frame.Payload;
    VarInt.Decode(payload, out int idLen); // packet id, expected 0x00 (Status Response)
    string json = MinecraftPrimitives.ReadString(payload[idLen..], out _);

    using var doc = System.Text.Json.JsonDocument.Parse(json);
    return doc.RootElement.GetProperty("version").GetProperty("protocol").GetInt32();
}

static byte[] EncodeString(string text)
{
    byte[] bytes = System.Text.Encoding.UTF8.GetBytes(text);
    return [.. VarInt.Encode(bytes.Length), .. bytes];
}
