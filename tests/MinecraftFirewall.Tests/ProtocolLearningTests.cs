using MinecraftFirewall.Proxy.Protocol;
using Microsoft.Extensions.Logging.Abstractions;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Teaching the firewall a Minecraft version it was never built with.
///
/// The point of these is the refusal, not the learning. Fetching a packet table is easy; the reason it
/// is safe to do unattended is that nothing fetched is believed until the same source has first
/// reproduced every table this build generated from Mojang's own data generator. Take that check away
/// and this becomes a security product downloading its own parsing rules from the internet.
/// </summary>
public class ProtocolLearningTests
{
    private static string TempStore() =>
        Path.Combine(Path.GetTempPath(), $"mcfw-learned-{Guid.NewGuid():N}.json");

    private static LearnedProtocolTable SampleTable(int protocol) => new()
    {
        Protocol = protocol,
        MinecraftVersion = "9.9",
        Source = "test",
        ConfigFinish = 0x03,
        Chat = 0x08,
        ChatCommand = 0x06,
        ChatCommandSigned = 0x07,
        Disconnect = 0x20,
        SystemChat = 0x77,
        MovePos = 0x1D,
        MovePosRot = 0x1E,
        MoveRot = 0x1F,
        MoveStatus = 0x20,
        CustomPayload = 0x15,
        Interact = 0x19,
        Swing = 0x3C,
        SignUpdate = 0x3B,
        EditBook = 0x17,
        Actions = [0x11, 0x19, 0x1D],
    };

    [Fact]
    public void EveryCompiledInVersionIsRecognisedAsBuiltIn()
    {
        Assert.NotEmpty(ProtocolVersionRegistry.BuiltInProtocols);

        foreach (int protocol in ProtocolVersionRegistry.BuiltInProtocols)
        {
            Assert.True(ProtocolVersionRegistry.IsBuiltIn(protocol));
            Assert.True(ProtocolVersionRegistry.TryGetBuiltIn(protocol, out _));
            Assert.NotNull(ProtocolVersionRegistry.BuiltInVersionName(protocol));
        }
    }

    [Fact]
    public void TheVersionThatBrokeThisIsNowKnown()
    {
        // 771 is what the live server's log showed being refused, and 774 is what the build shipped
        // with. Both, and everything between, are compiled in now.
        foreach (int protocol in new[] { 764, 767, 771, 774 })
            Assert.True(ProtocolVersionRegistry.TryGet(protocol, out _), $"protocol {protocol} should be known");
    }

    [Fact]
    public void ALearnedTableIsNeverAllowedToShadowACompiledInOne()
    {
        // The built-in tables came from Mojang's own generator and are the reference every learned
        // table is checked against. Letting a fetched file overwrite one would dissolve the only thing
        // that makes fetched files checkable.
        int builtIn = ProtocolVersionRegistry.BuiltInProtocols.First();
        ProtocolVersionRegistry.TryGetBuiltIn(builtIn, out PlayStatePacketIds original);

        bool accepted = ProtocolVersionRegistry.AddLearned(builtIn, SampleTable(builtIn).ToPacketIds());

        Assert.False(accepted);
        ProtocolVersionRegistry.TryGet(builtIn, out PlayStatePacketIds after);
        Assert.Equal(original, after);
    }

    [Fact]
    public void AStoreRefusesToOverwriteACompiledInVersionToo()
    {
        var store = new LearnedProtocolStore(TempStore(), NullLogger.Instance);
        int builtIn = ProtocolVersionRegistry.BuiltInProtocols.First();

        Assert.False(store.Add(SampleTable(builtIn)));
        Assert.Equal(0, store.Count);
    }

    [Fact]
    public void ALearnedTableSurvivesARestart()
    {
        // Relearning on every start would mean a version stays unprotected for however long the fetch
        // takes, every time the service restarts.
        string path = TempStore();
        const int protocol = 61_001;

        try
        {
            var store = new LearnedProtocolStore(path, NullLogger.Instance);
            Assert.True(store.Add(SampleTable(protocol)));
            Assert.True(File.Exists(path));

            var afterRestart = new LearnedProtocolStore(path, NullLogger.Instance);
            afterRestart.Load();

            Assert.Equal(1, afterRestart.Count);
            Assert.True(ProtocolVersionRegistry.TryGet(protocol, out PlayStatePacketIds ids));
            Assert.Equal(0x08, ids.PlayChatServerbound);
            Assert.Equal(0x06, ids.PlayChatCommandServerbound);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ADamagedStoreDoesNotStopTheService()
    {
        // Losing these costs one refetch. It must never be a reason the firewall fails to come up.
        string path = TempStore();
        try
        {
            File.WriteAllText(path, "{ this is not a protocol table");

            var store = new LearnedProtocolStore(path, NullLogger.Instance);
            store.Load();

            Assert.Equal(0, store.Count);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ATableRoundTripsThroughItsPacketIdsWithoutLosingAnything()
    {
        // The store and the registry speak different shapes, and a field dropped in that conversion
        // would be a packet the firewall silently stops recognising.
        LearnedProtocolTable original = SampleTable(61_002);

        LearnedProtocolTable rebuilt = LearnedProtocolTable.From(61_002, original.ToPacketIds());

        Assert.True(rebuilt.MatchesCoreOf(original));
        Assert.Equal(original.Interact, rebuilt.Interact);
        Assert.Equal(original.CustomPayload, rebuilt.CustomPayload);
        Assert.Equal(original.EditBook, rebuilt.EditBook);
        Assert.Equal<int>(original.Actions, rebuilt.Actions);
    }

    [Fact]
    public void ASingleDisagreeingFieldFailsTheComparison()
    {
        // This comparison is the gate the whole feature rests on. If it were lenient anywhere, a
        // drifted or tampered dataset would pass and go on to teach the firewall to misread packets.
        LearnedProtocolTable reference = SampleTable(61_003);

        foreach (Action<LearnedProtocolTable> corrupt in new Action<LearnedProtocolTable>[]
                 {
                     t => t.Chat++,
                     t => t.ChatCommand++,
                     t => t.ConfigFinish++,
                     t => t.Disconnect++,
                     t => t.SystemChat++,
                     t => t.MovePos++,
                     t => t.MovePosRot++,
                     t => t.Swing++,
                 })
        {
            LearnedProtocolTable altered = SampleTable(61_003);
            corrupt(altered);

            Assert.False(altered.MatchesCoreOf(reference), "a changed packet id must fail the comparison");
        }
    }

    [Fact]
    public void AnIdenticalTablePassesTheComparison() =>
        Assert.True(SampleTable(61_004).MatchesCoreOf(SampleTable(61_004)));

    [Fact]
    public void NotingAnUnknownVersionWhileDisabledDoesNothing()
    {
        // The switch has to mean it. A firewall told not to fetch anything must not queue work.
        var service = TestDoubles.DefenseTestFactory.CreateProtocolLearning();

        service.NoteUnknownVersion(61_005);

        Assert.False(ProtocolVersionRegistry.TryGet(61_005, out _));
    }

    [Fact]
    public void SupportedVersionsIncludesWhatWasLearned()
    {
        // What an admin is shown has to reflect what the running instance can actually do, not what
        // it was compiled with.
        const int protocol = 61_006;
        ProtocolVersionRegistry.AddLearned(protocol, SampleTable(protocol).ToPacketIds());

        Assert.Contains(protocol, ProtocolVersionRegistry.SupportedVersions);
        Assert.Contains(protocol.ToString(), ProtocolVersionRegistry.SupportedVersionsDescription, StringComparison.Ordinal);
    }
}
