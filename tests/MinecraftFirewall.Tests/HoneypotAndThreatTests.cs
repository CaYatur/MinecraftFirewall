using System.Net;
using MinecraftFirewall.Proxy;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Enforcement;
using MinecraftFirewall.Tests.TestDoubles;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MinecraftFirewall.Tests;

public class HoneypotServiceTests
{
    private static ServerProfile Profile(string name, int publicPort, int backendPort) => new()
    {
        Name = name,
        PublicPort = publicPort,
        BackendHost = "127.0.0.1",
        BackendPort = backendPort,
    };

    private static HoneypotService Create(HoneypotOptions options, params ServerProfile[] profiles) =>
        new(Options.Create(options),
            Options.Create(new FirewallBanOptions()),
            profiles,
            new StrikeTracker(),
            new FirewallBanService(Options.Create(new FirewallBanOptions()),
                new NeverBanList(Options.Create(new NeverBanOptions())),
                new FakeWindowsFirewallGateway(),
                new RecordingAlertSender(),
                NullLogger<FirewallBanService>.Instance),
            DefenseTestFactory.CreateThreatIntelligence(),
            new RecordingAlertSender(),
            NullLogger<HoneypotService>.Instance);

    [Fact]
    public void APortOneOfYourOwnServersUses_IsDroppedBeforeAnythingIsBound()
    {
        // The worst outcome this whole feature could produce: a decoy winning the race for a real
        // server's port, and then banning players for connecting to their own server. Dropping the
        // collision before binding is what makes that impossible rather than merely unlikely.
        HoneypotService service = Create(
            new HoneypotOptions { Ports = [25565, 25566, 25567] },
            Profile("main", publicPort: 25565, backendPort: 25566));

        int[] usable = service.UsablePorts();

        Assert.Equal([25567], usable);
    }

    [Fact]
    public void EveryProfileIsConsidered_NotJustTheFirst()
    {
        HoneypotService service = Create(
            new HoneypotOptions { Ports = [25565, 25575, 25585, 25595] },
            Profile("a", 25565, 25566),
            Profile("b", 25575, 25576));

        Assert.Equal([25585, 25595], service.UsablePorts());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(70000)]
    public void PortNumbersOutsideTheValidRange_AreDropped(int port)
    {
        HoneypotService service = Create(new HoneypotOptions { Ports = [port, 25567] });

        Assert.Equal([25567], service.UsablePorts());
    }

    [Fact]
    public void DuplicatePortsAreCollapsed()
    {
        // Configuration binding appends to a list that already has items, so duplicates arrive from
        // the option defaults alone. Binding the same port twice would fail the second attempt.
        HoneypotService service = Create(new HoneypotOptions { Ports = [25567, 25567, 25570] });

        Assert.Equal([25567, 25570], service.UsablePorts());
    }

    [Fact]
    public void WithNothingUsableLeft_TheListIsEmptyRatherThanTheServiceFailing()
    {
        HoneypotService service = Create(
            new HoneypotOptions { Ports = [25565] },
            Profile("main", 25565, 25566));

        Assert.Empty(service.UsablePorts());
    }
}

public class ThreatIntelligenceTests
{
    private static (ThreatIntelligence Intelligence, string Path) Create(TimeSpan? retention = null)
    {
        string path = Path.Combine(Path.GetTempPath(), $"mcfw-threats-{Guid.NewGuid():N}.txt");
        var options = new ThreatIntelOptions
        {
            FeedUrls = [],
            LocalThreatLogPath = path,
            LocalRetention = retention ?? TimeSpan.FromDays(30),
        };

        return (new ThreatIntelligence(Options.Create(options), NullLogger<ThreatIntelligence>.Instance), path);
    }

    [Fact]
    public void ObservationsRoundTripThroughTheFile()
    {
        (ThreatIntelligence intelligence, string path) = Create();
        try
        {
            intelligence.RecordLocalHit(IPAddress.Parse("198.51.100.5"), "honeypot port 25567", DateTimeOffset.UtcNow);
            Assert.True(intelligence.SaveIfChanged());

            // A second instance pointed at the same file — the restart case. Honeypot hits are the
            // only first-hand evidence this installation has, and losing them at every restart would
            // make the local list permanently empty on a machine that reboots nightly.
            var afterRestart = new ThreatIntelligence(Options.Create(new ThreatIntelOptions
            {
                FeedUrls = [],
                LocalThreatLogPath = path,
            }), NullLogger<ThreatIntelligence>.Instance);

            afterRestart.Load();

            Assert.True(afterRestart.IsLocallyObserved(IPAddress.Parse("198.51.100.5")));
            Assert.Equal(1, afterRestart.LocalRecordCount);
            Assert.Contains("25567", afterRestart.LocalSnapshot()[0].Reason, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void TheFileIsWrittenInTheSameFormatTheFeedsAreReadIn()
    {
        // The point of the format: a community that wants a shared feed can host this file as-is. If
        // it needed converting, nobody would.
        (ThreatIntelligence intelligence, string path) = Create();
        try
        {
            intelligence.RecordLocalHit(IPAddress.Parse("203.0.113.9"), "honeypot port 25575", DateTimeOffset.UtcNow);
            intelligence.SaveIfChanged();

            var table = MinecraftFirewall.Proxy.IpIntel.Ipv4RangeTable.Parse(File.ReadLines(path));

            Assert.True(table.Contains(IPAddress.Parse("203.0.113.9")));
            Assert.False(table.Contains(IPAddress.Parse("203.0.113.10")));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void RepeatHitsUpdateOneRecordRatherThanAddingMore()
    {
        (ThreatIntelligence intelligence, string path) = Create();
        try
        {
            for (int i = 0; i < 5; i++)
                intelligence.RecordLocalHit(IPAddress.Parse("198.51.100.7"), "honeypot port 25567", DateTimeOffset.UtcNow);

            Assert.Equal(1, intelligence.LocalRecordCount);
            Assert.Equal(5, intelligence.LocalSnapshot()[0].Hits);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ObservationsOlderThanTheRetentionWindow_AreDroppedOnLoad()
    {
        (ThreatIntelligence intelligence, string path) = Create(retention: TimeSpan.FromDays(1));
        try
        {
            File.WriteAllLines(path,
            [
                "# header",
                $"198.51.100.1\t# 1x honeypot port 25567, last {DateTimeOffset.UtcNow.AddDays(-30):u}, first {DateTimeOffset.UtcNow.AddDays(-30):u}",
                $"198.51.100.2\t# 1x honeypot port 25567, last {DateTimeOffset.UtcNow:u}, first {DateTimeOffset.UtcNow:u}",
            ]);

            intelligence.Load();

            Assert.False(intelligence.IsLocallyObserved(IPAddress.Parse("198.51.100.1")));
            Assert.True(intelligence.IsLocallyObserved(IPAddress.Parse("198.51.100.2")));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ADamagedFileDoesNotStopTheServiceStarting()
    {
        // Losing this history costs nothing that a fresh honeypot hit will not re-establish, so it
        // must never be a reason the firewall fails to come up.
        (ThreatIntelligence intelligence, string path) = Create();
        try
        {
            File.WriteAllText(path, "this is not a threat list\n\0\0\0garbage\n");

            intelligence.Load();

            Assert.Equal(0, intelligence.LocalRecordCount);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void SavingWithNothingChanged_DoesNoWork()
    {
        (ThreatIntelligence intelligence, string path) = Create();
        try
        {
            Assert.False(intelligence.SaveIfChanged());

            intelligence.RecordLocalHit(IPAddress.Parse("198.51.100.3"), "honeypot", DateTimeOffset.UtcNow);
            Assert.True(intelligence.SaveIfChanged());
            Assert.False(intelligence.SaveIfChanged());
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void AnImportedListIsKeptSeparateFromWhatThisServerSawItself()
    {
        // The two kinds of evidence justify different responses, so pooling them would mean the
        // weakest inherited the strongest.
        (ThreatIntelligence intelligence, string path) = Create();
        try
        {
            intelligence.UpdateImported(MinecraftFirewall.Proxy.IpIntel.Ipv4RangeTable.Parse(["198.51.100.0/24"]));
            intelligence.RecordLocalHit(IPAddress.Parse("203.0.113.1"), "honeypot", DateTimeOffset.UtcNow);

            Assert.True(intelligence.IsOnImportedList(IPAddress.Parse("198.51.100.44")));
            Assert.False(intelligence.IsLocallyObserved(IPAddress.Parse("198.51.100.44")));

            Assert.True(intelligence.IsLocallyObserved(IPAddress.Parse("203.0.113.1")));
            Assert.False(intelligence.IsOnImportedList(IPAddress.Parse("203.0.113.1")));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
