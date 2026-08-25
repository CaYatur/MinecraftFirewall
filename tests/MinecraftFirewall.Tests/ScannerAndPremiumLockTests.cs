using System.Net;
using MinecraftFirewall.Proxy.Defense;
using MinecraftFirewall.Proxy.Identity;
using MinecraftFirewall.Tests.TestDoubles;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Recognising the server-indexing crawlers that sweep for Minecraft servers.
///
/// The behaviour and the thresholds here come from watching a real server for an afternoon. The
/// owner's own connections arrived carrying the server's raw IP in the Handshake hostname field, which
/// is what a client sends when somebody typed an address. A crawler arrived carrying its own site's
/// domain — its brand, in the field meant for the server's name — because sweeping an address range
/// leaves it with no address to send. Those two cases have to be treated completely differently, and
/// this file is where that is pinned down.
/// </summary>
public class ScannerDetectorTests
{
    private static readonly IPAddress Crawler = IPAddress.Parse("51.159.149.103");
    private static readonly IPAddress Owner = IPAddress.Parse("159.146.99.204");

    private static ScannerDetector Create(int before = 3) =>
        DefenseTestFactory.CreateScannerDetector(new BotDefenseOptions { ScannerMismatchesBeforeBan = before });

    [Theory]
    [InlineData("slowstack.tv", HostnameMismatchKind.ForeignDomain)]
    [InlineData("some-scanner.example", HostnameMismatchKind.ForeignDomain)]
    [InlineData("", HostnameMismatchKind.ForeignDomain)]
    // Raw addresses: what the admin's own test connection looks like.
    [InlineData("159.146.99.204", HostnameMismatchKind.DirectIpConnect)]
    [InlineData("192.168.1.180", HostnameMismatchKind.DirectIpConnect)]
    [InlineData("2001:db8::1", HostnameMismatchKind.DirectIpConnect)]
    public void ADomainAndAnAddressAreNotTheSameKindOfMismatch(string hostname, HostnameMismatchKind expected) =>
        Assert.Equal(expected, ScannerDetector.Classify(hostname));

    [Fact]
    public void AnAddressAnnouncingItsOwnDomainRepeatedly_IsBannedForALongTime()
    {
        ScannerDetector detector = Create(before: 3);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        Assert.Null(detector.RecordMismatch(Crawler, "slowstack.tv", HostnameMismatchKind.ForeignDomain, now));
        Assert.Null(detector.RecordMismatch(Crawler, "scanner-two.example", HostnameMismatchKind.ForeignDomain, now));

        TimeSpan? ban = detector.RecordMismatch(Crawler, "scanner-three.example", HostnameMismatchKind.ForeignDomain, now);

        Assert.NotNull(ban);
        Assert.True(ban!.Value > TimeSpan.FromDays(7),
            "an ordinary ban is pointless against something on a crawl schedule");
    }

    [Fact]
    public void TheAdminConnectingByRawIp_IsNeverEscalated()
    {
        // This is the case that would have hurt: the server owner testing their own server sends the
        // server's IP in that field, and taking the same escalation would ban them from their own
        // machine for a month.
        ScannerDetector detector = Create(before: 3);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        for (int i = 0; i < 20; i++)
            Assert.Null(detector.RecordMismatch(Owner, "159.146.99.204", HostnameMismatchKind.DirectIpConnect, now));
    }

    [Fact]
    public void TheSameNameRepeatedIsOneSighting_NotThree()
    {
        // Counting attempts rather than distinct names would ban anything that retried, including a
        // player whose client is stuck reconnecting to an old address.
        ScannerDetector detector = Create(before: 3);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        for (int i = 0; i < 10; i++)
            Assert.Null(detector.RecordMismatch(Crawler, "slowstack.tv", HostnameMismatchKind.ForeignDomain, now.AddSeconds(i)));
    }

    [Fact]
    public void SightingsOutsideTheMemoryWindow_DoNotCount()
    {
        ScannerDetector detector = DefenseTestFactory.CreateScannerDetector(new BotDefenseOptions
        {
            ScannerMismatchesBeforeBan = 3,
            ScannerMemory = TimeSpan.FromHours(1),
        });

        DateTimeOffset now = DateTimeOffset.UtcNow;
        detector.RecordMismatch(Crawler, "a.example", HostnameMismatchKind.ForeignDomain, now.AddDays(-5));
        detector.RecordMismatch(Crawler, "b.example", HostnameMismatchKind.ForeignDomain, now.AddDays(-4));

        Assert.Null(detector.RecordMismatch(Crawler, "c.example", HostnameMismatchKind.ForeignDomain, now));
    }

    [Fact]
    public void AfterABan_TheCountStartsAgainRatherThanFiringOnTheNextSighting()
    {
        // The ban answers a pattern, so the pattern has to be re-established once it expires — one
        // sighting after a ban lapses is not evidence of anything.
        ScannerDetector detector = Create(before: 2);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        detector.RecordMismatch(Crawler, "a.example", HostnameMismatchKind.ForeignDomain, now);
        Assert.NotNull(detector.RecordMismatch(Crawler, "b.example", HostnameMismatchKind.ForeignDomain, now));

        Assert.Null(detector.RecordMismatch(Crawler, "c.example", HostnameMismatchKind.ForeignDomain, now));
    }

    [Fact]
    public void AddressesAreIndependent()
    {
        ScannerDetector detector = Create(before: 2);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        detector.RecordMismatch(Crawler, "a.example", HostnameMismatchKind.ForeignDomain, now);

        Assert.Null(detector.RecordMismatch(IPAddress.Parse("203.0.113.9"), "a.example", HostnameMismatchKind.ForeignDomain, now));
    }

    [Fact]
    public void AnAbsurdlyLongHostnameIsBounded()
    {
        // The hostname is attacker-controlled text used as a dictionary key. Storing it whole would be
        // a way to make this process allocate.
        ScannerDetector detector = Create(before: 3);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        for (int i = 0; i < 5; i++)
            detector.RecordMismatch(Crawler, new string('x', 5000) + i, HostnameMismatchKind.ForeignDomain, now);

        Assert.Equal(1, detector.TrackedAddresses);
    }

    [Fact]
    public void WhenBotDefenceIsOff_NothingEscalates()
    {
        ScannerDetector detector = DefenseTestFactory.CreateScannerDetector(new BotDefenseOptions
        {
            Enabled = false,
            ScannerMismatchesBeforeBan = 1,
        });

        Assert.Null(detector.RecordMismatch(Crawler, "slowstack.tv", HostnameMismatchKind.ForeignDomain, DateTimeOffset.UtcNow));
    }
}

/// <summary>
/// The player-initiated premium lock: a player asking for their own name to be tied to their
/// Microsoft account, on a server where the owner has not switched auto-claim on for everyone.
/// </summary>
public class PremiumSelfLockTests
{
    [Theory]
    [InlineData("premium", CayaDevCheckCommandKind.PremiumLockAsk)]
    [InlineData("PREMIUM", CayaDevCheckCommandKind.PremiumLockAsk)]
    // Anything that is not the confirmation word is treated as the question, so a typo explains
    // itself rather than silently arming something permanent.
    [InlineData("premium yes", CayaDevCheckCommandKind.PremiumLockAsk)]
    [InlineData("premium confirm", CayaDevCheckCommandKind.PremiumLockConfirm)]
    [InlineData("premium CONFIRM", CayaDevCheckCommandKind.PremiumLockConfirm)]
    public void TheCommandParses(string text, CayaDevCheckCommandKind expected) =>
        Assert.Equal(expected, CayaDevCheckCommandParser.Parse(text).Kind);

    [Fact]
    public void TheConfirmationWordIsNeverTreatedAsAPassword()
    {
        // It would otherwise be read as "a command with the password 'confirm'", and then redacted
        // from the log as though it were a secret — making the one action worth auditing invisible.
        CayaDevCheckCommand parsed = CayaDevCheckCommandParser.Parse("premium confirm");

        Assert.Equal("", parsed.Password);
    }

    [Fact]
    public void ThePremiumCommandsAreRecognisedForRedactionToo() =>
        Assert.True(CayaDevCheckCommandParser.LooksLikeCayaDevCheckCommand("premium confirm"));

    [Fact]
    public void AnArmedRequestIsLiveForAWhileAndThenIsNot()
    {
        // Long enough to close Minecraft, reopen it with the genuine account and rejoin — which is
        // exactly what the player has just been told to do.
        DateTimeOffset armed = DateTimeOffset.UtcNow;
        var request = new PremiumClaimRequest(armed);

        Assert.True(request.IsLive(armed));
        Assert.True(request.IsLive(armed.AddMinutes(5)));
        Assert.False(request.IsLive(armed.AddHours(1)));
    }

    [Fact]
    public void AnEntryStartsWithNoRequest() =>
        Assert.Null(new IdentityEntry { Username = "Steve" }.PremiumClaimRequested);
}
