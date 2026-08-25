using MinecraftFirewall.Proxy.Protocol;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Colouring the messages a player reads, using the codes every server owner already knows.
///
/// The care here is in what is NOT treated as a code. These strings are configuration, written by
/// people, in two languages, and an ampersand that happens to precede a letter must not silently turn
/// half a sentence green.
/// </summary>
public class TextColourTests
{
    [Fact]
    public void PlainTextIsLeftEntirelyAlone()
    {
        Assert.False(TextColour.HasCodes("This server requires an account."));

        TextRun run = Assert.Single(TextColour.Split("This server requires an account."));
        Assert.True(run.IsPlain);
        Assert.Equal("This server requires an account.", run.Text);
    }

    [Fact]
    public void AColourAppliesToEverythingAfterIt()
    {
        List<TextRun> runs = TextColour.Split("&cdenied");

        TextRun run = Assert.Single(runs);
        Assert.Equal("denied", run.Text);
        Assert.Equal("red", run.Colour);
    }

    [Fact]
    public void EachRunCarriesItsOwnAppearanceInFull()
    {
        // Minecraft's components inherit from their parent, so a run that simply left out a colour
        // would pick up whatever surrounded it. Every run states everything.
        List<TextRun> runs = TextColour.Split("&ayes &cno");

        Assert.Equal(2, runs.Count);
        Assert.Equal("green", runs[0].Colour);
        Assert.Equal("red", runs[1].Colour);
    }

    [Fact]
    public void ADecorationAppliesUntilAColourClearsIt()
    {
        // Exactly as the game behaves: a colour code resets bold, italic and the rest. Without that,
        // one bold word would make the remainder of the line bold too.
        List<TextRun> runs = TextColour.Split("&a&lbold green &cplain red");

        Assert.True(runs[0].Bold);
        Assert.Equal("green", runs[0].Colour);
        Assert.False(runs[1].Bold);
        Assert.Equal("red", runs[1].Colour);
    }

    [Fact]
    public void AColourClearsDecorationsTheWayTheGameDoes()
    {
        // Which is why the order matters: "&l&a" is green and NOT bold, because the colour came second
        // and reset it. Getting this backwards would leave a stray bold running to the end of a line.
        List<TextRun> boldFirst = TextColour.Split("&l&agreen");

        TextRun run = Assert.Single(boldFirst);
        Assert.Equal("green", run.Colour);
        Assert.False(run.Bold);
    }

    [Fact]
    public void ResetClearsEverything()
    {
        List<TextRun> runs = TextColour.Split("&c&lshouty&rquiet");

        Assert.Equal(2, runs.Count);
        Assert.True(runs[0].Bold);
        Assert.True(runs[1].IsPlain);
    }

    [Fact]
    public void TheSectionSignWorksToo()
    {
        // Nobody types it by accident, so it is accepted in either case.
        Assert.Equal("red", Assert.Single(TextColour.Split("§Cdenied")).Colour);
        Assert.Equal("red", Assert.Single(TextColour.Split("§cdenied")).Colour);
    }

    [Theory]
    [InlineData("Q&A about the server")]
    [InlineData("R&D notes")]
    [InlineData("you & me")]
    [InlineData("trailing &")]
    public void AnAmpersandInOrdinaryProseIsNotAColourCode(string text)
    {
        // The reason an ampersand only counts before a lowercase letter or a digit. These strings are
        // configuration written by people, and losing half a sentence to an accidental code would be a
        // bug nobody could diagnose from the symptom.
        Assert.False(TextColour.HasCodes(text));
        Assert.Equal(text, Assert.Single(TextColour.Split(text)).Text);
    }

    [Fact]
    public void StrippingRemovesTheCodesWithoutApplyingThem()
    {
        // For anywhere that holds plain text rather than a component: a log line, or the login-state
        // kick packet, which carries JSON and would show the codes verbatim.
        Assert.Equal("Login required", TextColour.Strip("&e&lLogin required"));
        Assert.Equal("Q&A", TextColour.Strip("Q&A"));
    }

    [Fact]
    public void TheCodesNeverSurviveIntoTheTextTheyFormat()
    {
        // If a marker leaked through, the player would read it. Checked across every default message
        // rather than a sample, because these are the strings that actually ship.
        var messages = new MinecraftFirewall.Proxy.Messages.MessagesOptions();

        foreach (System.Reflection.PropertyInfo property in messages.GetType().GetProperties())
        {
            if (property.PropertyType != typeof(string) || property.GetValue(messages) is not string text)
                continue;

            foreach (TextRun run in TextColour.Split(text))
            {
                Assert.DoesNotContain('§', run.Text);

                // An ampersand may legitimately remain — it just must not be one that opens a code.
                Assert.False(TextColour.HasCodes(run.Text),
                    $"{property.Name} left an unapplied code in the text a player reads: '{run.Text}'");
            }
        }
    }

    [Fact]
    public void EveryColourCodeMapsToAName()
    {
        // The sixteen the game has. A missing one would not fail, it would silently drop the code and
        // render the text in whatever came before.
        const string codes = "0123456789abcdef";

        foreach (char code in codes)
        {
            TextRun run = Assert.Single(TextColour.Split($"&{code}x"));
            Assert.NotNull(run.Colour);
        }
    }
}
