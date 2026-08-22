using MinecraftFirewall.Proxy.Identity;

namespace MinecraftFirewall.Tests;

public class CayaDevCheckCommandParserTests
{
    [Theory]
    [InlineData("register hunter2", CayaDevCheckCommandKind.Register, "hunter2")]
    [InlineData("login hunter2", CayaDevCheckCommandKind.Login, "hunter2")]
    [InlineData("REGISTER hunter2", CayaDevCheckCommandKind.Register, "hunter2")]
    [InlineData("cayadevcheck register hunter2", CayaDevCheckCommandKind.Register, "hunter2")]
    [InlineData("cayadevcheck login hunter2", CayaDevCheckCommandKind.Login, "hunter2")]
    [InlineData("cdc register hunter2", CayaDevCheckCommandKind.Register, "hunter2")]
    [InlineData("cdc login hunter2", CayaDevCheckCommandKind.Login, "hunter2")]
    [InlineData("CDC LOGIN hunter2", CayaDevCheckCommandKind.Login, "hunter2")]
    public void Parse_RecognizedForms_ExtractKindAndPassword(string commandText, CayaDevCheckCommandKind expectedKind, string expectedPassword)
    {
        var result = CayaDevCheckCommandParser.Parse(commandText);

        Assert.Equal(expectedKind, result.Kind);
        Assert.Equal(expectedPassword, result.Password);
    }

    [Theory]
    [InlineData("tpa SomePlayer")]
    [InlineData("register")]
    [InlineData("login")]
    [InlineData("register too many args")]
    [InlineData("")]
    [InlineData("spawn")]
    public void Parse_UnrecognizedForms_ReturnsNone(string commandText)
    {
        var result = CayaDevCheckCommandParser.Parse(commandText);

        Assert.Equal(CayaDevCheckCommandKind.None, result.Kind);
    }

    [Theory]
    [InlineData("register hunter2", true)]
    [InlineData("login hunter2", true)]
    [InlineData("register", true)]        // near-miss (wrong arg count) — must still be flagged for redaction
    [InlineData("cdc login hunter2", true)]
    [InlineData("tpa SomePlayer", false)]
    [InlineData("gamemode creative", false)]
    public void LooksLikeCayaDevCheckCommand_MatchesFirstTokenOnly(string commandText, bool expected)
    {
        Assert.Equal(expected, CayaDevCheckCommandParser.LooksLikeCayaDevCheckCommand(commandText));
    }
}
