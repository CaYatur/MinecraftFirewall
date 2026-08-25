using System.Text.RegularExpressions;

namespace MinecraftFirewall.Tests;

/// <summary>
/// Every brush and style the control panel asks for has to exist.
///
/// This is here because the compiler does not check it and the failure is invisible until somebody
/// opens the right page. A StaticResource is looked up when the element is created, so a key that
/// does not exist builds cleanly, ships cleanly, and throws the first time a user navigates to it.
/// That has already happened once in this project — a rewritten dropdown referenced two brush names
/// that had never been defined, and nothing caught it until the page was opened by hand.
///
/// A regular expression over XAML is a blunt instrument, and it is the right one here: the question is
/// only "is this name defined anywhere", which needs no understanding of the markup.
/// </summary>
public class XamlResourceTests
{
    private static readonly Regex Reference = new(@"\{StaticResource\s+([A-Za-z0-9_]+)\s*\}", RegexOptions.Compiled);
    private static readonly Regex Definition = new(@"x:Key=""([A-Za-z0-9_]+)""", RegexOptions.Compiled);

    private static string ReadAppSource(string relativePath)
    {
        // Walks up from the test binary to the repository root, so this works from a plain `dotnet
        // test` and from an IDE without either needing to know where it was run from.
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !Directory.Exists(Path.Combine(directory.FullName, "src")))
            directory = directory.Parent;

        Assert.NotNull(directory);
        string path = Path.Combine(directory!.FullName, "src", "MinecraftFirewall.App", relativePath);
        Assert.True(File.Exists(path), $"expected to find {path}");

        return File.ReadAllText(path);
    }

    [Fact]
    public void EveryStyleAndBrushTheWindowAsksForIsActuallyDefined()
    {
        string app = ReadAppSource("App.xaml");
        string window = ReadAppSource("MainWindow.xaml");

        HashSet<string> defined =
        [
            .. Definition.Matches(app).Select(m => m.Groups[1].Value),
            .. Definition.Matches(window).Select(m => m.Groups[1].Value),
        ];

        string[] missing =
        [
            .. Reference.Matches(window)
                .Select(m => m.Groups[1].Value)
                .Distinct(StringComparer.Ordinal)
                .Where(key => !defined.Contains(key))
                .Order(StringComparer.Ordinal),
        ];

        Assert.True(missing.Length == 0,
            $"MainWindow.xaml uses resource(s) nothing defines: {string.Join(", ", missing)}. " +
            "This builds fine and throws the moment somebody opens that page.");
    }

    [Fact]
    public void TheStylesTheAppItselfDeclaresAreConsistentToo()
    {
        string app = ReadAppSource("App.xaml");

        HashSet<string> defined = [.. Definition.Matches(app).Select(m => m.Groups[1].Value)];

        string[] missing =
        [
            .. Reference.Matches(app)
                .Select(m => m.Groups[1].Value)
                .Distinct(StringComparer.Ordinal)
                .Where(key => !defined.Contains(key))
                .Order(StringComparer.Ordinal),
        ];

        Assert.True(missing.Length == 0, $"App.xaml uses resource(s) nothing defines: {string.Join(", ", missing)}.");
    }

    [Fact]
    public void EveryPageTheNavigationSwitchesOnActuallyExists()
    {
        // The nav is wired by string tags, so a page added to one side and not the other compiles and
        // then quietly does nothing when clicked.
        string window = ReadAppSource("MainWindow.xaml");
        string code = ReadAppSource("MainWindow.xaml.cs");

        string[] tags =
        [
            .. Regex.Matches(window, @"Checked=""Nav_Checked""\s+Tag=""([A-Za-z]+)""")
                .Select(m => m.Groups[1].Value),
        ];

        Assert.NotEmpty(tags);

        foreach (string tag in tags)
        {
            Assert.True(window.Contains($"x:Name=\"Page{tag}\"", StringComparison.Ordinal),
                $"the navigation offers '{tag}' but there is no Page{tag} in MainWindow.xaml");

            Assert.True(code.Contains($"Page{tag}.Visibility", StringComparison.Ordinal),
                $"Page{tag} exists but Nav_Checked never shows or hides it");
        }
    }
}
