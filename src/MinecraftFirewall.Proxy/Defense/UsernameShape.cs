namespace MinecraftFirewall.Proxy.Defense;

/// <summary>
/// Judges whether a username looks generated rather than chosen.
///
/// This is the weakest signal in the bot score and is written to stay that way. Real Minecraft
/// usernames are strange: "xX_Steve_Xx", "Notch_Fan99", "iiiiillllii" are all plausibly human, and any
/// rule sharp enough to catch a generator catches those too. So the checks here are the narrow,
/// high-confidence ones — a single repeated character, no vowel at all, mostly digits — and each
/// contributes to a count rather than deciding anything by itself. The caller only treats a name as
/// generated when several agree.
///
/// A name failing this is never grounds for refusal on its own; see BotDefenseOptions.
/// </summary>
public static class UsernameShape
{
    private const string Vowels = "aeiouyAEIOUY";

    /// <summary>Number of independent "looks generated" traits the name has. Two or more is the
    /// threshold the detector uses.</summary>
    public static int GeneratedTraits(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return 0;

        int traits = 0;

        if (IsSingleRepeatedCharacter(username))
            traits += 2; // "aaaaaaa" is not a name anyone picked twice

        if (HasNoVowels(username))
            traits++;

        if (IsMostlyDigits(username))
            traits++;

        if (HasLongDigitRun(username))
            traits++;

        if (HasAlternatingCasePattern(username))
            traits++;

        return traits;
    }

    public static bool LooksGenerated(string username) => GeneratedTraits(username) >= 2;

    private static bool IsSingleRepeatedCharacter(string name)
    {
        if (name.Length < 4)
            return false;

        char first = name[0];
        foreach (char c in name)
        {
            if (c != first)
                return false;
        }

        return true;
    }

    /// <summary>No vowel anywhere in a name long enough for that to be unusual. Pronounceable names
    /// nearly always have one; random consonant strings do not.</summary>
    private static bool HasNoVowels(string name)
    {
        if (name.Length < 6)
            return false;

        foreach (char c in name)
        {
            if (Vowels.Contains(c))
                return false;
        }

        // Names made entirely of digits or punctuation have no vowels either, but that is already
        // covered by the digit checks; counting it twice would double-weight one observation.
        return name.Any(char.IsLetter);
    }

    private static bool IsMostlyDigits(string name)
    {
        int digits = name.Count(char.IsDigit);
        return name.Length >= 4 && digits * 2 > name.Length;
    }

    /// <summary>A run of four or more digits — the tail of a counter. Three is left alone because
    /// birth years and jersey numbers are extremely common in real names.</summary>
    private static bool HasLongDigitRun(string name)
    {
        int run = 0;
        foreach (char c in name)
        {
            run = char.IsDigit(c) ? run + 1 : 0;
            if (run >= 4)
                return true;
        }

        return false;
    }

    /// <summary>Case that flips on nearly every letter, as a random-case generator produces. Requires
    /// a long run of alternations so that "McDonald" or "xXaXx" style names do not qualify.</summary>
    private static bool HasAlternatingCasePattern(string name)
    {
        int alternations = 0;
        int comparableLetters = 0;
        char? previous = null;

        foreach (char c in name)
        {
            if (!char.IsLetter(c))
            {
                previous = null;
                continue;
            }

            if (previous is char p)
            {
                comparableLetters++;
                if (char.IsUpper(p) != char.IsUpper(c))
                    alternations++;
            }

            previous = c;
        }

        return comparableLetters >= 5 && alternations >= comparableLetters - 1;
    }
}
