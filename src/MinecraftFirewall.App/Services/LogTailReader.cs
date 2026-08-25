using System.IO;
using System.Text;

namespace MinecraftFirewall.App.Services;

/// <summary>
/// Reads the tail of the service's Serilog file directly, rather than pulling log lines through the
/// admin pipe. Simpler, and it keeps the pipe protocol to actual commands.
///
/// The file is written by the service (LocalSystem) while this reads it. Serilog's file sink opens
/// with FileShare.Read, so a concurrent reader is fine — verified against a running service rather
/// than assumed, but the share flags below are set explicitly anyway so a future sink change can't
/// quietly turn this into an access-denied.
/// </summary>
public static class LogTailReader
{
    /// <summary>Where the service keeps everything it writes: logs, the identity store, the cached IP
    /// lists and the honeypot's own record. Machine-wide rather than per-user, because the service
    /// runs as a system account and no individual user owns its data.</summary>
    public static readonly string DataDirectory = @"C:\ProgramData\MinecraftFirewall";

    public static readonly string LogDirectory = Path.Combine(DataDirectory, "logs");

    public static string? CurrentLogFile()
    {
        try
        {
            var directory = new DirectoryInfo(LogDirectory);
            if (!directory.Exists)
                return null;

            return directory.GetFiles("proxy-*.log")
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .FirstOrDefault()?.FullName;
        }
        catch
        {
            return null;
        }
    }

    public static IReadOnlyList<string> ReadLastLines(int count)
    {
        string? path = CurrentLogFile();
        if (path is null)
            return ["No log file yet — the service may not have started."];

        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Encoding.UTF8);

            // Ring buffer rather than reading the whole file: a long-running service's daily log can
            // reach many megabytes, and the UI only ever shows the last screenful.
            var window = new Queue<string>(count);
            while (reader.ReadLine() is { } line)
            {
                if (window.Count == count)
                    window.Dequeue();
                window.Enqueue(line);
            }

            return window.Count == 0 ? ["(log file is empty)"] : [.. window];
        }
        catch (Exception ex)
        {
            return [$"Could not read the log file: {ex.Message}"];
        }
    }
}
