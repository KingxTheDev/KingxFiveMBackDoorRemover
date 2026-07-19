using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace BackdoorScanner;

public class ScanResult
{
    public required string FullPath { get; init; }
    public required string RelativePath { get; init; }
    public required string Reasons { get; init; }
    public bool Hidden { get; init; }
    public int Score { get; init; }
}

public static class Scanner
{
    private static readonly Regex HexEscape = new(@"\\x[0-9A-Fa-f]{2}", RegexOptions.Compiled);
    private static readonly Regex VmRequire = new(@"require\(\s*['""]vm['""]\s*\)", RegexOptions.Compiled);

    // the actual smoking gun: a decoded payload fed straight into eval() as a bare function
    // call - eval(decodeFn(payload, key)) or eval(decodeFn(payload)). Legitimate code never
    // writes eval() this way regardless of file size; a real backdoor's payload array can be
    // arbitrarily large, so this must NOT be gated by file size the way the weak signals are.
    private static readonly Regex TightEvalOfDecode =
        new(@"eval\(\s*[A-Za-z_$][\w$]*\(\s*[A-Za-z_$][\w$]*\s*(,\s*[A-Za-z_$][\w$]*\s*)?\)\s*\)", RegexOptions.Compiled);

    private static readonly string[] SkipDirs = { "node_modules", ".git" };

    public static IEnumerable<ScanResult> Scan(string root, IProgress<int>? progress = null)
    {
        var scanned = 0;

        foreach (var file in EnumerateJsFiles(root))
        {
            scanned++;
            if (scanned % 200 == 0) progress?.Report(scanned);

            // a locked/deleted/inaccessible file (very common on a live, actively-written
            // FiveM server) must never abort the whole scan - skip it and keep going
            ScanResult? result;
            try
            {
                result = AnalyzeFile(root, file);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            if (result is not null) yield return result;
        }
    }

    private static ScanResult? AnalyzeFile(string root, string file)
    {
        var reasons = new List<string>();
        var score = 0;

        var attrs = File.GetAttributes(file);
        var hidden = attrs.HasFlag(FileAttributes.Hidden) || Path.GetFileName(file).StartsWith('.');
        if (hidden)
        {
            reasons.Add("hidden file");
            score += 100;
        }

        var content = File.ReadAllText(file);

        if (VmRequire.IsMatch(content))
        {
            reasons.Add("require('vm') present");
            score += 100;
        }

        if (content.Contains("runInThisContext"))
        {
            reasons.Add("vm.runInThisContext() execution");
            score += 100;
        }

        if (TightEvalOfDecode.IsMatch(content))
        {
            reasons.Add("eval() of a decode function's return value");
            score += 100;
        }

        // these are only ever corroborating evidence, never decisive on their own - a large
        // legitimate bundle (ox_inventory, wasabi, a webpack build.js) can trip one of these by
        // sheer size alone. Kept low-weight and uncapped by file size so they still add up
        // correctly on a real backdoor whose payload array happens to be large.
        if (content.Contains("fromCharCode") && content.Contains('^'))
        {
            reasons.Add("XOR decode loop (fromCharCode ^ key)");
            score += 10;
        }

        if (HasLargeNumericArray(content))
        {
            reasons.Add("large numeric byte array payload");
            score += 10;
        }

        if (HexEscape.Matches(content).Count > 100)
        {
            reasons.Add("hex-escaped payload string");
            score += 10;
        }

        if (score < 50) return null;

        return new ScanResult
        {
            FullPath = file,
            RelativePath = Path.GetRelativePath(root, file),
            Reasons = string.Join(", ", reasons),
            Hidden = hidden,
            Score = score,
        };
    }

    // linear-time replacement for a regex that used nested quantifiers (\d{1,3} repeated
    // 199+ times) - that pattern is a classic catastrophic-backtracking trap in .NET's
    // regex engine and could hang for a very long time on certain minified JS content
    private static bool HasLargeNumericArray(string content)
    {
        var run = 0;
        var i = 0;
        while (i < content.Length)
        {
            var start = i;
            while (i < content.Length && char.IsAsciiDigit(content[i])) i++;
            var digitCount = i - start;

            if (digitCount is >= 1 and <= 3)
            {
                run++;
                if (run >= 200) return true;

                if (i < content.Length && content[i] == ',')
                {
                    i++;
                    continue;
                }
            }

            run = 0;
            i++;
        }

        return false;
    }

    private static IEnumerable<string> EnumerateJsFiles(string root)
    {
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            var dir = pending.Pop();

            IEnumerable<string> files;
            IEnumerable<string> subDirs;
            try
            {
                files = Directory.EnumerateFiles(dir, "*.js");
                subDirs = Directory.EnumerateDirectories(dir);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                continue;
            }

            foreach (var file in files)
            {
                yield return file;
            }

            foreach (var subDir in subDirs)
            {
                var name = Path.GetFileName(subDir);
                if (name == "_quarantine") continue;

                // node_modules/.git are never loaded by the FiveM resource runtime and can be
                // hundreds of thousands of files deep, dwarfing the actual scan
                if (SkipDirs.Contains(name)) continue;

                // skip reparse points (symlinks/junctions) so a cyclic link can't recurse forever
                if (new DirectoryInfo(subDir).Attributes.HasFlag(FileAttributes.ReparsePoint)) continue;

                pending.Push(subDir);
            }
        }
    }

    public static void Quarantine(ScanResult result, string scanRoot, string quarantineRoot)
    {
        var dest = Path.Combine(quarantineRoot, result.RelativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
        if (File.Exists(dest))
        {
            dest = Path.Combine(quarantineRoot, result.RelativePath + "." + DateTime.Now.Ticks);
        }

        var attrs = File.GetAttributes(result.FullPath);
        if (attrs.HasFlag(FileAttributes.Hidden))
        {
            File.SetAttributes(result.FullPath, attrs & ~FileAttributes.Hidden);
        }

        File.Move(result.FullPath, dest);

        var logPath = Path.Combine(quarantineRoot, "quarantine-log.txt");
        File.AppendAllText(logPath,
            $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}\t{result.FullPath}\t{result.Reasons}{Environment.NewLine}");
    }
}
