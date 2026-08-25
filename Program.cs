// ============================================================================
//  StaticTriageTool - Automated Static Analysis Triage Tool
// ----------------------------------------------------------------------------
//  Console-based heuristic scanner for suspicious Windows API capability
//  indicators inside individual files and ZIP-family archives (.zip,
//  Office Open XML, .jar, .apk).
//
//  Design constraints honored by this implementation:
//    * Pure .NET Base Class Library. No external/NuGet dependencies.
//    * Fully streaming: no target file or archive entry is ever loaded into
//      a single in-memory string or buffer in its entirety. Fixed 1 MiB
//      scan windows with a 32-byte boundary-overlap guard are used instead.
//    * ZIP-family containers are identified by structural magic bytes, not
//      file extensions. Proprietary archive signatures (.7z, .rar, .gz, ...)
//      are detected and gracefully rejected with exit code 3.
//    * Zip-bomb sandboxing: global decompression volume cap, per-entry
//      expansion-ratio cap, entry-count cap, and nested-archive depth cap.
//
//  Exit codes:
//    0 = Clean / no threat indicators found
//    1 = Threat indicators identified
//    2 = General error / invalid input path / safety-limit abort
//    3 = Unsupported archive format signature detected
// ============================================================================

using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace StaticTriageTool;

internal static class Program
{
    // ------------------------------------------------------------------
    // Configurable safety constants (zip-bomb sandboxing / scan tuning)
    // ------------------------------------------------------------------
    private const long MaxTotalDecompressedBytes = 2L * 1024 * 1024 * 1024;   // 2 GB global volume cap
    private const long MaxExpansionRatio = 100;                               // per-entry decompressed/compressed cap
    private const int MaxArchiveEntries = 10_000;                             // total entry-count cap
    private const int MaxNestedArchiveDepth = 2;                              // nested-archive recursion cap
    private const int ScanBufferSize = 1024 * 1024;                           // 1 MiB fixed scan chunk
    private const int OverlapWindowSize = 32;                                 // longest flag length - 1
    private const int MaxRecordedLocationsPerFlag = 250;                      // report-listing cap per flag
    private const long MaxNestedArchiveMemoryBudget = 512L * 1024 * 1024;     // seekable-buffer cap for nested zips
    private const string ReportFileName = "triage_report.txt";

    private enum ExitCode
    {
        Clean = 0,
        ThreatsFound = 1,
        GeneralError = 2,
        UnsupportedArchive = 3
    }

    // ------------------------------------------------------------------
    // Rule classification matrix
    // ------------------------------------------------------------------
    private sealed record CapabilityRule(string Flag, string Category, bool HighNoise);

    private static readonly CapabilityRule[] Rules =
    {
        new("VirtualAlloc", "Memory Allocation / Injection", false),
        new("VirtualAllocEx", "Memory Allocation / Injection", false),
        new("VirtualQuery", "Memory Allocation / Injection", false),
        new("WriteProcessMemory", "Memory Allocation / Injection", false),

        new("OpenProcess", "Process Hijacking", false),
        new("DuplicateHandle", "Process Hijacking", false),
        new("Process32First", "Process Hijacking", false),
        new("Process32Next", "Process Hijacking", false),

        new("RegOpenKeyExW", "Registry Persistence Hooks", false),
        new("RegSetValueExW", "Registry Persistence Hooks", false),
        new("RegDeleteKeyW", "Registry Persistence Hooks", false),
        new("RegCreateKeyExW", "Registry Persistence Hooks", false),

        new("WSASocketW", "Network & C2 Foundations", false),
        new("connect", "Network & C2 Foundations", true),
        new("DnsQuery_W", "Network & C2 Foundations", false),
        new("GetAddrInfoW", "Network & C2 Foundations", false),
        new("InternetOpenW", "Network & C2 Foundations", false),

        new("CreateFileW", "File & Share Manipulation", false),
        new("WriteFileW", "File & Share Manipulation", false),
        new("DeleteFileW", "File & Share Manipulation", false),
        new("MoveFileExW", "File & Share Manipulation", false),
        new("NetShareAdd", "File & Share Manipulation", false),
        new("NetShareDel", "File & Share Manipulation", false),

        new("rdtsc", "Anti-Analysis / Anti-Sandbox", false),
        new("IsDebuggerPresent", "Anti-Analysis / Anti-Sandbox", false),
        new("CheckRemoteDebuggerPresent", "Anti-Analysis / Anti-Sandbox", false),
    };

    private static readonly Dictionary<string, CapabilityRule> RuleLookup =
        Rules.ToDictionary(static r => r.Flag, StringComparer.OrdinalIgnoreCase);

    // Component D: single precompiled alternation regex covering every rule.
    // Alternatives are ordered longest-first so that e.g. "VirtualAllocEx"
    // wins over its shorter prefix "VirtualAlloc" at the same position.
    private static readonly Regex CapabilityRegex = BuildCapabilityRegex();

    private static Regex BuildCapabilityRegex()
    {
        IEnumerable<string> alternatives = Rules
            .OrderByDescending(static r => r.Flag.Length)
            .Select(static r => Regex.Escape(r.Flag));

        return new Regex(
            string.Join("|", alternatives),
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    // ------------------------------------------------------------------
    // Archive signature tables (magic-byte based, extension independent)
    // ------------------------------------------------------------------
    private static readonly (string Label, byte[] Signature)[] UnsupportedSignatures =
    {
        ("7-Zip archive (.7z)", new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }),
        ("RAR archive (.rar)", new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 }),
        ("Gzip compressed stream (.gz)", new byte[] { 0x1F, 0x8B }),
        ("BZip2 compressed stream (.bz2)", new byte[] { 0x42, 0x5A, 0x68 }),
        ("XZ compressed stream (.xz)", new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 }),
        ("Microsoft Cabinet archive (.cab)", new byte[] { 0x4D, 0x53, 0x43, 0x46 }),
    };

    // ------------------------------------------------------------------
    // Scan bookkeeping
    // ------------------------------------------------------------------
    private readonly record struct HitLocation(long Offset, string Path);

    private sealed class HitRecord
    {
        public required CapabilityRule Rule { get; init; }
        public long TotalOccurrences { get; set; }
        public List<HitLocation> Locations { get; } = new();
    }

    private sealed class ScanState
    {
        public long TotalDecompressedBytes { get; internal set; }
        public int EntriesScanned { get; internal set; }
        public List<string> Anomalies { get; } = new();
        public Dictionary<string, HitRecord> Hits { get; } = new(StringComparer.OrdinalIgnoreCase);
        public bool LimitAborted { get; internal set; }
        public string? AbortReason { get; internal set; }

        public void RecordHit(CapabilityRule rule, long offset, string path)
        {
            if (!Hits.TryGetValue(rule.Flag, out HitRecord? record))
            {
                record = new HitRecord { Rule = rule };
                Hits.Add(rule.Flag, record);
            }

            record.TotalOccurrences++;
            if (record.Locations.Count < MaxRecordedLocationsPerFlag)
            {
                record.Locations.Add(new HitLocation(offset, path));
            }
        }

        public void Abort(string reason)
        {
            if (!LimitAborted)
            {
                LimitAborted = true;
                AbortReason = reason;
            }
        }
    }

    private enum BudgetResult
    {
        Completed,
        EntryBudgetExceeded,
        GlobalBudgetExceeded
    }

    private static StreamWriter? _report;

    // ------------------------------------------------------------------
    // Entry point
    // ------------------------------------------------------------------
    private static int Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("Usage: StaticTriageTool <path_to_file>");
            Console.WriteLine("Exit codes: 0=clean, 1=threat indicators, 2=general error/invalid input, 3=unsupported archive format");
            return (int)ExitCode.GeneralError;
        }

        string targetPath = args[0];

        FileInfo target;
        try
        {
            target = new FileInfo(targetPath);
        }
        catch (ArgumentException)
        {
            Console.WriteLine($"[ERROR] Invalid path argument: '{targetPath}'");
            return (int)ExitCode.GeneralError;
        }
        catch (NotSupportedException)
        {
            Console.WriteLine($"[ERROR] Path format not supported: '{targetPath}'");
            return (int)ExitCode.GeneralError;
        }

        if (!target.Exists || target.Length < 0)
        {
            Console.WriteLine($"[ERROR] Target not found or not a readable regular file: '{targetPath}'");
            return (int)ExitCode.GeneralError;
        }

        try
        {
            _report = new StreamWriter(ReportFileName, append: false, Encoding.UTF8);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            Console.WriteLine($"[WARN] Cannot write '{ReportFileName}' ({ex.Message}); continuing with console-only output.");
            _report = null;
        }

        try
        {
            return Run(target);
        }
        catch (UnauthorizedAccessException ex)
        {
            Emit($"[ERROR] Access denied while processing target: {ex.Message}", ConsoleColor.Red);
            return (int)ExitCode.GeneralError;
        }
        catch (IOException ex)
        {
            Emit($"[ERROR] I/O failure while processing target: {ex.Message}", ConsoleColor.Red);
            return (int)ExitCode.GeneralError;
        }
        catch (InvalidDataException ex)
        {
            Emit($"[ERROR] Corrupt or malformed container data: {ex.Message}", ConsoleColor.Red);
            return (int)ExitCode.GeneralError;
        }
        catch (Exception ex)
        {
            Emit($"[ERROR] Unexpected failure: {ex.GetType().Name}: {ex.Message}", ConsoleColor.Red);
            return (int)ExitCode.GeneralError;
        }
        finally
        {
            _report?.Dispose();
            _report = null;
        }
    }

    // ------------------------------------------------------------------
    // Root orchestration
    // ------------------------------------------------------------------
    private static int Run(FileInfo target)
    {
        Emit("======================================================================");
        Emit("              AUTOMATED STATIC ANALYSIS TRIAGE TOOL");
        Emit("======================================================================");

        using FileStream rootStream = new(
            target.FullName,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            ScanBufferSize,
            FileOptions.SequentialScan);

        byte[] header = new byte[262];
        int headerLen = ReadExactlyUpTo(rootStream, header, header.Length);

        string? unsupported = IdentifyUnsupportedArchive(header, headerLen);
        if (unsupported is not null)
        {
            Emit("");
            Emit($"[UNSUPPORTED ARCHIVE FORMAT] Magic bytes identify a {unsupported}.", ConsoleColor.Yellow);
            Emit("Proprietary container detected by structural signature; contents were NOT scanned.");
            Emit("Tool is exiting gracefully without crashing.");
            Emit($"Exit code: {(int)ExitCode.UnsupportedArchive}");
            return (int)ExitCode.UnsupportedArchive;
        }

        bool isZipFamily = headerLen >= 4 && IsZipMagic(header);

        // Component A: buffered, incremental SHA-256 (safe for multi-GB inputs).
        string sha256 = ComputeSha256(rootStream);

        Emit($"Target File       : {target.Name}");
        Emit($"Full Path         : {target.FullName}");
        Emit($"File Size         : {target.Length:N0} bytes ({target.Length / 1024.0 / 1024.0:F2} MB)");
        Emit($"SHA-256           : {sha256}");
        Emit($"Container Type    : {(isZipFamily ? "ZIP-family archive (structural magic verified)" : "Raw file stream (non-archive)")}");
        Emit("Scan Layers       : ASCII (Latin-1 mapped) + Windows UTF-16LE wide-char");
        Emit("Analysis Boundary : Heuristic string/byte scan, not a PE-import-table-aware analysis");
        Emit("----------------------------------------------------------------------");

        ScanState state = new();
        rootStream.Seek(0, SeekOrigin.Begin);

        if (isZipFamily)
        {
            ProcessZip(rootStream, depth: 1, containerPath: target.Name, state);
        }
        else
        {
            ScanStream(rootStream, target.Name, state, byteBudget: null);
        }

        if (state.LimitAborted)
        {
            Emit("");
            Emit($"[ABORTED] Safety constraint violated: {state.AbortReason}", ConsoleColor.Red);
            Emit("Processing halted to prevent resource exhaustion. Any results shown are partial.");
            Emit($"Exit code: {(int)ExitCode.GeneralError}");
            return (int)ExitCode.GeneralError;
        }

        Emit($"Archive Entries Scanned : {state.EntriesScanned:N0}");
        Emit($"Anomalous/Skipped Items : {state.Anomalies.Count:N0}");
        foreach (string anomaly in state.Anomalies)
        {
            Emit($"  - {anomaly}", ConsoleColor.DarkYellow);
        }
        Emit("----------------------------------------------------------------------");

        if (state.Hits.Count == 0)
        {
            Emit("");
            Emit("RESULT: CLEAN - no threat capability indicators detected.", ConsoleColor.Green);
            Emit($"Exit code: {(int)ExitCode.Clean}");
            return (int)ExitCode.Clean;
        }

        Emit("");
        Emit("[THREAT INDICATORS IDENTIFIED]", ConsoleColor.Red);
        Emit("");

        foreach (IGrouping<string, HitRecord> category in state.Hits.Values
                     .GroupBy(static h => h.Rule.Category)
                     .OrderBy(static g => g.Key, StringComparer.Ordinal))
        {
            Emit($"Category: {category.Key}", ConsoleColor.Red);
            foreach (HitRecord hit in category.OrderBy(static h => h.Rule.Flag, StringComparer.OrdinalIgnoreCase))
            {
                string noiseTag = hit.Rule.HighNoise
                    ? "  [CONTEXT WARNING: high natural-text noise flag]"
                    : string.Empty;
                Emit($"  Flag: {hit.Rule.Flag}  (occurrences: {hit.TotalOccurrences}){noiseTag}", ConsoleColor.Red);
                foreach (HitLocation location in hit.Locations)
                {
                    Emit($"    @ 0x{location.Offset:X16}  [{location.Path}]", ConsoleColor.Red);
                }

                long unlisted = hit.TotalOccurrences - hit.Locations.Count;
                if (unlisted > 0)
                {
                    Emit($"    (+{unlisted} additional occurrence(s) beyond listing cap)", ConsoleColor.Red);
                }
            }
            Emit("");
        }

        long totalOccurrences = state.Hits.Values.Sum(static h => h.TotalOccurrences);
        Emit("======================================================================");
        Emit("RESULT: THREAT INDICATORS IDENTIFIED.", ConsoleColor.Red);
        Emit($"Distinct flags matched: {state.Hits.Count}; total occurrences: {totalOccurrences}.");
        Emit("Reminder: Heuristic string/byte scan, not a PE-import-table-aware analysis.");
        Emit($"Exit code: {(int)ExitCode.ThreatsFound}");
        Emit("======================================================================");
        return (int)ExitCode.ThreatsFound;
    }

    // ------------------------------------------------------------------
    // Component A: buffered SHA-256 fingerprinting
    // ------------------------------------------------------------------
    private static string ComputeSha256(Stream stream)
    {
        stream.Seek(0, SeekOrigin.Begin);
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[ScanBufferSize];
        int read;
        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
        {
            hash.AppendData(buffer, 0, read);
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    // ------------------------------------------------------------------
    // Archive handling: ZIP-family parsing, sandboxing, nested recursion
    // ------------------------------------------------------------------
    private static void ProcessZip(Stream archiveStream, int depth, string containerPath, ScanState state)
    {
        using ZipArchive archive = new(archiveStream, ZipArchiveMode.Read, leaveOpen: true);

        if (archive.Entries.Count > MaxArchiveEntries)
        {
            state.Abort($"Archive '{containerPath}' declares {archive.Entries.Count} entries; hard limit is {MaxArchiveEntries}.");
            return;
        }

        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            if (state.LimitAborted)
            {
                return;
            }

            state.EntriesScanned++;
            if (state.EntriesScanned > MaxArchiveEntries)
            {
                state.Abort($"Archive entry count limit of {MaxArchiveEntries} exceeded while enumerating '{containerPath}'.");
                return;
            }

            if (entry.FullName.EndsWith("/", StringComparison.Ordinal))
            {
                continue; // directory placeholder entry
            }

            string entryPath = $"{containerPath}::{entry.FullName}";

            try
            {
                long declaredCompressed = entry.CompressedLength;
                long declaredDecompressed = entry.Length;

                if (declaredCompressed > 0 && declaredDecompressed > MaxExpansionRatio * declaredCompressed)
                {
                    double ratio = (double)declaredDecompressed / declaredCompressed;
                    state.Anomalies.Add(
                        $"Skipped '{entryPath}': declared expansion ratio {ratio:F1}x exceeds the {MaxExpansionRatio}x limit.");
                    continue;
                }

                long remainingGlobal = MaxTotalDecompressedBytes - state.TotalDecompressedBytes;
                if (declaredDecompressed > remainingGlobal)
                {
                    state.Anomalies.Add(
                        $"Skipped '{entryPath}': declared size {declaredDecompressed:N0} bytes would exceed the global " +
                        $"{MaxTotalDecompressedBytes:N0}-byte decompression budget.");
                    continue;
                }

                long budget = declaredCompressed > 0
                    ? Math.Min(MaxExpansionRatio * declaredCompressed, remainingGlobal)
                    : Math.Min(declaredDecompressed, remainingGlobal);

                using Stream entryStream = entry.Open();

                byte[] peek = new byte[4];
                int peeked = ReadExactlyUpTo(entryStream, peek, peek.Length);
                bool nestedZip = peeked == peek.Length && IsZipMagic(peek);

                if (nestedZip)
                {
                    if (depth >= MaxNestedArchiveDepth)
                    {
                        state.Anomalies.Add(
                            $"Skipped '{entryPath}': nested archive depth limit of {MaxNestedArchiveDepth} reached.");
                        continue;
                    }

                    if (declaredDecompressed > MaxNestedArchiveMemoryBudget)
                    {
                        state.Anomalies.Add(
                            $"Skipped '{entryPath}': nested archive ({declaredDecompressed:N0} bytes) exceeds the " +
                            $"{MaxNestedArchiveMemoryBudget:N0}-byte in-memory sandbox budget.");
                        continue;
                    }

                    // Nested ZipArchive instances require a seekable stream. The entry
                    // size has already been vetted against the sandbox budget above, so
                    // buffering it in memory here is bounded and never touches disk.
                    using MemoryStream nestedBuffer = new(checked((int)declaredDecompressed + peek.Length));
                    nestedBuffer.Write(peek, 0, peeked);

                    BudgetResult copyResult = CopyWithBudget(entryStream, nestedBuffer, declaredDecompressed - peeked, state, entryPath);
                    if (copyResult == BudgetResult.GlobalBudgetExceeded)
                    {
                        return;
                    }
                    if (copyResult == BudgetResult.EntryBudgetExceeded)
                    {
                        state.Anomalies.Add(
                            $"Skipped '{entryPath}': runtime decompressed size exceeded its declared/budgeted size (hostile header).");
                        continue;
                    }

                    nestedBuffer.Position = 0;
                    ProcessZip(nestedBuffer, depth + 1, entryPath, state);
                }
                else
                {
                    Stream scanSource = peeked > 0
                        ? new PrependedStream(peek, peeked, entryStream)
                        : entryStream;

                    BudgetResult scanResult = ScanStream(scanSource, entryPath, state, budget);
                    if (scanResult == BudgetResult.GlobalBudgetExceeded)
                    {
                        return;
                    }
                    if (scanResult == BudgetResult.EntryBudgetExceeded)
                    {
                        state.Anomalies.Add(
                            $"Skipped '{entryPath}': runtime decompressed byte volume exceeded its declared/budgeted size (hostile header).");
                    }
                }
            }
            catch (NotSupportedException)
            {
                state.Anomalies.Add($"Skipped '{entryPath}': entry is password-protected or uses an unsupported compression mechanism.");
            }
            catch (InvalidDataException ex)
            {
                state.Anomalies.Add($"Skipped '{entryPath}': corrupt or invalid compressed data ({ex.Message}).");
            }
            catch (IOException ex)
            {
                state.Anomalies.Add($"Skipped '{entryPath}': I/O failure while reading entry ({ex.Message}).");
            }
        }
    }

    private static BudgetResult CopyWithBudget(Stream source, Stream destination, long limit, ScanState state, string sourcePath)
    {
        byte[] buffer = new byte[64 * 1024];
        long copied = 0;
        int read;
        while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            copied += read;
            state.TotalDecompressedBytes += read;

            if (copied > limit)
            {
                return BudgetResult.EntryBudgetExceeded;
            }
            if (state.TotalDecompressedBytes > MaxTotalDecompressedBytes)
            {
                state.Abort($"Global decompressed volume limit of {MaxTotalDecompressedBytes:N0} bytes exceeded while expanding '{sourcePath}'.");
                return BudgetResult.GlobalBudgetExceeded;
            }

            destination.Write(buffer, 0, read);
        }

        return BudgetResult.Completed;
    }

    // ------------------------------------------------------------------
    // Components B + C: chunked multi-encoding scanning with overlap guard
    // ------------------------------------------------------------------
    private static BudgetResult ScanStream(Stream stream, string sourcePath, ScanState state, long? byteBudget)
    {
        byte[] work = new byte[ScanBufferSize + OverlapWindowSize];
        int overlapLen = 0;
        long windowStart = 0;                 // absolute stream offset of work[0]
        long consumedFromStream = 0;
        bool firstChunk = true;

        while (true)
        {
            int fresh = stream.Read(work, overlapLen, ScanBufferSize);
            if (fresh <= 0)
            {
                break;
            }

            consumedFromStream += fresh;
            state.TotalDecompressedBytes += fresh;

            if (byteBudget.HasValue && consumedFromStream > byteBudget.Value)
            {
                return BudgetResult.EntryBudgetExceeded;
            }
            if (state.TotalDecompressedBytes > MaxTotalDecompressedBytes)
            {
                state.Abort($"Global decompressed volume limit of {MaxTotalDecompressedBytes:N0} bytes exceeded while scanning '{sourcePath}'.");
                return BudgetResult.GlobalBudgetExceeded;
            }

            int windowLen = overlapLen + fresh;
            int previouslyScanned = firstChunk ? 0 : overlapLen;

            // Layer 1: ASCII / byte-oriented matching. Latin-1 maps every byte
            // 1:1 onto a char, so regex indices equal absolute byte offsets.
            string asciiLayer = Encoding.Latin1.GetString(work, 0, windowLen);
            CollectMatches(CapabilityRegex.Matches(asciiLayer), bytesPerChar: 1, previouslyScanned, windowStart, sourcePath, state, firstChunk);

            // Layer 2: Windows UTF-16LE wide-char matching. Char index * 2
            // reconstructs the byte offset within the working window.
            int evenLen = windowLen & ~1;
            if (evenLen > 1)
            {
                string wideLayer = Encoding.Unicode.GetString(work, 0, evenLen);
                CollectMatches(CapabilityRegex.Matches(wideLayer), bytesPerChar: 2, previouslyScanned, windowStart, sourcePath, state, firstChunk);
            }

            // Component C: retain the trailing overlap window for the next chunk
            // so flags split across chunk boundaries cannot escape detection.
            int newOverlap = Math.Min(OverlapWindowSize, windowLen);
            Buffer.BlockCopy(work, windowLen - newOverlap, work, 0, newOverlap);
            windowStart += windowLen - newOverlap;
            overlapLen = newOverlap;
            firstChunk = false;
        }

        return BudgetResult.Completed;
    }

    private static void CollectMatches(
        MatchCollection matches,
        int bytesPerChar,
        int previouslyScannedBytes,
        long windowStart,
        string sourcePath,
        ScanState state,
        bool firstChunk)
    {
        foreach (Match match in matches)
        {
            long endByte = (match.Index + match.Length) * bytesPerChar;

            // A match ending inside the retained overlap region was already
            // reported during the previous chunk; suppress the duplicate.
            if (!firstChunk && endByte <= previouslyScannedBytes)
            {
                continue;
            }

            if (!RuleLookup.TryGetValue(match.Value, out CapabilityRule? rule))
            {
                continue;
            }

            state.RecordHit(rule, windowStart + match.Index * bytesPerChar, sourcePath);
        }
    }

    // ------------------------------------------------------------------
    // Signature identification helpers
    // ------------------------------------------------------------------
    private static bool IsZipMagic(byte[] bytes)
    {
        return bytes.Length >= 4
            && bytes[0] == 0x50 && bytes[1] == 0x4B
            && ((bytes[2] == 0x03 && bytes[3] == 0x04)
                || (bytes[2] == 0x05 && bytes[3] == 0x06)
                || (bytes[2] == 0x07 && bytes[3] == 0x08));
    }

    private static string? IdentifyUnsupportedArchive(byte[] header, int headerLen)
    {
        foreach ((string label, byte[] signature) in UnsupportedSignatures)
        {
            if (headerLen >= signature.Length && header.AsSpan(0, signature.Length).SequenceEqual(signature))
            {
                return label;
            }
        }

        if (headerLen >= 262 && Encoding.ASCII.GetString(header, 257, 5) == "ustar")
        {
            return "POSIX tar archive (.tar)";
        }

        return null;
    }

    private static int ReadExactlyUpTo(Stream stream, byte[] buffer, int count)
    {
        int total = 0;
        while (total < count)
        {
            int read = stream.Read(buffer, total, count - total);
            if (read <= 0)
            {
                break;
            }
            total += read;
        }
        return total;
    }

    // ------------------------------------------------------------------
    // Output: console (with severity coloring) mirrored to triage_report.txt
    // ------------------------------------------------------------------
    private static void Emit(string text, ConsoleColor? color = null)
    {
        if (color.HasValue)
        {
            ConsoleColor previous = Console.ForegroundColor;
            Console.ForegroundColor = color.Value;
            Console.WriteLine(text);
            Console.ForegroundColor = previous;
        }
        else
        {
            Console.WriteLine(text);
        }

        _report?.WriteLine(text);
    }

    // ------------------------------------------------------------------
    // Minimal read-only stream that replays peeked prefix bytes before
    // delegating to the underlying entry stream (non-seekable by design).
    // ------------------------------------------------------------------
    private sealed class PrependedStream : Stream
    {
        private readonly byte[] _prefix;
        private readonly int _prefixLength;
        private int _prefixPosition;
        private readonly Stream _inner;

        public PrependedStream(byte[] prefix, int prefixLength, Stream inner)
        {
            _prefix = prefix;
            _prefixLength = prefixLength;
            _inner = inner;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int total = 0;
            if (_prefixPosition < _prefixLength)
            {
                int fromPrefix = Math.Min(count, _prefixLength - _prefixPosition);
                Buffer.BlockCopy(_prefix, _prefixPosition, buffer, offset, fromPrefix);
                _prefixPosition += fromPrefix;
                offset += fromPrefix;
                count -= fromPrefix;
                total += fromPrefix;
            }

            if (count > 0)
            {
                total += _inner.Read(buffer, offset, count);
            }

            return total;
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}