using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Detects a process whose main image in memory no longer matches the signed file it claims to run
    /// (process hollowing, image replacement, entry-point patching). Each process instance is checked once,
    /// after it has run long enough for the loader to finish.
    ///
    /// Scope is deliberately narrow so a mismatch means something: the main image only, under the Windows or
    /// Program Files directories, with a valid Authenticode signature, and not modified on disk after the
    /// process started (an update replaces the file while the old process keeps running). Anything the check
    /// cannot read is counted and logged, never reported as clean.
    ///
    /// Reports only (ResponseAction.LogOnly); the output feeds the correlation engine.
    ///
    /// Resource rules (docs/MEMORY_LEAK_3.7.8.md): the only wait is a self-completing Task.Delay; every
    /// process handle, file stream and Process object is released in a finally block; the per-instance table
    /// is pruned every scan and bounded by the number of live processes; work per scan is capped.
    /// </summary>
    public sealed class ImageIntegrityMonitor : BackgroundService
    {
        private static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(15);
        private const int FullScanEveryTicks = 4; // 60 seconds
        private static readonly TimeSpan MinimumAge = TimeSpan.FromSeconds(20);
        // A suspect is looked at again no sooner than this, so one burst of events costs one check, not one per event.
        private static readonly TimeSpan SuspectCooldown = TimeSpan.FromSeconds(45);
        // Bounds the work one 15-second tick can do however many processes were nominated.
        private const int MaxSuspectsPerTick = 12;
        private const long SuspectMaxBytes = 32L * 1024 * 1024;
        private static readonly TimeSpan RoundRobinBudget = TimeSpan.FromSeconds(2);
        private const int MaxModuleProcessesPerPass = 64;
        private int _tick;
        private const int MaxChecksPerScan = 8;
        private const long MaxBytesPerScan = 16L * 1024 * 1024;

        private readonly DetectionEngine _detectionEngine;
        private readonly SignerTrustService _signerTrust;
        private readonly ILogger<ImageIntegrityMonitor> _logger;
        // One entry per checked process instance, pruned against live processes every scan.
        private readonly ConcurrentDictionary<(int Pid, long StartTicks), byte> _checked = new();
        private long _unverifiableCount;

        // Module stage: loaded system DLLs are re-triaged periodically because stomping can happen at any time,
        // unlike hollowing of the main image, which happens at process start. All three tables are keyed on the
        // process instance and pruned every scan.
        private static readonly TimeSpan ModuleRecheck = TimeSpan.FromMinutes(10);
        private readonly ConcurrentDictionary<(int Pid, long StartTicks), DateTime> _moduleTriaged = new();
        private readonly ConcurrentDictionary<(int Pid, long StartTicks), byte> _moduleAlerted = new();
        private readonly ConcurrentDictionary<(int Pid, long StartTicks), byte> _mainAlerted = new();
        private readonly ConcurrentDictionary<(int Pid, long StartTicks), DateTime> _suspectChecked = new();
        // One reusable 64 KB scratch array (below the large-object threshold). The scan loop is single-threaded.
        private readonly ModuleStompTriage.WorkingSetExBlock[] _scratch = new ModuleStompTriage.WorkingSetExBlock[ModuleStompTriage.BatchPages];

        internal sealed class ModuleFinding
        {
            public string Name = "";
            public string Path = "";
            public ImageIntegrityVerifier.Result Result = new();
            public ImageIntegrityVerifier.Verdict Verdict;
        }

        public ImageIntegrityMonitor(
            DetectionEngine detectionEngine,
            SignerTrustService signerTrust,
            ILogger<ImageIntegrityMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _signerTrust = signerTrust;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ImageIntegrityMonitor] Started");
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TickInterval, ct);
                    // Suspects are handled every tick; the full pass (first-time main images and the round-robin
                    // over every process) runs on every fourth.
                    bool full = (++_tick % FullScanEveryTicks) == 0;
                    await ScanAsync(full, ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[ImageIntegrityMonitor] Scan error"); }
            }
        }

        private async Task ScanAsync(bool full, CancellationToken ct)
        {
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            int self = ProcessInstanceTable.CurrentPid;
            long bytes = 0;
            Process[] processes = Process.GetProcesses();
            try
            {
                // Stage 0: processes that were just nominated. Two reasons count here:
                //   Evidence  - a kernel Threat-Intelligence call (only where that provider is available to the service);
                //   ImageLoad - the process loaded a module late in its life (kernel-process provider, which is available
                //               without a protected anti-malware process). Loading a sacrificial DLL and overwriting its
                //               code is the stomp pattern, and a written page stays resident and private for a while, so a
                //               check within seconds sees what a ten-minute poll finds paged out.
                // Evidence gets the full check. An image-load nomination gets the module triage only: it is cheap, and a
                // main image does not change because a DLL was loaded.
                const InjectionSuspectBoard.MarkKind wanted = InjectionSuspectBoard.MarkKind.Evidence | InjectionSuspectBoard.MarkKind.ImageLoad;
                int[] suspects = InjectionSuspectBoard.Snapshot(wanted);
                if (suspects.Length > 0)
                {
                    var byId = new Dictionary<int, Process>(processes.Length);
                    foreach (Process p in processes) byId[p.Id] = p;
                    int handled = 0;
                    foreach (int suspect in suspects)
                    {
                        if (ct.IsCancellationRequested || handled >= MaxSuspectsPerTick) break;
                        if (suspect <= 4 || suspect == self || !byId.TryGetValue(suspect, out Process? sp)) continue;
                        if (!InjectionSuspectBoard.TryGetKinds(suspect, out var kinds)) continue;
                        bool evidence = (kinds & InjectionSuspectBoard.MarkKind.Evidence) != 0;
                        DateTime sstart;
                        try { sstart = sp.StartTime; }
                        catch (Exception) { continue; }
                        // Every process loads modules while it starts. Only later loads are interesting, so a young process
                        // is left on the board and looked at on a later tick, once it has settled.
                        if (!evidence && DateTime.UtcNow - sstart.ToUniversalTime() < MinimumAge) continue;
                        var skey = (suspect, sstart.Ticks);
                        if (_suspectChecked.TryGetValue(skey, out DateTime lastLook) && DateTime.UtcNow - lastLook < SuspectCooldown) continue;
                        _suspectChecked[skey] = DateTime.UtcNow;
                        handled++;

                        if (evidence)
                            bytes += await CheckMainImageAsync(sp, sstart, force: true, windows, programFiles, programFilesX86);
                        if (_moduleAlerted.ContainsKey(skey)) continue;
                        long suspectBytes = 0;
                        var found = CheckModules(sp, sstart, windows, _scratch, ref suspectBytes, SuspectMaxBytes, out int seen);
                        bytes += suspectBytes;
                        _logger.LogDebug("[ImageIntegrityMonitor] Suspect PID {Pid} ({Kinds}): {Count} system modules triaged, {Found} confirmed modified", suspect, kinds, seen, found.Count);
                        if (found.Count == 0) continue;
                        _moduleAlerted[skey] = 0;
                        await EmitModulesAsync(suspect, sp.ProcessName, found);
                    }
                }
                if (full)
                {
                    // Stage 1: main image of each process once, 20 seconds after it started.
                    int checks = 0;
                    foreach (Process p in processes)
                    {
                        if (ct.IsCancellationRequested) break;
                        if (checks >= MaxChecksPerScan || bytes >= MaxBytesPerScan) break;
                        int pid = p.Id;
                        if (pid <= 4 || pid == self) continue;
                        DateTime start;
                        try { start = p.StartTime; }
                        catch (Exception) { continue; } // exited or access denied
                        var key = (pid, start.Ticks);
                        if (_checked.ContainsKey(key)) continue;
                        if (DateTime.UtcNow - start.ToUniversalTime() < MinimumAge) continue; // not yet settled; try next scan
                        long compared = await CheckMainImageAsync(p, start, force: false, windows, programFiles, programFilesX86);
                        if (compared >= 0) { checks++; bytes += compared; }
                    }

                    // Stage 2: round-robin over loaded system modules of every process. Not limited to signed
                    // images: a stomping loader is usually the attacker's own, unsigned process. The pass is
                    // bounded by wall-clock time rather than a process count, because triage reads no code and a
                    // fixed count left most of a busy machine uncovered for many minutes.
                    var clock = Stopwatch.StartNew();
                    int moduleProcesses = 0;
                    foreach (Process p in processes)
                    {
                        if (ct.IsCancellationRequested) break;
                        if (moduleProcesses >= MaxModuleProcessesPerPass || clock.Elapsed >= RoundRobinBudget || bytes >= MaxBytesPerScan) break;
                        int pid = p.Id;
                        if (pid <= 4 || pid == self) continue;
                        DateTime start;
                        try { start = p.StartTime; }
                        catch (Exception) { continue; }
                        var key = (pid, start.Ticks);
                        if (DateTime.UtcNow - start.ToUniversalTime() < MinimumAge) continue;
                        if (_moduleAlerted.ContainsKey(key)) continue;
                        if (_moduleTriaged.TryGetValue(key, out DateTime last) && DateTime.UtcNow - last < ModuleRecheck) continue;
                        _moduleTriaged[key] = DateTime.UtcNow; // recorded first so a failing process is not retried every pass
                        moduleProcesses++;
                        // Also nominate it for the payload scan (PE headers in private executable memory), which otherwise
                        // runs only for processes the Threat-Intelligence provider flags. That provider is denied on an
                        // install without a protected anti-malware process.
                        InjectionSuspectBoard.MarkWeak(pid, InjectionSuspectBoard.MarkKind.Sweep);

                        var findings = CheckModules(p, start, windows, _scratch, ref bytes, MaxBytesPerScan, out int triaged);
                        _logger.LogDebug("[ImageIntegrityMonitor] PID {Pid}: {Count} system modules triaged, {Found} confirmed modified", pid, triaged, findings.Count);
                        if (findings.Count == 0) continue;
                        _moduleAlerted[key] = 0;
                        await EmitModulesAsync(pid, p.ProcessName, findings);
                    }
                    _logger.LogDebug("[ImageIntegrityMonitor] Round-robin: {Count} processes in {Ms} ms", moduleProcesses, clock.ElapsedMilliseconds);
                }
            }
            finally
            {
                foreach (Process p in processes) p.Dispose();
            }
            Prune();
        }

        /// <summary>
        /// Compares one process's main image with its file and reports a mismatch. Returns the bytes compared, or -1
        /// when the process was out of scope or could not be checked (so the caller does not count it as work done).
        /// <paramref name="force"/> re-checks an instance that was checked before and ignores the settling delay.
        /// </summary>
        private async Task<long> CheckMainImageAsync(Process p, DateTime start, bool force,
            string windows, string programFiles, string programFilesX86)
        {
            int pid = p.Id;
            var key = (pid, start.Ticks);
            string? path = SecurityValidation.GetProcessImagePath(pid);
            if (string.IsNullOrEmpty(path)) { _checked[key] = 0; Interlocked.Increment(ref _unverifiableCount); return -1; }
            if (!IsUnder(path!, windows) && !IsUnder(path!, programFiles) && !IsUnder(path!, programFilesX86))
            {
                _checked[key] = 0; // out of scope: unsigned or user-writable locations are other monitors' job
                return -1;
            }
            if (!NativeProcessMemory.CanInspect(pid, path)) { _checked[key] = 0; return -1; }
            try
            {
                // The file changed after the process started: an update, not a tamper.
                if (File.GetLastWriteTimeUtc(path!) > start.ToUniversalTime()) { _checked[key] = 0; return -1; }
            }
            catch (Exception) { _checked[key] = 0; return -1; }
            if (!_signerTrust.IsSignedFile(path!)) { _checked[key] = 0; return -1; }

            IntPtr baseAddress;
            try { baseAddress = p.MainModule.BaseAddress; }
            catch (Exception) { _checked[key] = 0; Interlocked.Increment(ref _unverifiableCount); return -1; }

            ImageIntegrityVerifier.Result result = CheckProcess(pid, path!, baseAddress);
            _checked[key] = 0;
            var verdict = ImageIntegrityVerifier.Classify(result);
            if (verdict == ImageIntegrityVerifier.Verdict.Incomparable)
            {
                Interlocked.Increment(ref _unverifiableCount);
                _logger.LogDebug("[ImageIntegrityMonitor] PID {Pid} {Name} not comparable: {Reason}", pid, p.ProcessName, result.Reason);
                return result.ComparedBytes;
            }
            if (verdict == ImageIntegrityVerifier.Verdict.Clean) return result.ComparedBytes;
            if (force && _mainAlerted.ContainsKey(key)) return result.ComparedBytes; // one alert per instance
            _mainAlerted[key] = 0;
            await EmitAsync(pid, p.ProcessName, path!, result, verdict);
            return result.ComparedBytes;
        }
        /// <summary>
        /// Triage every loaded system module of one process by working-set sharing, then byte-compare only the
        /// modules that have private executable pages. Releases the process handle and every ProcessModule.
        /// </summary>
        internal static System.Collections.Generic.List<ModuleFinding> CheckModules(
            Process process, DateTime startLocal, string windowsDirectory,
            ModuleStompTriage.WorkingSetExBlock[] scratch, ref long bytesCompared, long byteLimit, out int modulesTriaged)
        {
            var findings = new System.Collections.Generic.List<ModuleFinding>();
            modulesTriaged = 0;
            IntPtr handle = NativeProcessMemory.OpenRemoteHandle(
                NativeProcessMemory.AccessQuery | NativeProcessMemory.AccessVmRead, process.Id);
            if (handle == IntPtr.Zero) return findings;
            try
            {
                var modules = new System.Collections.Generic.List<(string Name, string Path, long Base, long Size)>();
                try
                {
                    foreach (ProcessModule m in process.Modules)
                    {
                        using (m) modules.Add((m.ModuleName ?? "", m.FileName ?? "", m.BaseAddress.ToInt64(), m.ModuleMemorySize));
                    }
                }
                catch (Exception ex) { /* exited, or a cross-bitness target: use what was listed */ BestEffort.Debug(ex, "ImageIntegrityMonitor.CheckModules"); }

                DateTime startUtc = startLocal.ToUniversalTime();
                foreach (var module in modules)
                {
                    if (bytesCompared >= byteLimit) break;
                    if (!IsUnder(module.Path, windowsDirectory)) continue;
                    var triage = ModuleStompTriage.Triage(handle, module.Base, module.Size, scratch);
                    modulesTriaged++;
                    if (triage.PrivatePages == 0) continue;
                    try
                    {
                        // Replaced on disk after the process started: an update, not a tamper.
                        if (File.GetLastWriteTimeUtc(module.Path) > startUtc) continue;
                    }
                    catch (Exception) { continue; }

                    ImageIntegrityVerifier.Result result = CompareImage(handle, module.Path, module.Base);
                    bytesCompared += result.ComparedBytes;
                    var verdict = ImageIntegrityVerifier.Classify(result);
                    if (verdict == ImageIntegrityVerifier.Verdict.Clean || verdict == ImageIntegrityVerifier.Verdict.Incomparable) continue;
                    findings.Add(new ModuleFinding { Name = module.Name, Path = module.Path, Result = result, Verdict = verdict });
                }
            }
            finally
            {
                NativeProcessMemory.CloseHandle(handle);
            }
            return findings;
        }

        /// <summary>Opens the process, compares its main image against the file, and releases every handle.</summary>
        internal static ImageIntegrityVerifier.Result CheckProcess(int pid, string imagePath, IntPtr baseAddress)
        {
            IntPtr handle = NativeProcessMemory.OpenRemoteHandle(
                NativeProcessMemory.AccessQuery | NativeProcessMemory.AccessVmRead, pid);
            if (handle == IntPtr.Zero)
                return new ImageIntegrityVerifier.Result { Comparable = false, Reason = "process could not be opened" };
            try
            {
                return CompareImage(handle, imagePath, baseAddress.ToInt64());
            }
            finally
            {
                NativeProcessMemory.CloseHandle(handle);
            }
        }

        /// <summary>Compares the image mapped at <paramref name="baseValue"/> with the file. The caller owns the handle.</summary>
        private static ImageIntegrityVerifier.Result CompareImage(IntPtr handle, string imagePath, long baseValue)
        {
            try
            {
                using var file = new FileStream(imagePath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan);
                return ImageIntegrityVerifier.Compare(file, (rva, buffer, count) =>
                    NativeResolver.ReadProcessMemory(handle, new IntPtr(baseValue + rva), buffer, count, out int got) && got == count);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                return new ImageIntegrityVerifier.Result { Comparable = false, Reason = "image file could not be read: " + ex.Message };
            }
        }

        private static bool IsUnder(string path, string directory)
        {
            if (string.IsNullOrEmpty(directory)) return false;
            return path.StartsWith(directory.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Drops entries for processes that have exited or whose PID was reused.</summary>
        private void Prune()
        {
            ProcessInstanceTable.Prune(_checked, ProcessInstanceTable.ReadStartTicks);
            ProcessInstanceTable.Prune(_moduleTriaged, ProcessInstanceTable.ReadStartTicks);
            ProcessInstanceTable.Prune(_moduleAlerted, ProcessInstanceTable.ReadStartTicks);
            ProcessInstanceTable.Prune(_mainAlerted, ProcessInstanceTable.ReadStartTicks);
            ProcessInstanceTable.Prune(_suspectChecked, ProcessInstanceTable.ReadStartTicks);
        }

        /// <summary>
        /// Network context for a process that is already proven to run modified code. An established outbound
        /// connection from it is what an in-memory reverse shell or C2 implant looks like, and no process-creation
        /// rule sees one because nothing was spawned.
        /// </summary>
        private static (string Text, double Confidence, Dictionary<string, string> Metadata) NetworkContext(int pid, double baseConfidence)
        {
            var connections = ProcessTcpConnections.GetEstablished(pid);
            var metadata = new Dictionary<string, string> { ["OutboundConnectionCount"] = connections.Count.ToString() };
            if (connections.Count == 0) return ("", baseConfidence, metadata);
            metadata["OutboundConnections"] = string.Join(",", connections);
            return (" It holds " + connections.Count + " established outbound connection(s) (" + string.Join(", ", connections) +
                    "), which matches an in-memory reverse shell or C2 implant.",
                    Math.Max(baseConfidence, 0.95), metadata);
        }

        private async Task EmitModulesAsync(int pid, string name, System.Collections.Generic.List<ModuleFinding> findings)
        {
            var shown = new System.Text.StringBuilder();
            int count = 0;
            foreach (var f in findings)
            {
                if (count++ == 5) { shown.Append("; ..."); break; }
                if (shown.Length > 0) shown.Append("; ");
                shown.Append($"{f.Name} ({f.Result.DifferingBytes} bytes differ, {f.Result.DenseBlocks} dense blocks, longest run {f.Result.LongestDifferingRun})");
            }
            var net = NetworkContext(pid, 0.92);
            var moduleMetadata = new Dictionary<string, string>(net.Metadata)
            {
                ["ModuleCount"] = findings.Count.ToString(),
                ["Modules"] = string.Join(";", findings.Select(f => f.Path).Take(10)),
                ["Verdicts"] = string.Join(";", findings.Select(f => f.Verdict.ToString()).Take(10)),
            };
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Image Integrity: Loaded system module code differs from the file on disk",
                Evidence = $"{name} (PID {pid}) holds modified code in {findings.Count} system module(s): {shown}." + net.Text,
                Reasoning = "The module's executable pages are private copies, not the shared pages Windows maps from the file, " +
                            "and their content differs from the genuine file beyond what hooks or relocations explain. " +
                            "This is module stomping or in-memory patching, the technique used to run a reflectively loaded " +
                            "payload from image-backed memory so that unbacked-memory scans do not see it (T1055, T1620).",
                Confidence = net.Confidence,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = name,
                ProcessId = pid,
                SignalType = SignalType.ProcessInjection,
                Metadata = moduleMetadata,
            });
        }

        private async Task EmitAsync(int pid, string name, string path, ImageIntegrityVerifier.Result r, ImageIntegrityVerifier.Verdict verdict)
        {
            string what = verdict switch
            {
                ImageIntegrityVerifier.Verdict.HeaderMismatch => "its PE headers in memory differ from the file (" + r.Reason + ")",
                ImageIntegrityVerifier.Verdict.CodeReplaced => $"{r.DifferingBytes} of {r.ComparedBytes} code bytes differ (longest run {r.LongestDifferingRun}, section {r.FirstDifferingSection})",
                _ => $"{r.EntryPointDifferingBytes} bytes differ at the entry point (section {r.FirstDifferingSection})",
            };
            var mainNet = NetworkContext(pid, verdict == ImageIntegrityVerifier.Verdict.EntryPointPatched ? 0.80 : 0.90);
            var mainMetadata = new Dictionary<string, string>(mainNet.Metadata)
            {
                ["Verdict"] = verdict.ToString(),
                ["ImagePath"] = path,
                ["ComparedBytes"] = r.ComparedBytes.ToString(),
                ["DifferingBytes"] = r.DifferingBytes.ToString(),
                ["LongestDifferingRun"] = r.LongestDifferingRun.ToString(),
                ["EntryPointDifferingBytes"] = r.EntryPointDifferingBytes.ToString(),
                ["UnreadablePages"] = r.UnreadablePages.ToString(),
            };
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Image Integrity: In-memory code differs from the signed file on disk",
                Evidence = $"{name} (PID {pid}) runs {path}, but {what}." + mainNet.Text,
                Reasoning = "The file is genuine and signed, so signature checks pass, but the executable code in memory is not " +
                            "the code in that file. This is how process hollowing, image replacement and entry-point patching " +
                            "look (T1055.012). Base relocations and the import table were excluded from the comparison.",
                Confidence = mainNet.Confidence,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = name,
                ProcessId = pid,
                SignalType = SignalType.ProcessInjection,
                Metadata = mainMetadata,
            });
        }
    }
}
