using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Flags run-to-completion Windows utilities (schtasks, reg, whoami, ...) that stay alive far longer
    /// than any normal invocation takes.
    ///
    /// Why: a process that was started, hung, orphaned or kept alive on purpose is a cheap place to hide.
    /// It is a signed system binary with no network connections, so GhostProcessMonitor (which needs an
    /// unresolvable image plus outbound sockets) and the injection rules (which need remote-memory API
    /// events) never look at it. EphemeralProcessMonitor covers the opposite case, processes that live
    /// too briefly to be seen. Nothing else keys on a process that lives too long.
    ///
    /// This monitor only reports (ResponseAction.LogOnly). Its output feeds the correlation engine, and
    /// killing a long but legitimate operation (for example icacls over a large tree) would be worse
    /// than the alert. The ceilings are deliberately generous, and interactive or open-ended tools
    /// (cmd, powershell, ping -t, timeout, netsh, certutil) are not listed.
    /// </summary>
    public sealed class LingeringProcessMonitor : BackgroundService
    {
        internal enum Verdict
        {
            /// <summary>Not a watched image, or still within its ceiling.</summary>
            Ok,
            /// <summary>A watched system binary running from the Windows system directory, past its ceiling.</summary>
            Lingering,
            /// <summary>Past its ceiling and the image path could not be read, so the binary cannot be vouched for.</summary>
            LingeringUnverifiable,
            /// <summary>Past its ceiling and not running from the Windows system directory (a masquerade).</summary>
            LingeringOffPath,
        }

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan Short = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan Long = TimeSpan.FromMinutes(30);

        // Name (no extension) -> longest plausible single run. Anything that can legitimately walk a large
        // tree, export logs or take a snapshot gets the longer ceiling.
        internal static readonly IReadOnlyDictionary<string, TimeSpan> Ceilings =
            new Dictionary<string, TimeSpan>(StringComparer.OrdinalIgnoreCase)
            {
                ["schtasks"] = Short, ["reg"] = Short, ["whoami"] = Short, ["hostname"] = Short,
                ["ipconfig"] = Short, ["tasklist"] = Short, ["taskkill"] = Short, ["sc"] = Short,
                ["net"] = Short, ["net1"] = Short, ["nslookup"] = Short, ["getmac"] = Short,
                ["arp"] = Short, ["klist"] = Short, ["cmdkey"] = Short, ["bcdedit"] = Short,
                ["mountvol"] = Short, ["systeminfo"] = Short,
                ["icacls"] = Long, ["takeown"] = Long, ["attrib"] = Long, ["wevtutil"] = Long,
                ["fsutil"] = Long, ["vssadmin"] = Long, ["gpresult"] = Long,
            };

        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly ILogger<LingeringProcessMonitor> _logger;
        // One alert per process instance. Keyed on PID plus start time so a reused PID is a new instance.
        private readonly ConcurrentDictionary<(int Pid, long StartTicks), DateTimeOffset> _alerted = new();

        public LingeringProcessMonitor(
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<LingeringProcessMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _logger = logger;
        }

        /// <summary>
        /// Pure decision function (no I/O) so it can be unit-tested. <paramref name="imagePath"/> is null
        /// when the path could not be read.
        /// </summary>
        internal static Verdict Evaluate(string processName, TimeSpan age, string? imagePath, string systemDirectory, string? wow64Directory)
        {
            string name = Normalize(processName);
            if (!Ceilings.TryGetValue(name, out TimeSpan ceiling)) return Verdict.Ok;
            if (age <= ceiling) return Verdict.Ok;
            if (string.IsNullOrWhiteSpace(imagePath)) return Verdict.LingeringUnverifiable;
            return IsUnder(imagePath!, systemDirectory) || (!string.IsNullOrEmpty(wow64Directory) && IsUnder(imagePath!, wow64Directory!))
                ? Verdict.Lingering
                : Verdict.LingeringOffPath;
        }

        private static string Normalize(string name)
        {
            string trimmed = (name ?? string.Empty).Trim();
            return trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? trimmed.Substring(0, trimmed.Length - 4) : trimmed;
        }

        private static bool IsUnder(string path, string directory)
        {
            string dir = directory.TrimEnd('\\') + "\\";
            return path.StartsWith(dir, StringComparison.OrdinalIgnoreCase);
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[LingeringProcessMonitor] Started");
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);
                    await ScanAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[LingeringProcessMonitor] Scan error"); }
            }
        }

        private async Task ScanAsync(CancellationToken ct)
        {
            string systemDir = Environment.SystemDirectory;
            string wowDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");
            int self = ProcessInstanceTable.CurrentPid;
            Process[] processes = Process.GetProcesses();
            try
            {
                foreach (Process p in processes)
                {
                    if (ct.IsCancellationRequested) break;
                    int pid = p.Id;
                    if (pid <= 4 || pid == self) continue;
                    string name;
                    DateTime start;
                    try
                    {
                        name = p.ProcessName;
                        if (!Ceilings.ContainsKey(Normalize(name))) continue;
                        start = p.StartTime;
                    }
                    catch (Exception) { continue; } // exited, or access denied for the start time

                    var key = (pid, start.Ticks);
                    if (_alerted.ContainsKey(key)) continue;

                    TimeSpan age = DateTime.UtcNow - start.ToUniversalTime();
                    string? imagePath = SecurityValidation.GetProcessImagePath(pid);
                    Verdict verdict = Evaluate(name, age, imagePath, systemDir, wowDir);
                    if (verdict == Verdict.Ok) continue;

                    _alerted[key] = DateTimeOffset.UtcNow;
                    await EmitAsync(pid, name, start, age, imagePath, verdict);
                }
            }
            finally
            {
                // Release every handle even when the loop exits early (cancellation or an exception).
                foreach (Process p in processes) p.Dispose();
            }

            // Forget instances that have exited so the table cannot grow without bound.
            ProcessInstanceTable.Prune(_alerted, ProcessInstanceTable.ReadStartTicks);
        }
        private async Task EmitAsync(int pid, string name, DateTime start, TimeSpan age, string? imagePath, Verdict verdict)
        {
            int parentPid = 0;
            string parentName = string.Empty;
            try { (parentPid, parentName) = _ancestryCache.GetParent(pid); } catch { }
            bool orphaned = parentPid > 0 && !IsLiveParentOf(parentPid, start);
            TimeSpan ceiling = Ceilings[Normalize(name)];
            bool strong = verdict != Verdict.Lingering;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Lingering Process: Run-to-completion utility exceeded its runtime ceiling",
                Evidence = $"{name} (PID {pid}) has been running for {(int)age.TotalMinutes} min " +
                           $"(normal ceiling {(int)ceiling.TotalMinutes} min). " +
                           $"Parent: {(parentPid > 0 ? parentName + " (PID " + parentPid + ")" : "unknown")}" +
                           (orphaned ? ", parent has exited" : "") + ". " +
                           $"Image: {imagePath ?? "unreadable"}.",
                Reasoning = "Short-lived system utilities finish in seconds. One that stays alive for this long was " +
                            "either hung, left running on purpose to serve as a cover process, or is not the " +
                            "genuine binary. It has no network sockets and a valid signature, so the ghost-process " +
                            "and injection monitors do not examine it." +
                            (verdict == Verdict.LingeringOffPath ? " It is running from outside the Windows system directory, which is how a masquerade appears." : "") +
                            (verdict == Verdict.LingeringUnverifiable ? " Its image path cannot be read, so it cannot be verified." : ""),
                Confidence = strong ? 0.75 : 0.55,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = name,
                ProcessId = pid,
                SignalType = SignalType.SuspiciousProcess,
                Metadata = new Dictionary<string, string>
                {
                    ["AgeSeconds"] = ((long)age.TotalSeconds).ToString(),
                    ["CeilingSeconds"] = ((long)ceiling.TotalSeconds).ToString(),
                    ["ParentPid"] = parentPid.ToString(),
                    ["ParentName"] = parentName,
                    ["ParentExited"] = orphaned.ToString(),
                    ["ImagePath"] = imagePath ?? string.Empty,
                    ["Verdict"] = verdict.ToString(),
                },
            });
        }

        /// <summary>True when a process with this PID exists and started no later than the child (so it is not a reused PID).</summary>
        private static bool IsLiveParentOf(int parentPid, DateTime childStart)
        {
            try
            {
                using var parent = Process.GetProcessById(parentPid);
                return parent.StartTime <= childStart;
            }
            catch (Exception) { return false; }
        }
    }
}
