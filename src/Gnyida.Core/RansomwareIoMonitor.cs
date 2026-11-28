using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Gnyida.Core
{
    /// <summary>
    /// Detects ransomware-style file damage from rename activity.
    ///
    /// A burst of renames alone is not proof of anything: installers, builds, OS-image tools,
    /// backup jobs and database maintenance all rename thousands of files. Kill authority therefore
    /// needs a damage pattern from <see cref="RansomwareRenameEvidence"/> (many file types funnelled
    /// into one new extension, or user documents each losing their type). A bare burst is logged as
    /// a Tier2 observation.
    ///
    /// Documents are not in the file-event scope the rest of the agent watches, so their renames
    /// arrive without a process id. Those are tallied host-wide at no per-event cost. Only when the
    /// tally shows a damage pattern does the monitor ask the attributor (Restart Manager) who holds a
    /// sample of the renamed files, and it kills only when several samples agree on one process.
    ///
    /// Purely behavioural: no file name or extension blocklists and no file is opened.
    /// Fed by FileActivityMonitor via RecordRename() for every observed file rename event.
    /// </summary>
    public sealed class RansomwareIoMonitor : BackgroundService
    {
        /// <summary>Renames in one 5-second window above which a bare burst is worth logging.</summary>
        internal const int ObserveRenameThreshold = 50;
        private const int MaxSamplePerWindow = 2000;
        private const int MaxAttributionSamples = 8;
        private const int MinAttributionAgreement = 2;

        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<RansomwareIoMonitor> _logger;
        private readonly object _gate = new();
        private WindowBucket _current = new();

        /// <summary>
        /// Resolves which process holds a file right now (Restart Manager holder). Supplied by
        /// FileActivityMonitor. Without it, unattributed damage is reported but never killed.
        /// </summary>
        public Func<string, (int pid, string name)>? Attributor { get; set; }

        // Browser and known high-IO apps that rename files legitimately (cache, IndexedDB, etc.)
        // SECURITY: Name-only matching here is supplemented by path verification - an attacker
        // naming malware "chrome.exe" from C:\Temp would still be caught.
        private static readonly HashSet<string> RansomwareIoWhitelist = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "msedgewebview2",
            // Browser installers unpack thousands of files (looks like ransomware IO on a fresh PC)
            "chromesetup", "chrome_installer", "mini_installer", "setup",
            "googleupdate", "googleupdated", "microsoftedgeupdate", "braveupdate",
            "code", "cursor", "Windsurf", "Kiro", "rider64",
            "steam", "steamwebhelper",
            "OneDrive", "Dropbox",
            "TmsaInstance64", "PtSessionAgent", "coreServiceShell",
        };

        // Cache of PIDs we've verified as legitimately matching the whitelist
        private readonly ConcurrentDictionary<int, bool> _verifiedWhitelistPids = new();

        private readonly GnyidaConfig? _config;

        public RansomwareIoMonitor(DetectionEngine detectionEngine, ILogger<RansomwareIoMonitor> logger, GnyidaConfig? config = null)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _config = config;
        }

        private sealed class PidRenames
        {
            public string Name = "";
            public int Count;
            public readonly List<(string OldPath, string NewPath)> Sample = new();
        }

        private sealed class WindowBucket
        {
            public readonly Dictionary<int, PidRenames> ByPid = new();
            public readonly PidRenames Unattributed = new();
        }

        /// <summary>
        /// Back-compat entry: a rename with no paths is counted but can never carry kill evidence.
        /// </summary>
        public void RecordRename(int processId, string processName) => RecordRename(processId, processName, "", "");

        /// <summary>
        /// Called by FileActivityMonitor for every file rename event observed.
        /// Thread-safe - designed to be called from FileSystemWatcher callbacks.
        /// A process id of 0 means the writer is unknown; the rename joins the host-wide tally.
        /// </summary>
        public void RecordRename(int processId, string processName, string oldPath, string newPath)
        {
            if (processId > 4 && IsLegitimateHighIo(processId, processName)) return;

            bool hasPaths = !string.IsNullOrEmpty(oldPath) && !string.IsNullOrEmpty(newPath);
            lock (_gate)
            {
                PidRenames target;
                if (processId > 4)
                {
                    if (!_current.ByPid.TryGetValue(processId, out target!))
                    {
                        target = new PidRenames { Name = processName };
                        _current.ByPid[processId] = target;
                    }
                }
                else
                {
                    // Count-only calls without paths carry no information about unknown writers.
                    if (!hasPaths) return;
                    target = _current.Unattributed;
                }

                target.Count++;
                if (hasPaths && target.Sample.Count < MaxSamplePerWindow)
                    target.Sample.Add((oldPath, newPath));
            }
        }

        private bool IsLegitimateHighIo(int processId, string processName)
        {
            // Fast path: cached "this PID is a legitimate high-IO process"
            if (_verifiedWhitelistPids.TryGetValue(processId, out var cachedOk)) return cachedOk;

            bool legitimate = false;
            try
            {
                var stem = Gnyida.Core.StringNet48.ReplaceIgnoreCase(processName, ".exe", "");
                var imagePath = SecurityValidation.GetProcessImagePath(processId);

                // 1) Known high-IO app names with path verification
                if (RansomwareIoWhitelist.Contains(processName) || RansomwareIoWhitelist.Contains(stem))
                {
                    if (!string.IsNullOrEmpty(imagePath))
                    {
                        var lower = imagePath!.ToLowerInvariant();
                        bool isSuspiciousDir = lower.Contains(@"\temp\") ||
                                               lower.Contains(@"\downloads\") ||
                                               lower.Contains(@"\appdata\local\temp\");
                        if (!isSuspiciousDir)
                        {
                            legitimate = lower.Contains(@"\program files") ||
                                         lower.Contains(@"\appdata\local\programs\") ||
                                         lower.Contains(@"\appdata\local\google\") ||
                                         lower.Contains(@"\appdata\local\microsoft\") ||
                                         lower.Contains(@"\steam\") ||
                                         lower.Contains(@"\windows\");
                        }
                    }
                }

                // 2) Signed installer / packager (Git-2.x-64-bit.exe, ChromeSetup, ...)
                if (!legitimate && !string.IsNullOrEmpty(imagePath) &&
                    (InstallerHeuristics.LooksLikeInstallerName(processName, imagePath) ||
                     InstallerHeuristics.IsInstallerExtractor(processName, imagePath)) &&
                    SecurityValidation.VerifyAuthenticodeSignature(imagePath!))
                {
                    legitimate = true;
                }

                // 3) Administrator-approved bulk-file software: exact image, admin-only location, valid signature.
                var approved = _config?.RansomwareIoApprovedImages ?? Array.Empty<string>();
                if (!legitimate && approved.Length > 0 &&
                    ApprovedImageExemption.Matches(imagePath, approved, SelfPathGuard.TryGetFinalPath,
                        path => !WritableLocationAcl.IsWritableByNonAdmin(path), path => SecurityValidation.VerifyAuthenticodeSignature(path)))
                {
                    legitimate = true;
                    _logger.LogInformation("[RansomwareIoMonitor] PID {Pid} ({Name}) matches an administrator-approved bulk-file image; rename bursts are not evaluated for it.", processId, processName);
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[RansomwareIoMonitor] IsLegitimateHighIo failed"); }

            _verifiedWhitelistPids[processId] = legitimate;
            return legitimate;
        }

        /// <summary>Back-compat shim for tests - delegates to <see cref="InstallerHeuristics"/>.</summary>
        internal static bool LooksLikeInstallerName(string processName, string? imagePath = null)
            => InstallerHeuristics.LooksLikeInstallerName(processName, imagePath);

        /// <summary>
        /// Closes the current window and returns the detections it justifies. Separate from the
        /// timer loop so the decision logic can be exercised without a running engine.
        /// </summary>
        internal List<DetectionEvent> EvaluateWindowAndReset()
        {
            WindowBucket window;
            lock (_gate)
            {
                window = _current;
                _current = new WindowBucket();
            }

            var results = new List<DetectionEvent>();

            foreach (var kv in window.ByPid)
            {
                var renames = kv.Value;
                var evidence = RansomwareRenameEvidence.Evaluate(renames.Sample, renames.Count);
                if (evidence.HasDamagePattern)
                    results.Add(BuildKill(kv.Key, renames.Name, evidence, renames.Sample, "ProcessAttributedAtEvent"));
                else if (renames.Count > ObserveRenameThreshold)
                    results.Add(BuildObserve(kv.Key, renames.Name, renames.Count, evidence));
            }

            var unknown = window.Unattributed;
            if (unknown.Count > 0)
            {
                var evidence = RansomwareRenameEvidence.Evaluate(unknown.Sample, unknown.Count);
                if (evidence.HasDamagePattern)
                {
                    var (pid, name, votes, resolved) = Attribute(unknown.Sample);
                    if (pid > 4 && !IsLegitimateHighIo(pid, name) && !IsProtectedServicingProcess(pid, name))
                        results.Add(BuildKill(pid, name, evidence, unknown.Sample, $"RestartManagerVote {votes}/{resolved}"));
                    else
                        results.Add(BuildObserve(0, "unknown", unknown.Count, evidence, unattributed: true));
                }
                else if (unknown.Count > ObserveRenameThreshold)
                {
                    results.Add(BuildObserve(0, "unknown", unknown.Count, evidence, unattributed: true));
                }
            }

            return results;
        }

        /// <summary>
        /// Picks the process holding most of an evenly spread sample of the renamed files. A single
        /// lookup can land on an indexer, scanner or the shell, so at least
        /// <see cref="MinAttributionAgreement"/> samples must agree and they must be a majority.
        /// </summary>
        private (int pid, string name, int votes, int resolved) Attribute(List<(string OldPath, string NewPath)> sample)
        {
            var attributor = Attributor;
            if (attributor == null || sample.Count == 0) return (0, "unknown", 0, 0);

            var tally = new Dictionary<int, (int Votes, string Name)>();
            int resolved = 0;
            int step = Math.Max(1, sample.Count / MaxAttributionSamples);
            for (int i = 0, taken = 0; i < sample.Count && taken < MaxAttributionSamples; i += step, taken++)
            {
                try
                {
                    var (pid, name) = attributor(sample[i].NewPath);
                    if (pid <= 4) continue;
                    resolved++;
                    tally.TryGetValue(pid, out var entry);
                    tally[pid] = (entry.Votes + 1, string.IsNullOrEmpty(name) ? entry.Name : name);
                }
                catch (Exception ex) { _logger.LogDebug(ex, "[RansomwareIoMonitor] Attribution lookup failed"); }
            }

            if (resolved == 0) return (0, "unknown", 0, 0);
            var best = tally.OrderByDescending(t => t.Value.Votes).First();
            if (best.Value.Votes < MinAttributionAgreement || best.Value.Votes * 2 <= resolved)
                return (0, "unknown", best.Value.Votes, resolved);
            return (best.Key, best.Value.Name ?? "unknown", best.Value.Votes, resolved);
        }

        private static bool IsProtectedServicingProcess(int pid, string name)
        {
            try
            {
                return WindowsServicingTrust.IsGenuineServicingActorStrict(name, SecurityValidation.GetProcessImagePath(pid));
            }
            catch { return false; }
        }

        private static DetectionEvent BuildKill(int pid, string? name, RenameEvidence evidence,
            List<(string OldPath, string NewPath)> sample, string attribution)
        {
            var pattern = evidence.Funnel && evidence.TypeChange ? "funnel+type-change"
                : evidence.Funnel ? "funnel" : "type-change";
            return new DetectionEvent
            {
                RuleName = "Ransomware: Mass File Rename",
                Evidence = $"Process '{name ?? "unknown"}' (PID {pid}) renamed {evidence.Total} files in 5 seconds with a damage pattern ({pattern}): " +
                           Describe(evidence) + " Sample: " + SamplePaths(sample),
                Reasoning = "The renames strip the type from user files. Either many different file types were renamed to " +
                            "one new extension, or most renamed files were user documents that each lost their extension. " +
                            "Installers, builds and backup tools do not do this.",
                Confidence = evidence.Funnel && evidence.TypeChange ? 0.97 : 0.92,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                ProcessName = name ?? "unknown",
                ProcessId = pid,
                SignalType = SignalType.Ransomware,
                Family = TerminalFamily.Ransomware,
                Timestamp = DateTime.UtcNow,
                Metadata = EvidenceMetadata(evidence, pattern, attribution),
            };
        }

        private static DetectionEvent BuildObserve(int pid, string? name, int count, RenameEvidence evidence, bool unattributed = false)
        {
            return new DetectionEvent
            {
                // Name avoids the ransomware terminal-family fragments on purpose: a rename burst
                // without a damage pattern is not terminal and must never be promoted.
                RuleName = "File Activity: Rapid Rename Burst",
                Evidence = $"{(unattributed ? "Unattributed writers" : $"Process '{name ?? "unknown"}' (PID {pid})")} renamed {count} files in 5 seconds " +
                           "without a file-damage pattern. " + Describe(evidence),
                Reasoning = "A rename count alone does not separate ransomware from installers, builds, OS-image tools or backup jobs. " +
                            "No funnel into one new extension and no mass loss of user-document types was seen, so this is logged only.",
                Confidence = 0.40,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = name ?? "unknown",
                ProcessId = pid,
                SignalType = SignalType.Generic,
                Timestamp = DateTime.UtcNow,
                Metadata = EvidenceMetadata(evidence, "none", unattributed ? "Unattributed" : "ProcessAttributedAtEvent"),
            };
        }

        private static Dictionary<string, string> EvidenceMetadata(RenameEvidence e, string pattern, string attribution) => new()
        {
            ["RenameCount"] = e.Total.ToString(CultureInfo.InvariantCulture),
            ["UserDataSources"] = e.UserDataSources.ToString(CultureInfo.InvariantCulture),
            ["DistinctDirectories"] = e.DistinctDirectories.ToString(CultureInfo.InvariantCulture),
            ["DominantNewExtension"] = e.DominantNewExtension,
            ["DominantCount"] = e.DominantCount.ToString(CultureInfo.InvariantCulture),
            ["DominantSourceExtensions"] = e.DominantDistinctSourceExtensions.ToString(CultureInfo.InvariantCulture),
            ["DamagePattern"] = pattern,
            ["Attribution"] = attribution,
        };

        private static string Describe(RenameEvidence e) =>
            $"user-document sources {e.UserDataSources}, folders {e.DistinctDirectories}, " +
            $"top new extension '{(e.DominantNewExtension.Length == 0 ? "-" : e.DominantNewExtension)}' x{e.DominantCount} from {e.DominantDistinctSourceExtensions} source types.";

        private static string SamplePaths(List<(string OldPath, string NewPath)> sample) =>
            string.Join("; ", sample.Take(3).Select(s => s.NewPath));

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("[RansomwareIoMonitor] Started");
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(5000, stoppingToken);
                    foreach (var detection in EvaluateWindowAndReset())
                        await _detectionEngine.EmitAsync(detection);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[RansomwareIoMonitor] Error");
                }
            }
        }
    }
}
