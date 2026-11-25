// System file ACL drift: a loadable binary in a protected tree that every standard user can write.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Gnyida.Core
{
    /// <summary>
    /// Image-customization tools (WinReducer, NTLite, manual takeown/icacls) take ownership of OS files and
    /// grant <c>Users</c> Full Control so they can delete or replace them, and leave that behind on files they
    /// could not remove. A standard user can then overwrite <c>amsi.dll</c> or a boot-start driver such as
    /// <c>WdFilter.sys</c>. This monitor finds those files from the real DACL, whatever tool or build caused it.
    /// <para>
    /// The Tier2 finding is LogOnly and never triggers a response action. Separately, as host hardening (not driven by
    /// the Tier2 event), the monitor hands each finding under System32/SysWOW64 to <see cref="SystemFileAclRepairer"/>,
    /// which backs up the DACL and removes the standard-user write grant. Program Files is report-only because legitimate
    /// apps grant Users write on their own folders.
    /// </para>
    /// Only files are checked, and only for broad principals (Users, Authenticated Users, Everyone, Interactive,
    /// Guests, Network, Anonymous). Per-service SIDs that Windows grants by design are not reported.
    /// </summary>
    public sealed class SystemFileAclDriftMonitor : BackgroundService
    {
        private static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan ScanInterval = TimeSpan.FromHours(6);
        private const int MaxFilesInEvidence = 20;

        private static readonly HashSet<string> BinaryExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".ax", ".drv", ".winmd", ".node",
        };

        private readonly DetectionEngine _detectionEngine;
        private readonly GnyidaConfig _config;
        private readonly SystemFileAclRepairer _repairer;
        private readonly ILogger<SystemFileAclDriftMonitor> _logger;
        private readonly HashSet<string> _reported = new(StringComparer.OrdinalIgnoreCase);

        public SystemFileAclDriftMonitor(DetectionEngine de, GnyidaConfig config, SystemFileAclRepairer repairer, ILogger<SystemFileAclDriftMonitor> logger)
        {
            _detectionEngine = de;
            _config = config;
            _repairer = repairer;
            _logger = logger;
        }

        public readonly struct Finding
        {
            public Finding(string path, string sid, string owner) { Path = path; Sid = sid; Owner = owner; }
            public string Path { get; }
            public string Sid { get; }
            public string Owner { get; }
        }

        /// <summary>Trees whose binaries run as SYSTEM or are loaded by trusted hosts.</summary>
        public static IReadOnlyList<string> ProtectedRoots()
        {
            var roots = new List<string>();
            var system = Environment.SystemDirectory;
            if (!string.IsNullOrEmpty(system))
            {
                roots.Add(system);
                var windows = Path.GetDirectoryName(system);
                if (!string.IsNullOrEmpty(windows)) roots.Add(Path.Combine(windows, "SysWOW64"));
            }
            roots.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            roots.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
            return roots.Where(r => !string.IsNullOrEmpty(r))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList();
        }

        /// <summary>
        /// Walks <paramref name="roots"/> (skipping reparse points) and returns every binary that grants write to a
        /// broad principal. Unreadable folders and files are passed to <paramref name="onError"/> so the caller can log
        /// them; they are never reported as clean.
        /// </summary>
        public static async Task<List<Finding>> ScanAsync(IEnumerable<string> roots, Action<string, Exception>? onError, CancellationToken ct)
        {
            var findings = new List<Finding>();
            var pending = new Stack<string>();
            foreach (var root in roots)
                if (Directory.Exists(root)) pending.Push(root);

            while (pending.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                var dir = pending.Pop();
                try
                {
                    foreach (var sub in Directory.EnumerateDirectories(dir))
                    {
                        if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0) continue;
                        pending.Push(sub);
                    }

                    foreach (var file in Directory.EnumerateFiles(dir))
                    {
                        if (!BinaryExtensions.Contains(Path.GetExtension(file))) continue;
                        try
                        {
                            var security = new FileInfo(file).GetAccessControl();
                            if (!WritableLocationAcl.GrantsBroadWrite(security, out var sid)) continue;
                            findings.Add(new Finding(file, sid ?? string.Empty, OwnerOf(security)));
                        }
                        catch (Exception ex) when (ex is UnauthorizedAccessException || ex is IOException)
                        {
                            onError?.Invoke(file, ex);
                        }
                    }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException || ex is IOException)
                {
                    onError?.Invoke(dir, ex);
                }

                // Yield between folders so the walk never starves the other monitors.
                await Task.Delay(2, ct).ConfigureAwait(false);
            }
            return findings;
        }

        private static string OwnerOf(FileSystemSecurity security)
        {
            try { return (security.GetOwner(typeof(System.Security.Principal.NTAccount)) as System.Security.Principal.NTAccount)?.Value ?? "unknown"; }
            catch (Exception ex) when (ex is System.Security.Principal.IdentityNotMappedException || ex is SystemException) { return "unknown"; }
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[SystemFileAclDriftMonitor] Started");
            try
            {
                await Task.Delay(StartupDelay, ct).ConfigureAwait(false);
                while (!ct.IsCancellationRequested)
                {
                    try { await RunOnceAsync(ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex) { _logger.LogWarning(ex, "[SystemFileAclDriftMonitor] Scan failed"); }
                    await Task.Delay(ScanInterval, ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException ex2) { _logger.LogDebug(ex2, "[SystemFileAclDriftMonitor] ExecuteAsync failed"); }
        }

        /// <summary>The single event raised for a batch of new findings. Tier2 and LogOnly by contract.</summary>
        public static DetectionEvent BuildEvent(IReadOnlyList<Finding> fresh) => BuildEvent(fresh, Array.Empty<SystemFileAclRepairer.RepairResult>());

        public static DetectionEvent BuildEvent(IReadOnlyList<Finding> fresh, IReadOnlyList<SystemFileAclRepairer.RepairResult> repairs)
        {
            int repaired = repairs.Count(r => r.Outcome == SystemFileAclRepairer.RepairOutcome.Repaired);
            int failed = repairs.Count(r => r.Outcome == SystemFileAclRepairer.RepairOutcome.Failed);
            var repairNote = repairs.Count == 0 ? string.Empty : $" Automatic repair: {repaired} fixed, {failed} failed (ACL backups under ProgramData\\Gnyida\\AclBackup).";
            var shown = fresh.Take(MaxFilesInEvidence)
                .Select(f => $"{f.Path} (writable by {f.Sid}, owner {f.Owner})");
            return new DetectionEvent
            {
                RuleName = "System File ACL Drift: Non-Admin Writable Binary",
                Evidence = $"{fresh.Count} binary file(s) under a protected tree grant write access to a standard-user group: " +
                           string.Join("; ", shown) + (fresh.Count > MaxFilesInEvidence ? $"; and {fresh.Count - MaxFilesInEvidence} more" : string.Empty) + repairNote,
                Reasoning = "A standard user can replace these files. Files loaded by SYSTEM, boot-start drivers and security components " +
                            "(amsi.dll, Defender drivers) turn that into privilege escalation or a detection bypass. Typical cause: an image " +
                            "customization tool (WinReducer, NTLite) or a manual takeown/icacls left Users with Full Control. Gnyida removes the write grant " +
                            "itself for files under System32/SysWOW64 (hardening, not a response to this Tier2 event); Program Files is report-only.",
                Confidence = 0.60,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
            };
        }
        internal async Task RunOnceAsync(CancellationToken ct)
        {
            int unreadable = 0;
            var findings = await ScanAsync(ProtectedRoots(), (path, ex) =>
            {
                unreadable++;
                _logger.LogDebug(ex, "[SystemFileAclDriftMonitor] Could not read ACL of {Path}", path);
            }, ct).ConfigureAwait(false);

            _logger.LogInformation("[SystemFileAclDriftMonitor] Scan complete: {Count} writable binaries, {Unreadable} unreadable", findings.Count, unreadable);

            // Repair every finding on every scan, not just new ones: a customization tool can undo a repair, and a
            // file that was repaired is forgotten so that the next regression is reported again.
            var repairs = new List<SystemFileAclRepairer.RepairResult>();
            if (ProductPosture.AllowsProactiveHostLockdown(_config))
            {
                foreach (var f in findings)
                {
                    ct.ThrowIfCancellationRequested();
                    var r = _repairer.Repair(f.Path, ct);
                    if (r.Outcome == SystemFileAclRepairer.RepairOutcome.Repaired || r.Outcome == SystemFileAclRepairer.RepairOutcome.Failed)
                        repairs.Add(r);
                    if (r.Outcome == SystemFileAclRepairer.RepairOutcome.Repaired) _reported.Remove(f.Path);
                }
            }

            var fresh = findings.Where(f => _reported.Add(f.Path)).ToList();
            var repairedNow = repairs.Where(r => r.Outcome == SystemFileAclRepairer.RepairOutcome.Repaired).Select(r => r.Path).ToList();
            if (fresh.Count == 0 && repairedNow.Count == 0) return;
            if (fresh.Count == 0) fresh = findings.Where(f => repairedNow.Contains(f.Path, StringComparer.OrdinalIgnoreCase)).ToList();

            var shown = fresh.Take(MaxFilesInEvidence)
                .Select(f => $"{f.Path} (writable by {f.Sid}, owner {f.Owner})");
            await _detectionEngine.EmitAsync(BuildEvent(fresh, repairs)).ConfigureAwait(false);
        }
    }
}
