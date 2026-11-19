using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Hardening step that removes standard-user write access from OS binaries that image-customization tools
    /// (WinReducer, NTLite) or manual takeown/icacls left writable. It is invoked by
    /// <see cref="SystemFileAclDriftMonitor"/> for files that monitor found, as host hardening in the same
    /// family as <see cref="HardeningModule"/>. It is not a response action and is never driven by a Tier2
    /// detection: the Tier2 finding is a separate, LogOnly event.
    /// <para>Scope is deliberately narrow (default deny):</para>
    /// <list type="bullet">
    /// <item>Only existing loadable binaries under System32 or SysWOW64. Program Files is report-only, because
    /// legitimate apps grant Users write on their own folders.</item>
    /// <item>No file, or ancestor up to the root, may be a reparse point.</item>
    /// <item>Only explicit ACEs that grant a write-like right to a broad principal are touched. If such an ACE is
    /// inherited, the file is refused: the parent folder must be fixed, not the file.</item>
    /// <item>The original DACL is saved first (SYSTEM/Administrators-only folder under ProgramData). If the backup
    /// cannot be written nothing is changed. After the change the DACL is re-read; if a broad write grant remains,
    /// the backup is restored.</item>
    /// </list>
    /// Read and execute rights of the removed ACE are kept for the same principal. The owner is not changed.
    /// </summary>
    public sealed class SystemFileAclRepairer
    {
        public enum RepairOutcome { Repaired, NotNeeded, Refused, Failed }

        public readonly struct RepairResult
        {
            public RepairResult(string path, RepairOutcome outcome, string detail, string? backupPath = null)
            {
                Path = path; Outcome = outcome; Detail = detail; BackupPath = backupPath;
            }
            public string Path { get; }
            public RepairOutcome Outcome { get; }
            public string Detail { get; }
            public string? BackupPath { get; }
        }

        private sealed class AclBackup
        {
            public string Path { get; set; } = string.Empty;
            public string AccessSddl { get; set; } = string.Empty;
            public DateTime CreatedUtc { get; set; }
        }

        private static readonly HashSet<string> BinaryExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".ax", ".drv", ".winmd", ".node",
        };

        private readonly ILogger<SystemFileAclRepairer> _logger;
        private readonly string _backupRoot;
        private readonly IReadOnlyList<string> _allowedRoots;
        private readonly bool _enforceBackupDirAcl;

        public SystemFileAclRepairer(ILogger<SystemFileAclRepairer> logger)
            : this(logger, Path.Combine(ProgramDataGuard.SentinelRoot, "AclBackup"), DefaultRoots(), true)
        {
        }

        internal SystemFileAclRepairer(ILogger<SystemFileAclRepairer> logger, string backupRoot,
            IReadOnlyList<string> allowedRoots, bool enforceBackupDirAcl)
        {
            _logger = logger;
            _backupRoot = backupRoot;
            _allowedRoots = allowedRoots;
            _enforceBackupDirAcl = enforceBackupDirAcl;
        }

        public string BackupRoot => _backupRoot;

        /// <summary>System32 and SysWOW64 only.</summary>
        public static IReadOnlyList<string> DefaultRoots()
        {
            var roots = new List<string>();
            var system = Environment.SystemDirectory;
            if (!string.IsNullOrEmpty(system))
            {
                roots.Add(system);
                var windows = Path.GetDirectoryName(system);
                if (!string.IsNullOrEmpty(windows)) roots.Add(Path.Combine(windows, "SysWOW64"));
            }
            return roots;
        }

        /// <summary>True when <paramref name="path"/> is inside the repair scope. The reason is set when it is not.</summary>
        public bool IsRepairable(string? path, out string reason)
        {
            reason = string.Empty;
            if (string.IsNullOrWhiteSpace(path)) { reason = "empty path"; return false; }
            string full;
            try { full = Path.GetFullPath(path!); }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException)
            { reason = "invalid path"; return false; }

            if (!BinaryExtensions.Contains(Path.GetExtension(full))) { reason = "not a loadable binary"; return false; }

            var root = _allowedRoots.FirstOrDefault(r =>
                full.StartsWith(r.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase));
            if (root == null) { reason = "outside System32/SysWOW64 (report-only)"; return false; }

            if (!File.Exists(full)) { reason = "file does not exist"; return false; }

            // No reparse point on the file or on any directory between it and the root.
            var current = full;
            var rootTrimmed = root.TrimEnd('\\');
            while (current.Length > rootTrimmed.Length)
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                { reason = "reparse point in path"; return false; }
                current = Path.GetDirectoryName(current) ?? string.Empty;
                if (current.Length == 0) break;
            }
            if (Directory.Exists(rootTrimmed) && (File.GetAttributes(rootTrimmed) & FileAttributes.ReparsePoint) != 0)
            { reason = "reparse point at root"; return false; }
            return true;
        }

        public RepairResult Repair(string path, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (!IsRepairable(path, out var scopeReason))
                return new RepairResult(path, RepairOutcome.Refused, scopeReason);

            var full = Path.GetFullPath(path);
            string? backupPath = null;
            try
            {
                var info = new FileInfo(full);
                var security = info.GetAccessControl();

                var offending = security.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier))
                    .Cast<FileSystemAccessRule>()
                    .Where(r => r.AccessControlType == AccessControlType.Allow
                                && (r.PropagationFlags & PropagationFlags.InheritOnly) == 0
                                && (r.FileSystemRights & InstallDirectoryPolicy.WriteLike) != 0
                                && WritableLocationAcl.IsBroadPrincipal((System.Security.Principal.SecurityIdentifier)r.IdentityReference))
                    .ToList();

                if (offending.Count == 0)
                    return new RepairResult(full, RepairOutcome.NotNeeded, "no broad write grant");
                if (offending.Any(r => r.IsInherited))
                    return new RepairResult(full, RepairOutcome.Refused, "write grant is inherited from the parent folder");

                backupPath = WriteBackup(full, security);

                foreach (var rule in offending)
                {
                    security.RemoveAccessRuleSpecific(rule);
                    var keep = rule.FileSystemRights & FileSystemRights.ReadAndExecute;
                    if (keep != 0)
                        security.AddAccessRule(new FileSystemAccessRule(
                            rule.IdentityReference, keep, rule.InheritanceFlags, rule.PropagationFlags, AccessControlType.Allow));
                }
                info.SetAccessControl(security);

                if (WritableLocationAcl.GrantsBroadWrite(new FileInfo(full).GetAccessControl(), out var remaining))
                {
                    RestoreFromBackup(backupPath);
                    return new RepairResult(full, RepairOutcome.Failed,
                        "broad write grant remained for " + remaining + "; original ACL restored", backupPath);
                }

                _logger.LogWarning("[SystemFileAclRepairer] Removed standard-user write access from {Path} (backup {Backup})", full, backupPath);
                return new RepairResult(full, RepairOutcome.Repaired, "removed " + offending.Count + " write grant(s)", backupPath);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[SystemFileAclRepairer] Could not repair {Path}", full);
                return new RepairResult(full, RepairOutcome.Failed, ex.GetType().Name + ": " + ex.Message, backupPath);
            }
        }

        /// <summary>Puts back the DACL saved in <paramref name="backupFile"/>. Same scope rules as <see cref="Repair"/>.</summary>
        public RepairResult Restore(string backupFile)
        {
            try
            {
                var backup = JsonSerializer.Deserialize<AclBackup>(File.ReadAllText(backupFile));
                if (backup == null || string.IsNullOrEmpty(backup.Path) || string.IsNullOrEmpty(backup.AccessSddl))
                    return new RepairResult(backupFile, RepairOutcome.Refused, "backup file is empty or malformed");
                if (!IsRepairable(backup.Path, out var scopeReason))
                    return new RepairResult(backup.Path, RepairOutcome.Refused, scopeReason);

                RestoreFromBackup(backupFile);
                return new RepairResult(backup.Path, RepairOutcome.Repaired, "original ACL restored", backupFile);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[SystemFileAclRepairer] Could not restore {Backup}", backupFile);
                return new RepairResult(backupFile, RepairOutcome.Failed, ex.GetType().Name + ": " + ex.Message);
            }
        }

        private string WriteBackup(string full, FileSystemSecurity security)
        {
            if (_enforceBackupDirAcl) ProgramDataGuard.EnsureProtectedDirectory(_backupRoot, false);
            else Directory.CreateDirectory(_backupRoot);

            string hash;
            using (var sha = SHA256.Create())
                hash = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(full.ToLowerInvariant()))).Replace("-", "").Substring(0, 8);
            var name = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff") + "-" + Path.GetFileName(full) + "-" + hash + ".json";
            var file = Path.Combine(_backupRoot, name);

            var json = JsonSerializer.Serialize(new AclBackup
            {
                Path = full,
                AccessSddl = security.GetSecurityDescriptorSddlForm(AccessControlSections.Access),
                CreatedUtc = DateTime.UtcNow,
            }, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(file, json, new UTF8Encoding(false));
            return file;
        }

        private static void RestoreFromBackup(string backupFile)
        {
            var backup = JsonSerializer.Deserialize<AclBackup>(File.ReadAllText(backupFile))
                         ?? throw new InvalidDataException("Empty ACL backup: " + backupFile);
            var info = new FileInfo(backup.Path);
            var security = info.GetAccessControl();
            security.SetSecurityDescriptorSddlForm(backup.AccessSddl, AccessControlSections.Access);
            info.SetAccessControl(security);
        }
    }
}
