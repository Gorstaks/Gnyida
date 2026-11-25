using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Microsoft.Extensions.Logging.Abstractions;
using Gnyida.Core;
using Xunit;

namespace Gnyida.Tests
{
    public class SystemFileAclRepairerTests : IDisposable
    {
        private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
        private readonly string _root = Path.Combine(Path.GetTempPath(), "gnyida_repair_" + Guid.NewGuid().ToString("N"));
        private readonly string _backups;
        private readonly string _scope;

        public SystemFileAclRepairerTests()
        {
            _scope = Path.Combine(_root, "System32");
            _backups = Path.Combine(_root, "backups");
            Directory.CreateDirectory(_scope);
        }

        public void Dispose()
        {
            try { Directory.Delete(_root, true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        private SystemFileAclRepairer Create(string? backupRoot = null) =>
            new(NullLogger<SystemFileAclRepairer>.Instance, backupRoot ?? _backups, new[] { _scope }, enforceBackupDirAcl: false);

        private string Plant(string name, FileSystemRights usersRights, string? dir = null)
        {
            var path = Path.Combine(dir ?? _scope, name);
            File.WriteAllText(path, "x");
            var info = new FileInfo(path);
            var security = info.GetAccessControl();
            security.AddAccessRule(new FileSystemAccessRule(Users, usersRights, AccessControlType.Allow));
            info.SetAccessControl(security);
            return path;
        }

        [Fact]
        public void Repair_RemovesWriteKeepsReadAndWritesBackup()
        {
            var file = Plant("amsi.dll", FileSystemRights.FullControl);
            Assert.True(WritableLocationAcl.GrantsBroadWrite(new FileInfo(file).GetAccessControl(), out _));

            var result = Create().Repair(file, CancellationToken.None);

            Assert.Equal(SystemFileAclRepairer.RepairOutcome.Repaired, result.Outcome);
            var after = new FileInfo(file).GetAccessControl();
            Assert.False(WritableLocationAcl.GrantsBroadWrite(after, out _));
            var usersRule = after.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                .Single(r => r.IdentityReference.Equals(Users));
            Assert.True((usersRule.FileSystemRights & FileSystemRights.ReadAndExecute) == FileSystemRights.ReadAndExecute);
            Assert.True(File.Exists(result.BackupPath));
            Assert.Contains(file.Replace("\\", "\\\\"), File.ReadAllText(result.BackupPath!), StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void Restore_PutsTheOriginalAclBack()
        {
            var file = Plant("restore.dll", FileSystemRights.Modify);
            var repairer = Create();
            var result = repairer.Repair(file, CancellationToken.None);
            Assert.Equal(SystemFileAclRepairer.RepairOutcome.Repaired, result.Outcome);
            Assert.False(WritableLocationAcl.GrantsBroadWrite(new FileInfo(file).GetAccessControl(), out _));

            var restored = repairer.Restore(result.BackupPath!);

            Assert.Equal(SystemFileAclRepairer.RepairOutcome.Repaired, restored.Outcome);
            Assert.True(WritableLocationAcl.GrantsBroadWrite(new FileInfo(file).GetAccessControl(), out _));
        }

        [Fact]
        public void Repair_CleanFile_IsNotNeeded_AndWritesNoBackup()
        {
            var path = Path.Combine(_scope, "clean.dll");
            File.WriteAllText(path, "x");
            var result = Create().Repair(path, CancellationToken.None);
            Assert.Equal(SystemFileAclRepairer.RepairOutcome.NotNeeded, result.Outcome);
            Assert.False(Directory.Exists(_backups));
        }

        // Default deny: nothing outside the narrow scope is ever touched.

        [Fact]
        public void Repair_RefusesFileOutsideTheAllowedRoots()
        {
            var outside = Path.Combine(_root, "ProgramFilesLike");
            Directory.CreateDirectory(outside);
            var file = Plant("app.dll", FileSystemRights.Modify, outside);

            var result = Create().Repair(file, CancellationToken.None);

            Assert.Equal(SystemFileAclRepairer.RepairOutcome.Refused, result.Outcome);
            Assert.True(WritableLocationAcl.GrantsBroadWrite(new FileInfo(file).GetAccessControl(), out _));
        }

        [Theory]
        [InlineData("notes.txt")]
        [InlineData("data.bin")]
        public void Repair_RefusesNonBinaryFiles(string name)
        {
            var file = Plant(name, FileSystemRights.Modify);
            Assert.Equal(SystemFileAclRepairer.RepairOutcome.Refused, Create().Repair(file, CancellationToken.None).Outcome);
            Assert.True(WritableLocationAcl.GrantsBroadWrite(new FileInfo(file).GetAccessControl(), out _));
        }

        [Fact]
        public void Repair_RefusesMissingFileAndSiblingPrefixDirectory()
        {
            Assert.Equal(SystemFileAclRepairer.RepairOutcome.Refused,
                Create().Repair(Path.Combine(_scope, "gone.dll"), CancellationToken.None).Outcome);

            // "System32-evil" shares the "System32" prefix but is not inside the root.
            var sibling = Path.Combine(_root, "System32-evil");
            Directory.CreateDirectory(sibling);
            var file = Plant("x.dll", FileSystemRights.Modify, sibling);
            Assert.Equal(SystemFileAclRepairer.RepairOutcome.Refused, Create().Repair(file, CancellationToken.None).Outcome);
        }

        [Fact]
        public void Repair_RefusesInheritedGrant()
        {
            var sub = Path.Combine(_scope, "inheriting");
            Directory.CreateDirectory(sub);
            var dirInfo = new DirectoryInfo(sub);
            var dirSecurity = dirInfo.GetAccessControl();
            dirSecurity.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.Modify,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            dirInfo.SetAccessControl(dirSecurity);

            var file = Path.Combine(sub, "child.dll");
            File.WriteAllText(file, "x");

            var result = Create().Repair(file, CancellationToken.None);

            Assert.Equal(SystemFileAclRepairer.RepairOutcome.Refused, result.Outcome);
            Assert.Contains("inherited", result.Detail);
        }

        [Fact]
        public void Repair_ChangesNothingWhenTheBackupCannotBeWritten()
        {
            var file = Plant("nobackup.dll", FileSystemRights.Modify);
            var blocker = Path.Combine(_root, "blocker");
            File.WriteAllText(blocker, "not a directory");

            var result = Create(Path.Combine(blocker, "sub")).Repair(file, CancellationToken.None);

            Assert.Equal(SystemFileAclRepairer.RepairOutcome.Failed, result.Outcome);
            Assert.True(WritableLocationAcl.GrantsBroadWrite(new FileInfo(file).GetAccessControl(), out _));
        }

        [Fact]
        public void Restore_RefusesABackupPointingOutsideTheScope()
        {
            Directory.CreateDirectory(_backups);
            var target = Path.Combine(_root, "elsewhere.dll");
            File.WriteAllText(target, "x");
            var backup = Path.Combine(_backups, "forged.json");
            File.WriteAllText(backup, System.Text.Json.JsonSerializer.Serialize(new
            {
                Path = target,
                AccessSddl = "D:(A;;FA;;;WD)",
                CreatedUtc = DateTime.UtcNow,
            }));

            var result = Create().Restore(backup);

            Assert.Equal(SystemFileAclRepairer.RepairOutcome.Refused, result.Outcome);
        }

        [Fact]
        public void Repair_HonorsCancellation()
        {
            var file = Plant("cancel.dll", FileSystemRights.Modify);
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            Assert.Throws<OperationCanceledException>(() => Create().Repair(file, cts.Token));
            Assert.True(WritableLocationAcl.GrantsBroadWrite(new FileInfo(file).GetAccessControl(), out _));
        }

        [Fact]
        public void DefaultRoots_AreOnlySystem32AndSysWow64()
        {
            var roots = SystemFileAclRepairer.DefaultRoots();
            Assert.Equal(2, roots.Count);
            Assert.Contains(roots, r => r.Equals(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase));
            Assert.Contains(roots, r => r.EndsWith("SysWOW64", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(roots, r => r.IndexOf("Program Files", StringComparison.OrdinalIgnoreCase) >= 0);
        }

    }
}
