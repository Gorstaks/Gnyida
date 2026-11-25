using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Gnyida.Core;
using Xunit;

namespace Gnyida.Tests
{
    public class SystemFileAclDriftMonitorTests : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "gnyida_acl_drift_" + Guid.NewGuid().ToString("N"));

        public SystemFileAclDriftMonitorTests() => Directory.CreateDirectory(_root);

        public void Dispose()
        {
            try { Directory.Delete(_root, true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        private string CreateFile(string name, params WellKnownSidType[] extraWriters)
        {
            var path = Path.Combine(_root, name);
            File.WriteAllText(path, "x");
            if (extraWriters.Length > 0)
            {
                var info = new FileInfo(path);
                var security = info.GetAccessControl();
                foreach (var sid in extraWriters)
                    security.AddAccessRule(new FileSystemAccessRule(
                        new SecurityIdentifier(sid, null), FileSystemRights.Modify, AccessControlType.Allow));
                info.SetAccessControl(security);
            }
            return path;
        }

        [Fact]
        public async Task Scan_ReportsBinaryWritableByUsers()
        {
            var bad = CreateFile("planted.dll", WellKnownSidType.BuiltinUsersSid);
            var findings = await SystemFileAclDriftMonitor.ScanAsync(new[] { _root }, null, CancellationToken.None);
            var hit = Assert.Single(findings);
            Assert.Equal(bad, hit.Path, ignoreCase: true);
            Assert.Equal(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null).Value, hit.Sid);
        }

        [Theory]
        [InlineData(WellKnownSidType.AuthenticatedUserSid)]
        [InlineData(WellKnownSidType.WorldSid)]
        [InlineData(WellKnownSidType.InteractiveSid)]
        public async Task Scan_ReportsEveryBroadPrincipal(WellKnownSidType writer)
        {
            CreateFile("x.sys", writer);
            var findings = await SystemFileAclDriftMonitor.ScanAsync(new[] { _root }, null, CancellationToken.None);
            Assert.Single(findings);
        }

        [Fact]
        public async Task Scan_IgnoresServiceSidAndNonBinaryFiles()
        {
            // A per-service SID (the Print Spooler pattern) is by design, not a standard-user group.
            var spooler = new SecurityIdentifier("S-1-5-99-216390572-1995538116-3857911515-2404958512-2623887229");
            var driver = CreateFile("driver.dll");
            var info = new FileInfo(driver);
            var security = info.GetAccessControl();
            security.AddAccessRule(new FileSystemAccessRule(spooler, FileSystemRights.Modify, AccessControlType.Allow));
            info.SetAccessControl(security);

            CreateFile("readme.txt", WellKnownSidType.BuiltinUsersSid);

            var findings = await SystemFileAclDriftMonitor.ScanAsync(new[] { _root }, null, CancellationToken.None);
            Assert.Empty(findings);
        }

        [Fact]
        public async Task Scan_DoesNotReportReadAndExecuteForUsers()
        {
            var path = CreateFile("ok.dll");
            var info = new FileInfo(path);
            var security = info.GetAccessControl();
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute, AccessControlType.Allow));
            info.SetAccessControl(security);

            Assert.Empty(await SystemFileAclDriftMonitor.ScanAsync(new[] { _root }, null, CancellationToken.None));
        }

        [Fact]
        public async Task Scan_WalksSubfolders_AndHonorsCancellation()
        {
            Directory.CreateDirectory(Path.Combine(_root, "sub", "deeper"));
            var nested = Path.Combine(_root, "sub", "deeper", "n.exe");
            File.WriteAllText(nested, "x");
            var info = new FileInfo(nested);
            var security = info.GetAccessControl();
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.Modify, AccessControlType.Allow));
            info.SetAccessControl(security);

            Assert.Single(await SystemFileAclDriftMonitor.ScanAsync(new[] { _root }, null, CancellationToken.None));

            using var cts = new CancellationTokenSource();
            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => SystemFileAclDriftMonitor.ScanAsync(new[] { _root }, null, cts.Token));
        }

        [Fact]
        public void Event_IsTier2Indicator_AndLogOnly()
        {
            var findings = new List<SystemFileAclDriftMonitor.Finding>
            {
                new(@"C:\Windows\System32\amsi.dll", "S-1-5-32-545", @"BUILTIN\Administrators"),
            };
            var evt = SystemFileAclDriftMonitor.BuildEvent(findings);
            Assert.Equal(DetectionTier.Tier2Indicator, evt.Tier);
            Assert.Equal(ResponseAction.LogOnly, evt.AuthorizedResponse);
            Assert.False(evt.KillAuthorized);
            Assert.Contains("amsi.dll", evt.Evidence);
        }

        [Fact]
        public void Event_CapsEvidenceAtTwentyFiles()
        {
            var findings = Enumerable.Range(0, 45)
                .Select(i => new SystemFileAclDriftMonitor.Finding($@"C:\Windows\System32\f{i}.dll", "S-1-5-32-545", "x"))
                .ToList();
            var evt = SystemFileAclDriftMonitor.BuildEvent(findings);
            Assert.Contains("45 binary file(s)", evt.Evidence);
            Assert.Contains("and 25 more", evt.Evidence);
            Assert.DoesNotContain("f44.dll", evt.Evidence);
        }

        [Fact]
        public void ProtectedRoots_CoverSystemTreesAndProgramFiles()
        {
            var roots = SystemFileAclDriftMonitor.ProtectedRoots();
            Assert.Contains(Environment.SystemDirectory, roots, StringComparer.OrdinalIgnoreCase);
            Assert.Contains(roots, r => r.EndsWith("SysWOW64", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), roots, StringComparer.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task Event_WithActiveResponseArmed_StaysLogOnly_AndWritesNoPreActionAudit()
        {
            var config = new GnyidaConfig { ActiveResponse = true };
            var logger = new JsonlEventLogger(Path.Combine(_root, "events.jsonl"));
            var engine = new AdvancedResponseEngine(config, new GnyidaMetrics(), logger, new QuarantineManager(_root));

            var evt = SystemFileAclDriftMonitor.BuildEvent(new List<SystemFileAclDriftMonitor.Finding>
            {
                new(@"C:\Windows\System32\drivers\WdFilter.sys", "S-1-5-32-545", @"BUILTIN\Administrators"),
            });
            // Even a mislabelled authorized action must not run for a Tier2 indicator.
            evt.AuthorizedResponse = ResponseAction.KillProcess;

            await engine.HandleAsync(evt);
            await logger.DisposeAsync();

            var audit = string.Join("", Directory.GetFiles(_root, "audit-*.jsonl").Select(f =>
            {
                using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(fs);
                return reader.ReadToEnd();
            }));
            Assert.DoesNotContain("PRE_ACTION", audit);
        }    }
}
