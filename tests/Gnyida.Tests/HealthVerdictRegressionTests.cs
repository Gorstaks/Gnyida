using System;
using System.Linq;
using Microsoft.Extensions.Logging.Abstractions;
using Gnyida.Core;
using Gnyida.Core.Monitors;
using Xunit;

namespace Gnyida.Tests
{
    /// <summary>
    /// Regression tests for the health verdict: a monitor that is off by policy must be reported
    /// as Completed (not Unavailable), sensors that expose no progress contract must not hold the
    /// dashboard at "limited", and the firewall registry watcher must attach to an existing key.
    /// </summary>
    public class HealthVerdictRegressionTests
    {
        [Fact]
        public void AggressiveSweep_IsStartupTask_SoPolicyOffIsCompletedNotUnavailable()
        {
            Assert.True(typeof(IMonitorStartupTask).IsAssignableFrom(typeof(AggressiveUnsignedDllSweepMonitor)));
        }

        [Fact]
        public void SensorWithoutProgressContract_IsNotCountedUnverified()
        {
            using var reg = new MonitorRegistry(null!, null!, NullLogger<MonitorRegistry>.Instance);
            reg.Register("NoProgressSensor", MonitorCategory.ThreatIntel, null);
            reg.MarkStarted("NoProgressSensor");
            reg.Heartbeat("NoProgressSensor");

            var stats = reg.GetStats();
            Assert.Equal(1, stats.Running);
            Assert.Equal(0, stats.CollectionUnverified);
            Assert.Equal(0, stats.Unhealthy);
        }

        [Fact]
        public void CompletedByPolicyMonitor_IsNotUnhealthy()
        {
            using var reg = new MonitorRegistry(null!, null!, NullLogger<MonitorRegistry>.Instance);
            reg.Register("OffByPolicy", MonitorCategory.ThreatIntel, null);
            reg.MarkStarted("OffByPolicy");
            reg.MarkCompleted("OffByPolicy", "off by policy");

            Assert.Equal(1, reg.GetStats().Completed);
            Assert.DoesNotContain(reg.GetUnhealthyMonitors(), m => m.Name == "OffByPolicy");
        }

        [Fact]
        public void MonitorWaitingForItsGroup_IsNotUnhealthyDuringStartupGrace()
        {
            using var reg = new MonitorRegistry(null!, null!, NullLogger<MonitorRegistry>.Instance);
            reg.Register("PeripheralX", MonitorCategory.UserProtection, null);
            reg.GetAllStatuses()[0].RegisteredAt = DateTimeOffset.UtcNow - TimeSpan.FromSeconds(45);
            Assert.Empty(reg.GetUnhealthyMonitors());

            reg.GetAllStatuses()[0].RegisteredAt = DateTimeOffset.UtcNow - MonitorRegistry.StartupGrace - TimeSpan.FromSeconds(1);
            Assert.Single(reg.GetUnhealthyMonitors());
        }

        [Fact]
        public void FirstReportGrace_CountsFromStart_AndHonoursDeclaredCadence()
        {
            var now = DateTimeOffset.UtcNow;
            var status = new MonitorStatus
            {
                RegisteredAt = now - TimeSpan.FromMinutes(10),
                StartedAt = now - TimeSpan.FromSeconds(45),
                Progress = new SensorProgressSnapshot { State = "Unknown", MaximumSilenceSeconds = 300 }
            };
            Assert.False(MonitorRegistry.FirstReportOverdue(status, now));   // registered long ago, started 45 s ago

            status.StartedAt = now - TimeSpan.FromSeconds(200);
            Assert.False(MonitorRegistry.FirstReportOverdue(status, now));   // within its own 300 s cadence

            status.StartedAt = now - TimeSpan.FromSeconds(301);
            Assert.True(MonitorRegistry.FirstReportOverdue(status, now));    // never reported: needs attention

            status.Progress.MaximumSilenceSeconds = 0;
            status.StartedAt = now - TimeSpan.FromSeconds(61);
            Assert.True(MonitorRegistry.FirstReportOverdue(status, now));    // 60 s floor
        }

        [Fact]
        public void WmiIntRead_MissingPropertyIsMinusOne_NotAnException()
        {
            using var searcher = new System.Management.ManagementObjectSearcher(@"root\cimv2", "SELECT * FROM Win32_OperatingSystem");
            foreach (System.Management.ManagementObject os in searcher.Get())
            {
                using (os)
                {
                    Assert.Equal(-1, NetworkInterfaceGuard.ReadInt(os, "PropertyThatDoesNotExist"));
                    Assert.True(NetworkInterfaceGuard.ReadInt(os, "OSType") >= 0);
                }
                return;
            }
        }

        private const string DefenderEngine = @"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MsMpEng.exe";

        [Fact]
        public void TokenTheft_ServiceExemption_RequiresAllThreeAnchors()
        {
            Func<string, bool> yes = _ => true, no = _ => false;

            // Running SCM service + Microsoft-signed + protected location: exempt (Defender).
            Assert.True(TokenTheftMonitor.IsVerifiedServiceProcess(true, DefenderEngine, yes, yes));

            // Any single anchor missing keeps the Tier1 kill path.
            Assert.False(TokenTheftMonitor.IsVerifiedServiceProcess(false, DefenderEngine, yes, yes)); // not a service
            Assert.False(TokenTheftMonitor.IsVerifiedServiceProcess(true, DefenderEngine, no, yes));   // not MS-signed
            Assert.False(TokenTheftMonitor.IsVerifiedServiceProcess(true, DefenderEngine, yes, no));   // user-writable
            Assert.False(TokenTheftMonitor.IsVerifiedServiceProcess(true, "", yes, yes));
        }

        [Theory]
        [InlineData(@"C:\Users\x\Downloads\MsMpEng.exe")]
        [InlineData(@"C:\Users\x\AppData\Local\Temp\svc.exe")]
        [InlineData(@"C:\Users\Public\MsMpEng.exe")]
        public void TokenTheft_ServiceExemption_NeverCoversDropPaths(string path)
        {
            // Even a registered, "signed", "protected" service in a drop path is not exempted.
            Assert.False(TokenTheftMonitor.IsVerifiedServiceProcess(true, path, _ => true, _ => true));
        }

        [Fact]
        public void TokenTheft_DefenderPlatformPath_IsNotNameOrPathTrustedOnItsOwn()
        {
            // The folder alone is not a trusted system image path; the service anchor is required.
            Assert.False(TokenTheftMonitor.IsTrustedSystemImagePath(DefenderEngine));
        }

        [Theory]
        [InlineData(@"C:\Users\x\AppData\Local\Microsoft\OneDrive\26.213.1101.0007\FileSyncShell64.dll", true)]
        [InlineData(@"C:\Users\x\AppData\Local\Microsoft\OneDrive\26.213.1101.0007\FileCoAuthLib64.dll", true)]
        [InlineData(@"C:\Users\x\AppData\Local\Microsoft\OneDriveEvil\x.dll", false)]
        [InlineData(@"C:\Users\x\AppData\Local\Temp\Microsoft\OneDrive\x.dll", false)]
        [InlineData(@"C:\Users\x\AppData\Roaming\Microsoft\OneDrive\x.dll", false)]
        public void OneDrivePerUserTree_IsScopedToTheInstallTree(string path, bool expected)
        {
            Assert.Equal(expected, ModuleIdentity.IsPerUserOneDriveTree(path));
        }

        [Fact]
        public void OneDrivePerUserTree_FolderAloneNeverAuthorizesAModule()
        {
            // A plant in the OneDrive tree without a Microsoft signer is still denied: the folder
            // is user-writable, so only the signature can authorize.
            var plant = @"C:\Users\x\AppData\Local\Microsoft\OneDrive\26.213.1101.0007\FileSyncShell64.dll";
            Assert.False(ModuleIdentity.Evaluate(@"C:\Windows\explorer.exe", plant, _ => false).Allowed);
            Assert.False(ModuleIdentity.Evaluate(@"C:\Windows\explorer.exe", plant, null).Allowed);
        }

        [Fact]
        public void OneDrivePerUserTree_HijackNamesStayDenied_EvenWhenSigned()
        {
            var hijack = @"C:\Users\x\AppData\Local\Microsoft\OneDrive\26.213.1101.0007\version.dll";
            Assert.True(DllUnloadEngine.IsSideloadTargetFileName(hijack));
            Assert.False(ModuleIdentity.Evaluate(@"C:\Windows\explorer.exe", hijack, _ => true).Allowed);
        }

        [Theory]
        [InlineData("C:", @"C:\Users")]
        [InlineData(@"C:\", @"C:\Users")]
        [InlineData("D:", @"D:\Users")]
        [InlineData(null, @"C:\Users")]
        public void FileActivity_UsersRoot_IsAbsoluteNotDriveRelative(string? systemDrive, string expected)
        {
            var root = FileActivityMonitor.UsersRoot(systemDrive);
            Assert.Equal(expected, root);
            Assert.True(System.IO.Path.IsPathRooted(root) && root[2] == '\\');
        }

        [Theory]
        [InlineData(80, 6)] [InlineData(443, 6)] [InlineData(8080, 6)] [InlineData(8443, 6)]
        [InlineData(515, 6)] [InlineData(631, 6)] [InlineData(9100, 6)] [InlineData(554, 6)]
        [InlineData(10243, 6)] [InlineData(1723, 6)] [InlineData(2179, 6)] [InlineData(3702, 17)]
        [InlineData(5357, 6)] [InlineData(5358, 6)] [InlineData(5050, 17)] [InlineData(7680, 6)]
        [InlineData(5800, 6)] [InlineData(5901, 6)] [InlineData(5938, 6)] [InlineData(7070, 6)]
        [InlineData(6516, 6)] [InlineData(47001, 6)]
        // Previously-covered file-transfer and remote-admin ports must stay blocked.
        [InlineData(21, 6)] [InlineData(22, 6)] [InlineData(69, 17)] [InlineData(139, 6)] [InlineData(445, 6)]
        [InlineData(3389, 6)] [InlineData(5985, 6)] [InlineData(5986, 6)] [InlineData(5900, 6)]
        public void CommonlyExposedServicePorts_AreBlockedInbound(int port, int protocol)
        {
            Assert.Contains(HardeningModule.PortBlockSpecifications(),
                s => s.Port == port && s.LastPort == port && s.Protocol == protocol && s.Direction == 1);
        }

        [Fact]
        public void NewExposureBlocks_AreInboundOnly_SoOutboundUseIsUntouched()
        {
            var outbound = HardeningModule.PortBlockSpecifications().Where(s => s.Direction == 2).Select(s => s.Port).Distinct();
            Assert.All(outbound, p => Assert.Contains(p, new[] { 137, 138, 139, 445 }));
        }

        [Fact]
        public void RpcDynamicRange_IsACompiledBlockFromEveryRemoteAddress()
        {
            var rpc = Assert.Single(HardeningModule.PortBlockSpecifications(), s => s.LastPort > s.Port);
            Assert.Equal("49664-49699", rpc.PortText);
            Assert.Equal("Gnyida-PortBlock-6-1-49664-49699", rpc.Name);
            Assert.Equal(1, rpc.Direction);
            Assert.True(rpc.Port <= 49664 && rpc.LastPort >= 49671); // covers lsass..services on this host

            // Matches requires the exact range and "*" remote addresses (the legacy rule was LocalSubnet).
            Assert.True(WindowsPortBlockPolicy.Matches(rpc, true, 0, 6, 1, 7, "49664-49699", "*", null, null, "*", "*", "All"));
            Assert.False(WindowsPortBlockPolicy.Matches(rpc, true, 0, 6, 1, 7, "49664-49699", "*", null, null, "*", "LocalSubnet", "All"));
            Assert.False(WindowsPortBlockPolicy.Matches(rpc, true, 0, 6, 1, 7, "49664", "*", null, null, "*", "*", "All"));
        }

        [Fact]
        public void PortBlockSpecs_HaveUniqueNames_AndRejectInvalidRanges()
        {
            var names = HardeningModule.PortBlockSpecifications().Select(s => s.Name).ToList();
            Assert.Equal(names.Count, names.Distinct(StringComparer.OrdinalIgnoreCase).Count());
            Assert.Throws<ArgumentOutOfRangeException>(() => new PortBlockSpec(500, 400, 6, 1));
            Assert.Throws<ArgumentOutOfRangeException>(() => new PortBlockSpec(0, 6, 1));
            Assert.Equal("445", new PortBlockSpec(445, 6, 1).PortText);
        }

        [Fact]
        public void FirewallPolicyWatcher_FallsBackToNearestExistingAncestor()
        {
            string missing = @"SOFTWARE\Microsoft\Windows\GnyidaMissing_" + Guid.NewGuid().ToString("N") + @"\Child";
            Assert.Equal(@"SOFTWARE\Microsoft\Windows", LocalFirewallPolicyService.NearestExistingKey(missing));
            Assert.Equal(@"SOFTWARE\Microsoft\Windows", LocalFirewallPolicyService.NearestExistingKey(@"SOFTWARE\Microsoft\Windows"));
        }
    }
}
