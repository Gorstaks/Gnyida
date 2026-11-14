using System.IO.Compression;
using System.Security.Cryptography;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>Tests for the 3.7.4 additions: Avast parity monitors, redirect checks and stdin-staged PowerShell.</summary>
    public class AvastParityTests
    {
        // Look-alike domains

        [Theory]
        [InlineData("paypa1.com", "paypal")]
        [InlineData("micr0soft.com", "microsoft")]
        [InlineData("rnicrosoft.com", "microsoft")]
        [InlineData("\u0440aypal.com", "paypal")]          // Cyrillic er
        [InlineData("xn--aypal-uye.com", "paypal")]         // punycode of the Cyrillic form
        [InlineData("microsofft.com", "microsoft")]         // one-character typo
        [InlineData("paypal.com.account-check.net", "paypal")]
        [InlineData("login.paypal.com.evil.co.uk", "paypal")]
        public void LookalikeIsReported(string domain, string brand)
        {
            var v = LookalikeDomainDetector.Evaluate(domain);
            Assert.True(v.HasValue, domain);
            Assert.Equal(brand, v!.Value.Brand);
        }

        [Theory]
        [InlineData("paypal.com")]
        [InlineData("www.paypal.com")]
        [InlineData("login.microsoftonline.com")]
        [InlineData("github.io")]
        [InlineData("paypal.net")]          // same label on another TLD is not imitation
        [InlineData("example.com")]
        [InlineData("apples.com")]          // short brand: typo rule needs 7+ letters
        [InlineData("localhost")]
        [InlineData("")]
        public void GenuineOrUnrelatedDomainIsNotReported(string domain)
        {
            Assert.False(LookalikeDomainDetector.Evaluate(domain).HasValue, domain);
        }

        // Browser redirect guard

        [Fact]
        public void RedirectDiffReportsAddChangeAndRemove()
        {
            var before = new Dictionary<string, string> { ["home"] = "https://a", ["search"] = "https://s", ["gone"] = "x" };
            var after = new Dictionary<string, string> { ["home"] = "https://evil", ["search"] = "https://s", ["new"] = "y" };
            var changes = BrowserRedirectGuard.Diff(before, after);
            Assert.Equal(3, changes.Count);
            Assert.Contains(changes, c => c.StartsWith("home changed"));
            Assert.Contains(changes, c => c.StartsWith("new added"));
            Assert.Contains(changes, c => c.StartsWith("gone removed"));
        }

        [Fact]
        public void RedirectDiffIsEmptyWhenNothingChanged()
        {
            var same = new Dictionary<string, string> { ["home"] = "https://a" };
            Assert.Empty(BrowserRedirectGuard.Diff(same, new Dictionary<string, string>(same)));
        }

        // Capture device use

        [Fact]
        public void CaptureDeviceInUseFollowsConsentStoreTimes()
        {
            Assert.True(CaptureDeviceUseMonitor.IsInUse(100L, 0L));
            Assert.True(CaptureDeviceUseMonitor.IsInUse(200L, 100L));
            Assert.False(CaptureDeviceUseMonitor.IsInUse(100L, 200L));
            Assert.False(CaptureDeviceUseMonitor.IsInUse(0L, 0L));
            Assert.False(CaptureDeviceUseMonitor.IsInUse(null, null));
        }

        [Fact]
        public void CaptureDeviceTrustNeedsAdminOnlyRoot()
        {
            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            Assert.True(CaptureDeviceUseMonitor.IsTrustedInstallRoot(Path.Combine(pf, "Zoom", "zoom.exe")));
            Assert.True(CaptureDeviceUseMonitor.IsTrustedInstallRoot(Path.Combine(win, "System32", "app.exe")));
            Assert.False(CaptureDeviceUseMonitor.IsTrustedInstallRoot(Path.Combine(win, "Temp", "spy.exe")));
            Assert.False(CaptureDeviceUseMonitor.IsTrustedInstallRoot(Path.Combine(profile, "AppData", "Roaming", "Program Files", "spy.exe")));
            Assert.False(CaptureDeviceUseMonitor.IsTrustedInstallRoot(pf + "Evil\\spy.exe")); // prefix without separator
            Assert.False(CaptureDeviceUseMonitor.IsTrustedInstallRoot(""));
        }

        [Fact]
        public void ConsentStoreKeyNameDecodesToPath()
        {
            Assert.Equal(@"C:\Users\a\x.exe", CaptureDeviceUseMonitor.DecodeAppPath("C:#Users#a#x.exe"));
        }

        // LAN inventory

        [Fact]
        public void ArpParserKeepsDynamicUnicastOnly()
        {
            const string output = "\r\nInterface: 192.168.1.10 --- 0x5\r\n" +
                "  Internet Address      Physical Address      Type\r\n" +
                "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic   \r\n" +
                "  192.168.1.20          11-22-33-44-55-66     dynamic   \r\n" +
                "  192.168.1.255         ff-ff-ff-ff-ff-ff     static    \r\n" +
                "  224.0.0.22            01-00-5e-00-00-16     static    \r\n" +
                "  192.168.1.30          01-00-5e-00-00-01     dynamic   \r\n";
            var devices = LanDeviceInventoryMonitor.ParseArp(output);
            Assert.Equal(2, devices.Count);
            Assert.Equal("192.168.1.1", devices[0].Ip);
            Assert.Equal("aa-bb-cc-dd-ee-ff", devices[0].Mac);
        }

        // Scheduled scan

        [Fact]
        public void ScheduledScanDueRules()
        {
            var now = new DateTime(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);
            Assert.True(ScheduledScanService.IsDue(null, now));
            Assert.True(ScheduledScanService.IsDue(now.AddHours(-25), now));
            Assert.False(ScheduledScanService.IsDue(now.AddHours(-1), now));
            Assert.True(ScheduledScanService.IsDue(now.AddDays(3), now)); // clock moved back: do not wait days
        }

        // Stdin-staged PowerShell

        private const string FirewallBridgeShape =
            "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoLogo -NoProfile -NonInteractive -Command \"$ErrorActionPreference='Stop'; . ([ScriptBlock]::Create([Console]::In.ReadToEnd().TrimStart([char]0xFEFF))); Invoke-X\"";

        [Theory]
        [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", FirewallBridgeShape)]
        [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell -c \"$input | iex\"")]
        [InlineData(@"C:\Program Files\PowerShell\7\pwsh.exe", "pwsh -NoProfile -Command -")]
        [InlineData("", "powershell.exe -nop -File -")]
        [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell -c \"iex ([Console]::In.ReadToEnd())\"")]
        public void StdinStagedPowerShellIsReported(string image, string cmd)
        {
            Assert.NotNull(StdinStagedPowerShellRule.Match(image, cmd));
        }

        [Theory]
        [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell -NoProfile -Command Get-Date")]
        [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell -File C:\\scripts\\a.ps1")]
        [InlineData(@"C:\Windows\System32\cmd.exe", "cmd /c type x | powershell -c \"$input | iex\"")] // cmd.exe itself is not the PowerShell host
        [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "")]
        public void OrdinaryPowerShellIsNotReported(string image, string cmd)
        {
            Assert.Null(StdinStagedPowerShellRule.Match(image, cmd));
        }

        [Fact]
        public void StdinStagedRuleIsTier2LogOnly()
        {
            var ctx = new FusedTelemetryContext
            {
                TriggeringEvent = new ProcessTelemetry
                {
                    ProcessId = 4321, ProcessName = "powershell",
                    ImagePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    CommandLine = FirewallBridgeShape, ParentProcessId = 100, ParentProcessName = "Sentinel.Service",
                },
            };
            var d = new StdinStagedPowerShellRule().Evaluate(ctx);
            Assert.NotNull(d);
            Assert.Equal(DetectionTier.Tier2Indicator, d!.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
            Assert.True(ManagementChildRegistry.IsRoutineObservation(d));
        }

        // PowerShell host pipe noise filter

        [Fact]
        public void PowerShellHostPipeNeedsMatchingOwnerAndProtectedImage()
        {
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var ps = Path.Combine(win, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
            const string pipe = "PSHost.134391502522560514.10612.DefaultAppDomain.powershell";
            Assert.True(NamedPipeMonitor.IsGenuinePowerShellHostPipe(pipe, 10612, ps));
            Assert.False(NamedPipeMonitor.IsGenuinePowerShellHostPipe(pipe, 999, ps));                         // PID mismatch
            Assert.False(NamedPipeMonitor.IsGenuinePowerShellHostPipe(pipe, 10612, @"C:\Users\a\powershell.exe")); // copied binary
            Assert.False(NamedPipeMonitor.IsGenuinePowerShellHostPipe(pipe, 10612, null));                     // unknown image
            Assert.False(NamedPipeMonitor.IsGenuinePowerShellHostPipe(pipe, 0, ps));
            Assert.False(NamedPipeMonitor.IsGenuinePowerShellHostPipe("PSHost.1.10612.evil", 10612, ps));
        }

        // Executables inside archives

        [Fact]
        public void ArchiveInspectorHashesInnerExecutablesIncludingNested()
        {
            var dir = Path.Combine(Path.GetTempPath(), "sentinel-archive-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var pe = new byte[600];
                pe[0] = 0x4D; pe[1] = 0x5A;
                for (int i = 2; i < pe.Length; i++) pe[i] = (byte)(i * 7);
                string expected;
                using (var sha = SHA256.Create()) expected = BitConverter.ToString(sha.ComputeHash(pe)).Replace("-", string.Empty);

                byte[] inner;
                using (var ms = new MemoryStream())
                {
                    using (var z = new ZipArchive(ms, ZipArchiveMode.Create, true))
                        using (var s = z.CreateEntry("deep/tool.bin").Open()) s.Write(pe, 0, pe.Length);
                    inner = ms.ToArray();
                }
                var path = Path.Combine(dir, "outer.zip");
                using (var fs = File.Create(path))
                using (var z = new ZipArchive(fs, ZipArchiveMode.Create))
                {
                    using (var s = z.CreateEntry("app.exe").Open()) s.Write(pe, 0, pe.Length);
                    using (var s = z.CreateEntry("readme.txt").Open()) s.Write(new byte[] { 65, 66, 67 }, 0, 3);
                    using (var s = z.CreateEntry("nested.zip").Open()) s.Write(inner, 0, inner.Length);
                }

                var result = ArchiveContentInspector.Inspect(path);
                Assert.True(result.ContainsExecutable);
                Assert.Equal(2, result.ExecutableEntries.Count);
                Assert.All(result.ExecutableEntries, e => Assert.Equal(expected, e.Sha256));
                Assert.Contains(result.ExecutableEntries, e => e.Name == "app.exe" && e.Depth == 0);
                Assert.Contains(result.ExecutableEntries, e => e.Name == "deep/tool.bin" && e.Depth == 1);
                Assert.False(result.ExecutableHashingIncomplete);
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch (IOException) { }
            }
        }
    }
}
