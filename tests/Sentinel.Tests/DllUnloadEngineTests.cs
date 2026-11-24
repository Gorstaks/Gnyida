using System.Collections.Generic;
using System.Linq;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for DllUnloadEngine's sideload detection and OS servicing exclusion logic.
    /// Covers: all sideload targets, boundary values, DISM/NTLite exclusions,
    /// path normalization, and protected process names.
    /// </summary>
    public class DllUnloadEngineTests
    {
        // 
        // IsSideloadTargetFileName - positive cases (all known targets)
        // 

        [Theory]
        [InlineData("version.dll")]
        [InlineData("dbghelp.dll")]
        [InlineData("winmm.dll")]
        [InlineData("dwrite.dll")]
        [InlineData("cryptsp.dll")]
        [InlineData("userenv.dll")]
        [InlineData("profapi.dll")]
        [InlineData("wtsapi32.dll")]
        [InlineData("dhcpcsvc.dll")]
        [InlineData("iphlpapi.dll")]
        [InlineData("msasn1.dll")]
        [InlineData("netapi32.dll")]
        [InlineData("samcli.dll")]
        [InlineData("sspicli.dll")]
        [InlineData("crypt32.dll")]
        [InlineData("textshaping.dll")]
        [InlineData("winhttp.dll")]
        [InlineData("urlmon.dll")]
        [InlineData("propsys.dll")]
        [InlineData("dwmapi.dll")]
        public void IsSideloadTargetFileName_ReturnsTrue_ForAllKnownTargets(string fileName)
        {
            Assert.True(DllUnloadEngine.IsSideloadTargetFileName(fileName));
        }

        //  Full path extraction (Path.GetFileName is used internally) 

        [Theory]
        [InlineData(@"C:\evil\version.dll")]
        [InlineData(@"C:\Users\Attacker\AppData\Local\Temp\dbghelp.dll")]
        [InlineData(@"\\network\share\winmm.dll")]
        [InlineData(@"D:\Program Files\App\cryptsp.dll")]
        public void IsSideloadTargetFileName_ExtractsFileName_FromFullPath(string fullPath)
        {
            Assert.True(DllUnloadEngine.IsSideloadTargetFileName(fullPath));
        }

        //  Case insensitivity 

        [Theory]
        [InlineData("VERSION.DLL")]
        [InlineData("Version.Dll")]
        [InlineData("DBGHELP.DLL")]
        [InlineData("WinMM.DLL")]
        public void IsSideloadTargetFileName_IsCaseInsensitive(string fileName)
        {
            Assert.True(DllUnloadEngine.IsSideloadTargetFileName(fileName));
        }

        // 
        // IsSideloadTargetFileName - negative cases
        // 

        [Theory]
        [InlineData("DismCorePS.dll")]
        [InlineData("dismprov.dll")]
        [InlineData("OSProvider.dll")]
        [InlineData("dismhost.exe")]
        [InlineData("DismApi.dll")]
        public void IsSideloadTargetFileName_ReturnsFalse_ForDismServicingModules(string fileName)
        {
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName(fileName));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void IsSideloadTargetFileName_ReturnsFalse_ForNullOrEmpty(string? pathOrName)
        {
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName(pathOrName));
        }

        [Theory]
        [InlineData("kernel32.dll")]
        [InlineData("ntdll.dll")]
        [InlineData("user32.dll")]
        [InlineData("gdi32.dll")]
        [InlineData("advapi32.dll")]
        [InlineData("shell32.dll")]
        [InlineData("ole32.dll")]
        [InlineData("msvcrt.dll")]
        [InlineData("myapp.dll")]
        [InlineData("custom_plugin.dll")]
        public void IsSideloadTargetFileName_ReturnsFalse_ForNonTargetDlls(string fileName)
        {
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName(fileName));
        }

        [Theory]
        [InlineData("version.exe")]
        [InlineData("dbghelp.sys")]
        [InlineData("winmm.txt")]
        [InlineData("version")]
        public void IsSideloadTargetFileName_ReturnsFalse_ForWrongExtensions(string fileName)
        {
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName(fileName));
        }

        // 
        // SideloadTargets collection - completeness
        // 

        [Fact]
        public void SideloadTargets_HasExpectedCount()
        {
            // 20 known sideload target DLLs as of v2.0.3
            Assert.Equal(20, DllUnloadEngine.SideloadTargets.Count);
        }

        [Fact]
        public void SideloadTargets_AllEndWithDll()
        {
            foreach (var target in DllUnloadEngine.SideloadTargets)
            {
                Assert.EndsWith(".dll", target, System.StringComparison.OrdinalIgnoreCase);
            }
        }

        [Fact]
        public void SideloadTargets_NoDuplicates()
        {
            var lower = DllUnloadEngine.SideloadTargets.Select(t => t.ToLowerInvariant()).ToList();
            Assert.Equal(lower.Count, lower.Distinct().Count());
        }

        // 
        // Boundary values for IsSideloadTargetFileName
        // 

        [Fact]
        public void IsSideloadTargetFileName_DirectoryOnly_ReturnsFalse()
        {
            // Path with no file name component
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName(@"C:\Windows\System32\"));
        }

        [Fact]
        public void IsSideloadTargetFileName_PartialMatch_ReturnsFalse()
        {
            // "version" without .dll extension
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName("version"));
            // "my_version.dll" is not an exact sideload target
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName("my_version.dll"));
        }

        [Fact]
        public void IsSideloadTargetFileName_PathTraversalAttack_StillExtractsCorrectFileName()
        {
            // Path traversal in directory portion - file name should still resolve correctly
            Assert.True(DllUnloadEngine.IsSideloadTargetFileName(@"C:\app\..\temp\version.dll"));
        }

        // 
        // DllUnloadResult model
        // 

        [Theory]
        [InlineData(@"C:\Program Files\App\dbghelp.dll")]
        [InlineData(@"C:\Program Files\Ceprkac\version.dll")]
        [InlineData(@"C:\Users\Admin\AppData\Local\Temp\winmm.dll")]
        [InlineData(@"C:\Users\Admin\Downloads\winhttp.dll")]
        [InlineData(@"D:\SteamLibrary\steamapps\common\Grand Theft Auto V\dbghelp.dll")]
        [InlineData(@"C:\Program Files (x86)\Steam\steamapps\common\Star Trek Online\version.dll")]
        public void IsHijackPlantPath_ReturnsTrue_ForHijackNameOutsideOsTree(string path)
        {
            Assert.True(DllUnloadEngine.IsHijackPlantPath(path));
        }

        [Theory]
        [InlineData(@"C:\Windows\System32\dbghelp.dll")]
        [InlineData(@"C:\Windows\SysWOW64\version.dll")]
        [InlineData(@"C:\Windows\WinSxS\x86_something\winmm.dll")]
        public void IsHijackPlantPath_ReturnsFalse_ForOsCopy(string path)
        {
            Assert.False(DllUnloadEngine.IsHijackPlantPath(path));
        }

        [Fact]
        public void IsHijackPlantPath_ReturnsFalse_ForHoneypotFolder()
        {
            Assert.False(DllUnloadEngine.IsHijackPlantPath(
                @"C:\Program Files\Sentinel\honeypot\dbghelp.dll"));
        }

        [Fact]
        public void IsHijackPlantPath_ReturnsFalse_ForNtLiteScratch()
        {
            Assert.False(DllUnloadEngine.IsHijackPlantPath(
                @"C:\Users\Admin\AppData\Local\Temp\NLTmpScratch\dbghelp.dll"));
        }

        [Fact]
        public void IsHijackPlantPath_ReturnsFalse_ForChromeElf()
        {
            Assert.False(DllUnloadEngine.IsHijackPlantPath(
                @"C:\Program Files\Google\Chrome\Application\chrome_elf.dll"));
        }

        // 
        // IsLoadableModuleFileName - full module-extension coverage
        // 

        [Theory]
        [InlineData("foo.dll")]
        [InlineData("Windows.Foundation.winmd")]
        [InlineData("flash.ocx")]
        [InlineData("desk.cpl")]
        [InlineData("quartz.ax")]
        [InlineData("addon.node")]
        [InlineData("legacy.drv")]
        [InlineData("codec.acm")]
        [InlineData("provider.tsp")]
        [InlineData("shell32.mui")]
        [InlineData("boot.efi")]
        public void IsLoadableModuleFileName_ReturnsTrue_ForModuleExtensions(string fileName)
        {
            Assert.True(DllUnloadEngine.IsLoadableModuleFileName(fileName));
        }

        [Theory]
        [InlineData(@"C:\Users\Attacker\AppData\Local\Temp\Evil.Component.winmd")]
        [InlineData(@"C:\evil\hijack.ocx")]
        public void IsLoadableModuleFileName_ExtractsExtension_FromFullPath(string fullPath)
        {
            Assert.True(DllUnloadEngine.IsLoadableModuleFileName(fullPath));
        }

        [Theory]
        [InlineData("readme.txt")]
        [InlineData("photo.png")]
        [InlineData("payload.exe")]
        [InlineData("script.ps1")]
        [InlineData("noext")]
        [InlineData(null)]
        [InlineData("")]
        public void IsLoadableModuleFileName_ReturnsFalse_ForNonModules(string? fileName)
        {
            Assert.False(DllUnloadEngine.IsLoadableModuleFileName(fileName));
        }

        [Fact]
        public void ModuleExtensions_ContainsWinmdAndOcx()
        {
            Assert.Contains(".winmd", ModuleIdentity.ModuleExtensions);
            Assert.Contains(".ocx", ModuleIdentity.ModuleExtensions);
            Assert.Contains(".dll", ModuleIdentity.ModuleExtensions);
        }

        [Fact]
        public void DllUnloadResult_DefaultValues_AreEmpty()
        {
            var result = new DllUnloadResult();
            Assert.Equal(0, result.ProcessId);
            Assert.Equal("", result.ProcessName);
            Assert.False(result.Success);
            Assert.Empty(result.QuarantinedDlls);
        }

        [Fact]
        public void DllUnloadResult_TracksQuarantinedDlls()
        {
            var result = new DllUnloadResult
            {
                ProcessId = 1234,
                ProcessName = "target.exe"
            };
            result.RecordFileOutcome("version.dll", DllFileOutcome.Quarantined);
            result.RecordFileOutcome("dbghelp.dll", DllFileOutcome.Quarantined);

            Assert.Equal(2, result.QuarantinedDlls.Count);
            Assert.Contains("version.dll", result.QuarantinedDlls);
        }

        // 
        // Per-process module cache is bound to process identity (PID + creation time)
        // 
        [Fact]
        public void ResolvePidCache_SameProcess_ReturnsSameCache()
        {
            var map = new System.Collections.Concurrent.ConcurrentDictionary<int, DllUnloadEngine.PidModuleCache>();
            var first = DllUnloadEngine.ResolvePidCache(map, 4242, 1000);
            first.Paths.Add(@"C:\Evil\helper.dll");

            var again = DllUnloadEngine.ResolvePidCache(map, 4242, 1000);

            Assert.Same(first, again);
            Assert.Contains(@"C:\Evil\helper.dll", again.Paths);
        }

        [Fact]
        public void ResolvePidCache_ReusedPid_DoesNotInheritPreviousProcessState()
        {
            var map = new System.Collections.Concurrent.ConcurrentDictionary<int, DllUnloadEngine.PidModuleCache>();
            var old = DllUnloadEngine.ResolvePidCache(map, 4242, 1000);
            old.Paths.Add(@"C:\Evil\helper.dll");
            old.StartupModules.Add(@"C:\Evil\helper.dll");
            old.DiskPlantsChecked = true;
            old.LateLoadFlagged = true;

            // Same PID, different process (new creation time).
            var reused = DllUnloadEngine.ResolvePidCache(map, 4242, 2000);

            Assert.NotSame(old, reused);
            Assert.Equal(2000, reused.CreationTime);
            Assert.Empty(reused.Paths);              // module will be identity-checked again
            Assert.Empty(reused.StartupModules);
            Assert.False(reused.DiskPlantsChecked); // disk-plant check runs for the new process
            Assert.False(reused.LateLoadFlagged);
            Assert.Same(reused, map[4242]);
        }

        [Fact]
        public void ResolvePidCache_ConcurrentCallers_AgreeOnOneCachePerProcess()
        {
            var map = new System.Collections.Concurrent.ConcurrentDictionary<int, DllUnloadEngine.PidModuleCache>();
            var results = new DllUnloadEngine.PidModuleCache[64];
            System.Threading.Tasks.Parallel.For(0, results.Length,
                i => results[i] = DllUnloadEngine.ResolvePidCache(map, 7, 555));

            Assert.All(results, r => Assert.Same(map[7], r));
        }

        // 
        // Pruning keeps live processes and drops exited / reused ones
        // 
        [Fact]
        public void IsCacheStale_LiveProcess_IsKeptEvenWhenIdle()
        {
            var cache = new DllUnloadEngine.PidModuleCache(1000) { LastSeenUtc = System.DateTime.UtcNow.AddHours(-2) };
            Assert.False(DllUnloadEngine.IsCacheStale(cache, 1000, System.DateTime.UtcNow.AddMinutes(-3)));
        }

        [Theory]
        [InlineData(0L)]    // process exited (creation time unreadable)
        [InlineData(2000L)] // PID now belongs to another process
        public void IsCacheStale_ExitedOrReusedProcess_IsDropped(long currentCreationTime)
        {
            var cache = new DllUnloadEngine.PidModuleCache(1000) { LastSeenUtc = System.DateTime.UtcNow };
            Assert.True(DllUnloadEngine.IsCacheStale(cache, currentCreationTime, System.DateTime.UtcNow.AddMinutes(-3)));
        }

        [Fact]
        public void IsCacheStale_UnknownCreationTime_FallsBackToIdleRule()
        {
            var cutoff = System.DateTime.UtcNow.AddMinutes(-3);
            var fresh = new DllUnloadEngine.PidModuleCache(0) { LastSeenUtc = System.DateTime.UtcNow };
            var idle = new DllUnloadEngine.PidModuleCache(0) { LastSeenUtc = System.DateTime.UtcNow.AddMinutes(-10) };

            Assert.False(DllUnloadEngine.IsCacheStale(fresh, 0, cutoff));
            Assert.True(DllUnloadEngine.IsCacheStale(idle, 0, cutoff));
        }

        // 
        // IsProtectedPath - case-insensitive, no "\Sentinel" substring trust
        // 
        [Fact]
        public void IsProtectedPath_IsCaseInsensitive_ForWindowsDirectory()
        {
            var win = System.Environment.GetFolderPath(System.Environment.SpecialFolder.Windows);
            Assert.True(DllUnloadEngine.IsProtectedPath(win.ToUpperInvariant() + @"\SYSTEM32\MSIEXEC.EXE"));
            Assert.True(DllUnloadEngine.IsProtectedPath(win.ToLowerInvariant() + @"\system32\msiexec.exe"));
        }

        [Theory]
        [InlineData(@"C:\Users\Admin\Downloads\Sentinel\Sentinel.Service.exe")]
        [InlineData(@"D:\Gorstak\Sentinel\bin\Sentinel.Agent.exe")]
        [InlineData(@"C:\Users\Admin\AppData\Local\Temp\msiexec.exe")]
        [InlineData(@"C:\WindowsFake\System32\lsass.exe")]
        public void IsProtectedPath_ReturnsFalse_ForLookalikes(string path)
        {
            Assert.False(DllUnloadEngine.IsProtectedPath(path));
        }

        [Fact]
        public void FailedQuarantineBackoff_IsBounded()
        {
            Assert.InRange(DllUnloadEngine.FailedQuarantineBackoff, System.TimeSpan.FromMinutes(1), System.TimeSpan.FromHours(1));
        }
    }
}
