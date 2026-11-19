using System;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class LingeringProcessMonitorTests
    {
        private const string Sys = @"C:\Windows\System32";
        private const string Wow = @"C:\Windows\SysWOW64";
        private static LingeringProcessMonitor.Verdict Eval(string name, int minutes, string? path) =>
            LingeringProcessMonitor.Evaluate(name, TimeSpan.FromMinutes(minutes), path, Sys, Wow);

        [Fact]
        public void WithinCeiling_IsOk() =>
            Assert.Equal(LingeringProcessMonitor.Verdict.Ok, Eval("schtasks.exe", 5, Sys + @"\schtasks.exe"));

        [Fact]
        public void PastCeiling_SystemPath_IsLingering() =>
            Assert.Equal(LingeringProcessMonitor.Verdict.Lingering, Eval("schtasks.exe", 11, Sys + @"\schtasks.exe"));

        [Fact]
        public void PastCeiling_Wow64Path_IsLingering() =>
            Assert.Equal(LingeringProcessMonitor.Verdict.Lingering, Eval("reg", 11, Wow + @"\reg.exe"));

        [Fact]
        public void PastCeiling_OutsideSystemDirectory_IsOffPath() =>
            Assert.Equal(LingeringProcessMonitor.Verdict.LingeringOffPath, Eval("whoami.exe", 11, @"C:\Users\Public\whoami.exe"));

        [Fact]
        public void PastCeiling_PrefixLookalikeDirectory_IsOffPath() =>
            Assert.Equal(LingeringProcessMonitor.Verdict.LingeringOffPath, Eval("reg.exe", 11, @"C:\Windows\System32Evil\reg.exe"));

        [Fact]
        public void PastCeiling_UnreadablePath_IsUnverifiable()
        {
            Assert.Equal(LingeringProcessMonitor.Verdict.LingeringUnverifiable, Eval("net.exe", 11, null));
            Assert.Equal(LingeringProcessMonitor.Verdict.LingeringUnverifiable, Eval("net.exe", 11, "  "));
        }

        [Fact]
        public void LongCeilingTools_AreNotFlaggedAtTenMinutes() =>
            Assert.Equal(LingeringProcessMonitor.Verdict.Ok, Eval("icacls.exe", 20, Sys + @"\icacls.exe"));

        [Fact]
        public void LongCeilingTools_AreFlaggedPastThirtyMinutes() =>
            Assert.Equal(LingeringProcessMonitor.Verdict.Lingering, Eval("icacls.exe", 31, Sys + @"\icacls.exe"));

        [Theory]
        [InlineData("cmd.exe")]
        [InlineData("powershell.exe")]
        [InlineData("ping.exe")]
        [InlineData("explorer.exe")]
        public void UnwatchedImages_AreNeverFlagged(string name) =>
            Assert.Equal(LingeringProcessMonitor.Verdict.Ok, Eval(name, 600, Sys + @"\" + name));

        [Fact]
        public void NameMatchIsCaseInsensitive() =>
            Assert.Equal(LingeringProcessMonitor.Verdict.Lingering, Eval("SCHTASKS.EXE", 11, Sys.ToLowerInvariant() + @"\schtasks.exe"));
    }
}
