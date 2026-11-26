using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Gnyida.Core;
using Xunit;

namespace Gnyida.Tests
{
    /// <summary>
    /// Guards for how Gnyida starts and waits on child processes: full tool paths, deadlines that actually hold, and
    /// no registration left on a long-lived cancellation token (docs/MEMORY_LEAK_3.7.8.md).
    /// </summary>
    public class ProcessLaunchHygieneTests
    {
        private static string Cmd => Path.Combine(Environment.SystemDirectory, "cmd.exe");
        private static string Ping => Path.Combine(Environment.SystemDirectory, "ping.exe");

        // ---- SystemTools ----

        [Fact]
        public void System32_BuildsAnAbsolutePathInsideTheSystemDirectory()
        {
            string path = SystemTools.System32("netsh.exe");
            Assert.True(Path.IsPathRooted(path));
            Assert.Equal(Environment.SystemDirectory, Path.GetDirectoryName(path), ignoreCase: true);
            Assert.True(File.Exists(path), path);
        }

        [Theory]
        [InlineData(@"..\evil.exe")]
        [InlineData(@"C:\Temp\evil.exe")]
        [InlineData("sub/evil.exe")]
        [InlineData("")]
        [InlineData("  ")]
        public void System32_RejectsAnythingButABareFileName(string name) =>
            Assert.Throws<ArgumentException>(() => SystemTools.System32(name));

        [Fact]
        public void ResolveDocker_FindsOnlyTheInstallLocation_NeverSearchesPath()
        {
            string root = Path.Combine(Path.GetTempPath(), "gnyida-docker-" + Guid.NewGuid().ToString("N"));
            try
            {
                Assert.Null(SystemTools.ResolveDocker(root, null, ""));
                string bin = Path.Combine(root, "Docker", "Docker", "resources", "bin");
                Directory.CreateDirectory(bin);
                string exe = Path.Combine(bin, "docker.exe");
                File.WriteAllText(exe, "x");
                Assert.Equal(exe, SystemTools.ResolveDocker(null, "", root));
                Assert.Equal(exe, SystemTools.ResolveDocker(Path.Combine(root, "missing"), root));
            }
            finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
        }

        [Fact]
        public void ConstantPowerShell_StartsWindowsPowerShellByFullPath()
        {
            var psi = ConstantPowerShell.CreateStartInfo("Get-Date");
            Assert.True(Path.IsPathRooted(psi.FileName));
            Assert.Equal(ConstantPowerShell.SystemPowerShellPath, psi.FileName);
        }

        [Fact]
        public void NoSourceFile_LaunchesAToolByBareName()
        {
            string root = FindSourceRoot();
            var launch = new Regex(@"(ProcessStartInfo\(\s*|FileName\s*=\s*|Process\.Start\(\s*)""([^""\\/:]+)""", RegexOptions.CultureInvariant);
            var offenders = new List<string>();
            foreach (string file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
            {
                if (file.Contains(@"\obj\") || file.Contains(@"\bin\")) continue;
                string[] lines = File.ReadAllLines(file);
                for (int i = 0; i < lines.Length; i++)
                {
                    if (lines[i].TrimStart().StartsWith("//", StringComparison.Ordinal)) continue;
                    Match m = launch.Match(lines[i]);
                    if (m.Success && !m.Groups[2].Value.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                        offenders.Add(Path.GetFileName(file) + ":" + (i + 1) + " " + m.Groups[2].Value);
                }
            }
            Assert.True(offenders.Count == 0, "tool started by bare name: " + string.Join(", ", offenders));
        }

        // ---- BoundedProcess (async) ----

        private static Process Start(string file, string args) =>
            Process.Start(new ProcessStartInfo(file, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })!;

        [Fact]
        public async Task ReadOutputAsync_ReturnsOutputOfAFinishedProcess()
        {
            using var p = Start(Cmd, "/c echo async-ok");
            string output = await BoundedProcess.ReadOutputAsync(p, 10000, CancellationToken.None);
            Assert.Contains("async-ok", output);
            Assert.True(p.HasExited);
        }

        [Fact]
        public async Task ReadOutputAsync_DeadlineFiresOnAChildThatNeverFinishes_AndKillsIt()
        {
            using var p = Start(Ping, "-t 127.0.0.1");
            try
            {
                var clock = Stopwatch.StartNew();
                string output = await BoundedProcess.ReadOutputAsync(p, 1500, CancellationToken.None);
                clock.Stop();
                Assert.True(clock.Elapsed < TimeSpan.FromSeconds(10), "returned after " + clock.Elapsed);
                Assert.True(p.WaitForExit(5000), "the hung child was not killed");
                Assert.Contains("Pinging", output);
            }
            finally { if (!p.HasExited) { try { p.Kill(); } catch { } } }
        }

        [Fact]
        public async Task ReadOutputAsync_CallerCancellation_KillsTheChildAndPropagates()
        {
            using var p = Start(Ping, "-t 127.0.0.1");
            using var cts = new CancellationTokenSource(500);
            try
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => BoundedProcess.ReadOutputAsync(p, 60000, cts.Token));
                Assert.True(p.WaitForExit(5000), "the child outlived its cancelled read");
            }
            finally { if (!p.HasExited) { try { p.Kill(); } catch { } } }
        }

        // ---- no registration left on a long-lived token ----

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static async Task<WeakReference> WaitOnceAsync(CancellationToken longLived, bool legacy)
        {
            using var p = Process.Start(new ProcessStartInfo(Cmd, "/c exit 0") { UseShellExecute = false, CreateNoWindow = true })!;
            Task wait = legacy ? LegacyWaitForExitAsync(p, longLived) : p.WaitForExitAsync(longLived);
            await wait;
            return new WeakReference(wait);
        }

        // The implementation this repository used to have: the registration is never disposed.
        private static Task LegacyWaitForExitAsync(Process process, CancellationToken ct)
        {
            if (process.HasExited) return Task.CompletedTask;
            var tcs = new TaskCompletionSource<object?>();
            void Handler(object? s, EventArgs e) => tcs.TrySetResult(null);
            process.EnableRaisingEvents = true;
            process.Exited += Handler;
            if (process.HasExited) tcs.TrySetResult(null);
            if (ct.CanBeCanceled) ct.Register(() => tcs.TrySetCanceled(ct));
            return tcs.Task;
        }

        private static async Task<int> SurvivorsAfterManyWaits(bool legacy)
        {
            using var serviceLifetime = new CancellationTokenSource(); // stands in for the service's stopping token
            var weak = new List<WeakReference>();
            for (int i = 0; i < 25; i++) weak.Add(await WaitOnceAsync(serviceLifetime.Token, legacy));
            // The registration is released by a continuation on the thread pool; let the last few run before collecting,
            // so the count measures what stays registered, not what hasn't been cleaned up yet.
            await Task.Delay(500);
            for (int i = 0; i < 3; i++) { GC.Collect(); GC.WaitForPendingFinalizers(); }
            int alive = 0;
            foreach (var w in weak) if (w.IsAlive) alive++;
            GC.KeepAlive(serviceLifetime);
            return alive;
        }

        [Fact]
        public async Task WaitForExitAsync_LeavesNothingRegisteredOnALongLivedToken()
        {
            int alive = await SurvivorsAfterManyWaits(legacy: false);
            Assert.True(alive <= 2, alive + " of 25 completed waits are still reachable from the long-lived token");
        }

        [Fact]
        public async Task TheLegacyImplementation_DoesLeak_SoThisTestCanTellTheDifference()
        {
            int alive = await SurvivorsAfterManyWaits(legacy: true);
            Assert.True(alive >= 20, "expected the old implementation to keep its waits reachable, but only " + alive + " were");
        }

        private static string FindSourceRoot()
        {
            string? dir = AppContext.BaseDirectory;
            while (dir != null && !Directory.Exists(Path.Combine(dir, "src", "Gnyida.Core"))) dir = Path.GetDirectoryName(dir);
            Assert.NotNull(dir);
            return Path.Combine(dir!, "src");
        }
    }
}
