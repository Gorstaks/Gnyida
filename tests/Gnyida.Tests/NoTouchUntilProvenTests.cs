using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Gnyida.Core;
using Xunit;

namespace Gnyida.Tests
{
    /// <summary>
    /// Owner policy (3.7.6): Gnyida does not open, hash, signature-check or quarantine a file
    /// just because it was created, changed or exists on disk. Driver staging failed with 0x20
    /// while Gnyida held read handles on freshly written files.
    /// </summary>
    public class NoTouchUntilProvenTests
    {
        [Fact]
        public void ProactiveFileInspectionAndUnsignedDllSweepAreOffByDefault()
        {
            var config = new GnyidaConfig();
            Assert.False(config.EnableProactiveFileInspection);
            Assert.False(config.EnableAggressiveUnsignedDllSweep);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void PrintNightmarePlantWithoutSignatureCheckIsTier2LogOnly(bool recent)
        {
            var evt = PrintSpoolerMonitor.BuildDriverDllPlantEvent(@"C:\Windows\System32\spool\drivers\x64\3\new.dll",
                isSigned: null, isRecent: recent, DateTime.UtcNow, 4096);
            Assert.Equal(DetectionTier.Tier2Indicator, evt.Tier);
            Assert.Equal(ResponseAction.LogOnly, evt.AuthorizedResponse);
            Assert.Equal("not checked", evt.Metadata!["IsSigned"]);

            // Tier2 log-only contract: dispatch policy can never arm a response for it.
            evt.AuthorizedResponse = ResponseAction.QuarantineAndKill;
            ResponsePolicy.EnforceDispatchPolicy(evt);
            Assert.Equal(ResponseAction.LogOnly, evt.AuthorizedResponse);
        }

        [Fact]
        public void PrintNightmareUnsignedRecentPlantStaysTier1WhenInspectionEnabled()
        {
            var evt = PrintSpoolerMonitor.BuildDriverDllPlantEvent(@"C:\Windows\System32\spool\drivers\x64\3\new.dll",
                isSigned: false, isRecent: true, DateTime.UtcNow, 4096);
            Assert.Equal(DetectionTier.Tier1Behavioral, evt.Tier);
            Assert.Equal(ResponseAction.QuarantineAndKill, evt.AuthorizedResponse);
        }

        [Fact]
        public async Task LnkShortcutMonitorCompletesAsPolicyStartupTaskWithoutReadingShortcuts()
        {
            using var monitor = new LnkShortcutMonitor(null!, null!, null!, NullLogger<LnkShortcutMonitor>.Instance);
            Assert.IsAssignableFrom<IMonitorStartupTask>(monitor);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await monitor.StartAsync(cts.Token);
            var execute = monitor.ExecuteTask;
            Assert.NotNull(execute);
            var finished = await Task.WhenAny(execute!, Task.Delay(TimeSpan.FromSeconds(5), cts.Token));
            Assert.Same(execute, finished);
            Assert.Equal(TaskStatus.RanToCompletion, execute!.Status);
            await monitor.StopAsync(CancellationToken.None);
        }

        [Fact]
        public async Task FileVerdictScannerCompletesAsPolicyStartupTaskWithoutWatchers()
        {
            // Dependencies are never used on the off-by-policy path.
            using var scanner = new FileVerdictScanner(null!, null!, null!, null!, null!,
                NullLogger<FileVerdictScanner>.Instance);
            Assert.IsAssignableFrom<IMonitorStartupTask>(scanner);
            Assert.Contains("Off by policy", scanner.Progress.Scope);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await scanner.StartAsync(cts.Token);
            var execute = scanner.ExecuteTask;
            Assert.NotNull(execute);
            var finished = await Task.WhenAny(execute!, Task.Delay(TimeSpan.FromSeconds(5), cts.Token));
            Assert.Same(execute, finished);
            Assert.Equal(TaskStatus.RanToCompletion, execute!.Status);
            // No collection cycle ran, so the scanner never claims healthy coverage.
            Assert.Equal("Unknown", scanner.Progress.Snapshot().State);
            await scanner.StopAsync(CancellationToken.None);
        }
    }
}
