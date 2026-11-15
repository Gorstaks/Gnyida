using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// Owner policy (3.7.6): Sentinel does not open, hash, signature-check or quarantine a file
    /// just because it was created, changed or exists on disk. Driver staging failed with 0x20
    /// while Sentinel held read handles on freshly written files.
    /// </summary>
    public class NoTouchUntilProvenTests
    {
        [Fact]
        public void ProactiveFileInspectionAndUnsignedDllSweepAreOffByDefault()
        {
            var config = new SentinelConfig();
            Assert.False(config.EnableProactiveFileInspection);
            Assert.False(config.EnableAggressiveUnsignedDllSweep);
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
