using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
namespace Sentinel.Core
{
    /// <summary>
    /// Scheduled system scan. Runs the existing on-demand <see cref="ScanEngine"/> once a day and
    /// records when it last ran, so a restart does not rescan early and a long outage catches up.
    /// The scan is a point-in-time audit; this service takes no response action.
    /// </summary>
    public sealed class ScheduledScanService : BackgroundService
    {
        internal static readonly TimeSpan Period = TimeSpan.FromHours(24);
        private static readonly TimeSpan StartupGrace = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan CheckInterval = TimeSpan.FromMinutes(15);
        private readonly ScanEngine _scanEngine;
        private readonly ILogger<ScheduledScanService> _logger;
        private readonly string _statePath;
        public ScheduledScanService(ScanEngine scanEngine, ILogger<ScheduledScanService> logger)
        {
            _scanEngine = scanEngine;
            _logger = logger;
            _statePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel", "scheduled-scan.json");
        }
        internal static bool IsDue(DateTime? lastRunUtc, DateTime nowUtc)
            => lastRunUtc == null || nowUtc - lastRunUtc.Value >= Period || lastRunUtc.Value > nowUtc;
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ScheduledScan] Started (daily)");
            try { await Task.Delay(StartupGrace, ct); } catch (OperationCanceledException) { return; }
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    if (IsDue(ReadLastRun(), DateTime.UtcNow) && !_scanEngine.IsRunning)
                    {
                        var result = await _scanEngine.RunFullScanAsync(ct);
                        WriteLastRun(DateTime.UtcNow);
                        _logger.LogInformation("[ScheduledScan] Done: completed={Completed} findings={Count} critical={Crit} high={High}",
                            result.Completed, result.Findings.Count, result.CriticalCount, result.HighCount);
                    }
                    await Task.Delay(CheckInterval, ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[ScheduledScan] Scan failed");
                    try { await Task.Delay(CheckInterval, ct); } catch (OperationCanceledException) { break; }
                }
            }
        }
        private DateTime? ReadLastRun()
        {
            try
            {
                if (!File.Exists(_statePath)) return null;
                var s = JsonSerializer.Deserialize<State>(File.ReadAllText(_statePath));
                return s?.LastRunUtc;
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[ScheduledScan] state unreadable; treating as never run"); return null; }
        }
        private void WriteLastRun(DateTime utc)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);
                File.WriteAllText(_statePath, JsonSerializer.Serialize(new State { LastRunUtc = utc }));
            }
            catch (Exception ex) { _logger.LogWarning(ex, "[ScheduledScan] could not record last run"); }
        }
        private sealed class State { public DateTime LastRunUtc { get; set; } }
    }
}