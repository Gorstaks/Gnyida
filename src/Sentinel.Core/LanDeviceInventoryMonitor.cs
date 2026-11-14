using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
namespace Sentinel.Core
{
    /// <summary>
    /// Network inspector (observe-only). Keeps an inventory of the devices in the local ARP table
    /// and reports a new device joining the LAN. Tier2 / LogOnly; it never blocks a device.
    /// </summary>
    public sealed class LanDeviceInventoryMonitor : BackgroundService
    {
        private static readonly TimeSpan Interval = TimeSpan.FromMinutes(2);
        private static readonly Regex ArpLine = new(@"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(dynamic|static)\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<LanDeviceInventoryMonitor> _logger;
        private readonly HashSet<string> _known = new(StringComparer.OrdinalIgnoreCase);
        private bool _baselined;
        public LanDeviceInventoryMonitor(DetectionEngine detectionEngine, ILogger<LanDeviceInventoryMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[LanInventory] Started (observe-only)");
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var found = ParseArp(await RunArpAsync(ct));
                    foreach (var d in found)
                    {
                        if (!_known.Add(d.Mac) || !_baselined) continue;
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Network Inspector: New LAN Device",
                            Evidence = $"New device {d.Ip} ({d.Mac}) appeared in the ARP table.",
                            Reasoning = "A device not seen since Sentinel started now answers on the local network. Review it if you do not recognise it. No response is taken.",
                            Confidence = 0.30,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                        });
                    }
                    if (_known.Count > 2048) _known.Clear();
                    _baselined = true;
                    await Task.Delay(Interval, ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[LanInventory] scan failed"); try { await Task.Delay(Interval, ct); } catch (OperationCanceledException) { break; } }
            }
        }
        internal readonly struct Device
        {
            public Device(string ip, string mac) { Ip = ip; Mac = mac; }
            public string Ip { get; }
            public string Mac { get; }
        }
        /// <summary>Dynamic entries only, excluding broadcast and multicast (01-00-5e / ff-ff-ff).</summary>
        internal static List<Device> ParseArp(string output)
        {
            var list = new List<Device>();
            foreach (var line in output.Split('\n'))
            {
                var m = ArpLine.Match(line.TrimEnd('\r'));
                if (!m.Success || !m.Groups[3].Value.Equals("dynamic", StringComparison.OrdinalIgnoreCase)) continue;
                var mac = m.Groups[2].Value.ToLowerInvariant();
                if (mac.StartsWith("ff-ff-ff") || mac.StartsWith("01-00-5e")) continue;
                list.Add(new Device(m.Groups[1].Value, mac));
            }
            return list;
        }
        private static async Task<string> RunArpAsync(CancellationToken ct)
        {
            var psi = new ProcessStartInfo(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "arp.exe"), "-a")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
            };
            using var p = Process.Start(psi);
            if (p == null) return string.Empty;
            var read = p.StandardOutput.ReadToEndAsync();
            var done = await Task.WhenAny(read, Task.Delay(TimeSpan.FromSeconds(10), ct));
            if (done != read)
            {
                try { p.Kill(); } catch (InvalidOperationException) { }
                ct.ThrowIfCancellationRequested();
                return string.Empty;
            }
            return await read;
        }
    }
}