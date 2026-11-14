using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
namespace Sentinel.Core
{
    /// <summary>
    /// Webcam and microphone shield (observe-only). Windows records every app that opens the
    /// camera or microphone in the CapabilityAccessManager consent store, per user. This reports
    /// a desktop app running from a user-writable location that starts using either device.
    /// Tier2 / LogOnly: it never kills, blocks or changes device access.
    /// </summary>
    public sealed class CaptureDeviceUseMonitor : BackgroundService
    {
        private static readonly string[] Devices = { "webcam", "microphone" };
        private const string StoreSuffix = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";
        private static readonly TimeSpan Interval = TimeSpan.FromSeconds(20);
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<CaptureDeviceUseMonitor> _logger;
        private readonly HashSet<string> _reported = new(StringComparer.OrdinalIgnoreCase);
        public CaptureDeviceUseMonitor(DetectionEngine detectionEngine, ILogger<CaptureDeviceUseMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[CaptureDeviceUse] Started (observe-only)");
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    foreach (var hit in Scan())
                    {
                        if (!_reported.Add(hit.Key)) continue;
                        if (_reported.Count > 4096) _reported.Clear();
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Privacy: Capture Device In Use By User-Writable App",
                            Evidence = $"{hit.Device} in use by '{hit.AppPath}' (user SID {hit.Sid}).",
                            Reasoning = "Windows records camera and microphone use per app. This app runs from a location a standard user can write to, so it is reported for review. No response is taken.",
                            Confidence = 0.40,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = Path.GetFileName(hit.AppPath),
                            ProcessId = 0,
                        });
                    }
                    await Task.Delay(Interval, ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[CaptureDeviceUse] scan failed"); try { await Task.Delay(Interval, ct); } catch (OperationCanceledException) { break; } }
            }
        }
        internal readonly struct Hit
        {
            public Hit(string device, string appPath, string sid) { Device = device; AppPath = appPath; Sid = sid; }
            public string Device { get; }
            public string AppPath { get; }
            public string Sid { get; }
            public string Key => Device + "|" + AppPath + "|" + Sid;
        }
        private static IEnumerable<Hit> Scan()
        {
            string[] sids;
            try { sids = Registry.Users.GetSubKeyNames(); } catch { yield break; }
            foreach (var sid in sids)
            {
                if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
                foreach (var device in Devices)
                {
                    using var key = SafeOpen(Registry.Users, sid + "\\" + StoreSuffix + "\\" + device + "\\NonPackaged");
                    if (key == null) continue;
                    foreach (var appKeyName in key.GetSubKeyNames())
                    {
                        using var app = key.OpenSubKey(appKeyName);
                        if (app == null) continue;
                        if (!IsInUse(app.GetValue("LastUsedTimeStart"), app.GetValue("LastUsedTimeStop"))) continue;
                        var path = DecodeAppPath(appKeyName);
                        if (IsTrustedInstallRoot(path)) continue;
                        yield return new Hit(device, path, sid);
                    }
                }
            }
        }
        private static RegistryKey? SafeOpen(RegistryKey root, string sub)
        {
            try { return root.OpenSubKey(sub); } catch { return null; }
        }
        /// <summary>Windows marks a device as in use when a start time exists and the stop time is zero or older.</summary>
        internal static bool IsInUse(object? start, object? stop)
        {
            if (!(start is long s) || s == 0) return false;
            long e = stop is long l ? l : 0;
            return e == 0 || s > e;
        }
        /// <summary>The consent store encodes backslashes in an app path as '#'.</summary>
        internal static string DecodeAppPath(string keyName) => keyName.Replace('#', '\\');
        /// <summary>
        /// Program Files and the Windows tree are admin-only. Anything else (including Windows\Temp
        /// and user profiles) stays reportable, so a drop in a writable folder is never skipped.
        /// </summary>
        internal static bool IsTrustedInstallRoot(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            string[] roots =
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64"),
            };
            foreach (var r in roots)
            {
                if (string.IsNullOrEmpty(r)) continue;
                var prefix = r.TrimEnd('\\') + "\\";
                if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }
}