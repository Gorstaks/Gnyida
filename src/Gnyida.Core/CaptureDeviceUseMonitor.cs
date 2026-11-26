using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
namespace Gnyida.Core
{
    /// <summary>
    /// Webcam, microphone and screen-capture shield (observe-only). Windows records every app that opens the
    /// camera or microphone, or captures the screen through the Windows.Graphics.Capture API, in the
    /// CapabilityAccessManager consent store, per user. This reports a desktop app running from a location
    /// outside Program Files / System32 that starts using one of them.
    /// <para>
    /// Screen capture is correlated with the network: when a running process with the capturing image also has
    /// established outbound TCP connections, the finding says so and carries higher confidence (a capture that
    /// leaves the machine is what desktop spyware looks like). An unsigned image raises confidence further.
    /// </para>
    /// <para>
    /// Limits: the consent store records the Windows.Graphics.Capture API only. Desktop Duplication and GDI
    /// (BitBlt) capture leave no record here. Tier2 / LogOnly: it never kills, blocks or changes device access,
    /// and "Privacy:" findings are weak observe signals that cannot seed a kill chain.
    /// </para>
    /// </summary>
    public sealed class CaptureDeviceUseMonitor : BackgroundService
    {
        internal const string DeviceRuleName = "Privacy: Capture Device In Use By User-Writable App";
        internal const string ScreenRuleName = "Privacy: Screen Capture By User-Writable App";

        // Consent-store capability names. The graphicsCapture* entries are written for screen/window capture.
        private static readonly string[] Devices =
            { "webcam", "microphone", "graphicsCaptureProgrammatic", "graphicsCaptureWithoutBorder" };
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
                        await _detectionEngine.EmitAsync(hit.IsScreenCapture ? BuildScreenDetection(hit, Correlate(hit.AppPath)) : BuildDeviceDetection(hit));
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
            public bool IsScreenCapture => IsScreenCaptureDevice(Device);
            public string Key => Device + "|" + AppPath + "|" + Sid;
        }

        /// <summary>What was found about the capturing app at report time.</summary>
        internal readonly struct CaptureContext
        {
            public CaptureContext(int pid, IReadOnlyList<string> remotes, bool signed)
            {
                Pid = pid; Remotes = remotes ?? Array.Empty<string>(); Signed = signed;
            }
            /// <summary>PID of a running process with the capturing image, or 0 when none is running.</summary>
            public int Pid { get; }
            /// <summary>Established non-loopback TCP peers of that process ("address:port").</summary>
            public IReadOnlyList<string> Remotes { get; }
            /// <summary>Valid Authenticode signature on the image. Context only: a signature is not an allow.</summary>
            public bool Signed { get; }
        }

        internal static bool IsScreenCaptureDevice(string device) =>
            device.StartsWith("graphicsCapture", StringComparison.OrdinalIgnoreCase);

        internal static DetectionEvent BuildDeviceDetection(Hit hit) => new DetectionEvent
        {
            RuleName = DeviceRuleName,
            Evidence = $"{hit.Device} in use by '{hit.AppPath}' (user SID {hit.Sid}).",
            Reasoning = "Windows records camera and microphone use per app. This app runs from a location a standard user can write to, so it is reported for review. No response is taken.",
            Confidence = 0.40,
            Tier = DetectionTier.Tier2Indicator,
            AuthorizedResponse = ResponseAction.LogOnly,
            ProcessName = Path.GetFileName(hit.AppPath),
            ProcessId = 0,
        };

        /// <summary>
        /// Tier2 / LogOnly at every confidence. Confidence: 0.45 capture only, 0.60 with outbound connections,
        /// 0.65 with outbound connections from an unsigned image.
        /// </summary>
        internal static DetectionEvent BuildScreenDetection(Hit hit, CaptureContext ctx)
        {
            bool online = ctx.Remotes.Count > 0;
            double confidence = !online ? 0.45 : (ctx.Signed ? 0.60 : 0.65);
            string network = online
                ? $" The process (PID {ctx.Pid}) has established outbound connections to {string.Join(", ", ctx.Remotes)}."
                : ctx.Pid > 0 ? $" The process (PID {ctx.Pid}) has no established outbound TCP connection right now." : " No running process with this image was found.";
            return new DetectionEvent
            {
                RuleName = ScreenRuleName,
                Evidence = $"Screen capture ({hit.Device}) by '{hit.AppPath}' (user SID {hit.Sid}), {(ctx.Signed ? "signed" : "unsigned")} image.{network}",
                Reasoning = "Windows records apps that capture the screen through the Windows.Graphics.Capture API. This app runs from a location a standard user can write to. " +
                            (online ? "It also has outbound network connections, which is how a desktop stream or screenshot upload leaves the machine. " : "") +
                            "Reported for review; no response is taken. Screen sharing in meeting or chat apps installed per user (Discord, Teams, Zoom) also appears here.",
                Confidence = confidence,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = Path.GetFileName(hit.AppPath),
                ProcessId = ctx.Pid,
                Metadata = new Dictionary<string, string>
                {
                    ["CaptureCapability"] = hit.Device,
                    ["ImagePath"] = hit.AppPath,
                    ["OutboundConnections"] = ctx.Remotes.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["Signed"] = ctx.Signed ? "true" : "false",
                    ["Technique"] = "T1113",
                },
            };
        }

        /// <summary>
        /// Finds a running process whose OS-resolved image is the capturing app and reads its established
        /// outbound connections. Runs only for a new finding (deduplicated), never on every poll.
        /// </summary>
        private CaptureContext Correlate(string appPath)
        {
            bool signed = false;
            try { signed = SecurityValidation.VerifyAuthenticodeSignature(appPath); }
            catch (Exception ex) { _logger.LogDebug(ex, "[CaptureDeviceUse] signature check failed for {Path}", appPath); }

            Process[] candidates;
            try { candidates = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(appPath)); }
            catch (Exception ex) { _logger.LogDebug(ex, "[CaptureDeviceUse] process lookup failed"); return new CaptureContext(0, Array.Empty<string>(), signed); }

            int pid = 0;
            IReadOnlyList<string> remotes = Array.Empty<string>();
            foreach (var proc in candidates)
            {
                try
                {
                    // The name only narrows the search; the match is on the image path the OS reports.
                    if (!ApplicationIntegrityMonitor.IsSameImagePath(SecurityValidation.GetProcessImagePath(proc.Id), appPath)) continue;
                    var found = ProcessTcpConnections.GetEstablished(proc.Id, max: 5);
                    if (pid == 0 || found.Count > remotes.Count) { pid = proc.Id; remotes = found; }
                }
                catch (Exception ex) { _logger.LogDebug(ex, "[CaptureDeviceUse] correlate failed for PID {Pid}", proc.Id); }
                finally { proc.Dispose(); }
            }
            return new CaptureContext(pid, remotes, signed);
        }

        private static IEnumerable<Hit> Scan()
        {
            string[] sids;
            try { sids = Registry.Users.GetSubKeyNames(); }
            catch (Exception ex) { BestEffort.Debug(ex, "CaptureDeviceUseMonitor.Scan(users)"); yield break; }
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
            try { return root.OpenSubKey(sub); }
            catch (Exception ex) { BestEffort.Debug(ex, "CaptureDeviceUseMonitor.SafeOpen"); return null; }
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
