using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Gnyida.Core;
using Xunit;

namespace Gnyida.Tests
{
    /// <summary>
    /// "Privacy: Screen Capture By User-Writable App" (CaptureDeviceUseMonitor): Tier2Indicator and LogOnly at
    /// every confidence, never kill authority, never a chain seed, and unchanged by an armed ActiveResponse.
    /// </summary>
    public class ScreenCaptureConsentTests : IDisposable
    {
        private readonly string _tempDir = Path.Combine(Path.GetTempPath(), "gnyida_screencap_" + Guid.NewGuid().ToString("N").Substring(0, 8));

        public ScreenCaptureConsentTests() { Directory.CreateDirectory(_tempDir); }

        private static CaptureDeviceUseMonitor.Hit ScreenHit(string device = "graphicsCaptureProgrammatic") =>
            new CaptureDeviceUseMonitor.Hit(device, @"C:\Users\x\AppData\Roaming\spy\spy.exe", "S-1-5-21-1-2-3-1001");

        private static readonly IReadOnlyList<string> Remotes = new[] { "203.0.113.10:443" };

        [Theory]
        [InlineData("graphicsCaptureProgrammatic", true)]
        [InlineData("graphicsCaptureWithoutBorder", true)]
        [InlineData("webcam", false)]
        [InlineData("microphone", false)]
        public void OnlyGraphicsCaptureCapabilitiesAreScreenCapture(string device, bool expected)
        {
            Assert.Equal(expected, CaptureDeviceUseMonitor.IsScreenCaptureDevice(device));
        }

        [Theory]
        [InlineData(0, false, false, 0.45)]   // capture only, process not running
        [InlineData(4242, false, false, 0.45)] // running, no outbound connection
        [InlineData(4242, true, true, 0.60)]  // outbound, signed image
        [InlineData(4242, true, false, 0.65)] // outbound, unsigned image
        public void ScreenCapture_IsTier2LogOnly_AtEveryConfidence(int pid, bool online, bool signed, double confidence)
        {
            var ctx = new CaptureDeviceUseMonitor.CaptureContext(pid, online ? Remotes : Array.Empty<string>(), signed);
            var d = CaptureDeviceUseMonitor.BuildScreenDetection(ScreenHit(), ctx);

            Assert.Equal(CaptureDeviceUseMonitor.ScreenRuleName, d.RuleName);
            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
            Assert.False(d.KillAuthorized);
            Assert.Equal(confidence, d.Confidence, 3);
            Assert.Equal(pid, d.ProcessId);
            Assert.Equal("T1113", d.Metadata!["Technique"]);
        }

        [Fact]
        public void ScreenCapture_WithUpload_NamesThePeersInEvidence()
        {
            var ctx = new CaptureDeviceUseMonitor.CaptureContext(4242, Remotes, signed: false);
            var d = CaptureDeviceUseMonitor.BuildScreenDetection(ScreenHit(), ctx);
            Assert.Contains("203.0.113.10:443", d.Evidence);
            Assert.Contains("unsigned", d.Evidence);
            Assert.Equal("1", d.Metadata!["OutboundConnections"]);
        }

        [Fact]
        public void ScreenCapture_IsWeakObserveSeed_NeverChainFuel()
        {
            var ctx = new CaptureDeviceUseMonitor.CaptureContext(4242, Remotes, signed: false);
            Assert.True(ResponsePolicy.IsWeakObserveSeed(CaptureDeviceUseMonitor.BuildScreenDetection(ScreenHit(), ctx)));
        }

        [Fact]
        public void DeviceRule_IsUnchanged_Tier2LogOnly()
        {
            var d = CaptureDeviceUseMonitor.BuildDeviceDetection(new CaptureDeviceUseMonitor.Hit("webcam", @"C:\Users\x\cam.exe", "S-1"));
            Assert.Equal(CaptureDeviceUseMonitor.DeviceRuleName, d.RuleName);
            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
            Assert.Equal(0.40, d.Confidence, 3);
        }

        [Fact]
        public async Task ScreenCapture_WithActiveResponseAndForgedKill_StillTakesNoAction()
        {
            // Tier2 log-only contract: even if a destructive action were attached, Tier2 never acts.
            var config = new GnyidaConfig { ActiveResponse = true };
            var logger = new JsonlEventLogger(Path.Combine(_tempDir, "events.jsonl"));
            var engine = new AdvancedResponseEngine(config, new GnyidaMetrics(), logger, new QuarantineManager(_tempDir));
            var d = CaptureDeviceUseMonitor.BuildScreenDetection(ScreenHit(),
                new CaptureDeviceUseMonitor.CaptureContext(int.MaxValue - 13, Remotes, signed: false));
            d.AuthorizedResponse = ResponseAction.KillProcessTree;

            await engine.HandleAsync(d);
            await logger.DisposeAsync();

            var audit = string.Concat(Array.ConvertAll(Directory.GetFiles(_tempDir, "audit-*.jsonl"), File.ReadAllText));
            Assert.True(string.IsNullOrEmpty(audit), "Tier2 must not produce a pre-action audit entry. Audit: " + audit);
        }

        public void Dispose()
        {
            try { Directory.Delete(_tempDir, true); }
            catch (IOException) { /* temp cleanup is best effort */ }
            catch (UnauthorizedAccessException) { /* temp cleanup is best effort */ }
        }
    }
}
