using System;
using System.IO;
using Sentinel.Agent;
using Xunit;

namespace Sentinel.Tests
{
    public class WebView2InstallerTests
    {
        [Fact]
        public void AnUnsignedFileIsNeverTreatedAsTheMicrosoftBootstrapper()
        {
            string path = Path.Combine(Path.GetTempPath(), "fake-webview2-" + Guid.NewGuid().ToString("N") + ".exe");
            File.WriteAllBytes(path, new byte[200 * 1024]);
            try { Assert.False(WebView2Installer.IsSignedByMicrosoft(path)); }
            finally { File.Delete(path); }
        }

        [Fact]
        public void AMissingFileIsNotSigned() =>
            Assert.False(WebView2Installer.IsSignedByMicrosoft(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".exe")));

        [Fact]
        public void RuntimeDetectionReadsTheRegistryWithoutThrowing()
        {
            bool installed = WebView2Installer.IsRuntimeInstalled();
            Assert.True(installed || !installed);
        }

        [Fact]
        public void TheBootstrapperComesFromMicrosoftsOwnLinkOverHttps()
        {
            var uri = new Uri(WebView2Installer.BootstrapperUrl);
            Assert.Equal("https", uri.Scheme);
            Assert.Equal("go.microsoft.com", uri.Host);
        }

        /// <summary>
        /// Live check of the download and signature step (no install). Opt-in, because it depends on the network and on
        /// Microsoft's site: set SENTINEL_LIVE_NETWORK_TESTS=1.
        /// </summary>
        [Fact]
        public void Live_DownloadedBootstrapperIsSignedByMicrosoft()
        {
            if (Environment.GetEnvironmentVariable("SENTINEL_LIVE_NETWORK_TESTS") != "1") return;
            string folder = Path.Combine(Path.GetTempPath(), "wv2-live-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            try { Assert.Equal(WebView2Installer.Outcome.Installed, WebView2Installer.DownloadVerified(Path.Combine(folder, "setup.exe"))); }
            finally { Directory.Delete(folder, true); }
        }
    }
}
