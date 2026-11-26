using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using Gnyida.Core;

namespace Gnyida.Agent
{
    /// <summary>
    /// Installs the Microsoft Edge WebView2 Evergreen Runtime when the settings window can't start. The approach follows
    /// the Ceprkac browser (download Microsoft's bootstrapper, run it silently), with two changes a security product needs:
    ///   - the bootstrapper must carry a valid Authenticode signature from Microsoft before it is run; and
    ///   - it is written to a new, randomly named folder, not a fixed %TEMP% file name another program could pre-plant
    ///     or swap between the download and the launch.
    /// Runs as the signed-in user (the Agent is never elevated), so the bootstrapper does a per-user install.
    /// Uses no WebView2 types: the runtime is detected from the registry, so this works when the WebView2 assemblies
    /// themselves are what failed to load.
    /// </summary>
    internal static class WebView2Installer
    {
        /// <summary>Official Microsoft link to the Evergreen WebView2 Runtime bootstrapper.</summary>
        internal const string BootstrapperUrl = "https://go.microsoft.com/fwlink/p/?LinkId=2124703";

        private const string RuntimeClientKey = @"Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
        private static readonly TimeSpan InstallTimeout = TimeSpan.FromMinutes(10);
        private const long MinimumBootstrapperBytes = 100 * 1024;
        private const long MaximumBootstrapperBytes = 50L * 1024 * 1024;

        internal enum Outcome { Installed, DownloadFailed, NotSignedByMicrosoft, InstallerFailed, TimedOut }

        /// <summary>True when the WebView2 Runtime is registered machine-wide or for this user.</summary>
        internal static bool IsRuntimeInstalled()
        {
            foreach (var hive in new[] { Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryHive.CurrentUser })
            {
                foreach (var view in new[] { Microsoft.Win32.RegistryView.Registry32, Microsoft.Win32.RegistryView.Registry64 })
                {
                    try
                    {
                        using var root = Microsoft.Win32.RegistryKey.OpenBaseKey(hive, view);
                        string path = (hive == Microsoft.Win32.RegistryHive.LocalMachine ? @"SOFTWARE\WOW6432Node\" : @"Software\") + RuntimeClientKey;
                        using var key = root.OpenSubKey(path) ?? root.OpenSubKey(@"SOFTWARE\" + RuntimeClientKey);
                        string? version = key?.GetValue("pv") as string;
                        if (!string.IsNullOrEmpty(version) && version != "0.0.0.0") return true;
                    }
                    catch (Exception ex) { /* key absent or unreadable in this view */ BestEffort.Debug(ex, "WebView2Installer.IsRuntimeInstalled()"); }
                }
            }
            return false;
        }

        /// <summary>
        /// Downloads the bootstrapper to <paramref name="setupPath"/> and checks its size and Microsoft signature.
        /// Returns Installed when the file is ready to run (the name is reused to keep one outcome type).
        /// </summary>
        internal static Outcome DownloadVerified(string setupPath)
        {
            try
            {
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
                using var client = new WebClient();
                client.DownloadFile(BootstrapperUrl, setupPath);
            }
            catch (Exception) { return Outcome.DownloadFailed; }
            long size = new FileInfo(setupPath).Length;
            if (size < MinimumBootstrapperBytes || size > MaximumBootstrapperBytes) return Outcome.DownloadFailed;
            return IsSignedByMicrosoft(setupPath) ? Outcome.Installed : Outcome.NotSignedByMicrosoft;
        }

        /// <summary>A valid Authenticode signature that chains to a trusted root, from a known Microsoft signing identity.</summary>
        internal static bool IsSignedByMicrosoft(string path) =>
            SecurityValidation.VerifyAuthenticodeSignature(path) &&
            MicrosoftPublisher.IsMicrosoftCommonName(SecurityValidation.TryGetAuthenticodePublisher(path));

        /// <summary>Downloads, verifies and runs the bootstrapper. Blocking: call from a background thread.</summary>
        internal static Outcome DownloadAndInstall()
        {
            string folder = Path.Combine(Path.GetTempPath(), "Gnyida-WebView2-" + Guid.NewGuid().ToString("N"));
            string setup = Path.Combine(folder, "MicrosoftEdgeWebview2Setup.exe");
            try
            {
                Directory.CreateDirectory(folder);
                Outcome fetched = DownloadVerified(setup);
                if (fetched != Outcome.Installed) return fetched;

                // Hold the file open against writes while it is re-checked and started, so it can't change in between.
                using (new FileStream(setup, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (!IsSignedByMicrosoft(setup)) return Outcome.NotSignedByMicrosoft;

                    using var process = Process.Start(new ProcessStartInfo(setup, "/silent /install")
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        WorkingDirectory = folder,
                    });
                    if (process == null) return Outcome.InstallerFailed;
                    if (!process.WaitForExit((int)InstallTimeout.TotalMilliseconds))
                        return Outcome.TimedOut;
                }
                return IsRuntimeInstalled() ? Outcome.Installed : Outcome.InstallerFailed;
            }
            catch (Exception) { return Outcome.InstallerFailed; }
            finally
            {
                try { Directory.Delete(folder, recursive: true); } catch (Exception ex) { /* left for the user's temp clean-up */ BestEffort.Debug(ex, "WebView2Installer.DownloadAndInstall()"); }
            }
        }
    }
}
