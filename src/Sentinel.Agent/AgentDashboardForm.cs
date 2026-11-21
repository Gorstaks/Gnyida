using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace Sentinel.Agent
{
    /// <summary>
    /// Thin shell form hosting an embedded browser that displays the Sentinel web dashboard
    /// served by <see cref="WebDashboardService"/> on localhost.
    ///
    /// The page needs the Edge/Chromium WebView2 control. Until 3.8 a host without the WebView2 Runtime fell back to
    /// the WinForms WebBrowser (IE11 emulation); the redesigned page uses CSS the IE engine can't render, so that host
    /// now gets a native panel that says what to install, instead of a broken window (graceful degradation, NFR-2).
    /// WebView2 ships with current Windows 10 and 11.
    ///
    /// v3.2.7: WebView2 types are isolated in <see cref="WebView2Host"/> so the CLR never
    /// JIT-compiles WebView2 method bodies when the assemblies are absent. Previously a
    /// TypeLoadException during JIT of TryStartWebView2() would escape the try/catch and crash
    /// the STA thread before the tray icon appeared.
    ///
    /// No async/await is used on the Agent STA thread (NFR-6): WebView2 initialization is driven
    /// via the CoreWebView2InitializationCompleted event, not awaited.
    /// </summary>
    public sealed class AgentDashboardForm : Form
    {
        private readonly string _launchUrl;
        private readonly string _version;

        public AgentDashboardForm(string version, string launchUrl)
        {
            _launchUrl = launchUrl;
            _version = version;

            Text = "Sentinel";
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(980, 640);
            Size = new Size(1200, 780);
            BackColor = Color.FromArgb(0x0D, 0x11, 0x17);
            ShowInTaskbar = true;
            FormBorderStyle = FormBorderStyle.Sizable;
            MaximizeBox = true;
            MinimizeBox = true;

            try
            {
                var icoPath = Path.Combine(AppContext.BaseDirectory, "Sentinel.ico");
                if (File.Exists(icoPath))
                    Icon = new Icon(icoPath);
                else
                    Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            }
            catch (Exception ex) { /* icon optional */ Sentinel.Core.BestEffort.Debug(ex, "AgentDashboardForm.AgentDashboardForm"); }

            Load += OnFormLoad;
        }

        private void OnFormLoad(object? sender, EventArgs e)
        {
            // v3.2.7: WebView2Host is a separately-compiled helper class. Calling it through a
            // method boundary means the CLR only JIT-compiles WebView2 method bodies if the
            // assemblies actually load. A TypeLoadException / BadImageFormatException raised here
            // is caught and degrades cleanly to the legacy browser — previously the exception
            // escaped the try/catch in TryStartWebView2 because it fired during JIT of that very
            // method, before execution reached the try block.
            bool webViewStarted = false;
            try
            {
                webViewStarted = WebView2Host.TryStart(this, _launchUrl, _version, OnFallbackRequested);
            }
            catch (Exception ex) when (IsWebView2AssemblyException(ex))
            {
                // WebView2 managed assemblies or native loader are absent. Degrade immediately.
                ReportWebView2Unavailable("assembly load failed: " + ex.GetBaseException().Message);
                MarkLegacyMode();
            }

            if (!webViewStarted)
                ShowWebView2Required();
        }

        // Called by WebView2Host on the STA thread when WebView2 init fails at runtime.
        private void OnFallbackRequested(string reason)
        {
            if (_fellBack) return;
            _fellBack = true;
            ReportWebView2Unavailable(reason);
            MarkLegacyMode();
            ShowWebView2Required();
        }

        private bool _fellBack;

        /// <summary>
        /// Returns true for exceptions that indicate the WebView2 managed assemblies or native
        /// loader could not be found or loaded — distinct from runtime-absent errors which
        /// ProbeWebView2Runtime inside WebView2Host handles separately.
        /// </summary>
        private static bool IsWebView2AssemblyException(Exception ex)
        {
            for (var e = ex; e != null; e = e.InnerException)
            {
                if (e is System.IO.FileNotFoundException ||
                    e is System.IO.FileLoadException ||
                    e is BadImageFormatException ||
                    e is TypeLoadException)
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Records that WebView2 is unavailable, so the window shows the install notice instead of the page.
        /// Written to agent_runtime.log (not agent_crash.log — this is a status notice, not a crash).
        /// </summary>
        private void ReportWebView2Unavailable(string reason)
        {
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var logPath = Path.Combine(programData, "Sentinel", "agent_runtime.log");
                var msg = $"[{DateTime.UtcNow:o}] [Info] WebView2 unavailable: {reason}. " +
                          "Settings window shows the install notice. " +
                          "Install the Microsoft Edge WebView2 Runtime (Evergreen) to use it." +
                          Environment.NewLine;
                File.AppendAllText(logPath, msg);
                System.Diagnostics.Trace.TraceWarning(
                    "Sentinel: WebView2 unavailable ({0}); settings window needs the WebView2 Runtime.", reason);
            }
            catch (Exception ex) { /* logging is best-effort */ Sentinel.Core.BestEffort.Debug(ex, "AgentDashboardForm.ReportWebView2Unavailable"); }
        }

        private void MarkLegacyMode()
        {
            try { Text = "Sentinel"; }
            catch (Exception ex) { /* cosmetic */ Sentinel.Core.BestEffort.Debug(ex, "AgentDashboardForm.MarkLegacyMode"); }
        }

        /// <summary>
        /// Shown when WebView2 can't start. Plain WinForms, so it works on any Windows. It deliberately offers no
        /// "open in your browser" link: the launch URL carries the session token, which would end up in browser history.
        /// </summary>
        private void ShowWebView2Required()
        {
            SuspendLayout();
            Controls.Clear();
            var panel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Padding = new Padding(48),
                BackColor = Color.FromArgb(0x11, 0x13, 0x18),
            };
            var title = new Label
            {
                Text = "This window needs Microsoft Edge WebView2", AutoSize = true, ForeColor = Color.FromArgb(0xEE, 0xF0, 0xF4),
                Font = new Font("Segoe UI", 16f, FontStyle.Bold), Margin = new Padding(0, 0, 0, 10),
            };
            var body = new Label
            {
                Text = "Sentinel shows its settings with WebView2, a free Microsoft component that comes with Windows 10 and 11. " +
                       "It isn't installed or working on this PC. Sentinel keeps protecting the PC either way; only this window is affected." +
                       Environment.NewLine + Environment.NewLine +
                       "Sentinel can install it for you. It downloads from Microsoft and installs only for your account, so no administrator approval is needed.",
                AutoSize = true, MaximumSize = new Size(620, 0), ForeColor = Color.FromArgb(0xA3, 0xA9, 0xB6),
                Font = new Font("Segoe UI", 10.5f), Margin = new Padding(0, 0, 0, 22),
            };
            var install = new Button
            {
                Text = "Install WebView2", AutoSize = true, FlatStyle = FlatStyle.Flat, Padding = new Padding(14, 6, 14, 6),
                BackColor = Color.FromArgb(0x5B, 0x9D, 0xFF), ForeColor = Color.White, Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            };
            install.FlatAppearance.BorderSize = 0;
            var progress = new Label
            {
                Text = "", AutoSize = true, MaximumSize = new Size(620, 0), ForeColor = Color.FromArgb(0xA3, 0xA9, 0xB6),
                Font = new Font("Segoe UI", 10f), Margin = new Padding(0, 14, 0, 0),
            };
            install.Click += (s, e) => InstallWebView2(install, progress);
            var close = new Button
            {
                Text = "Close", AutoSize = true, FlatStyle = FlatStyle.Flat, Padding = new Padding(14, 6, 14, 6), Margin = new Padding(0, 10, 0, 0),
                BackColor = Color.FromArgb(0x22, 0x26, 0x30), ForeColor = Color.FromArgb(0xEE, 0xF0, 0xF4), Font = new Font("Segoe UI", 10f),
            };
            close.FlatAppearance.BorderSize = 0;
            close.Click += (s, e) => Close();
            panel.Controls.Add(title, 0, 0);
            panel.Controls.Add(body, 0, 1);
            panel.Controls.Add(install, 0, 2);
            panel.Controls.Add(close, 0, 3);
            panel.Controls.Add(progress, 0, 4);
            Controls.Add(panel);
            ResumeLayout();
        }

        /// <summary>
        /// Installs WebView2 on a background thread (no async/await on the Agent STA thread, NFR-6), then tries to open
        /// the page again on the UI thread.
        /// </summary>
        private void InstallWebView2(Button install, Label progress)
        {
            install.Enabled = false;
            progress.Text = "Downloading WebView2 from Microsoft and installing it. This can take a minute...";
            System.Threading.Tasks.Task.Run(() => WebView2Installer.DownloadAndInstall()).ContinueWith(t =>
            {
                var outcome = t.Status == System.Threading.Tasks.TaskStatus.RanToCompletion ? t.Result : WebView2Installer.Outcome.InstallerFailed;
                try { BeginInvoke(new Action(() => AfterWebView2Install(outcome, install, progress))); }
                catch (InvalidOperationException ex) { /* window closed while installing */ Sentinel.Core.BestEffort.Debug(ex, "AgentDashboardForm.InstallWebView2"); }
            }, System.Threading.Tasks.TaskScheduler.Default);
        }

        private void AfterWebView2Install(WebView2Installer.Outcome outcome, Button install, Label progress)
        {
            if (IsDisposed) return;
            if (outcome == WebView2Installer.Outcome.Installed)
            {
                Controls.Clear();
                _fellBack = false;
                bool started = false;
                try { started = WebView2Host.TryStart(this, _launchUrl, _version, OnFallbackRequested); }
                catch (Exception ex) when (IsWebView2AssemblyException(ex)) { started = false; }
                if (!started)
                {
                    ShowWebView2Required();
                    MessageBox.Show(this, "WebView2 is installed. Close this window and open Sentinel again from the tray icon.",
                        "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                return;
            }
            install.Enabled = true;
            progress.Text = outcome switch
            {
                WebView2Installer.Outcome.DownloadFailed => "The download didn't work. Check your internet connection and try again.",
                WebView2Installer.Outcome.NotSignedByMicrosoft => "The downloaded file wasn't signed by Microsoft, so Sentinel didn't run it. Try again later.",
                WebView2Installer.Outcome.TimedOut => "The installer is taking unusually long. It may still finish; reopen Sentinel in a few minutes.",
                _ => "The installer didn't finish. You can also get WebView2 from microsoft.com/edge/webview2.",
            };
        }

        /// <summary>
        /// Opens the specified folder in Explorer. Used by TrayIconService context menu.
        /// </summary>
        internal static void OpenFolder(string path)
        {
            try
            {
                if (!Directory.Exists(path))
                {
                    MessageBox.Show(
                        $"Folder does not exist yet:\n{path}",
                        "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = path,
                    UseShellExecute = true,
                    Verb = "open"
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Could not open folder:\n{path}\n\n{ex.Message}",
                    "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

    }
}
