using System;
using System.IO;

namespace Gnyida.Agent
{
    /// <summary>
    /// The Gnyida settings window. The page is the embedded resource Dashboard/dashboard.html (plain HTML, CSS and
    /// JavaScript, so it can be edited and previewed as a normal file), loaded once and cached.
    ///
    /// The page never contains a secret: the bearer token reaches it only through sessionStorage after the tray launch
    /// (see DashboardRequestGuard.BootstrapHtml).
    /// </summary>
    public static class DashboardHtml
    {
        internal const string ResourceName = "Gnyida.Agent.Dashboard.dashboard.html";

        private static readonly Lazy<string> Page = new Lazy<string>(Load);

        public static string GetHtml() => Page.Value;

        private static string Load()
        {
            using Stream? stream = typeof(DashboardHtml).Assembly.GetManifestResourceStream(ResourceName);
            if (stream == null)
                throw new InvalidOperationException("Dashboard page resource '" + ResourceName + "' is missing from the build.");
            using var reader = new StreamReader(stream, System.Text.Encoding.UTF8);
            return reader.ReadToEnd();
        }
    }
}