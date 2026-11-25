using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;

namespace Gnyida.Core
{
    /// <summary>
    /// Decides whether a cross-process memory call from a browser-named process is the browser's own sandbox
    /// model (the broker allocating in its own renderer) or something else.
    ///
    /// Before this policy <see cref="ThreatIntelInjectionRule"/> exempted any caller whose process NAME was a
    /// browser, to any non-sensitive target. A malware binary called chrome.exe was exempt from a kill-grade
    /// rule, and so was a real browser writing into an unrelated process. Now both conditions must hold:
    /// the caller's image is the real browser (valid Authenticode signature from the browser's publisher), and
    /// the target process belongs to the same browser family.
    ///
    /// Bounded state: the signature cache is keyed on image path (a handful of distinct browser paths), capped
    /// and expiring, so it cannot grow with PIDs or events.
    /// </summary>
    internal static class BrowserSandboxPolicy
    {
        private sealed class Family
        {
            public string Name = "";
            public string[] Publishers = Array.Empty<string>();
            public bool AnySignature;
        }

        private static readonly Dictionary<string, Family> ByProcess = Build();

        private static Dictionary<string, Family> Build()
        {
            var chrome = new Family { Name = "chrome", Publishers = new[] { "Google LLC" } };
            var edge = new Family { Name = "edge", Publishers = new[] { "Microsoft Corporation", "Microsoft Windows" } };
            var firefox = new Family { Name = "firefox", Publishers = new[] { "Mozilla Corporation" } };
            var brave = new Family { Name = "brave", Publishers = new[] { "Brave Software, Inc." } };
            var opera = new Family { Name = "opera", Publishers = new[] { "Opera Norway AS", "Opera Software AS" } };
            var vivaldi = new Family { Name = "vivaldi", Publishers = new[] { "Vivaldi Technologies AS" } };
            // Electron apps carry their own publisher; only a valid signature is required.
            var electron = new Family { Name = "electron", AnySignature = true };
            return new Dictionary<string, Family>(StringComparer.OrdinalIgnoreCase)
            {
                ["chrome"] = chrome,
                ["msedge"] = edge, ["msedgewebview2"] = edge, ["iexplore"] = edge,
                ["firefox"] = firefox, ["brave"] = brave, ["opera"] = opera, ["vivaldi"] = vivaldi,
                ["electron"] = electron,
            };
        }

        internal static string Normalize(string? processName)
        {
            string name = (processName ?? "").Trim();
            if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) name = name.Substring(0, name.Length - 4);
            return name;
        }

        /// <summary>True when the two process names belong to the same browser family (chrome to chrome, msedge to msedgewebview2).</summary>
        internal static bool SameFamily(string? callerName, string? targetName)
        {
            return ByProcess.TryGetValue(Normalize(callerName), out var caller) &&
                   ByProcess.TryGetValue(Normalize(targetName), out var target) &&
                   ReferenceEquals(caller, target);
        }

        /// <summary>
        /// Pure publisher check, separated so it can be tested without signing a binary.
        /// </summary>
        internal static bool PublisherMatches(string callerName, string? publisher)
        {
            if (!ByProcess.TryGetValue(Normalize(callerName), out var family)) return false;
            if (family.AnySignature) return !string.IsNullOrWhiteSpace(publisher);
            if (string.IsNullOrWhiteSpace(publisher)) return false;
            foreach (string expected in family.Publishers)
                if (string.Equals(publisher!.Trim(), expected, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static readonly ConcurrentDictionary<string, (bool Genuine, DateTime At)> Cache = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(10);
        private const int CacheCap = 64;

        /// <summary>The real browser: file name matches, signature is valid, publisher is the browser's.</summary>
        internal static bool IsGenuineImage(int pid, string callerName)
        {
            string? path = SecurityValidation.GetProcessImagePath(pid);
            if (string.IsNullOrEmpty(path)) return false;
            if (!string.Equals(Path.GetFileNameWithoutExtension(path), Normalize(callerName), StringComparison.OrdinalIgnoreCase)) return false;
            if (Cache.TryGetValue(path!, out var cached) && DateTime.UtcNow - cached.At < CacheTtl) return cached.Genuine;
            bool genuine = false;
            try
            {
                genuine = SecurityValidation.VerifyAuthenticodeSignature(path!) &&
                          PublisherMatches(callerName, SecurityValidation.TryGetAuthenticodePublisher(path!));
            }
            catch (Exception) { genuine = false; }
            if (Cache.Count >= CacheCap) Cache.Clear(); // a few paths in practice; clearing keeps the bound hard
            Cache[path!] = (genuine, DateTime.UtcNow);
            return genuine;
        }

        internal enum Verdict
        {
            /// <summary>Genuine browser calling into its own family: the sandbox model.</summary>
            SandboxModel,
            /// <summary>Genuine browser image writing into a process that is not part of its family.</summary>
            GenuineBrowserForeignTarget,
            /// <summary>
            /// The caller carries a browser's name but is not the signed browser, and it only touches its own family.
            /// This is what an unsigned Chromium build (Puppeteer, Playwright, a developer build) does all day, so it is
            /// reported without a kill. It is also what malware named chrome.exe would do to a real chrome, which is why
            /// it is not exempt.</summary>
            UnverifiedSameFamily,
            /// <summary>The caller only carries a browser's name and aims at something outside that family.</summary>
            Masquerade,
        }

        /// <summary>Seam so rule tests do not need real signed browsers.</summary>
        internal delegate Verdict Classifier(ThreatIntelTelemetry telemetry);

        internal static Verdict Classify(ThreatIntelTelemetry tit)
        {
            string callerName = tit.ProcessName ?? "";
            bool genuine = IsGenuineImage(tit.ProcessId, callerName);
            string targetName = "";
            if (tit.TargetProcessId > 4)
            {
                try
                {
                    using var target = System.Diagnostics.Process.GetProcessById(tit.TargetProcessId);
                    targetName = target.ProcessName ?? "";
                }
                catch (Exception ex) { /* target gone or unreadable: treated as foreign below */ BestEffort.Debug(ex, "BrowserSandboxPolicy.Classify()"); }
            }
            bool same = SameFamily(callerName, targetName);
            if (genuine) return same ? Verdict.SandboxModel : Verdict.GenuineBrowserForeignTarget;
            return same ? Verdict.UnverifiedSameFamily : Verdict.Masquerade;
        }
    }
}
