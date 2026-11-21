using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
namespace Sentinel.Core
{
    /// <summary>
    /// Browser redirect guard (observe-only). Reports a change to the settings a hijacker uses to
    /// send a user somewhere else: Chrome/Edge policy for home page, startup pages, default search
    /// engine and proxy, and the default handler for http/https. Existing guards already cover the
    /// hosts file, system proxy, DNS and forced extensions. Tier2 / LogOnly; no setting is rewritten.
    /// </summary>
    public sealed class BrowserRedirectGuard : BackgroundService
    {
        private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);
        private static readonly string[] PolicyRoots =
        {
            @"Software\Policies\Google\Chrome",
            @"Software\Policies\Microsoft\Edge",
        };
        private static readonly string[] PolicyValues =
        {
            "HomepageLocation", "HomepageIsNewTabPage", "NewTabPageLocation", "RestoreOnStartup",
            "DefaultSearchProviderEnabled", "DefaultSearchProviderSearchURL", "DefaultSearchProviderName",
            "ProxyMode", "ProxyServer", "ProxyPacUrl",
        };
        private static readonly string[] UrlSchemes = { "http", "https" };
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<BrowserRedirectGuard> _logger;
        public BrowserRedirectGuard(DetectionEngine detectionEngine, ILogger<BrowserRedirectGuard> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BrowserRedirectGuard] Started (observe-only)");
            Dictionary<string, string>? previous = null;
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var current = Snapshot();
                    if (previous != null)
                    {
                        foreach (var change in Diff(previous, current))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Browser Redirect: Home/Search/Proxy/Default-Handler Setting Changed",
                                Evidence = change,
                                Reasoning = "A setting that controls where the browser starts, searches or sends web links changed. Hijackers use these to redirect a user. Review the change if you did not make it. No response is taken.",
                                Confidence = 0.55,
                                Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM",
                                ProcessId = 0,
                            });
                        }
                    }
                    previous = current;
                    await Task.Delay(Interval, ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[BrowserRedirectGuard] pass failed"); try { await Task.Delay(Interval, ct); } catch (OperationCanceledException) { break; } }
            }
        }
        /// <summary>One line per added, removed or changed setting. Empty when nothing changed.</summary>
        internal static List<string> Diff(IReadOnlyDictionary<string, string> previous, IReadOnlyDictionary<string, string> current)
        {
            var changes = new List<string>();
            foreach (var kv in current)
            {
                if (!previous.TryGetValue(kv.Key, out var old)) changes.Add($"{kv.Key} added: '{kv.Value}'");
                else if (!string.Equals(old, kv.Value, StringComparison.Ordinal)) changes.Add($"{kv.Key} changed: '{old}' -> '{kv.Value}'");
            }
            foreach (var kv in previous)
                if (!current.ContainsKey(kv.Key)) changes.Add($"{kv.Key} removed (was '{kv.Value}')");
            return changes;
        }
        private static Dictionary<string, string> Snapshot()
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try { AddPolicies(map, "HKLM", Registry.LocalMachine, string.Empty); } catch (Exception ex) { BestEffort.Debug(ex, "BrowserRedirectGuard.Snapshot()"); }
            string[] sids;
            try { sids = Registry.Users.GetSubKeyNames(); } catch (Exception) { sids = Array.Empty<string>(); }
            foreach (var sid in sids.Where(s => !s.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)))
            {
                try
                {
                    AddPolicies(map, "HKU\\" + sid, Registry.Users, sid + "\\");
                    foreach (var scheme in UrlSchemes)
                    {
                        using var k = Registry.Users.OpenSubKey(sid + @"\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\" + scheme + @"\UserChoice");
                        var prog = k?.GetValue("ProgId")?.ToString();
                        if (prog != null) map[$"HKU\\{sid} default {scheme} handler"] = prog;
                    }
                }
                catch (Exception ex) { /* a user hive that cannot be read is skipped for this pass */ BestEffort.Debug(ex, "BrowserRedirectGuard.Snapshot()"); }
            }
            return map;
        }
        private static void AddPolicies(Dictionary<string, string> map, string label, RegistryKey hive, string prefix)
        {
            foreach (var root in PolicyRoots)
            {
                using var key = hive.OpenSubKey(prefix + root);
                if (key == null) continue;
                foreach (var name in PolicyValues)
                {
                    var v = key.GetValue(name);
                    if (v != null) map[$"{label}\\{root}\\{name}"] = v.ToString() ?? string.Empty;
                }
                using var startup = key.OpenSubKey("RestoreOnStartupURLs");
                if (startup == null) continue;
                foreach (var n in startup.GetValueNames())
                    map[$"{label}\\{root}\\RestoreOnStartupURLs\\{n}"] = startup.GetValue(n)?.ToString() ?? string.Empty;
            }
        }
    }
}