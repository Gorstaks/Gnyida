using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Sentinel.Core
{
    [RuleCategory(DetectionCategory.ProcessInjection)]
    public class ThreatIntelInjectionRule : IDetectionRule
    {
        public string Name => "ThreatIntelInjectionRule";

        private readonly Action<int, bool> _queueCandidate;
        private readonly BrowserSandboxPolicy.Classifier _classifyBrowser;
        public ThreatIntelInjectionRule() : this(InjectionSuspectBoard.Mark) { }
        internal ThreatIntelInjectionRule(Action<int, bool> queueCandidate)
            : this(queueCandidate, BrowserSandboxPolicy.Classify) { }
        internal ThreatIntelInjectionRule(Action<int, bool> queueCandidate, BrowserSandboxPolicy.Classifier classifyBrowser)
        {
            _queueCandidate = queueCandidate ?? throw new ArgumentNullException(nameof(queueCandidate));
            _classifyBrowser = classifyBrowser ?? throw new ArgumentNullException(nameof(classifyBrowser));
        }

        // Browsers legitimately use cross-process memory APIs for their sandbox model
        // (broker process allocates memory in renderer/tab processes). Skip to avoid FP kills.
        private static readonly HashSet<string> KnownBrowserProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "iexplore",
            "msedgewebview2", "electron"
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is not ThreatIntelTelemetry tit)
                return null;

            if (!ThreatIntelMap.IsRemoteInjection(tit.ApiName))
                return null;

            // Suppressing a noisy API observation is not trust for its target.
            // Memory inspection stays off the ETW callback and retains CanInspect gates.
            _queueCandidate(tit.ProcessId, true);
            if (tit.TargetProcessId > 4) _queueCandidate(tit.TargetProcessId, true);

            // Browser sandbox: chrome->chrome is normal. The exemption used to rest on the caller's NAME alone,
            // so a binary called chrome.exe, or a real browser writing into an unrelated process, was exempt.
            // BrowserSandboxPolicy now requires the real signed browser image AND a target in the same family.
            var callerName = tit.ProcessName ?? "";
            if (callerName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                callerName = callerName.Substring(0, callerName.Length - 4);
            if (KnownBrowserProcesses.Contains(callerName))
            {
                var browser = _classifyBrowser(tit);
                if (browser == BrowserSandboxPolicy.Verdict.SandboxModel) return null;
                if ((browser == BrowserSandboxPolicy.Verdict.GenuineBrowserForeignTarget ||
                     browser == BrowserSandboxPolicy.Verdict.UnverifiedSameFamily) &&
                    tit.TargetProcessId > 4 && !IsSensitiveTargetName(tit.TargetProcessId))
                {
                    // A signed browser is not killed on this signal alone, but it must not be invisible either.
                    _queueCandidate(tit.TargetProcessId, false);
                    return new DetectionEvent
                    {
                        RuleName = browser == BrowserSandboxPolicy.Verdict.UnverifiedSameFamily
                            ? "Injection: Unverified Browser-Named Process Calls Into Its Own Family"
                            : "Injection: Browser Calls Into Unrelated Process",
                        ProcessName = tit.ProcessName ?? "",
                        ProcessId = tit.ProcessId,
                        SignalType = SignalType.ProcessInjection,
                        Confidence = 0.60,
                        Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        Evidence = browser == BrowserSandboxPolicy.Verdict.UnverifiedSameFamily
                            ? $"{tit.ProcessName} (PID {tit.ProcessId}) is not the signed browser it is named after, and used {ThreatIntelMap.Describe(tit.ApiName)} on PID {tit.TargetProcessId} of the same name. Normal for an unsigned Chromium build; also what a binary posing as the browser would do."
                            : $"Genuine browser {tit.ProcessName} (PID {tit.ProcessId}) used {ThreatIntelMap.Describe(tit.ApiName)} on PID {tit.TargetProcessId}, which is not part of its own process family.",
                        Reasoning = "Browsers use cross-process memory calls only between their own broker and renderer processes. This call targets an unrelated process, which is how a compromised browser would be used to inject. Logged without a kill because the caller is the signed browser.",
                        Metadata = new Dictionary<string, string> { { "TargetProcessId", tit.TargetProcessId.ToString() }, { "WeakObserveSeed", "true" } }
                    };
                }
                // Masquerade, or a browser aimed at System/lsass-class targets: the normal kill-grade path below.
            }

            var imagePath = SecurityValidation.GetProcessImagePath(tit.ProcessId);
            if (AlwaysOnPolicies.IsProtectedGamePath(imagePath))
                return null;

            _queueCandidate(tit.ProcessId, false);
            if (tit.TargetProcessId > 4) _queueCandidate(tit.TargetProcessId, false);

            var label = ThreatIntelMap.Describe(tit.ApiName);
            return new DetectionEvent
            {
                RuleName = Name,
                ProcessName = tit.ProcessName ?? "",
                ProcessId = tit.ProcessId,
                SignalType = SignalType.ProcessInjection,
                Family = TerminalFamily.Injection,
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.QuarantineAndKill,
                Evidence = $"Injection TI {label} by {tit.ProcessName} (PID {tit.ProcessId}) targeting PID {tit.TargetProcessId}",
                Reasoning = "Kernel Threat-Intelligence observed a remote memory/thread API (T1055).",
                Metadata = new Dictionary<string, string>
                {
                    { "TargetProcessId", tit.TargetProcessId.ToString() },
                    { "ApiName", tit.ApiName },
                    { "TiLabel", label }
                }
            };
        }

        private static bool IsSensitiveTargetName(int pid)
        {
            try
            {
                using var p = System.Diagnostics.Process.GetProcessById(pid);
                var n = p.ProcessName ?? "";
                return n.Equals("lsass", StringComparison.OrdinalIgnoreCase)
                    || n.Equals("winlogon", StringComparison.OrdinalIgnoreCase)
                    || n.Equals("csrss", StringComparison.OrdinalIgnoreCase)
                    || n.Equals("services", StringComparison.OrdinalIgnoreCase)
                    || n.Equals("smss", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }
    }


    [RuleCategory(DetectionCategory.ProcessInjection)]
    public class DllSideloadingDetectionRule : IDetectionRule
    {
        public string Name => "DllSideloadingDetectionRule";

        private static readonly HashSet<string> SystemToolNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "onedrive", "msoju", "winword", "excel", "powershell", "cmd"
        };

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (context.TriggeringEvent is ProcessTelemetry pt)
            {
                var path = pt.ImagePath.ToLowerInvariant();
                
                // Check if process runs out of user-writeable paths
                bool isUserWriteablePath = path.Contains(@"\users\") || 
                                           path.Contains(@"\appdata\") || 
                                           path.Contains(@"\temp\");

                if (isUserWriteablePath)
                {
                    // A binary whose NAME matches a Microsoft system tool but which runs from a
                    // user-writable path is a classic sideload/masquerade (T1574.002). The genuine
                    // tool lives in System32 / Program Files.
                    var procName = Sentinel.Core.StringNet48.ReplaceIgnoreCase(pt.ProcessName, ".exe", "");
                    // Case-insensitive: the real images are "OneDrive.exe" and "WINWORD.EXE", so the
                    // former lowercase-only compare let a masquerade with the genuine casing through.
                    bool isSystemToolName = SystemToolNames.Contains(procName);

                    if (isSystemToolName)
                    {
                        // Genuine per-user Microsoft installs (OneDrive lives in %LOCALAPPDATA%) are
                        // Microsoft-signed. The signer, not the path or name, is the anchor; an
                        // impostor cannot produce a valid Microsoft signature.
                        if (WindowsServicingTrust.IsMicrosoftSigned(pt.ImagePath))
                            return null;

                        // The developer-build exclusion (\bin\debug, \bin\release, .nuget) is a
                        // path fragment an attacker fully controls - dropping a fake "powershell.exe"
                        // under any "...\bin\debug\..." folder previously bypassed this KILL entirely.
                        // Per docs/constraints.md a path allow must combine with a
                        // non-attacker-controllable anchor. Only honor the dev-env skip when the
                        // binary is Authenticode-signed: a real signed tool a developer staged there
                        // is exonerated, but an UNSIGNED system-tool-named impostor in a dev path is
                        // still caught. (Developer build output is essentially never named after an
                        // OS system tool, so genuine dev binaries do not hit this branch at all.)
                        bool inDevEnvPath = path.Contains(@"\bin\debug") ||
                                            path.Contains(@"\bin\release") ||
                                            path.Contains(@".nuget");
                        if (inDevEnvPath && SecurityValidation.VerifyAuthenticodeSignature(pt.ImagePath))
                        {
                            return null;
                        }

                        return new DetectionEvent
                        {
                            RuleName = Name,
                            ProcessName = pt.ProcessName,
                            ProcessId = pt.ProcessId,
                            SignalType = SignalType.SuspiciousProcess,
                            Confidence = 0.85,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            Evidence = $"System-tool-named binary '{pt.ProcessName}' running from user-writeable path (not Authenticode-signed): {pt.ImagePath}",
                            Reasoning = "A binary named after a Microsoft system utility executed from an untrusted user-writeable directory without a valid Authenticode signature. The genuine tool lives in System32 / Program Files; a signed dev-staged copy is exempt. This is highly indicative of masquerade / DLL sideloading (T1574.002)."
                        };
                    }
                }
            }
            return null;
        }
    }

    // 
    // Full-Path Parent-Child Verification Rule  (SENT-003)
    // Ported from GorstaksProtection SuspiciousParentChildRule.cs
    // 

    /// <summary>
    /// Detects Office apps, browsers, and PDF readers spawning shells / scripting
    /// engines - with FULL PATH verification of the parent binary.
    ///
    /// Why full-path? Sentinel's AttackToolsRule matches parent by process name only,
    /// which an attacker can trivially spoof by naming malware "winword.exe".
    /// This rule also verifies that the parent lives in a known legitimate install
    /// path before firing - a winword.exe in C:\Temp\ is NOT a genuine Office install.
    ///
    /// Confidence: 0.75  ->  Tier2 / LogOnly (feeds BehavioralCorrelationEngine).
    /// The correlation engine promotes to Tier1 once additional signals arrive.
    /// </summary>
}
