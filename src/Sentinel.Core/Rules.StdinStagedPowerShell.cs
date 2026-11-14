using System;
using System.Collections.Generic;
using System.IO;

namespace Sentinel.Core
{
    /// <summary>
    /// PowerShell started with a command that builds and runs code it reads from standard input
    /// (or from <c>$input</c>), so the real script never appears on the command line. This is the
    /// pattern AV behavior shields score as a command-line stager (Avast IDP.HELU.PSE*). Avast's
    /// verdict on this host came from Sentinel's own firewall bridge, which uses the same shape;
    /// that child is still reported, coalesced through <see cref="ManagementChildRegistry"/> only
    /// when its kernel identity is verified. Tier2 / LogOnly: the shape alone is not kill-grade.
    /// </summary>
    [RuleCategory(DetectionCategory.FilelessAttack)]
    public sealed class StdinStagedPowerShellRule : IDetectionRule
    {
        internal const string RuleTitle = "PowerShell: Code Staged Through Standard Input";
        public string Name => "StdinStagedPowerShellRule";

        public DetectionEvent? Evaluate(FusedTelemetryContext context)
        {
            if (!(context.TriggeringEvent is ProcessTelemetry process) || process.ProcessId <= 4) return null;
            var reason = Match(process.ImagePath, process.CommandLine);
            if (reason == null) return null;
            var cmd = process.CommandLine ?? string.Empty;
            return new DetectionEvent
            {
                RuleName = RuleTitle,
                ProcessId = process.ProcessId,
                ProcessName = process.ProcessName,
                Confidence = 0.60,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                SignalType = SignalType.SecurityEvasion,
                Evidence = $"PowerShell PID {process.ProcessId} (parent {process.ParentProcessName} PID {process.ParentProcessId}) {reason}. Command: '{cmd.Substring(0, Math.Min(400, cmd.Length))}'",
                Reasoning = "The command line only loads code from standard input and runs it, so the script itself is hidden from command-line logging. Droppers and loaders use this. Some admin tools do too, so this is reported for review and no response is taken.",
                Metadata = new Dictionary<string, string>
                {
                    ["ParentProcessId"] = process.ParentProcessId.ToString(),
                    ["Technique"] = "T1059.001",
                    ["WeakObserveSeed"] = "true",
                },
            };
        }

        /// <summary>Returns why the command is stdin-staged, or null. Pure function for tests.</summary>
        internal static string? Match(string? imagePath, string? commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return null;
            var cmd = commandLine!.ToLowerInvariant();
            var image = Path.GetFileName(imagePath ?? string.Empty).ToLowerInvariant();
            bool isPowerShell = image == "powershell.exe" || image == "pwsh.exe"
                || (image.Length == 0 && (cmd.Contains("powershell") || cmd.Contains("pwsh")));
            if (!isPowerShell) return null;
            var compact = cmd.Replace(" ", string.Empty);
            bool readsStdin = compact.Contains("[console]::in.readtoend()") || compact.Contains("[console]::in.readline()")
                || compact.Contains("[console]::openstandardinput()") || compact.Contains("$input|");
            bool runsCode = compact.Contains("[scriptblock]::create(") || compact.Contains("invoke-expression")
                || compact.Contains("|iex") || compact.Contains("iex(") || compact.Contains(".invoke(");
            if (readsStdin && runsCode) return "runs code it reads from standard input";
            // "-Command -" / "-File -" makes powershell.exe read the whole script from stdin.
            if (cmd.TrimEnd().EndsWith(" -command -", StringComparison.Ordinal) || cmd.TrimEnd().EndsWith(" -c -", StringComparison.Ordinal)
                || cmd.TrimEnd().EndsWith(" -file -", StringComparison.Ordinal))
                return "reads its whole script from standard input";
            return null;
        }
    }
}