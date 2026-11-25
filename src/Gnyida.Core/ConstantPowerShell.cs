using System;
using System.Diagnostics;

namespace Gnyida.Core
{
    /// <summary>
    /// Starts Windows PowerShell with a fixed, compile-time command. Caller data is passed only
    /// through <c>GNYIDA_ARG_n</c> environment variables and referenced as
    /// <c>$env:GNYIDA_ARG_n</c> inside the command, so it is never parsed as code.
    ///
    /// Replaces <c>-EncodedCommand</c>: same injection safety (the command text never contains
    /// caller data), without the encoded-command launch that sandbox engines score as a
    /// trojan/dropper behaviour, and that Gnyida's own rules treat as suspicious.
    /// </summary>
    internal static class ConstantPowerShell
    {
        internal const string ArgPrefix = "GNYIDA_ARG_";

        // Distinct name on purpose: an overload CreateStartInfo(fileName, command, params args) next to
        // CreateStartInfo(command, params args) makes a 2-string call bind to (fileName, command), which
        // would turn caller DATA into the command text (injection). Pinned by IndicatorCatalogTests.
        internal static ProcessStartInfo CreateStartInfoForPath(string fileName, string command, params string[] args)
        {
            if (string.IsNullOrWhiteSpace(command))
                throw new ArgumentException("PowerShell command must not be empty", nameof(command));
            // The command is wrapped in one pair of double quotes on the CreateProcess line.
            // A double quote or a trailing backslash inside it would change the argument split.
            if (command.IndexOf('"') >= 0 || command.EndsWith("\\", StringComparison.Ordinal))
                throw new ArgumentException("PowerShell command must not contain '\"' or end with '\\'", nameof(command));

            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = "-NoLogo -NoProfile -NonInteractive -Command \"" + command + "\"",
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            for (int i = 0; i < args.Length; i++)
                psi.EnvironmentVariables[ArgPrefix + i] = args[i] ?? string.Empty;
            return psi;
        }

        internal static ProcessStartInfo CreateStartInfo(string command, params string[] args)
            => CreateStartInfoForPath(SystemPowerShellPath, command, args);

        /// <summary>
        /// Windows PowerShell by full path. A bare "powershell.exe" is found through the application directory and PATH,
        /// and this is the entry point for every PowerShell call the service makes as SYSTEM.
        /// </summary>
        internal static string SystemPowerShellPath { get; } =
            System.IO.Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
    }
}
