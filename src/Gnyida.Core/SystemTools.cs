using System;
using System.IO;

namespace Gnyida.Core
{
    /// <summary>
    /// Full paths for the tools Gnyida runs. A bare name such as "netsh" or "docker" is resolved by CreateProcess
    /// through the application directory, the current directory and PATH, in an order that depends on registry and
    /// process state. The service runs as SYSTEM, so a binary that wins that search runs as SYSTEM. A full path
    /// removes the question.
    /// </summary>
    internal static class SystemTools
    {
        /// <summary>
        /// A tool that ships in the Windows system directory, for example "netsh.exe". The path is built, not searched,
        /// so it does not depend on the file existing on this machine; a missing tool fails at launch like before.
        /// </summary>
        internal static string System32(string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName) || fileName.IndexOfAny(new[] { '\\', '/', ':' }) >= 0)
                throw new ArgumentException("Expected a bare file name such as \"netsh.exe\".", nameof(fileName));
            return Path.Combine(Environment.SystemDirectory, fileName);
        }

        /// <summary>
        /// docker.exe from Docker Desktop's install location, or null when Docker is not installed there. Docker is not
        /// a Windows component, so there is no system-directory path; a null result means "skip", never "search PATH".
        /// </summary>
        internal static string? Docker() => ResolveDocker(
            Environment.GetEnvironmentVariable("ProgramW6432"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));

        internal static string? ResolveDocker(params string?[] programFilesRoots)
        {
            foreach (string? root in programFilesRoots)
            {
                if (string.IsNullOrWhiteSpace(root)) continue;
                string candidate = Path.Combine(root, "Docker", "Docker", "resources", "bin", "docker.exe");
                if (File.Exists(candidate)) return candidate;
            }
            return null;
        }
    }
}
