using System;
using System.Collections.Generic;
using System.IO;

namespace Gnyida.Core
{
    /// <summary>
    /// Decides whether a running image is one an administrator approved for bulk file work.
    ///
    /// Legitimate software can look exactly like ransomware to a behaviour rule: file-encryption and
    /// data-loss-prevention agents rename user documents to a new extension, and migration or archive
    /// tools rewrite folders. The behaviour cannot tell them apart, so the administrator names the
    /// image. Trust is never granted on a name an attacker can pick. All three anchors must hold:
    ///   1. the OS-recorded image path equals an approved entry exactly, after resolving links;
    ///   2. the image sits in a location whose ACL only SYSTEM, Administrators and TrustedInstaller
    ///      can write (the DACL is read, not guessed from a folder name);
    ///   3. the image has a valid Authenticode signature.
    /// Approved entries come from the DPAPI-protected, admin-only <c>--set-config</c> channel.
    /// The check fails closed: any lookup failure means "not approved".
    /// </summary>
    internal static class ApprovedImageExemption
    {
        internal static bool Matches(
            string? imagePath,
            IReadOnlyList<string> approved,
            Func<string, string?> resolveFinalPath,
            Func<string, bool> isProtectedLocation,
            Func<string, bool> isSigned)
        {
            if (string.IsNullOrWhiteSpace(imagePath) || approved.Count == 0) return false;
            try
            {
                string resolved = resolveFinalPath(imagePath!) ?? Path.GetFullPath(imagePath!);
                foreach (var entry in approved)
                {
                    if (string.IsNullOrWhiteSpace(entry)) continue;
                    string expected = Path.GetFullPath(entry.Trim());
                    if (!string.Equals(resolved, expected, StringComparison.OrdinalIgnoreCase)) continue;
                    return isProtectedLocation(resolved) && isSigned(resolved);
                }
            }
            catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException || ex is IOException)
            {
                BestEffort.Debug(ex, "ApprovedImageExemption.Matches()");
            }
            return false;
        }

        /// <summary>Splits the stored list. '|' cannot appear in a Windows path, unlike ',' or ';'.</summary>
        internal static string[] Parse(string? stored) =>
            string.IsNullOrWhiteSpace(stored)
                ? Array.Empty<string>()
                : stored!.Split(new[] { '|' }, StringSplitOptions.RemoveEmptyEntries);
    }
}
