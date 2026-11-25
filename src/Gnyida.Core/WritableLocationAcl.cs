using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Gnyida.Core
{
    /// <summary>
    /// Answers "can a non-administrator plant or replace a file here?" from the real DACL instead of a
    /// fixed list of folder names. A folder name is attacker-chosen and a list only knows the holes
    /// that were already found; the ACL is the anchor an attacker cannot change without admin rights.
    /// Same principal and rights rules as <see cref="InstallDirectoryPolicy"/>: SYSTEM, Administrators
    /// and TrustedInstaller are trusted, any other allow ACE carrying a write-like right is a hole.
    /// Fail closed: an ACL that cannot be read is reported as not protected.
    /// Stateless and pure apart from the ACL read, so callers can cache per directory if they need to.
    /// </summary>
    public static class WritableLocationAcl
    {
        /// <summary>
        /// True when <paramref name="security"/> grants a write-like right to a principal other than
        /// SYSTEM, Administrators or TrustedInstaller on the object itself. Inherit-only entries do not
        /// apply to the object and are skipped. Deny entries are ignored, which can only over-report.
        /// </summary>
        public static bool GrantsNonAdminWrite(FileSystemSecurity security, out string? sid)
        {
            sid = null;
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType != AccessControlType.Allow) continue;
                if ((rule.PropagationFlags & PropagationFlags.InheritOnly) != 0) continue;
                if ((rule.FileSystemRights & InstallDirectoryPolicy.WriteLike) == 0) continue;
                var id = (SecurityIdentifier)rule.IdentityReference;
                if (InstallDirectoryPolicy.IsTrusted(id)) continue;
                sid = id.Value;
                return true;
            }
            return false;
        }

        private static readonly WellKnownSidType[] BroadPrincipals =
        {
            WellKnownSidType.WorldSid, WellKnownSidType.AuthenticatedUserSid, WellKnownSidType.BuiltinUsersSid,
            WellKnownSidType.InteractiveSid, WellKnownSidType.BuiltinGuestsSid, WellKnownSidType.NetworkSid,
            WellKnownSidType.AnonymousSid,
        };

        /// <summary>
        /// True for groups every standard user (or every logon) belongs to. A write grant to one of these
        /// means any non-admin process can plant, as opposed to a single service SID or LocalService that
        /// Windows grants by design (for example the Print Spooler's service SID on its driver files).
        /// </summary>
        public static bool IsBroadPrincipal(SecurityIdentifier sid)
        {
            foreach (var kind in BroadPrincipals)
                if (sid.IsWellKnown(kind)) return true;
            return false;
        }

        /// <summary>
        /// Like <see cref="GrantsNonAdminWrite"/> but only counts <see cref="IsBroadPrincipal"/> groups.
        /// Used by the system-file drift monitor so by-design service-SID grants do not raise findings.
        /// </summary>
        public static bool GrantsBroadWrite(FileSystemSecurity security, out string? sid)
        {
            sid = null;
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType != AccessControlType.Allow) continue;
                if ((rule.PropagationFlags & PropagationFlags.InheritOnly) != 0) continue;
                if ((rule.FileSystemRights & InstallDirectoryPolicy.WriteLike) == 0) continue;
                var id = (SecurityIdentifier)rule.IdentityReference;
                if (!IsBroadPrincipal(id)) continue;
                sid = id.Value;
                return true;
            }
            return false;
        }
        /// <summary>
        /// Checks the file (when <paramref name="path"/> is an existing file) and the directory that
        /// contains it, or the nearest existing ancestor when the path does not exist.
        /// <see cref="InstallDirectoryPolicy.Result.Ok"/> is true only when the location is proven
        /// protected; the reason names the offending SID or the read failure.
        /// </summary>
        public static InstallDirectoryPolicy.Result Evaluate(string? path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return new InstallDirectoryPolicy.Result(false, "Path is empty.");
            try
            {
                var full = Path.GetFullPath(path!).TrimEnd('\\');
                if (File.Exists(full))
                {
                    var fileVerdict = Check(new FileInfo(full).GetAccessControl(), full);
                    if (!fileVerdict.Ok) return fileVerdict;
                    full = Path.GetDirectoryName(full) ?? string.Empty;
                }

                while (full.Length > 0 && !Directory.Exists(full))
                    full = Path.GetDirectoryName(full) ?? string.Empty;
                if (full.Length == 0)
                    return new InstallDirectoryPolicy.Result(false, "No existing directory on the path.");

                return Check(new DirectoryInfo(full).GetAccessControl(), full);
            }
            catch (Exception ex)
            {
                return new InstallDirectoryPolicy.Result(false, "ACL could not be verified: " + ex.Message);
            }
        }

        /// <summary>True when the location is not proven protected (writable by a non-admin, or unreadable).</summary>
        public static bool IsWritableByNonAdmin(string? path) => !Evaluate(path).Ok;

        private static InstallDirectoryPolicy.Result Check(FileSystemSecurity security, string where)
            => GrantsNonAdminWrite(security, out var sid)
                ? new InstallDirectoryPolicy.Result(false, where + " grants write access to " + sid + ".")
                : new InstallDirectoryPolicy.Result(true, "Protected.");
    }
}
