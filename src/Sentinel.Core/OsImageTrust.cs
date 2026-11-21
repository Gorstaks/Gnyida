using System.IO;

namespace Sentinel.Core
{
    /// <summary>
    /// Decides whether a process image is a genuine OS binary. A folder under the Windows directory is
    /// not proof by itself: <c>Tasks</c>, <c>Temp</c>, <c>tracing</c>, spool color and similar folders are
    /// writable by standard users, so an attacker can drop <c>svchost.exe</c> there. The anchors are the
    /// ones an attacker cannot change without administrator rights: the real DACL of the location and a
    /// valid Authenticode (embedded or catalog) signature. Stateless; the signature check is injected so
    /// the decision is testable without a live system.
    /// </summary>
    internal static class OsImageTrust
    {
        /// <summary>
        /// True when <paramref name="imagePath"/> sits under <paramref name="windowsRoot"/>, is not a known
        /// default-writable drop, and its file/directory ACL grants non-administrators no write access.
        /// </summary>
        public static bool IsProtectedWindowsLocation(string? imagePath, string windowsRoot)
        {
            if (string.IsNullOrWhiteSpace(imagePath) || string.IsNullOrWhiteSpace(windowsRoot)) return false;
            try
            {
                string full = Path.GetFullPath(imagePath!);
                string root = Path.GetFullPath(windowsRoot).TrimEnd('\\') + "\\";
                if (!full.StartsWith(root, System.StringComparison.OrdinalIgnoreCase)) return false;
                return ModuleIdentity.IsKeepTree(full)
                    && !ModuleIdentity.IsUserWritableDrop(full)
                    && !WritableLocationAcl.IsWritableByNonAdmin(full);
            }
            catch (System.Exception ex)
            {
                // Fail closed: a path that cannot be normalized or evaluated is not proven protected.
                BestEffort.Debug(ex, "OsImageTrust.IsProtectedWindowsLocation");
                return false;
            }
        }

        /// <summary>Protected Windows location and a valid signature.</summary>
        public static bool IsSignedWindowsImage(string? imagePath, string windowsRoot, System.Func<string, bool> isSigned)
        {
            if (!IsProtectedWindowsLocation(imagePath, windowsRoot)) return false;
            try
            {
                return isSigned(imagePath!);
            }
            catch (System.Exception ex)
            {
                BestEffort.Debug(ex, "OsImageTrust.IsSignedWindowsImage");
                return false;
            }
        }
    }
}
