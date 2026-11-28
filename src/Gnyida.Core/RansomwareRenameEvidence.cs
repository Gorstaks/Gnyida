using System;
using System.Collections.Generic;
using System.IO;

namespace Gnyida.Core
{
    /// <summary>
    /// Result of analysing a window of file renames for encryption-style damage.
    /// </summary>
    public sealed class RenameEvidence
    {
        public int Total { get; init; }
        public int UserDataSources { get; init; }
        public int DistinctDirectories { get; init; }
        /// <summary>Most common new extension among type-changing renames, or empty.</summary>
        public string DominantNewExtension { get; init; } = "";
        public int DominantCount { get; init; }
        public int DominantDistinctSourceExtensions { get; init; }
        /// <summary>Many different file types were all renamed to one new extension.</summary>
        public bool Funnel { get; init; }
        /// <summary>Most renamed files were user documents and each lost its type.</summary>
        public bool TypeChange { get; init; }
        public bool HasDamagePattern => Funnel || TypeChange;
    }

    /// <summary>
    /// Metadata-only test for "this burst of renames is destroying user files". No file is opened.
    ///
    /// A raw rename count cannot tell ransomware from an installer, a build, an OS-image tool or a
    /// backup job. What separates them is what the renames DO to file identity:
    ///   - Funnel: many different source extensions all end up with one new extension
    ///     (report.docx, photo.jpg, data.xlsx -> *.locked). Installers and builds rename
    ///     one temp extension to many final ones, which is the opposite shape.
    ///   - TypeChange: most renamed files are user documents and every one of them loses its type.
    /// Renames that keep the extension (moves, folder reorganisation, sync clients) never count.
    /// Neither signal depends on process name, path or signer, so a renamed binary gains nothing.
    /// </summary>
    public static class RansomwareRenameEvidence
    {
        /// <summary>Minimum renames in one window before pattern evidence can authorise a kill.</summary>
        public const int MinRenamesForEvidence = 25;

        private const double DominantShare = 0.50;
        private const double UserDataShare = 0.70;
        private const double TypeLossShare = 0.80;
        private const int MinDistinctSourceExtensions = 3;

        // User files whose loss matters. Deliberately data formats, not code or installer payloads.
        private static readonly HashSet<string> UserDataExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".doc", ".docx", ".docm", ".dot", ".dotx", ".xls", ".xlsx", ".xlsm", ".xlsb", ".ppt", ".pptx", ".pptm",
            ".pdf", ".odt", ".ods", ".odp", ".rtf", ".txt", ".csv", ".md", ".one", ".vsd", ".vsdx", ".pub",
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".raw", ".cr2", ".nef", ".psd", ".ai",
            ".mp3", ".wav", ".flac", ".mp4", ".mov", ".avi", ".mkv", ".wmv",
            ".zip", ".rar", ".7z", ".tar", ".gz",
            ".sql", ".mdb", ".accdb", ".db", ".sqlite", ".mdf", ".ndf", ".ldf", ".dbf", ".bak", ".pst", ".ost",
            ".vmdk", ".vhd", ".vhdx", ".vdi", ".dwg", ".dxf", ".kdbx",
        };

        // Extensions that ordinary tools put on files while working. Never evidence of damage.
        private static readonly HashSet<string> BenignTargetExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".tmp", ".temp", ".bak", ".old", ".orig", ".part", ".partial", ".crdownload", ".download",
            ".swp", ".swx", ".lock", ".log", ".new", ".prev", ".1", ".2", ".3",
        };

        public static bool IsUserDataExtension(string? ext) => !string.IsNullOrEmpty(ext) && UserDataExtensions.Contains(ext!);

        /// <summary>
        /// Analyses renames given as (old path, new path). Entries with an empty path are skipped.
        /// <paramref name="totalRenames"/> may exceed the sample size when the caller caps retained records.
        /// </summary>
        public static RenameEvidence Evaluate(IReadOnlyList<(string OldPath, string NewPath)> renames, int? totalRenames = null)
        {
            int sampled = 0, userData = 0, typeChanging = 0, userDataLost = 0;
            var dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var byNewExt = new Dictionary<string, (int Count, HashSet<string> Sources)>(StringComparer.OrdinalIgnoreCase);

            foreach (var (oldPath, newPath) in renames)
            {
                if (string.IsNullOrEmpty(oldPath) || string.IsNullOrEmpty(newPath)) continue;
                string oldExt, newExt;
                try
                {
                    oldExt = Path.GetExtension(oldPath) ?? "";
                    newExt = Path.GetExtension(newPath) ?? "";
                    var dir = Path.GetDirectoryName(newPath);
                    if (!string.IsNullOrEmpty(dir)) dirs.Add(dir!);
                }
                catch (ArgumentException) { continue; }

                sampled++;
                bool sourceIsUserData = UserDataExtensions.Contains(oldExt);
                if (sourceIsUserData) userData++;

                bool typeChanged = !string.Equals(oldExt, newExt, StringComparison.OrdinalIgnoreCase)
                                   && newExt.Length > 0
                                   && !BenignTargetExtensions.Contains(newExt);
                if (!typeChanged) continue;

                typeChanging++;
                if (sourceIsUserData && !UserDataExtensions.Contains(newExt)) userDataLost++;

                byNewExt.TryGetValue(newExt, out var entry);
                entry.Sources ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                entry.Sources.Add(oldExt);
                byNewExt[newExt] = (entry.Count + 1, entry.Sources);
            }

            string dominant = "";
            int dominantCount = 0, dominantSources = 0;
            foreach (var kv in byNewExt)
            {
                if (kv.Value.Count > dominantCount)
                {
                    dominant = kv.Key; dominantCount = kv.Value.Count; dominantSources = kv.Value.Sources.Count;
                }
            }

            int total = Math.Max(totalRenames ?? sampled, sampled);
            bool enough = sampled >= MinRenamesForEvidence;
            bool funnel = enough
                          && dominantCount >= MinRenamesForEvidence
                          && dominantCount >= DominantShare * sampled
                          && dominantSources >= MinDistinctSourceExtensions;
            bool typeChange = enough
                              && userData >= UserDataShare * sampled
                              && userDataLost >= TypeLossShare * userData;

            return new RenameEvidence
            {
                Total = total,
                UserDataSources = userData,
                DistinctDirectories = dirs.Count,
                DominantNewExtension = dominant,
                DominantCount = dominantCount,
                DominantDistinctSourceExtensions = dominantSources,
                Funnel = funnel,
                TypeChange = typeChange,
            };
        }
    }
}
