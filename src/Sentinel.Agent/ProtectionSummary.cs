using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.Json;

namespace Sentinel.Agent
{
    /// <summary>
    /// Figures for the Overview cards, read from the event log.
    ///
    /// "Threats stopped" counts only responses Sentinel can prove: a response_result whose effective action kills or
    /// quarantines and whose Status is Verified. Failed and refused attempts, and the thousands of LogOnly observations,
    /// are not counted, so the number never overstates what Sentinel did.
    /// </summary>
    internal sealed class ProtectionSummary
    {
        public int ThreatsStopped { get; set; }
        public int ResponsesFailed { get; set; }
        public DateTime? LastThreatStoppedUtc { get; set; }
        /// <summary>False when the readable log starts inside the window, so the count may be missing older days.</summary>
        public bool WindowComplete { get; set; }

        internal static readonly TimeSpan Window = TimeSpan.FromDays(7);

        private static readonly HashSet<string> StoppingActions = new HashSet<string>(StringComparer.Ordinal)
        {
            "KillProcess", "KillProcessTree", "Quarantine", "QuarantineAndKill", "RemoveCertAndKillAdder",
        };

        /// <summary>Pure counting over log lines (oldest first or in any order), for tests and for the cached reader.</summary>
        internal static ProtectionSummary Count(IEnumerable<string> lines, DateTime nowUtc)
        {
            var result = new ProtectionSummary();
            DateTime since = nowUtc - Window;
            DateTime? oldestSeen = null;
            foreach (string line in lines)
            {
                if (string.IsNullOrEmpty(line)) continue;
                // Every line is read, but only response_result lines are parsed as JSON. The timestamp needed for the
                // window check is sliced out of the text, because parsing tens of thousands of observation lines a
                // minute would cost far more than the figure is worth.
                DateTime? stamp = FastTimestamp(line);
                if (stamp.HasValue && (!oldestSeen.HasValue || stamp.Value < oldestSeen.Value)) oldestSeen = stamp;
                if (line.IndexOf("\"type\":\"response_result\"", StringComparison.Ordinal) < 0) continue;
                if (!stamp.HasValue || stamp.Value < since || stamp.Value > nowUtc.AddMinutes(5)) continue;
                try
                {
                    using var doc = JsonDocument.Parse(line);
                    JsonElement root = doc.RootElement;
                    if (!root.TryGetProperty("data", out JsonElement data) || data.ValueKind != JsonValueKind.Object) continue;
                    string action = Text(data, "EffectiveAction");
                    if (!StoppingActions.Contains(action)) continue;
                    if (Text(data, "Status") == "Verified")
                    {
                        result.ThreatsStopped++;
                        if (!result.LastThreatStoppedUtc.HasValue || stamp.Value > result.LastThreatStoppedUtc.Value)
                            result.LastThreatStoppedUtc = stamp.Value;
                    }
                    else
                    {
                        result.ResponsesFailed++;
                    }
                }
                catch (JsonException ex) { /* a torn or foreign line: skip it */ Sentinel.Core.BestEffort.Debug(ex, "ProtectionSummary.Count()"); }
            }
            result.WindowComplete = oldestSeen.HasValue && oldestSeen.Value <= since;
            return result;
        }

        private const string TimestampKey = "\"timestamp\":\"";

        /// <summary>The top-level "timestamp" of a log line without parsing the whole record; null if absent or malformed.</summary>
        internal static DateTime? FastTimestamp(string line)
        {
            int start = line.IndexOf(TimestampKey, StringComparison.Ordinal);
            if (start < 0) return null;
            start += TimestampKey.Length;
            int end = line.IndexOf('"', start);
            if (end <= start || end - start > 40) return null;
            return DateTime.TryParse(line.Substring(start, end - start), CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out DateTime parsed) ? parsed : (DateTime?)null;
        }

        private static string Text(JsonElement obj, string name) =>
            obj.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";

        // ---- cached reader ----

        private static readonly object Gate = new object();
        private static ProtectionSummary? _cached;
        private static DateTime _cachedAtUtc;
        private static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(60);

        /// <summary>Counts across the given log files, recomputed at most once a minute.</summary>
        internal static ProtectionSummary Read(IReadOnlyList<string> paths)
        {
            lock (Gate)
            {
                DateTime now = DateTime.UtcNow;
                if (_cached != null && now - _cachedAtUtc < CacheFor) return _cached;
                _cached = Count(ReadLines(paths), now);
                _cachedAtUtc = now;
                return _cached;
            }
        }

        private static IEnumerable<string> ReadLines(IReadOnlyList<string> paths)
        {
            foreach (string path in paths)
            {
                if (!File.Exists(path)) continue;
                FileStream? stream = null;
                try
                {
                    stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536, FileOptions.SequentialScan);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }
                using (stream)
                using (var reader = new StreamReader(stream))
                {
                    string? line;
                    while ((line = reader.ReadLine()) != null) yield return line;
                }
            }
        }
    }
}
