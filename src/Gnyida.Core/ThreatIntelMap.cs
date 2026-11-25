using System;
using System.Collections.Concurrent;

namespace Gnyida.Core
{
    /// <summary>
    /// Microsoft-Windows-Threat-Intelligence ETW event IDs as shipped on
    /// Win10/11. UnifiedEtwSession labels them ThreatIntel_EventId_N.
    /// Remote alloc/write/APC/context/map are injection. Local write is JIT noise.
    /// </summary>
    public static class ThreatIntelMap
    {
        public const string EventIdPrefix = "ThreatIntel_EventId_";

        // Remote injection (kernel TI). Local 1/2/3/11/12 are too noisy (JIT).
        private static readonly int[] RemoteInjectionIds =
        {
            4, 5, 6, 7, 8, 13, 14,
            26, 27, 28, 29, 30
        };

        public static bool TryParseEventId(string? apiName, out int eventId)
        {
            eventId = 0;
            if (string.IsNullOrEmpty(apiName) ||
                !apiName!.StartsWith(EventIdPrefix, StringComparison.Ordinal))
                return false;
            return int.TryParse(apiName.Substring(EventIdPrefix.Length), out eventId);
        }

        private static readonly string[] RemoteInjectionApiNames = IndicatorCatalog.List("threatIntel.remoteInjectionApis");

        public static bool IsRemoteInjection(string? apiName)
        {
            if (string.IsNullOrEmpty(apiName)) return false;
            if (TryParseEventId(apiName, out int id))
            {
                for (int i = 0; i < RemoteInjectionIds.Length; i++)
                    if (RemoteInjectionIds[i] == id) return true;
                return false;
            }

            // API names live in the compressed indicator resource (see IndicatorCatalog). Same
            // ordinal ignore-case substring match.
            return IndicatorCatalog.ContainsAny(apiName, RemoteInjectionApiNames);
        }

        public static string Describe(string? apiName)
        {
            if (TryParseEventId(apiName, out int id))
            {
                return id switch
                {
                    4 or 26 => "ALLOCVM_REMOTE",
                    5 or 27 => "PROTECTVM_REMOTE",
                    6 or 28 => "MAPVIEW_REMOTE",
                    7 or 29 => "QUEUEUSERAPC_REMOTE",
                    8 or 30 => "SETTHREADCONTEXT_REMOTE",
                    13 => "READVM_REMOTE",
                    14 => "WRITEVM_REMOTE",
                    _ => apiName ?? "TI"
                };
            }
            return apiName ?? "TI";
        }
    }

    /// <summary>
    /// PIDs worth a memory inspection, with the reason each one was marked. EtwThreatIntelMonitor scans only these
    /// (no full-system 5s EnumModules - that was the LatencyMon hard-fault source).
    ///
    /// A mark carries flags, not one slot, so a weak reason can never hide or downgrade a strong one:
    ///   Evidence  - the kernel Threat-Intelligence provider saw an injection-related call by this process. That provider
    ///               needs a protected anti-malware process, so on a SYSTEM-only install it is denied (Win32 5) and this
    ///               flag is never set.
    ///   Sweep     - a periodic round-robin visited this process. Gives coverage without the provider.
    ///   ImageLoad - this process loaded a module (kernel-process provider, which does work without protection).
    /// Sweep and ImageLoad marks are weak: payload inspection only, and only of pages already resident, so they cannot
    /// cause hard faults.
    /// </summary>
    public static class InjectionSuspectBoard
    {
        [Flags]
        internal enum MarkKind { None = 0, Sweep = 1, ImageLoad = 2, Evidence = 4 }

        private const int SoftCap = 8192;
        private static readonly ConcurrentDictionary<int, (DateTimeOffset When, bool PayloadOnly, MarkKind Kinds)> Pids = new();
        private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(2);
        // Most recent ETW-TI captured call-stack frames per caller PID. Stashed cheaply on
        // the ETW callback thread; the heavy per-frame memory classification runs off-thread
        // in EtwThreatIntelMonitor (same reason the module walk lives there, not here).
        private static readonly ConcurrentDictionary<int, (DateTimeOffset When, ulong[] Frames)> StackFrames = new();

        public static void Mark(int pid) => Mark(pid, payloadOnly: false);

        internal static void Mark(int pid, bool payloadOnly)
        {
            if (pid <= 4) return;
            var now = DateTimeOffset.UtcNow;
            Pids[pid] = (now, payloadOnly, MarkKind.Evidence);
        }

        /// <summary>
        /// Adds a weak reason. An existing Evidence mark keeps its payload-only setting; a new or expired entry is
        /// payload-only. Cheap enough for the ETW callback thread: one dictionary write.
        /// </summary>
        internal static void MarkWeak(int pid, MarkKind kind)
        {
            if (pid <= 4 || kind == MarkKind.None || (kind & MarkKind.Evidence) != 0) return;
            var now = DateTimeOffset.UtcNow;
            if (Pids.Count >= SoftCap) PruneExpired(now);
            Pids.AddOrUpdate(pid,
                _ => (now, true, kind),
                (_, old) => now - old.When > Ttl ? (now, true, kind) : (now, old.PayloadOnly, old.Kinds | kind));
        }

        /// <summary>Removes one weak reason once it has been acted on; the entry goes when no reason is left.</summary>
        internal static void ClearWeak(int pid, MarkKind kind)
        {
            for (int attempt = 0; attempt < 4; attempt++)
            {
                if (!Pids.TryGetValue(pid, out var old)) return;
                var left = old.Kinds & ~(kind & ~MarkKind.Evidence);
                if (left == old.Kinds) return;
                bool done = left == MarkKind.None
                    ? ((ICollection<KeyValuePair<int, (DateTimeOffset, bool, MarkKind)>>)Pids).Remove(new KeyValuePair<int, (DateTimeOffset, bool, MarkKind)>(pid, old))
                    : Pids.TryUpdate(pid, (old.When, old.PayloadOnly, left), old);
                if (done) return;
            }
        }

        internal static bool IsPayloadOnly(int pid) =>
            !Pids.TryGetValue(pid, out var entry) || entry.PayloadOnly;

        /// <summary>True when the only reasons for this PID are weak ones (no Threat-Intelligence evidence).</summary>
        internal static bool IsWeakOnly(int pid) =>
            Pids.TryGetValue(pid, out var entry) && (entry.Kinds & MarkKind.Evidence) == 0;

        internal static bool TryGetKinds(int pid, out MarkKind kinds)
        {
            bool found = Pids.TryGetValue(pid, out var entry);
            kinds = found ? entry.Kinds : MarkKind.None;
            return found;
        }

        /// <summary>
        /// Stash a captured user-mode return-address chain for later off-thread analysis.
        /// Marks the PID as a suspect as well. No memory inspection happens here.
        /// </summary>
        public static void RecordStack(int pid, ulong[] frames)
        {
            if (pid <= 4 || frames == null || frames.Length == 0)
                return;
            StackFrames[pid] = (DateTimeOffset.UtcNow, frames);
            Mark(pid);
        }

        /// <summary>
        /// Takes (and clears) the stashed frames for a PID if fresh, else returns null.
        /// One-shot: consuming the stash prevents re-alerting on the same capture.
        /// </summary>
        public static ulong[]? TakeStack(int pid)
        {
            if (!StackFrames.TryRemove(pid, out var entry))
                return null;
            if (DateTimeOffset.UtcNow - entry.When > Ttl)
                return null;
            return entry.Frames;
        }

        /// <summary>The payload scanner's candidates: Threat-Intelligence evidence and periodic sweeps.</summary>
        public static int[] Snapshot() => Snapshot(MarkKind.Sweep | MarkKind.Evidence);

        /// <summary>PIDs that carry at least one of the wanted reasons. Also expires old entries.</summary>
        internal static int[] Snapshot(MarkKind wanted)
        {
            var now = DateTimeOffset.UtcNow;
            PruneExpired(now);
            var list = new List<int>(Pids.Count);
            foreach (var kv in Pids)
            {
                if ((kv.Value.Kinds & wanted) != 0) list.Add(kv.Key);
            }
            return list.ToArray();
        }

        private static void PruneExpired(DateTimeOffset now)
        {
            foreach (var kv in Pids)
            {
                if (now - kv.Value.When > Ttl)
                    Pids.TryRemove(kv.Key, out _);
            }
            foreach (var kv in StackFrames)
            {
                if (now - kv.Value.When > Ttl)
                    StackFrames.TryRemove(kv.Key, out _);
            }
        }

        /// <summary>Test seam: forgets every mark.</summary>
        internal static void ResetForTests()
        {
            Pids.Clear();
            StackFrames.Clear();
        }
    }
}