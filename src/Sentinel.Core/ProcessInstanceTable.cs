using System;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace Sentinel.Core
{
    /// <summary>
    /// Pruning for per-process-instance tables keyed on (PID, start time). A table that records "already
    /// checked" or "already alerted" must shrink when a process exits, otherwise it grows for the life of
    /// the service (the class of leak recorded in docs/CHANGELOG.md for 3.7.3 and 3.7.8).
    /// </summary>
    internal static class ProcessInstanceTable
    {
        /// <summary>
        /// Removes every entry whose process has exited, or whose PID now belongs to a different process
        /// (start time differs). Returns the number removed.
        /// </summary>
        /// <param name="liveStartTicks">Start-time ticks for a PID, or null when no such process is running.</param>
        internal static int Prune<TValue>(ConcurrentDictionary<(int Pid, long StartTicks), TValue> table, Func<int, long?> liveStartTicks)
        {
            int removed = 0;
            foreach (var key in table.Keys)
            {
                long? live = liveStartTicks(key.Pid);
                if (live == null || live.Value != key.StartTicks)
                {
                    if (table.TryRemove(key, out _)) removed++;
                }
            }
            return removed;
        }

        /// <summary>This process's PID. Read once; Process.GetCurrentProcess() returns a new handle-owning object each call.</summary>
        internal static readonly int CurrentPid = ReadCurrentPid();

        private static int ReadCurrentPid()
        {
            using var me = Process.GetCurrentProcess();
            return me.Id;
        }

        /// <summary>Start-time ticks of a running process, or null if it has exited or cannot be read.</summary>
        internal static long? ReadStartTicks(int pid)
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                return p.StartTime.Ticks;
            }
            catch (Exception) { return null; }
        }
    }
}
