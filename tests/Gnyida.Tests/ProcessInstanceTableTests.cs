using System.Collections.Concurrent;
using System.Diagnostics;
using Gnyida.Core;
using Xunit;

namespace Gnyida.Tests
{
    /// <summary>
    /// Regression guard for per-process tables in LingeringProcessMonitor and ImageIntegrityMonitor. A table
    /// keyed on process instances must shrink when processes exit (see docs/MEMORY_LEAK_3.7.8.md).
    /// </summary>
    public class ProcessInstanceTableTests
    {
        [Fact]
        public void Prune_RemovesExitedProcesses_AndTableStaysBounded()
        {
            var table = new ConcurrentDictionary<(int Pid, long StartTicks), byte>();
            // Simulate a long uptime: many short-lived processes seen over time, a handful alive at the end.
            for (int round = 0; round < 50; round++)
            {
                for (int i = 0; i < 200; i++) table[(10_000 + round * 200 + i, round)] = 0;
                // Only the last 5 PIDs of each round are still running.
                ProcessInstanceTable.Prune(table, pid => pid >= 10_000 + round * 200 + 195 ? (long?)round : null);
                Assert.True(table.Count <= 5, $"table kept {table.Count} entries after round {round}");
            }
        }

        [Fact]
        public void Prune_RemovesReusedPid()
        {
            var table = new ConcurrentDictionary<(int Pid, long StartTicks), byte>();
            table[(4242, 100)] = 0;
            int removed = ProcessInstanceTable.Prune(table, pid => 999L); // PID 4242 now belongs to a newer process
            Assert.Equal(1, removed);
            Assert.Empty(table);
        }

        [Fact]
        public void Prune_KeepsLiveInstance()
        {
            var table = new ConcurrentDictionary<(int Pid, long StartTicks), byte>();
            table[(4242, 100)] = 0;
            Assert.Equal(0, ProcessInstanceTable.Prune(table, pid => 100L));
            Assert.Single(table);
        }

        [Fact]
        public void ReadStartTicks_ForMissingProcess_IsNull() =>
            Assert.Null(ProcessInstanceTable.ReadStartTicks(int.MaxValue));

        [Fact]
        public void ReadStartTicks_ForCurrentProcess_MatchesStartTime()
        {
            using var me = Process.GetCurrentProcess();
            Assert.Equal(me.StartTime.Ticks, ProcessInstanceTable.ReadStartTicks(ProcessInstanceTable.CurrentPid));
        }
    }
}
