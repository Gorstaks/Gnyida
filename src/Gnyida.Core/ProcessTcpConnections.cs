using System;
using System.Collections.Generic;
using System.Net;

namespace Gnyida.Core
{
    /// <summary>
    /// Established TCP connections owned by one process. Used when another monitor has already proven that a
    /// process runs code that is not its file (hollowed, stomped): an established outbound socket from such a
    /// process is what an in-memory reverse shell or C2 implant looks like, and no process-creation rule sees it
    /// because nothing was spawned.
    ///
    /// Called only on a confirmed finding, never in a polling loop. Reads through <see cref="NativeConnectionTable"/>.
    /// </summary>
    internal static class ProcessTcpConnections
    {
        /// <summary>"address:port" for each established non-loopback connection of the process, up to <paramref name="max"/>.</summary>
        internal static List<string> GetEstablished(int pid, int max = 10)
        {
            var result = new List<string>();
            try
            {
                NativeConnectionTable.Enumerate(false, row =>
                {
                    if (Matches(row, pid)) result.Add(row.RemoteAddress + ":" + row.RemotePort);
                    return result.Count < max;
                });
            }
            catch (Exception ex) { /* best effort: the finding is reported without network context */ BestEffort.Debug(ex, "ProcessTcpConnections.GetEstablished()"); }
            return result;
        }

        /// <summary>Parses a MIB_TCPTABLE_OWNER_PID or MIB_TCP6TABLE_OWNER_PID buffer. Loopback peers are skipped.</summary>
        internal static IEnumerable<string> ParseEstablished(byte[] table, int family, int pid)
        {
            var found = new List<string>();
            if (table == null || table.Length < 4) return found;
            NativeConnectionTable.Parse(table, family, udp: false, row =>
            {
                if (Matches(row, pid)) found.Add(row.RemoteAddress + ":" + row.RemotePort);
                return true;
            });
            return found;
        }

        private static bool Matches(ConnectionRow row, int pid)
        {
            if (row.Pid != pid || !row.IsEstablished) return false;
            string address = row.RemoteAddress.Trim('[', ']');
            int scope = address.IndexOf('%');
            if (scope >= 0) address = address.Substring(0, scope);
            return !(IPAddress.TryParse(address, out var ip) && IPAddress.IsLoopback(ip));
        }
    }
}
