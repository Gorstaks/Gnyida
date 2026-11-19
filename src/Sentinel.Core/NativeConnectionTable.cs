using System;
using System.Net;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    /// <summary>One TCP or UDP endpoint from the kernel's connection tables.</summary>
    internal readonly struct ConnectionRow
    {
        public ConnectionRow(string protocol, int pid, string localAddress, int localPort, string remoteAddress, int remotePort, string state)
        {
            Protocol = protocol; Pid = pid; LocalAddress = localAddress; LocalPort = localPort;
            RemoteAddress = remoteAddress; RemotePort = remotePort; State = state;
        }

        /// <summary>"TCP" or "UDP".</summary>
        public string Protocol { get; }
        public int Pid { get; }
        /// <summary>IPv4 as dotted text; IPv6 in brackets, as netstat prints it.</summary>
        public string LocalAddress { get; }
        public int LocalPort { get; }
        /// <summary>"*" for UDP, which has no peer.</summary>
        public string RemoteAddress { get; }
        public int RemotePort { get; }
        /// <summary>netstat's English state names, fixed in code, or "N/A" for UDP.</summary>
        public string State { get; }

        public bool IsEstablished => State == "ESTABLISHED";
        public bool IsListening => State == "LISTENING";
        public bool IsIpv6 => LocalAddress.Length > 0 && LocalAddress[0] == '[';

        /// <summary>The row as netstat -ano would print it, for evidence text.</summary>
        public string ToNetstatLine() =>
            Protocol.PadRight(6) + (LocalAddress + ":" + LocalPort).PadRight(24) +
            (RemoteAddress + ":" + (Protocol == "UDP" ? "*" : RemotePort.ToString())).PadRight(24) +
            (Protocol == "TCP" ? State.PadRight(14) : "".PadRight(14)) + Pid;
    }

    /// <summary>
    /// The kernel's TCP and UDP connection tables, read through iphlpapi instead of parsing netstat.exe output.
    ///
    /// Why: netstat localizes its state words (on a German Windows ESTABLISHED is HERGESTELLT), so every place that
    /// searched its text for "ESTABLISHED" or "LISTENING" found nothing on a non-English system. It also costs a
    /// process launch per poll, can hang (see <see cref="BoundedProcess"/>), and is found by name on a search path.
    /// The table is also complete: it includes IPv6, which "netstat -p TCP" does not.
    ///
    /// Memory: the table is read into a native buffer that is freed in a finally block and walked in place, rows are
    /// handed to a callback one at a time, and nothing is copied into a managed array. A busy machine's table is well
    /// over the 85 KB large-object threshold, and these readers poll.
    /// </summary>
    internal static class NativeConnectionTable
    {
        private const int AfInet = 2;
        private const int AfInet6 = 23;
        private const int TcpTableOwnerPidAll = 5;
        private const int UdpTableOwnerPid = 1;
        private const int ErrorInsufficientBuffer = 122;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, uint reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, uint reserved);

        /// <summary>
        /// Visits every TCP (and optionally UDP) endpoint, IPv4 then IPv6. The visitor returns false to stop early.
        /// Returns false if no table could be read at all, so a caller can tell "nothing found" from "could not look".
        /// </summary>
        internal static bool Enumerate(bool includeUdp, Func<ConnectionRow, bool> visit)
        {
            bool any = false;
            foreach (int family in new[] { AfInet, AfInet6 })
            {
                bool stopped = false;
                if (WithTable(family, udp: false, (table, size) => { any = true; stopped = !WalkTcp(table, size, family, visit); }) && stopped) return true;
                if (includeUdp && WithTable(family, udp: true, (table, size) => { any = true; stopped = !WalkUdp(table, size, family, visit); }) && stopped) return true;
            }
            return any;
        }

        private static bool WithTable(int family, bool udp, Action<IntPtr, int> use)
        {
            int size = 0;
            Call(IntPtr.Zero, ref size, family, udp);
            for (int attempt = 0; attempt < 3 && size > 0; attempt++)
            {
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    uint status = Call(buffer, ref size, family, udp);
                    if (status == 0) { use(buffer, size); return true; }
                    if (status != ErrorInsufficientBuffer) return false; // the table grew: retry with the size the call reported
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            return false;
        }

        private static uint Call(IntPtr buffer, ref int size, int family, bool udp) =>
            udp ? GetExtendedUdpTable(buffer, ref size, false, family, UdpTableOwnerPid, 0)
                : GetExtendedTcpTable(buffer, ref size, false, family, TcpTableOwnerPidAll, 0);

        /// <summary>Walks a MIB_TCPTABLE_OWNER_PID or MIB_TCP6TABLE_OWNER_PID in place. False when the visitor stopped it.</summary>
        internal static bool WalkTcp(IntPtr table, int size, int family, Func<ConnectionRow, bool> visit)
        {
            if (size < 4) return true;
            int rowSize = family == AfInet ? 24 : 56;
            long count = (uint)Marshal.ReadInt32(table);
            for (long i = 0; i < count; i++)
            {
                long offset = 4 + i * rowSize;
                if (offset + rowSize > size) return true; // a table that claims more rows than it holds is cut short, not trusted
                IntPtr row = IntPtr.Add(table, (int)offset);
                ConnectionRow value;
                if (family == AfInet)
                {
                    value = new ConnectionRow("TCP", Marshal.ReadInt32(row, 20),
                        V4(Marshal.ReadInt32(row, 4)), Port(Marshal.ReadInt32(row, 8)),
                        V4(Marshal.ReadInt32(row, 12)), Port(Marshal.ReadInt32(row, 16)),
                        StateName((uint)Marshal.ReadInt32(row, 0)));
                }
                else
                {
                    value = new ConnectionRow("TCP", Marshal.ReadInt32(row, 52),
                        V6(row, 0, Marshal.ReadInt32(row, 16)), Port(Marshal.ReadInt32(row, 20)),
                        V6(row, 24, Marshal.ReadInt32(row, 40)), Port(Marshal.ReadInt32(row, 44)),
                        StateName((uint)Marshal.ReadInt32(row, 48)));
                }
                if (!visit(value)) return false;
            }
            return true;
        }

        /// <summary>Walks a MIB_UDPTABLE_OWNER_PID or MIB_UDP6TABLE_OWNER_PID in place. False when the visitor stopped it.</summary>
        internal static bool WalkUdp(IntPtr table, int size, int family, Func<ConnectionRow, bool> visit)
        {
            if (size < 4) return true;
            int rowSize = family == AfInet ? 12 : 28;
            long count = (uint)Marshal.ReadInt32(table);
            for (long i = 0; i < count; i++)
            {
                long offset = 4 + i * rowSize;
                if (offset + rowSize > size) return true;
                IntPtr row = IntPtr.Add(table, (int)offset);
                ConnectionRow value = family == AfInet
                    ? new ConnectionRow("UDP", Marshal.ReadInt32(row, 8), V4(Marshal.ReadInt32(row, 0)), Port(Marshal.ReadInt32(row, 4)), "*", 0, "N/A")
                    : new ConnectionRow("UDP", Marshal.ReadInt32(row, 24), V6(row, 0, Marshal.ReadInt32(row, 16)), Port(Marshal.ReadInt32(row, 20)), "*", 0, "N/A");
                if (!visit(value)) return false;
            }
            return true;
        }

        /// <summary>
        /// Test seam: walks a table held in a managed array by copying it to native memory for the call.
        /// </summary>
        internal static void Parse(byte[] table, int family, bool udp, Func<ConnectionRow, bool> visit)
        {
            IntPtr buffer = Marshal.AllocHGlobal(Math.Max(1, table.Length));
            try
            {
                Marshal.Copy(table, 0, buffer, table.Length);
                if (udp) WalkUdp(buffer, table.Length, family, visit);
                else WalkTcp(buffer, table.Length, family, visit);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        // The address bytes are in network order in memory, which is the little-endian layout IPAddress(long) expects.
        private static string V4(int raw) => new IPAddress((uint)raw).ToString();

        private static string V6(IntPtr row, int offset, int scope)
        {
            var bytes = new byte[16];
            Marshal.Copy(IntPtr.Add(row, offset), bytes, 0, 16);
            return "[" + new IPAddress(bytes, (uint)scope) + "]";
        }

        private static int Port(int raw) => ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);

        /// <summary>netstat's own English names, so existing comparisons keep working and no longer depend on the locale.</summary>
        internal static string StateName(uint state)
        {
            switch (state)
            {
                case 1: return "CLOSED";
                case 2: return "LISTENING";
                case 3: return "SYN_SENT";
                case 4: return "SYN_RECEIVED";
                case 5: return "ESTABLISHED";
                case 6: return "FIN_WAIT_1";
                case 7: return "FIN_WAIT_2";
                case 8: return "CLOSE_WAIT";
                case 9: return "CLOSING";
                case 10: return "LAST_ACK";
                case 11: return "TIME_WAIT";
                case 12: return "DELETE_TCB";
                default: return "UNKNOWN";
            }
        }
    }
}
