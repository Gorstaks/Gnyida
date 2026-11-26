using System;
using System.Linq;
using Gnyida.Core;
using Xunit;

namespace Gnyida.Tests
{
    public class ProcessTcpConnectionsTests
    {
        private static byte[] V4Table(params (uint State, byte[] Remote, ushort Port, uint Pid)[] rows)
        {
            var buffer = new byte[4 + rows.Length * 24];
            BitConverter.GetBytes((uint)rows.Length).CopyTo(buffer, 0);
            for (int i = 0; i < rows.Length; i++)
            {
                int o = 4 + i * 24;
                BitConverter.GetBytes(rows[i].State).CopyTo(buffer, o);
                rows[i].Remote.CopyTo(buffer, o + 12);
                // The port is stored in network byte order in the low 16 bits.
                BitConverter.GetBytes((uint)(((rows[i].Port & 0xFF) << 8) | (rows[i].Port >> 8))).CopyTo(buffer, o + 16);
                BitConverter.GetBytes(rows[i].Pid).CopyTo(buffer, o + 20);
            }
            return buffer;
        }

        [Fact]
        public void V4_ReturnsOnlyEstablishedNonLoopbackConnectionsOfThatProcess()
        {
            var table = V4Table(
                (5, new byte[] { 203, 0, 113, 9 }, 4444, 100),    // established, ours
                (5, new byte[] { 127, 0, 0, 1 }, 8080, 100),      // loopback: skipped
                (2, new byte[] { 203, 0, 113, 10 }, 443, 100),    // listening-ish state: skipped
                (5, new byte[] { 198, 51, 100, 7 }, 443, 200));   // another process: skipped
            var found = ProcessTcpConnections.ParseEstablished(table, 2, 100).ToList();
            Assert.Equal(new[] { "203.0.113.9:4444" }, found);
        }

        [Fact]
        public void V6_ParsesAddressAndPort()
        {
            var buffer = new byte[4 + 56];
            BitConverter.GetBytes(1u).CopyTo(buffer, 0);
            int o = 4;
            var remote = System.Net.IPAddress.Parse("2001:db8::5").GetAddressBytes();
            remote.CopyTo(buffer, o + 24);
            BitConverter.GetBytes((uint)(((4444 & 0xFF) << 8) | (4444 >> 8))).CopyTo(buffer, o + 44);
            BitConverter.GetBytes(5u).CopyTo(buffer, o + 48);
            BitConverter.GetBytes(77u).CopyTo(buffer, o + 52);
            Assert.Equal(new[] { "[2001:db8::5]:4444" }, ProcessTcpConnections.ParseEstablished(buffer, 23, 77).ToList());
        }

        [Fact]
        public void TruncatedOrEmptyTables_YieldNothingAndDoNotThrow()
        {
            Assert.Empty(ProcessTcpConnections.ParseEstablished(new byte[2], 2, 1));
            var lying = new byte[4 + 10];
            BitConverter.GetBytes(50u).CopyTo(lying, 0); // claims 50 rows, holds less than one
            Assert.Empty(ProcessTcpConnections.ParseEstablished(lying, 2, 1));
        }

        [Fact]
        public void LiveCall_DoesNotThrowAndRespectsTheLimit()
        {
            var connections = ProcessTcpConnections.GetEstablished(ProcessInstanceTable.CurrentPid, max: 3);
            Assert.True(connections.Count <= 3);
        }
    }
}
