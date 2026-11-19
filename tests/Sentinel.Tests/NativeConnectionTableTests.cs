using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class NativeConnectionTableTests
    {
        private static void PutPort(byte[] buffer, int offset, ushort port) =>
            BitConverter.GetBytes((uint)(((port & 0xFF) << 8) | (port >> 8))).CopyTo(buffer, offset);

        private static List<ConnectionRow> Rows(byte[] table, int family, bool udp)
        {
            var rows = new List<ConnectionRow>();
            NativeConnectionTable.Parse(table, family, udp, r => { rows.Add(r); return true; });
            return rows;
        }

        [Theory]
        [InlineData(2u, "LISTENING")]
        [InlineData(5u, "ESTABLISHED")]
        [InlineData(11u, "TIME_WAIT")]
        [InlineData(4u, "SYN_RECEIVED")]
        [InlineData(99u, "UNKNOWN")]
        public void StateNames_AreFixedEnglishWords_NotLocalized(uint state, string expected) =>
            Assert.Equal(expected, NativeConnectionTable.StateName(state));

        [Fact]
        public void V4Tcp_ParsesAddressesPortsStateAndPid()
        {
            var table = new byte[4 + 24];
            BitConverter.GetBytes(1u).CopyTo(table, 0);
            BitConverter.GetBytes(5u).CopyTo(table, 4);                          // state
            new byte[] { 10, 0, 0, 7 }.CopyTo(table, 4 + 4);                     // local address
            PutPort(table, 4 + 8, 50321);
            new byte[] { 203, 0, 113, 9 }.CopyTo(table, 4 + 12);                 // remote address
            PutPort(table, 4 + 16, 443);
            BitConverter.GetBytes(1234u).CopyTo(table, 4 + 20);                  // owning pid
            var row = Assert.Single(Rows(table, 2, udp: false));
            Assert.Equal("TCP", row.Protocol);
            Assert.Equal(1234, row.Pid);
            Assert.Equal("10.0.0.7", row.LocalAddress);
            Assert.Equal(50321, row.LocalPort);
            Assert.Equal("203.0.113.9", row.RemoteAddress);
            Assert.Equal(443, row.RemotePort);
            Assert.True(row.IsEstablished);
            Assert.False(row.IsIpv6);
        }

        [Fact]
        public void V6Tcp_ParsesBracketedAddresses()
        {
            var table = new byte[4 + 56];
            BitConverter.GetBytes(1u).CopyTo(table, 0);
            IPAddress.Parse("2001:db8::1").GetAddressBytes().CopyTo(table, 4);       // local
            PutPort(table, 4 + 20, 8080);
            IPAddress.Parse("2001:db8::5").GetAddressBytes().CopyTo(table, 4 + 24);  // remote
            PutPort(table, 4 + 44, 4444);
            BitConverter.GetBytes(2u).CopyTo(table, 4 + 48);                         // listening
            BitConverter.GetBytes(77u).CopyTo(table, 4 + 52);
            var row = Assert.Single(Rows(table, 23, udp: false));
            Assert.Equal("[2001:db8::1]", row.LocalAddress);
            Assert.Equal("[2001:db8::5]", row.RemoteAddress);
            Assert.Equal(4444, row.RemotePort);
            Assert.True(row.IsListening);
            Assert.True(row.IsIpv6);
        }

        [Fact]
        public void V4Udp_HasNoPeerAndNoState()
        {
            var table = new byte[4 + 12];
            BitConverter.GetBytes(1u).CopyTo(table, 0);
            new byte[] { 0, 0, 0, 0 }.CopyTo(table, 4);
            PutPort(table, 4 + 4, 5353);
            BitConverter.GetBytes(808u).CopyTo(table, 4 + 8);
            var row = Assert.Single(Rows(table, 2, udp: true));
            Assert.Equal("UDP", row.Protocol);
            Assert.Equal(5353, row.LocalPort);
            Assert.Equal("*", row.RemoteAddress);
            Assert.Equal("N/A", row.State);
            Assert.Equal(808, row.Pid);
            Assert.False(row.IsEstablished);
        }

        [Fact]
        public void TableThatClaimsMoreRowsThanItHolds_IsCutShortNotRead()
        {
            var table = new byte[4 + 10];
            BitConverter.GetBytes(50u).CopyTo(table, 0);
            Assert.Empty(Rows(table, 2, udp: false));
            Assert.Empty(Rows(new byte[2], 2, udp: false));
        }

        [Fact]
        public void NetstatLine_ContainsPidAndEndpoints()
        {
            var row = new ConnectionRow("TCP", 4321, "10.0.0.7", 50321, "203.0.113.9", 443, "ESTABLISHED");
            string line = row.ToNetstatLine();
            Assert.Contains("10.0.0.7:50321", line);
            Assert.Contains("203.0.113.9:443", line);
            Assert.Contains("ESTABLISHED", line);
            Assert.EndsWith("4321", line);
        }

        // ---- against the real kernel table ----

        [Fact]
        public void Live_ReportsThisProcessListenerAndConnection_WithoutAnyTextParsing()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                using var client = new TcpClient();
                client.Connect(IPAddress.Loopback, port);
                using var accepted = listener.AcceptTcpClient();

                int me = ProcessInstanceTable.CurrentPid;
                bool sawListening = false, sawClientSide = false;
                bool read = NativeConnectionTable.Enumerate(false, row =>
                {
                    if (row.Pid != me) return true;
                    if (row.IsListening && row.LocalPort == port) sawListening = true;
                    if (row.IsEstablished && row.RemotePort == port && row.LocalPort != port) sawClientSide = true;
                    return true;
                });
                Assert.True(read);
                Assert.True(sawListening, "the listening socket opened by this test was not in the TCP table");
                Assert.True(sawClientSide, "the established client connection was not in the TCP table");
            }
            finally { listener.Stop(); }
        }

        [Fact]
        public void Live_VisitorCanStopTheWalkEarly()
        {
            int seen = 0;
            NativeConnectionTable.Enumerate(true, row => { seen++; return false; });
            Assert.True(seen <= 1);
        }

        [Fact]
        public void Live_ProcessTcpConnections_FindsTheTestHostsEstablishedPeer()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                using var client = new TcpClient();
                client.Connect(IPAddress.Loopback, port);
                using var accepted = listener.AcceptTcpClient();
                // Loopback peers are deliberately skipped, so a connection to ourselves must not be reported.
                Assert.DoesNotContain(ProcessTcpConnections.GetEstablished(ProcessInstanceTable.CurrentPid, 50), e => e.EndsWith(":" + port, StringComparison.Ordinal));
            }
            finally { listener.Stop(); }
        }
    }
}
