using System;
using System.Diagnostics;
using System.Threading;
using Gnyida.Core;
using Xunit;

namespace Gnyida.Tests
{
    /// <summary>
    /// UDP datagram floods (QUIC, DNS, streaming) must not reach fusion one packet at a time, and
    /// must not push DNS, PowerShell, task, firewall or WMI events out of their queue.
    /// </summary>
    public class UdpDatagramCoalescerTests
    {
        private static readonly long Second = Stopwatch.Frequency;
        private static UdpFlowKey Key(int pid = 1234, ulong high = 0, ulong low = 0x0A000001, ushort port = 443, bool send = true)
            => new(pid, high, low, port, send);

        [Fact]
        public void FirstDatagramToAnEndpointIsAdmitted()
        {
            var c = new UdpDatagramCoalescer();
            Assert.True(c.TryAdmit(Key(), 100));
            Assert.Equal(0, c.Coalesced);
        }

        [Fact]
        public void RepeatsInsideTheWindowAreSkippedAndCounted()
        {
            var c = new UdpDatagramCoalescer();
            Assert.True(c.TryAdmit(Key(), 100));
            for (int i = 1; i <= 50; i++) Assert.False(c.TryAdmit(Key(), 100 + i));
            Assert.Equal(50, c.Coalesced);
        }

        [Fact]
        public void TheFlowIsAdmittedAgainAfterTheWindow()
        {
            var c = new UdpDatagramCoalescer();
            Assert.True(c.TryAdmit(Key(), 100));
            Assert.False(c.TryAdmit(Key(), 100 + Second - 1));
            Assert.True(c.TryAdmit(Key(), 100 + Second));
        }

        [Fact]
        public void AWindowIsMeasuredFromTheLastAdmittedDatagramNotTheLastRepeat()
        {
            // A steady flood must still be sampled once per window, not starved forever.
            var c = new UdpDatagramCoalescer();
            long t = 0;
            int admitted = 0;
            for (int i = 0; i < 5 * 100; i++)
            {
                t += Second / 100; // 100 datagrams per second for five seconds
                if (c.TryAdmit(Key(), t)) admitted++;
            }
            Assert.InRange(admitted, 5, 6);
        }

        [Theory]
        [InlineData(1235, 0UL, 0x0A000001UL, (ushort)443, true)]   // other process
        [InlineData(1234, 0UL, 0x0A000002UL, (ushort)443, true)]   // other address
        [InlineData(1234, 0UL, 0x0A000001UL, (ushort)4444, true)]  // other port: bad-port detection must see it
        [InlineData(1234, 0UL, 0x0A000001UL, (ushort)443, false)]  // other direction
        [InlineData(1234, 1UL, 0x0A000001UL, (ushort)443, true)]   // other IPv6 half
        public void ANewEndpointOrDirectionIsNeverSuppressed(int pid, ulong high, ulong low, ushort port, bool send)
        {
            var c = new UdpDatagramCoalescer();
            Assert.True(c.TryAdmit(Key(), 100));
            Assert.True(c.TryAdmit(Key(pid, high, low, port, send), 101));
            Assert.Equal(0, c.Coalesced);
        }

        [Fact]
        public void TheTableIsBounded()
        {
            var c = new UdpDatagramCoalescer();
            for (int i = 0; i < UdpDatagramCoalescer.MaxEntries + 10; i++)
                Assert.True(c.TryAdmit(Key(low: (ulong)i + 1), 100));
            // After the table was cleared an old flow is simply admitted again; nothing is lost.
            Assert.True(c.TryAdmit(Key(low: 1), 101));
        }

        [Fact]
        public void ConcurrentCallersNeverThrowAndAdmitEachFlowOncePerWindow()
        {
            var c = new UdpDatagramCoalescer();
            int admitted = 0;
            var threads = new Thread[4];
            for (int t = 0; t < threads.Length; t++)
            {
                threads[t] = new Thread(() =>
                {
                    for (int i = 0; i < 2000; i++)
                        if (c.TryAdmit(Key(low: (ulong)(i % 20) + 1), 100)) Interlocked.Increment(ref admitted);
                });
                threads[t].Start();
            }
            foreach (var th in threads) th.Join();
            // 20 distinct flows, all at one instant: concurrent first-sights may double count, never more than once per thread.
            Assert.InRange(admitted, 20, 20 * threads.Length);
        }
    }

    public class NetworkLaneIsolationTests
    {
        [Fact]
        public void UdpFloodCannotDropDnsPowerShellOrWmiEvents()
        {
            using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
            using var completed = new CountdownEvent(3);
            using var dispatcher = new PartitionedEtwDispatcher(_ => { }, laneCapacity: 1, laneByteLimit: 1);
            try
            {
                Assert.True(dispatcher.TryDispatch(new EtwRawEvent { ProviderId = UnifiedEtwSession.Providers.KernelNetwork },
                    _ => { entered.Set(); release.Wait(TimeSpan.FromSeconds(10)); }));
                Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
                Assert.False(dispatcher.TryDispatch(new EtwRawEvent { ProviderId = UnifiedEtwSession.Providers.KernelNetwork }, _ => { }));
                // Each of these shares the general lane (capacity 1), so wait for one before sending the next.
                foreach (var provider in new[] { UnifiedEtwSession.Providers.DnsClient, UnifiedEtwSession.Providers.PowerShell, UnifiedEtwSession.Providers.WmiActivity })
                {
                    int before = completed.CurrentCount;
                    Assert.True(dispatcher.TryDispatch(new EtwRawEvent { ProviderId = provider }, _ => completed.Signal()));
                    SpinWait.SpinUntil(() => completed.CurrentCount < before, TimeSpan.FromSeconds(5));
                }
                Assert.True(completed.Wait(TimeSpan.FromSeconds(5)));
                var drops = dispatcher.DropSnapshot();
                Assert.Equal(1, drops["Network"]);
                Assert.Equal(0, drops["Other"]);
            }
            finally { release.Set(); }
        }

        [Fact]
        public void NetworkLaneScaleEnlargesOnlyTheNetworkLane()
        {
            using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
            using var dispatcher = new PartitionedEtwDispatcher(_ => { }, laneCapacity: 2, laneByteLimit: 1024, networkLaneScale: 4);
            try
            {
                var net = new EtwRawEvent { ProviderId = UnifiedEtwSession.Providers.KernelNetwork };
                Assert.True(dispatcher.TryDispatch(net, _ => { entered.Set(); release.Wait(TimeSpan.FromSeconds(10)); }));
                Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
                // Capacity 2 * 4 = 8: the in-flight event holds one slot, seven more fit, the next is dropped.
                for (int i = 0; i < 7; i++) Assert.True(dispatcher.TryDispatch(net, _ => { }));
                Assert.False(dispatcher.TryDispatch(net, _ => { }));
                Assert.Equal(1, dispatcher.DropSnapshot()["Network"]);
            }
            finally { release.Set(); }
        }

        [Fact]
        public void EveryProviderMapsToAKnownLane()
        {
            Assert.Equal(0, PartitionedEtwDispatcher.Lane(UnifiedEtwSession.Providers.KernelProcess));
            Assert.Equal(1, PartitionedEtwDispatcher.Lane(UnifiedEtwSession.Providers.KernelFile));
            Assert.Equal(2, PartitionedEtwDispatcher.Lane(UnifiedEtwSession.Providers.KernelRegistry));
            Assert.Equal(4, PartitionedEtwDispatcher.Lane(UnifiedEtwSession.Providers.KernelNetwork));
            Assert.Equal(3, PartitionedEtwDispatcher.Lane(UnifiedEtwSession.Providers.DnsClient));
            Assert.Equal(3, PartitionedEtwDispatcher.Lane(Guid.NewGuid()));
        }
    }
}
