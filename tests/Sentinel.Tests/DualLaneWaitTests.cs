using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// Regression for the 3.7.7 leak: the DetectionEngine drain loop started a new WaitToReadAsync on
    /// BOTH lanes every idle pass and raced them, leaving the losing wait pending (15.8 M leaked
    /// AsyncOperation/Task/CancellationCallbackInfo, ~5 GB). No elevation, network or file state.
    /// </summary>
    public class DualLaneWaitTests
    {
        private sealed class CountingReader : ChannelReader<int>
        {
            private readonly ChannelReader<int> _inner;
            public int WaitCalls;
            public CountingReader(ChannelReader<int> inner) => _inner = inner;
            public override bool TryRead(out int item) => _inner.TryRead(out item);
            public override ValueTask<bool> WaitToReadAsync(CancellationToken cancellationToken = default)
            {
                Interlocked.Increment(ref WaitCalls);
                return _inner.WaitToReadAsync(cancellationToken);
            }
        }

        [Fact]
        public async Task IdleLane_IsNotReWaited_WhenOtherLaneKeepsWaking()
        {
            var priority = Channel.CreateUnbounded<int>();
            var normal = Channel.CreateUnbounded<int>();
            var priorityReader = new CountingReader(priority.Reader);
            var normalReader = new CountingReader(normal.Reader);
            var lanes = new DualLaneWait<int, int>(priorityReader, normalReader);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            const int cycles = 500;
            for (int i = 0; i < cycles; i++)
            {
                normal.Writer.TryWrite(i);
                var ready = await lanes.WaitAsync(cts.Token);
                Assert.True(ready.Result);
                Assert.True(normal.Reader.TryRead(out _));
            }

            // One normal-lane wait per cycle, but the never-written priority lane is waited on once.
            Assert.Equal(1, priorityReader.WaitCalls);
            Assert.Equal(cycles, normalReader.WaitCalls);
        }

        [Fact]
        public async Task PriorityLane_WaitIsReissued_AfterItCompletes()
        {
            var priority = Channel.CreateUnbounded<int>();
            var normal = Channel.CreateUnbounded<int>();
            var priorityReader = new CountingReader(priority.Reader);
            var normalReader = new CountingReader(normal.Reader);
            var lanes = new DualLaneWait<int, int>(priorityReader, normalReader);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            for (int i = 0; i < 3; i++)
            {
                priority.Writer.TryWrite(i);
                var ready = await lanes.WaitAsync(cts.Token);
                Assert.True(ready.Result);
                Assert.True(priority.Reader.TryRead(out _));
            }

            Assert.Equal(3, priorityReader.WaitCalls);
            Assert.Equal(1, normalReader.WaitCalls);
        }

        [Fact]
        public async Task Cancellation_UnblocksPendingWait()
        {
            var priority = Channel.CreateUnbounded<int>();
            var normal = Channel.CreateUnbounded<int>();
            var lanes = new DualLaneWait<int, int>(priority.Reader, normal.Reader);
            using var cts = new CancellationTokenSource();

            var pending = lanes.WaitAsync(cts.Token);
            Assert.False(pending.IsCompleted);
            cts.Cancel();

            // The wait that completes is reported as cancelled (the engine checks Status before Result,
            // and its loop-top ThrowIfCancellationRequested then exits).
            var ready = await pending;
            Assert.True(ready.IsCanceled);
            Assert.Throws<OperationCanceledException>(() => cts.Token.ThrowIfCancellationRequested());
        }

        [Fact]
        public async Task CompletedChannels_ReportNoMoreData()
        {
            var priority = Channel.CreateUnbounded<int>();
            var normal = Channel.CreateUnbounded<int>();
            var lanes = new DualLaneWait<int, int>(priority.Reader, normal.Reader);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            priority.Writer.Complete();
            normal.Writer.Complete();
            var ready = await lanes.WaitAsync(cts.Token);

            Assert.False(ready.Result);
            Assert.True(priority.Reader.Completion.IsCompleted);
            Assert.True(normal.Reader.Completion.IsCompleted);
        }
    }
}
