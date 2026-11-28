using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace Gnyida.Core
{
    // One FIFO worker per lane. File/registry floods cannot consume process/image
    // slots or block their worker. This preserves ordering within every provider;
    // cross-provider arrival order is not a causality or response-authority guarantee.
    internal sealed class PartitionedEtwDispatcher : IDisposable
    {
        private readonly BoundedEtwDispatcher[] _lanes;
        private readonly long[] _drops = new long[5];
        // The file lane absorbs bursty Kernel-File traffic (installers, builds, scans). A scale
        // above 1 enlarges only that lane; capacity and bytes stay bounded, so memory is capped.
        internal PartitionedEtwDispatcher(Action<Exception> failure, int laneCapacity = 2048, long laneByteLimit = 4 * 1024 * 1024, int fileLaneScale = 1, int networkLaneScale = 1)
        {
            if (fileLaneScale < 1) throw new ArgumentOutOfRangeException(nameof(fileLaneScale));
            if (networkLaneScale < 1) throw new ArgumentOutOfRangeException(nameof(networkLaneScale));
            _lanes = new BoundedEtwDispatcher[5];
            for (int i = 0; i < _lanes.Length; i++)
            {
                int scale = i == 1 ? fileLaneScale : i == 4 ? networkLaneScale : 1;
                _lanes[i] = new BoundedEtwDispatcher(failure, laneCapacity * scale, laneByteLimit * scale);
            }
        }
        internal static int Lane(Guid provider) => provider == UnifiedEtwSession.Providers.KernelProcess ? 0 :
            provider == UnifiedEtwSession.Providers.KernelFile ? 1 :
            provider == UnifiedEtwSession.Providers.KernelRegistry ? 2 :
            // Datagram-level network events are bursty. Their own lane keeps them from displacing DNS,
            // PowerShell, task, firewall and WMI events that share the general lane.
            provider == UnifiedEtwSession.Providers.KernelNetwork ? 4 : 3;
        internal bool TryDispatch(EtwRawEvent evt, Action<EtwRawEvent> handler)
        {
            int lane = Lane(evt.ProviderId);
            if (_lanes[lane].TryDispatch(evt, handler)) return true;
            Interlocked.Increment(ref _drops[lane]); return false;
        }
        internal bool IsAlive => _lanes.All(l => l.IsAlive);
        internal int QueueDepth => _lanes.Sum(l => l.QueueDepth);
        internal long QueuedBytes => _lanes.Sum(l => l.QueuedBytes);
        internal double HandlerBusyMs => _lanes.Max(l => l.HandlerBusyMs);
        internal Dictionary<string, long> DropSnapshot() => new()
        {
            ["ProcessImage"] = Interlocked.Read(ref _drops[0]),
            ["File"] = Interlocked.Read(ref _drops[1]),
            ["Registry"] = Interlocked.Read(ref _drops[2]),
            ["Other"] = Interlocked.Read(ref _drops[3]),
            ["Network"] = Interlocked.Read(ref _drops[4])
        };
        public void Dispose()
        {
            var errors = new List<Exception>();
            // Stop every lane even if an earlier worker cannot finish.
            foreach (var lane in _lanes)
                try { lane.Dispose(); } catch (Exception ex) { errors.Add(ex); }
            if (errors.Count > 0) throw new AggregateException("ETW lane shutdown incomplete", errors);
        }
    }
}
