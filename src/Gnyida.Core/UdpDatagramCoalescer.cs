using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading;

namespace Gnyida.Core
{
    /// <summary>Identity of a UDP flow as seen from one process: remote endpoint and direction.</summary>
    internal readonly struct UdpFlowKey : IEquatable<UdpFlowKey>
    {
        public readonly int ProcessId;
        public readonly ulong AddressHigh;
        public readonly ulong AddressLow;
        public readonly ushort RemotePort;
        public readonly bool Send;

        public UdpFlowKey(int processId, ulong addressHigh, ulong addressLow, ushort remotePort, bool send)
        {
            ProcessId = processId; AddressHigh = addressHigh; AddressLow = addressLow; RemotePort = remotePort; Send = send;
        }

        public bool Equals(UdpFlowKey other) =>
            ProcessId == other.ProcessId && AddressHigh == other.AddressHigh && AddressLow == other.AddressLow &&
            RemotePort == other.RemotePort && Send == other.Send;

        public override bool Equals(object? obj) => obj is UdpFlowKey other && Equals(other);

        public override int GetHashCode()
        {
            unchecked
            {
                int h = ProcessId;
                h = h * 397 ^ AddressHigh.GetHashCode();
                h = h * 397 ^ AddressLow.GetHashCode();
                h = h * 397 ^ RemotePort;
                return h * 397 ^ (Send ? 1 : 0);
            }
        }
    }

    /// <summary>
    /// Collapses repeated UDP datagrams to the same remote endpoint into one observation per window.
    ///
    /// Kernel-Network reports every datagram. QUIC, DNS, VoIP, game and streaming traffic produce
    /// thousands per second, and each one used to cost a process-name lookup plus a full fusion and
    /// detection pass. That filled the shared dispatch queue, dropped events and kept the ETW health
    /// guard reporting a visibility gap. The detections downstream key on (process, remote address,
    /// remote port, direction), so the first datagram to each distinct endpoint per window carries
    /// all the information the repeats would. A new endpoint is never suppressed, which keeps
    /// bad-port and first-contact detection intact. Repeats are counted, not hidden.
    ///
    /// Memory is bounded: when the table fills it is cleared, which only causes some repeats to be
    /// admitted again.
    /// </summary>
    internal sealed class UdpDatagramCoalescer
    {
        internal const int MaxEntries = 32768;
        private static readonly long WindowTicks = Stopwatch.Frequency; // one second

        private readonly ConcurrentDictionary<UdpFlowKey, long> _lastAdmitted = new();
        private int _entries;
        private long _coalesced;

        /// <summary>Datagrams skipped because the same flow was already admitted in the current window.</summary>
        internal long Coalesced => Interlocked.Read(ref _coalesced);

        /// <summary>True when the datagram should be analysed; false when it repeats a recent flow.</summary>
        internal bool TryAdmit(in UdpFlowKey key, long nowTimestamp)
        {
            if (_lastAdmitted.TryGetValue(key, out var last))
            {
                if (nowTimestamp - last < WindowTicks)
                {
                    Interlocked.Increment(ref _coalesced);
                    return false;
                }
                _lastAdmitted[key] = nowTimestamp;
                return true;
            }

            if (Interlocked.Increment(ref _entries) > MaxEntries)
            {
                _lastAdmitted.Clear();
                Interlocked.Exchange(ref _entries, 1);
            }
            _lastAdmitted[key] = nowTimestamp;
            return true;
        }

        internal bool TryAdmit(in UdpFlowKey key) => TryAdmit(key, Stopwatch.GetTimestamp());
    }
}
