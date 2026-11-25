using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Gnyida.Core
{
    /// <summary>
    /// Awaits readability on either of two channel lanes while keeping at most ONE outstanding
    /// <c>WaitToReadAsync</c> per lane. A wait is re-issued only after it has completed.
    /// <para>
    /// Issuing a fresh pair of waits on every idle pass and racing them with <c>Task.WhenAny</c> leaves
    /// the losing wait pending. Each pending wait stays registered on the (service-lifetime) token and in
    /// the channel's waiter list until that lane next receives data, so a rarely-written lane accumulates
    /// one waiter per idle pass. In 3.7.7 this reached 15.8 M AsyncOperation/Task/CancellationCallbackInfo
    /// objects (~5 GB) in <see cref="DetectionEngine"/>'s drain loop.
    /// </para>
    /// Not thread-safe: one instance per single consumer loop.
    /// </summary>
    internal sealed class DualLaneWait<TPriority, TNormal>
    {
        private readonly ChannelReader<TPriority> _priority;
        private readonly ChannelReader<TNormal> _normal;
        private Task<bool>? _priorityWait;
        private Task<bool>? _normalWait;

        public DualLaneWait(ChannelReader<TPriority> priority, ChannelReader<TNormal> normal)
        {
            _priority = priority;
            _normal = normal;
        }

        /// <summary>
        /// Completes when either lane reports readable data (result true) or completion (result false).
        /// Returns the wait that completed; it is consumed, so the next call re-issues it.
        /// </summary>
        public async Task<Task<bool>> WaitAsync(CancellationToken ct)
        {
            _priorityWait ??= _priority.WaitToReadAsync(ct).AsTask();
            _normalWait ??= _normal.WaitToReadAsync(ct).AsTask();
            var ready = await Task.WhenAny(_priorityWait, _normalWait).ConfigureAwait(false);
            if (ReferenceEquals(ready, _priorityWait)) _priorityWait = null;
            else _normalWait = null;
            return ready;
        }
    }
}
