using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    /// <summary>
    /// Reads a child process's redirected stdout with a deadline that actually holds.
    ///
    /// The pattern this replaces is
    ///     var output = p.StandardOutput.ReadToEnd();
    ///     p.WaitForExit(5000);
    /// where ReadToEnd() blocks until the child closes its output, so the timeout on the next line can never fire.
    /// A hung netstat, netsh, bcdedit or logman then parks the calling monitor's thread for good, and a monitor that
    /// is parked is a monitor that is off. (The same flaw was fixed in SentinelAutoRotate's Scheduler.Run.)
    ///
    /// Here the read starts first and the deadline is applied to the process. On timeout the child is killed, which
    /// closes its pipe. The caller still owns and disposes the Process.
    /// </summary>
    internal static class BoundedProcess
    {
        /// <summary>
        /// Output of an already started process whose stdout is redirected. Returns what was read; on timeout the
        /// process is killed and whatever arrived before the deadline is returned.
        /// </summary>
        internal static string ReadOutput(Process process, int timeoutMs)
        {
            Task<string> read = process.StandardOutput.ReadToEndAsync();
            if (process.WaitForExit(timeoutMs))
            {
                process.WaitForExit(); // let the asynchronous reader flush before the result is taken
                return Result(read, 5000);
            }
            try { process.Kill(); }
            catch (Exception ex) { /* exited between the timeout and the kill, or access denied */ BestEffort.Debug(ex, "BoundedProcess.ReadOutput()"); }
            try { process.WaitForExit(2000); } catch (Exception ex) { BestEffort.Debug(ex, "BoundedProcess.ReadOutput()"); }
            // A grandchild that inherited the pipe can keep it open after the kill; do not wait for it.
            return Result(read, 1000);
        }

        /// <summary>
        /// Async form of <see cref="ReadOutput"/>. The deadline and the caller's token share one per-call linked token
        /// source that is disposed on every path, so nothing is registered on a long-lived token and left there
        /// (the leak recorded in docs/MEMORY_LEAK_3.7.8.md). If the caller's token is cancelled the child is killed
        /// and the cancellation is rethrown; if only the deadline passes, the child is killed and what had arrived
        /// is returned.
        /// </summary>
        internal static async Task<string> ReadOutputAsync(Process process, int timeoutMs, System.Threading.CancellationToken ct)
        {
            Task<string> read = process.StandardOutput.ReadToEndAsync();
            using (var linked = System.Threading.CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                linked.CancelAfter(timeoutMs);
                try
                {
                    await process.WaitForExitAsync(linked.Token).ConfigureAwait(false);
                    return await ResultAsync(read, 5000).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    try { process.Kill(); }
                    catch (Exception ex) { /* already exited, or access denied */ BestEffort.Debug(ex, "BoundedProcess.ReadOutputAsync()"); }
                    if (ct.IsCancellationRequested) throw;
                    return await ResultAsync(read, 1000).ConfigureAwait(false);
                }
            }
        }

        // Task.Delay without a token completes by itself, so this wait cannot leave a registration behind.
        private static async Task<string> ResultAsync(Task<string> read, int waitMs)
        {
            Task finished = await Task.WhenAny(read, Task.Delay(waitMs)).ConfigureAwait(false);
            return finished == read && !read.IsFaulted && !read.IsCanceled ? read.Result : "";
        }
        private static string Result(Task<string> read, int waitMs)
        {
            try { return read.Wait(waitMs) ? read.Result : ""; }
            catch (AggregateException) { return ""; }
        }
    }
}
