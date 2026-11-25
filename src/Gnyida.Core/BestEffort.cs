using System.Diagnostics;

namespace Gnyida.Core
{
    /// <summary>
    /// Records an exception that a best-effort operation deliberately tolerates (a process that exited
    /// mid-scan, a registry key that is absent, an optional cleanup). Constraint: no silent exception
    /// swallowing - every catch must log, debug level at minimum.
    /// <para>
    /// Callable from static helpers, finalizers and Dispose paths that have no injected
    /// <see cref="Microsoft.Extensions.Logging.ILogger"/>. Output goes through <see cref="Trace"/>; the
    /// Service host and the Agent attach <see cref="LoggerTraceListener"/>, so warnings reach their logs.
    /// </para>
    /// <list type="bullet">
    /// <item><see cref="Debug"/> - expected, high-volume failures (a process exited mid-scan). Off unless the
    /// <c>Gnyida.BestEffort</c> trace switch is raised to Verbose, and even then dropped by the Service's
    /// diagnostic sink below its Information threshold. It records the tolerated exception at the call
    /// site for debugging; it is not an operational alert.</item>
    /// <item><see cref="Warn"/> - a failure that can weaken protection (key or ACL handling, a lost
    /// detection, a response action that did not complete). Always emitted and kept by the sink.</item>
    /// </list>
    /// Never throws: a broken trace listener must not terminate a detection thread.
    /// </summary>
    public static class BestEffort
    {
        private static readonly TraceSwitch Verbosity = new("Gnyida.BestEffort",
            "Verbose enables debug records for tolerated exceptions", nameof(TraceLevel.Warning));

        public static void Debug(Exception ex, string site)
        {
            try
            {
                if (!Verbosity.TraceVerbose) return;
                Trace.WriteLine(Format(ex, site), "Gnyida.BestEffort");
            }
            catch (Exception)
            {
                // A faulty trace listener is not allowed to propagate into the caller.
            }
        }

        public static void Warn(Exception ex, string site)
        {
            try
            {
                Trace.TraceWarning(Format(ex, site));
            }
            catch (Exception)
            {
                // A faulty trace listener is not allowed to propagate into the caller.
            }
        }

        private static string Format(Exception ex, string site)
        {
            string message = ex.Message ?? string.Empty;
            if (message.Length > 500) message = message.Substring(0, 500);
            return site + ": " + ex.GetType().Name + ": " + message;
        }
    }
}
