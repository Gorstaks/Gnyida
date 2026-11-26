using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Gnyida.Core
{
    /// <summary>
    /// Forwards <see cref="Trace"/> output to an <see cref="ILogger"/> so <see cref="BestEffort"/> warnings and
    /// legacy Trace warnings/errors land in the host's log instead of a debugger-only channel. Warnings and
    /// errors keep their level; plain Write/WriteLine is Debug, which the Service's diagnostic sink drops
    /// under its default Information threshold.
    /// </summary>
    public sealed class LoggerTraceListener : TraceListener
    {
        private readonly ILogger _logger;
        // Re-entrancy guard: a sink that reports its own failure through Trace (DiagnosticFileLoggerProvider
        // does) must not loop back into the same sink on the same thread.
        private readonly ThreadLocal<bool> _inside = new(() => false);

        public LoggerTraceListener(ILogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public override void Write(string? message) => WriteLine(message);

        public override void WriteLine(string? message)
        {
            if (string.IsNullOrWhiteSpace(message)) return;
            Forward(LogLevel.Debug, default, message!);
        }

        public override void TraceEvent(TraceEventCache? eventCache, string source, TraceEventType eventType, int id, string? message)
        {
            if (string.IsNullOrWhiteSpace(message)) return;
            Forward(Map(eventType), new EventId(id), message!);
        }

        private void Forward(LogLevel level, EventId id, string message)
        {
            if (_inside.Value) return;
            _inside.Value = true;
            try { _logger.Log(level, id, "{TraceMessage}", message); }
            finally { _inside.Value = false; }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _inside.Dispose();
            base.Dispose(disposing);
        }

        public override void TraceEvent(TraceEventCache? eventCache, string source, TraceEventType eventType, int id, string? format, params object?[]? args)
        {
            string? message = args == null || args.Length == 0 || format == null ? format : string.Format(format, args);
            TraceEvent(eventCache, source, eventType, id, message);
        }

        private static LogLevel Map(TraceEventType type)
        {
            switch (type)
            {
                case TraceEventType.Critical: return LogLevel.Critical;
                case TraceEventType.Error: return LogLevel.Error;
                case TraceEventType.Warning: return LogLevel.Warning;
                case TraceEventType.Information: return LogLevel.Information;
                default: return LogLevel.Debug;
            }
        }
    }
}
