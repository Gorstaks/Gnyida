using System;

namespace Gnyida.Core
{
    /// <summary>
    /// Lets a poll loop log a state when it changes and then only as a bounded reminder.
    ///
    /// A reconciler that runs every few seconds and reports the same unchanged condition each time
    /// fills the diagnostic log (one firewall conflict was written more than 4,000 times in a day)
    /// and hides the lines that matter. The caller still performs and records every check; only the
    /// log line is thinned. A change of state always logs immediately.
    /// </summary>
    internal sealed class RepeatedStateLogGate
    {
        private readonly object _gate = new();
        private string? _lastSignature;
        private DateTimeOffset _lastLogged;

        /// <summary>True when <paramref name="signature"/> differs from the last logged state or the reminder interval has passed.</summary>
        internal bool ShouldLog(string signature, DateTimeOffset now, TimeSpan reminder)
        {
            lock (_gate)
            {
                bool changed = !string.Equals(signature, _lastSignature, StringComparison.Ordinal);
                if (!changed && now - _lastLogged < reminder) return false;
                _lastSignature = signature;
                _lastLogged = now;
                return true;
            }
        }
    }
}
