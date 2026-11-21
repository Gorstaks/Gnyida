using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Sentinel.Core
{
    // Manifest reference: Microsoft-Windows-Kernel-File, NameCreate v0, Read v0/v1.
    // Only sensitive names are retained; no cache/browser-event firehose enters fusion.
    internal sealed class CredentialReadTracker
    {
        private readonly object _gate = new();
        private readonly Dictionary<ulong, (string path, DateTime seen)> _names = new();
        private readonly Dictionary<(int pid, ulong key), DateTime> _recent = new();
        private const int Capacity = 4096;

        // Admission state read on the ETW callback thread. Kernel-File Read (15) fires for every read on the
        // system; only reads of a key already named as a credential store can ever match, so the rest are not
        // queued. _sensitiveKeys mirrors _names. _pendingNames counts NameCreate/NameDelete events queued but
        // not yet observed, so a read that arrives before its name is processed is still admitted; the file lane
        // is FIFO, so Observe sees that name first, exactly as before admission existed.
        private readonly ConcurrentDictionary<ulong, byte> _sensitiveKeys = new();
        private readonly ConcurrentDictionary<ulong, int> _pendingNames = new();

        /// <summary>FileKey of a NameCreate/NameDelete v0 payload, under the same checks Observe applies.</summary>
        internal static bool TryReadNameKey(IntPtr data, int length, ushort id, byte version, int width, out ulong key)
        {
            key = 0;
            if ((id != 10 && id != 11) || version != 0 || (width != 4 && width != 8) ||
                data == IntPtr.Zero || length < width + 2) return false;
            key = ReadPointer(data, 0, width);
            return true;
        }

        /// <summary>FileKey of a Read v0/v1 payload, under the same checks Observe applies.</summary>
        internal static bool TryReadReadKey(IntPtr data, int length, byte version, int width, int pid, out ulong key)
        {
            key = 0;
            if (version > 1 || pid <= 4 || (width != 4 && width != 8) || data == IntPtr.Zero) return false;
            int offset = ReadKeyOffset(version, width);
            if (length < offset + width + (version == 0 ? 8 : 16)) return false;
            key = ReadPointer(data, offset, width);
            return true;
        }

        private static int ReadKeyOffset(byte version, int width) => 8 + (version == 0 ? 3 : 2) * width;

        /// <summary>True when a read of this key could resolve to a credential store.</summary>
        internal bool MayMatchRead(ulong key) => _sensitiveKeys.ContainsKey(key) || _pendingNames.ContainsKey(key);

        /// <summary>Call before queueing a name event; pair with Observe or, if the event was not queued, ReleasePending.</summary>
        internal void NotePending(ulong key) => _pendingNames.AddOrUpdate(key, 1, (_, n) => n + 1);

        internal void ReleasePending(ulong key)
        {
            for (int attempt = 0; attempt < 8; attempt++)
            {
                if (!_pendingNames.TryGetValue(key, out int n)) return;
                bool done = n <= 1
                    ? ((ICollection<KeyValuePair<ulong, int>>)_pendingNames).Remove(new KeyValuePair<ulong, int>(key, n))
                    : _pendingNames.TryUpdate(key, n - 1, n);
                if (done) return;
            }
        }

        // Indicator data lives in Indicators/indicators.txt (compressed resource); see IndicatorCatalog.
        // All values are lower-case and matched ordinally against the lower-cased path, as before.
        private static readonly string[] SensitiveSuffixes = IndicatorCatalog.List("credRead.suffixes");
        private static readonly string[] SshKeySuffixes = IndicatorCatalog.List("credRead.sshKeySuffixes");
        private static readonly string[] ChatSessionStores = IndicatorCatalog.List("credRead.chatSessionStores");

        internal static bool IsSensitivePath(string path)
        {
            var p = path.Replace('/', '\\').ToLowerInvariant();
            return IsWindowsVaultPath(p) ||
                SensitiveSuffixes.Any(s => p.EndsWith(s, StringComparison.Ordinal)) ||
                (p.Contains("\\.ssh\\") && SshKeySuffixes.Any(s => p.EndsWith(s, StringComparison.Ordinal))) ||
                (ChatSessionStores.Any(s => p.Contains(s)) &&
                 (p.EndsWith(".ldb", StringComparison.Ordinal) || p.EndsWith(".log", StringComparison.Ordinal)));
        }

        private static bool IsWindowsVaultPath(string path)
        {
            foreach (var root in new[] { @"\appdata\local\microsoft\vault\", @"\appdata\roaming\microsoft\vault\" })
            {
                int start = path.IndexOf(root, StringComparison.Ordinal);
                if (start < 0) continue;
                var parts = path.Substring(start + root.Length).Split('\\');
                if (parts.Length != 2) continue;
                if (parts[0] == "userprofileroaming" && parts[1] == "latest.dat") return true;
                if (!Guid.TryParse(parts[0], out _)) continue;
                if (parts[1] == "policy.vpol") return true;
                if (parts[1].EndsWith(".vcrd", StringComparison.Ordinal) &&
                    Guid.TryParse(parts[1].Substring(0, parts[1].Length - 5), out _)) return true;
            }
            return false;
        }

        internal string? Observe(EtwRawEvent evt)
        {
            int width = evt.PointerSize;
            if ((width != 4 && width != 8) || evt.UserData == IntPtr.Zero) return null;
            lock (_gate)
            {
                if (TryReadNameKey(evt.UserData, evt.UserDataLength, evt.EventId, evt.Version, width, out ulong key))
                {
                    try { return ObserveName(evt, width, key); }
                    // The mapping is settled (set or removed) before the pending mark goes.
                    finally { ReleasePending(key); }
                }
                if (evt.EventId != 15 ||
                    !TryReadReadKey(evt.UserData, evt.UserDataLength, evt.Version, width, evt.ProcessId, out ulong fileKey))
                    return null;
                if (!_names.TryGetValue(fileKey, out var entry)) return null;
                var age = evt.Timestamp - entry.seen;
                if (age < TimeSpan.Zero || age > TimeSpan.FromMinutes(2))
                {
                    RemoveName(fileKey);
                    return null;
                }
                var identity = (evt.ProcessId, fileKey);
                if (_recent.TryGetValue(identity, out var last) && evt.Timestamp >= last &&
                    evt.Timestamp - last < TimeSpan.FromSeconds(20)) return null;
                if (_recent.Count >= Capacity) _recent.Clear();
                _recent[identity] = evt.Timestamp;
                return entry.path;
            }
        }

        // Caller holds _gate.
        private string? ObserveName(EtwRawEvent evt, int width, ulong key)
        {
            // Invalidate even an uninteresting replacement name (FileKey reuse).
            RemoveName(key);
            if (evt.EventId == 11 || key == 0) return null;
            int bytes = evt.UserDataLength - width;
            if ((bytes & 1) != 0 || bytes > 2048) return null;
            string name = Marshal.PtrToStringUni(IntPtr.Add(evt.UserData, width), bytes / 2) ?? "";
            int end = name.IndexOf('\0');
            if (end < 0) return null;
            name = name.Substring(0, end);
            if (!IsSensitivePath(name)) return null;
            if (_names.Count >= Capacity) { _names.Clear(); _sensitiveKeys.Clear(); }
            _names[key] = (name, evt.Timestamp);
            _sensitiveKeys[key] = 0;
            return null;
        }

        private void RemoveName(ulong key)
        {
            _names.Remove(key);
            _sensitiveKeys.TryRemove(key, out _);
        }

        private static ulong ReadPointer(IntPtr data, int offset, int width) => width == 8
            ? unchecked((ulong)Marshal.ReadInt64(data, offset))
            : unchecked((uint)Marshal.ReadInt32(data, offset));
    }
}
