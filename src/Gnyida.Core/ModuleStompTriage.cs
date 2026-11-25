using System;
using System.Runtime.InteropServices;

namespace Gnyida.Core
{
    /// <summary>
    /// Cheap first stage for module-stomping detection. A pristine image's code pages are shared
    /// copy-on-write pages. When a process writes to one (to hook it, or to overwrite it with a payload),
    /// Windows gives that process a private copy, and QueryWorkingSetEx reports the page as not shared.
    /// So a module whose executable pages are all still shared has not been modified, and no code bytes
    /// need to be read to know that.
    ///
    /// Limits, stated so nobody over-trusts a clean result: only resident pages are reported. A modified
    /// page that has been paged out is invisible here. A private page is not proof of tampering (hooks and
    /// compatibility shims also make private pages), so the caller confirms with
    /// <see cref="ImageIntegrityVerifier"/> before reporting anything.
    ///
    /// Resource rules (docs/MEMORY_LEAK_3.7.8.md): no handles are opened here, no state is kept, and the
    /// scratch array is supplied by the caller and reused, 64 KB at most (below the 85 KB large-object threshold).
    /// </summary>
    internal static class ModuleStompTriage
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct WorkingSetExBlock
        {
            public IntPtr VirtualAddress;
            public UIntPtr Attributes;
        }

        internal sealed class Outcome
        {
            public int ExecutablePages;
            public int PrivatePages;
            public int NotResidentPages;
            /// <summary>An image region that is writable and executable at once (never normal for a system DLL).</summary>
            public bool WritableExecutableImage;
            public bool QueryFailed;
        }

        [DllImport("kernel32.dll", EntryPoint = "K32QueryWorkingSetEx", SetLastError = true)]
        private static extern bool QueryWorkingSetEx(IntPtr process, [In, Out] WorkingSetExBlock[] info, int size);

        private const int PageSize = 4096;
        private const ulong ValidBit = 1UL;
        private const ulong SharedBit = 1UL << 15;

        /// <summary>Scratch array length. 4096 entries of 16 bytes is 64 KB.</summary>
        internal const int BatchPages = 4096;

        internal static bool IsPrivateResident(ulong attributes) => (attributes & ValidBit) != 0 && (attributes & SharedBit) == 0;
        internal static bool IsResident(ulong attributes) => (attributes & ValidBit) != 0;

        /// <summary>
        /// Counts private resident executable pages of the image mapped at <paramref name="moduleBase"/>.
        /// <paramref name="process"/> needs PROCESS_QUERY_INFORMATION and PROCESS_VM_READ.
        /// </summary>
        internal static Outcome Triage(IntPtr process, long moduleBase, long moduleSize, WorkingSetExBlock[] scratch)
        {
            var outcome = new Outcome();
            if (moduleSize <= 0 || scratch == null || scratch.Length == 0) { outcome.QueryFailed = true; return outcome; }
            int entry = Marshal.SizeOf(typeof(WorkingSetExBlock));
            int filled = 0;
            long address = moduleBase;
            long end = moduleBase + moduleSize;
            while (address < end)
            {
                if (NativeProcessMemory.QueryRemoteRegion(process, new IntPtr(address), out var mbi) == 0) break;
                long regionStart = mbi.BaseAddress.ToInt64();
                long regionEnd = Math.Min(regionStart + mbi.RegionSize.ToInt64(), end);
                if (regionEnd <= address) break;
                if (mbi.Type == NativeProcessMemory.TypeImage && mbi.State == NativeProcessMemory.StateCommit &&
                    NativeProcessMemory.IsExecutableProtection(mbi.Protect))
                {
                    if (mbi.Protect == NativeProcessMemory.ProtRWX) outcome.WritableExecutableImage = true;
                    for (long page = Math.Max(address, regionStart) & ~(long)(PageSize - 1); page < regionEnd; page += PageSize)
                    {
                        scratch[filled].VirtualAddress = new IntPtr(page);
                        scratch[filled].Attributes = UIntPtr.Zero;
                        if (++filled == scratch.Length)
                        {
                            if (!Flush(process, scratch, filled, entry, outcome)) return outcome;
                            filled = 0;
                        }
                    }
                }
                address = regionEnd;
            }
            if (filled > 0) Flush(process, scratch, filled, entry, outcome);
            return outcome;
        }

        /// <summary>
        /// True when the page containing <paramref name="address"/> is in the target's working set. Reading a page that is
        /// not resident makes the system fetch it, which is a hard fault in the target; callers that sweep many
        /// processes use this to read only what is already in memory.
        /// </summary>
        internal static bool IsResident(IntPtr process, long address)
        {
            var one = new WorkingSetExBlock[1];
            one[0].VirtualAddress = new IntPtr(address & ~(long)(PageSize - 1));
            return QueryWorkingSetEx(process, one, Marshal.SizeOf(typeof(WorkingSetExBlock))) &&
                   IsResident(one[0].Attributes.ToUInt64());
        }

        private static bool Flush(IntPtr process, WorkingSetExBlock[] scratch, int count, int entrySize, Outcome outcome)
        {
            if (!QueryWorkingSetEx(process, scratch, count * entrySize))
            {
                outcome.QueryFailed = true;
                return false;
            }
            for (int i = 0; i < count; i++)
            {
                ulong attributes = scratch[i].Attributes.ToUInt64();
                outcome.ExecutablePages++;
                if (!IsResident(attributes)) outcome.NotResidentPages++;
                else if (IsPrivateResident(attributes)) outcome.PrivatePages++;
            }
            return true;
        }
    }
}
