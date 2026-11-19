using System;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class ModuleStompTriageTests
    {
        // PSAPI_WORKING_SET_EX_BLOCK: bit 0 Valid, bit 15 Shared.
        [Theory]
        [InlineData(0x0UL, false, false)]               // not resident
        [InlineData(0x1UL, true, true)]                 // resident, not shared: a private copy
        [InlineData(0x1UL | (1UL << 15), true, false)]  // resident and shared: pristine image page
        [InlineData(1UL << 15, false, false)]           // shared bit without Valid is not resident
        public void WorkingSetBits_AreDecodedCorrectly(ulong attributes, bool resident, bool privatePage)
        {
            Assert.Equal(resident, ModuleStompTriage.IsResident(attributes));
            Assert.Equal(privatePage, ModuleStompTriage.IsPrivateResident(attributes));
        }

        [Fact]
        public void ScratchBuffer_StaysBelowTheLargeObjectThreshold()
        {
            int bytes = ModuleStompTriage.BatchPages * System.Runtime.InteropServices.Marshal.SizeOf(typeof(ModuleStompTriage.WorkingSetExBlock));
            Assert.True(bytes < 85_000, "scratch array would be allocated on the large object heap: " + bytes);
        }

        [Fact]
        public void InvalidHandle_ReportsNothingAndDoesNotThrow()
        {
            var scratch = new ModuleStompTriage.WorkingSetExBlock[16];
            var outcome = ModuleStompTriage.Triage(IntPtr.Zero, 0x10000, 0x100000, scratch);
            Assert.Equal(0, outcome.PrivatePages);
            Assert.Equal(0, outcome.ExecutablePages);
        }

        [Fact]
        public void EmptyModule_IsRejectedWithoutQuerying()
        {
            var outcome = ModuleStompTriage.Triage(IntPtr.Zero, 0x10000, 0, new ModuleStompTriage.WorkingSetExBlock[16]);
            Assert.True(outcome.QueryFailed);
        }

        [Fact]
        public void CleanSystemModuleInThisProcess_HasFewOrNoPrivateCodePages()
        {
            // Sanity check against a real process: the code of a loaded system DLL is overwhelmingly shared.
            // The assertion is loose on purpose (hooks by other software can make a few pages private).
            var scratch = new ModuleStompTriage.WorkingSetExBlock[ModuleStompTriage.BatchPages];
            using var self = System.Diagnostics.Process.GetCurrentProcess();
            IntPtr handle = NativeProcessMemory.OpenRemoteHandle(
                NativeProcessMemory.AccessQuery | NativeProcessMemory.AccessVmRead, self.Id);
            if (handle == IntPtr.Zero) return; // the self-inspection gate refused; nothing to assert
            try
            {
                foreach (System.Diagnostics.ProcessModule m in self.Modules)
                {
                    using (m)
                    {
                        if (!string.Equals(m.ModuleName, "kernel32.dll", StringComparison.OrdinalIgnoreCase)) continue;
                        var outcome = ModuleStompTriage.Triage(handle, m.BaseAddress.ToInt64(), m.ModuleMemorySize, scratch);
                        Assert.False(outcome.QueryFailed);
                        Assert.True(outcome.ExecutablePages > 0);
                        Assert.True(outcome.PrivatePages * 10 <= outcome.ExecutablePages, $"{outcome.PrivatePages} of {outcome.ExecutablePages} pages private");
                    }
                }
            }
            finally { NativeProcessMemory.CloseHandle(handle); }
        }
    }
}
