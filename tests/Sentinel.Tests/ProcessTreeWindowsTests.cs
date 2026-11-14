using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Xunit;

namespace Sentinel.Tests
{
    public sealed class WindowsContainmentFactAttribute : FactAttribute
    {
        public WindowsContainmentFactAttribute()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                Skip = "Requires Windows process handles and process enumeration.";
        }
    }

    public class ProcessTreeWindowsTests
    {
        // The fixture tree is cmd.exe -> cmd.exe -> ping.exe, with ping as a plain sleeper. It uses no
        // PowerShell and no encoded commands: hidden nested -EncodedCommand PowerShell is what AV
        // behavior shields block as a stager, which made this fixture fail on machines with such AV.
        private static readonly string SystemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
        private static readonly string Cmd = Path.Combine(SystemDirectory, "cmd.exe");
        private static readonly string Ping = Path.Combine(SystemDirectory, "PING.EXE");

        [WindowsContainmentFact]
        public async Task KillTree_VerifiesParentChildAndGrandchildExit_LeavesUnrelatedProcessRunning()
        {
            string sleep = "\"" + Ping + "\" -n 120 127.0.0.1 >nul";
            Process? root = null, child = null, grandchild = null, unrelated = null;
            try
            {
                root = Start(Cmd, "/d /c start /b \"\" \"" + Cmd + "\" /d /c " + sleep + " & " + sleep);
                unrelated = Start(Ping, "-n 120 127.0.0.1");
                int rootPid = root.Id;
                int childPid = await WaitForChildAsync(rootPid, "cmd.exe");
                int grandchildPid = await WaitForChildAsync(childPid, "ping.exe");
                child = Process.GetProcessById(childPid);
                grandchild = Process.GetProcessById(grandchildPid);
                // Pin the original instances before containment, including for test cleanup.
                _ = root.Handle;
                _ = child.Handle;
                _ = grandchild.Handle;
                _ = unrelated.Handle;

                var result = root.KillTree();

                Assert.True(result.Success,
                    $"{result.Error}; rootExited={result.RootExited}; discoveryComplete={result.DiscoveryComplete}; " +
                    $"exited={string.Join(",", result.ExitedProcessIds)}; " +
                    $"failed={string.Join(",", result.FailedProcessIds)}; " +
                    $"refused={string.Join(",", result.RefusedProcessIds)}");
                Assert.Contains(rootPid, result.ExitedProcessIds);
                Assert.Contains(childPid, result.ExitedProcessIds);
                Assert.Contains(grandchildPid, result.ExitedProcessIds);
                Assert.True(root.WaitForExit(5000));
                Assert.True(child.WaitForExit(5000));
                Assert.True(grandchild.WaitForExit(5000));
                Assert.False(unrelated.HasExited);
            }
            finally
            {
                foreach (var process in new[] { grandchild, child, root, unrelated })
                {
                    if (process == null) continue;
                    try
                    {
                        if (!process.HasExited) { process.Kill(); process.WaitForExit(5000); }
                    }
                    catch (InvalidOperationException) { /* fixture already exited */ }
                    catch (System.ComponentModel.Win32Exception) { /* fixture exiting or access lost */ }
                    finally { process.Dispose(); }
                }
            }
        }

        [WindowsContainmentFact]
        public void ChildLookup_FindsOnlyDirectChildrenOfThatParent()
        {
            int self = Process.GetCurrentProcess().Id;
            using var p = Start(Ping, "-n 30 127.0.0.1");
            try
            {
                var deadline = Stopwatch.StartNew();
                List<int> found;
                do { found = FindChildren(self, "ping.exe"); } while (!found.Contains(p.Id) && deadline.Elapsed < TimeSpan.FromSeconds(5));
                Assert.Contains(p.Id, found);
                Assert.DoesNotContain(p.Id, FindChildren(self, "cmd.exe"));
                Assert.DoesNotContain(p.Id, FindChildren(p.Id, "ping.exe"));
            }
            finally
            {
                try { if (!p.HasExited) { p.Kill(); p.WaitForExit(5000); } } catch (InvalidOperationException) { }
            }
        }

        private static Process Start(string executable, string arguments)
            => Process.Start(new ProcessStartInfo(executable, arguments) { UseShellExecute = false, CreateNoWindow = true })
               ?? throw new InvalidOperationException("Unable to start process-tree fixture.");

        private static async Task<int> WaitForChildAsync(int parentPid, string imageName)
        {
            var timer = Stopwatch.StartNew();
            while (timer.Elapsed < TimeSpan.FromSeconds(30))
            {
                var children = FindChildren(parentPid, imageName);
                if (children.Count > 0) return children[0];
                await Task.Delay(50);
            }
            throw new TimeoutException("Process-tree fixture did not start " + imageName + " under PID " + parentPid + ".");
        }

        // Kernel process table (Toolhelp), so the parent link is the OS record, not fixture output.
        private static List<int> FindChildren(int parentPid, string imageName)
        {
            var result = new List<int>();
            IntPtr snapshot = CreateToolhelp32Snapshot(0x00000002, 0);
            if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1)) return result;
            try
            {
                var entry = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32)) };
                for (bool ok = Process32First(snapshot, ref entry); ok; ok = Process32Next(snapshot, ref entry))
                {
                    if (entry.th32ParentProcessID == (uint)parentPid &&
                        string.Equals(entry.szExeFile, imageName, StringComparison.OrdinalIgnoreCase))
                        result.Add((int)entry.th32ProcessID);
                }
            }
            finally { CloseHandle(snapshot); }
            return result;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "Process32FirstW", SetLastError = true)]
        private static extern bool Process32First(IntPtr snapshot, ref PROCESSENTRY32 entry);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "Process32NextW", SetLastError = true)]
        private static extern bool Process32Next(IntPtr snapshot, ref PROCESSENTRY32 entry);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
    }
}