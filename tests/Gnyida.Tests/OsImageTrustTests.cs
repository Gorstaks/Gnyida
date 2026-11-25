using System;
using System.IO;
using Gnyida.Core;
using Xunit;

namespace Gnyida.Tests
{
    /// <summary>
    /// Adversarial coverage for OsImageTrust: a name or a folder under C:\Windows never self-authorizes.
    /// </summary>
    public class OsImageTrustTests
    {
        private static string WindowsRoot => Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void EmptyPath_IsNotProtected(string? path)
        {
            Assert.False(OsImageTrust.IsProtectedWindowsLocation(path, WindowsRoot));
        }

        [Fact]
        public void PathOutsideWindowsRoot_IsNotProtected()
        {
            var path = Path.Combine(Path.GetTempPath(), "svchost.exe");
            Assert.False(OsImageTrust.IsProtectedWindowsLocation(path, WindowsRoot));
        }

        [Theory]
        [InlineData(@"Tasks\svchost.exe")]
        [InlineData(@"Temp\svchost.exe")]
        [InlineData(@"tracing\svchost.exe")]
        [InlineData(@"System32\Tasks\svchost.exe")]
        [InlineData(@"System32\spool\drivers\color\svchost.exe")]
        public void DefaultWritableFolderUnderWindows_IsNotProtected(string relative)
        {
            // These folders sit under the Windows directory but are writable by standard users.
            var path = Path.Combine(WindowsRoot, relative);
            Assert.False(OsImageTrust.IsProtectedWindowsLocation(path, WindowsRoot));
        }

        [Fact]
        public void SignedWindowsImage_UnsignedBinaryInDropFolder_IsRejectedWithoutAskingForSignature()
        {
            bool asked = false;
            var path = Path.Combine(WindowsRoot, "Tasks", "svchost.exe");
            bool trusted = OsImageTrust.IsSignedWindowsImage(path, WindowsRoot, _ => { asked = true; return true; });
            Assert.False(trusted);
            Assert.False(asked);
        }

        [Fact]
        public void SignedWindowsImage_RealSystemBinary_NeedsValidSignature()
        {
            var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            if (!File.Exists(cmd) || !OsImageTrust.IsProtectedWindowsLocation(cmd, WindowsRoot)) return;

            Assert.True(OsImageTrust.IsSignedWindowsImage(cmd, WindowsRoot, _ => true));
            Assert.False(OsImageTrust.IsSignedWindowsImage(cmd, WindowsRoot, _ => false));
        }

        [Fact]
        public void SignatureCheckThatThrows_FailsClosed()
        {
            var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            if (!File.Exists(cmd) || !OsImageTrust.IsProtectedWindowsLocation(cmd, WindowsRoot)) return;

            Assert.False(OsImageTrust.IsSignedWindowsImage(cmd, WindowsRoot, _ => throw new IOException("boom")));
        }
    }
}
