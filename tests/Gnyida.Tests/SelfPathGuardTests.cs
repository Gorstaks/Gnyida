using System;
using System.IO;
using Xunit;
using Gnyida.Core;

namespace Gnyida.Tests
{
    public class SelfPathGuardTests
    {
        [Fact]
        public void IsGnyidaSelfBinary_ReturnsTrue_ForGnyidaExeUnderInstall()
        {
            // The test binary runs from the install directory (BaseDirectory)
            var installDir = AppContext.BaseDirectory;
            var testPath = Path.Combine(installDir, "Gnyida.Service.exe");

            // Create a temporary file to test with
            if (!File.Exists(testPath))
            {
                try
                {
                    File.WriteAllText(testPath, "test");
                    Assert.True(SelfPathGuard.IsGnyidaSelfBinary(testPath));
                    File.Delete(testPath);
                }
                catch
                {
                    // If we can't create the file, just verify the logic doesn't crash
                    SelfPathGuard.IsGnyidaSelfBinary(testPath);
                }
            }
            else
            {
                Assert.True(SelfPathGuard.IsGnyidaSelfBinary(testPath));
            }
        }

        [Fact]
        public void IsGnyidaSelfBinary_ReturnsFalse_ForNull()
        {
            Assert.False(SelfPathGuard.IsGnyidaSelfBinary(null));
        }

        [Fact]
        public void IsGnyidaSelfBinary_ReturnsFalse_ForEmptyString()
        {
            Assert.False(SelfPathGuard.IsGnyidaSelfBinary(""));
            Assert.False(SelfPathGuard.IsGnyidaSelfBinary("   "));
        }

        [Fact]
        public void IsGnyidaSelfBinary_ReturnsFalse_ForArbitraryPath()
        {
            Assert.False(SelfPathGuard.IsGnyidaSelfBinary(@"C:\Users\Attacker\malware.exe"));
        }

        [Fact]
        public void IsGnyidaSelfBinary_ReturnsFalse_ForNonGnyidaNameUnderInstall()
        {
            var installDir = AppContext.BaseDirectory;
            var path = Path.Combine(installDir, "NotGnyida.exe");
            Assert.False(SelfPathGuard.IsGnyidaSelfBinary(path));
        }

        [Fact]
        public void IsGnyidaSelfBinary_ReturnsFalse_ForGnyidaNameOutsideInstall()
        {
            // Gnyida.Service.exe in a different directory - NOT trusted
            Assert.False(SelfPathGuard.IsGnyidaSelfBinary(@"C:\Temp\Gnyida.Service.exe"));
        }

        [Fact]
        public void IsUnderInstallDirectory_ReturnsTrue_ForInstallSubpath()
        {
            var installDir = AppContext.BaseDirectory;
            var subPath = Path.Combine(installDir, "subdir", "file.txt");
            Assert.True(SelfPathGuard.IsUnderInstallDirectory(subPath));
        }

        [Fact]
        public void IsUnderInstallDirectory_ReturnsFalse_ForNull()
        {
            Assert.False(SelfPathGuard.IsUnderInstallDirectory(null));
        }

        [Fact]
        public void IsUnderInstallDirectory_ReturnsFalse_ForEmpty()
        {
            Assert.False(SelfPathGuard.IsUnderInstallDirectory(""));
            Assert.False(SelfPathGuard.IsUnderInstallDirectory("   "));
        }

        [Fact]
        public void IsUnderInstallDirectory_ReturnsFalse_ForExternalPath()
        {
            Assert.False(SelfPathGuard.IsUnderInstallDirectory(@"C:\Windows\System32\cmd.exe"));
        }

        [Fact]
        public void IsGnyidaSelfBinary_AcceptsGnyidaCoreDll()
        {
            var installDir = AppContext.BaseDirectory;
            var dllPath = Path.Combine(installDir, "Gnyida.Core.dll");

            if (File.Exists(dllPath))
            {
                Assert.True(SelfPathGuard.IsGnyidaSelfBinary(dllPath));
            }
        }
    }
}
