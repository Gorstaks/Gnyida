using System;
using System.IO;
using Xunit;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class FileActivityMonitorTests : IDisposable
    {
        private readonly string _tempPath;

        public FileActivityMonitorTests()
        {
            _tempPath = Path.Combine(Path.GetTempPath(), "sentinel_fam_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempPath);
        }

        private FileActivityMonitor CreateMonitor(out SignerTrustService signerTrust, bool proactiveFileInspection = false)
        {
            var logger = NullLogger<FileActivityMonitor>.Instance;
            var trustLogger = NullLogger<SignerTrustService>.Instance;
            signerTrust = new SignerTrustService(trustLogger);
            
            var config = new SentinelConfig { WatchPath = _tempPath, EnableProactiveFileInspection = proactiveFileInspection };

            return new FileActivityMonitor(null!, null!, config, logger, signerTrust);
        }

        [Theory]
        [InlineData("trustedinstaller")]
        [InlineData("svchost")]
        [InlineData("svchost_x.exe")]
        [InlineData("sfc_helper.exe")]
        [InlineData("services")]
        [InlineData("system")]
        [InlineData("windowssentinel.service")]
        public void IsTrustedSystemWriter_TrustedLookingNameAlone_IsNotTrusted(string name)
        {
            // Adversarial: the writer's name is attacker-chosen. A PID that cannot resolve to a
            // signed image must stay untrusted no matter what the process is called.
            using var monitor = CreateMonitor(out _);
            Assert.False(monitor.IsTrustedSystemWriter(int.MaxValue - 13, name, "dummy.txt"));
        }

        [Fact]
        public void IsTrustedWriterImage_NullOrEmptyPath_IsNotTrusted()
        {
            using var monitor = CreateMonitor(out _);
            Assert.False(monitor.IsTrustedWriterImage(null));
            Assert.False(monitor.IsTrustedWriterImage(string.Empty));
        }

        [Theory]
        [InlineData("Sentinel", "evil.exe")]
        [InlineData("Windows Defender", "MsMpEng.exe")]
        [InlineData("Microsoft Security Client", "msseces.exe")]
        public void IsTrustedWriterImage_UnsignedFileInTrustedLookingFolder_IsNotTrusted(string folder, string file)
        {
            // Folder names are attacker-chosen: a drop under ...\Sentinel\ or ...\Windows Defender\
            // used to be trusted by substring. Only a valid signature (or the ACL-proven install image) counts.
            var dir = Path.Combine(_tempPath, folder);
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, file);
            File.WriteAllBytes(path, new byte[] { 0x4D, 0x5A, 0x00, 0x00 });

            using var monitor = CreateMonitor(out _);
            Assert.False(monitor.IsTrustedWriterImage(path));
        }

        [Theory]
        [InlineData("Sentinel.Service.exe")]
        [InlineData("Sentinel.Agent.exe")]
        public void IsTrustedWriterImage_SentinelBinaryNameInWritableSentinelFolder_IsNotTrusted(string file)
        {
            // The real attack on the former "\Sentinel\" substring trust: drop a file named like Sentinel's
            // own executable into a user-writable folder called Sentinel. Old code trusted this path; the
            // install-image check now requires Sentinel's own directory AND a DACL non-admins cannot write.
            var dir = Path.Combine(_tempPath, "Sentinel");
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, file);
            File.WriteAllBytes(path, new byte[] { 0x4D, 0x5A, 0x00, 0x00 });

            using var monitor = CreateMonitor(out _);
            Assert.False(monitor.IsTrustedWriterImage(path));
        }

        [Fact]
        public void IsTrustedWriterImage_UntrustedResultIsNotCached_SoLaterVerdictCanChange()
        {
            // A negative verdict must not be pinned: the same path is evaluated afresh each time.
            var path = Path.Combine(_tempPath, "writer.exe");
            File.WriteAllBytes(path, new byte[] { 0x4D, 0x5A, 0x00, 0x00 });
            using var monitor = CreateMonitor(out _);
            Assert.False(monitor.IsTrustedWriterImage(path));
            Assert.False(monitor.IsTrustedWriterImage(path));
        }

        [Fact]
        public void IsTrustedWriterImage_CatalogSignedSystemBinary_IsTrusted()
        {
            using var monitor = CreateMonitor(out _);
            var cmdPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
            if (File.Exists(cmdPath) && SecurityValidation.VerifyAuthenticodeSignature(cmdPath))
            {
                Assert.True(monitor.IsTrustedWriterImage(cmdPath));
            }
        }

        [Fact]
        public void IsTrustedSystemWriter_SystemPid_ReturnsTrue()
        {
            using var monitor = CreateMonitor(out _);
            Assert.True(monitor.IsTrustedSystemWriter(4, "any_process", "dummy.txt"));
        }

        [Fact]
        public void IsTrustedSystemWriter_UntrustedProcess_ReturnsFalse()
        {
            using var monitor = CreateMonitor(out _);
            // Use a PID that cannot exist and a name that does not substring-match
            // trusted writers (e.g. "services"/"msiexec"). PID 9999 can be a live
            // Microsoft-signed process on GitHub-hosted runners, which made this flaky.
            Assert.False(monitor.IsTrustedSystemWriter(
                int.MaxValue - 13,
                "totally-evil-dropper.exe",
                @"C:\Temp\sentinel_fp_untrusted_writer_test.dll"));
        }

        [Fact]
        public void IsTrustedSystemWriter_PidZeroNonExistentFile_ReturnsFalse()
        {
            using var monitor = CreateMonitor(out _);
            // Non-existent file should return false for PID 0
            Assert.False(monitor.IsTrustedSystemWriter(0, "unknown", "C:\\nonexistent_file_path_12345.dll"));
        }

        [Fact]
        public void IsTrustedSystemWriter_PidZero_DefaultPolicyDoesNotOpenFileAndStaysUntrusted()
        {
            // No touch until proven malicious: the file is not opened to prove a signature.
            using var monitor = CreateMonitor(out _);
            var cmdPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
            Assert.False(monitor.IsTrustedSystemWriter(0, "unknown", cmdPath));
        }
        [Fact]
        public void IsTrustedSystemWriter_PidZeroMicrosoftSignedFile_ReturnsTrueWhenProactiveInspectionEnabled()
        {
            using var monitor = CreateMonitor(out _, proactiveFileInspection: true);
            
            // 1. Verify embedded-signed Microsoft/Dotnet binary (should always succeed)
            var dotnetDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "host", "fxr");
            if (Directory.Exists(dotnetDir))
            {
                var files = Directory.GetFiles(dotnetDir, "hostfxr.dll", SearchOption.AllDirectories);
                if (files.Length > 0)
                {
                    Assert.True(monitor.IsTrustedSystemWriter(0, "unknown", files[0]));
                }
            }

            // 2. Verify catalog-signed system file (if catalog checking works in this environment)
            var cmdPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
            if (File.Exists(cmdPath) && SecurityValidation.VerifyAuthenticodeSignature(cmdPath))
            {
                Assert.True(monitor.IsTrustedSystemWriter(0, "unknown", cmdPath));
            }
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(_tempPath))
                    Directory.Delete(_tempPath, true);
            }
            catch { }
        }
    }
}
