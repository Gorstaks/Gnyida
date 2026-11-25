using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using Gnyida.Core;
using Xunit;

namespace Gnyida.Tests
{
    public class WritableLocationAclTests
    {
        private static DirectorySecurity Descriptor(params (WellKnownSidType Sid, FileSystemRights Rights, PropagationFlags Propagation)[] allows)
        {
            var security = new DirectorySecurity();
            security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            security.SetAccessRuleProtection(true, false);
            foreach (var (sid, rights, propagation) in allows)
                security.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(sid, null), rights,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, propagation, AccessControlType.Allow));
            return security;
        }

        [Fact]
        public void AdminOnlyWriteWithUserReadExecute_IsProtected()
        {
            var security = Descriptor(
                (WellKnownSidType.LocalSystemSid, FileSystemRights.FullControl, PropagationFlags.None),
                (WellKnownSidType.BuiltinAdministratorsSid, FileSystemRights.FullControl, PropagationFlags.None),
                (WellKnownSidType.BuiltinUsersSid, FileSystemRights.ReadAndExecute, PropagationFlags.None));
            Assert.False(WritableLocationAcl.GrantsNonAdminWrite(security, out _));
        }

        [Theory]
        [InlineData(WellKnownSidType.BuiltinUsersSid)]
        [InlineData(WellKnownSidType.AuthenticatedUserSid)]
        [InlineData(WellKnownSidType.WorldSid)]
        [InlineData(WellKnownSidType.InteractiveSid)]
        public void AnyNonAdminWriter_IsReported(WellKnownSidType writer)
        {
            var security = Descriptor(
                (WellKnownSidType.BuiltinAdministratorsSid, FileSystemRights.FullControl, PropagationFlags.None),
                (writer, FileSystemRights.CreateFiles, PropagationFlags.None));
            Assert.True(WritableLocationAcl.GrantsNonAdminWrite(security, out var sid));
            Assert.Equal(new SecurityIdentifier(writer, null).Value, sid);
        }

        [Fact]
        public void InheritOnlyEntry_DoesNotApplyToTheObjectItself()
        {
            // The ProgramData pattern: CREATOR OWNER full control that only applies to children.
            var security = Descriptor(
                (WellKnownSidType.BuiltinAdministratorsSid, FileSystemRights.FullControl, PropagationFlags.None),
                (WellKnownSidType.CreatorOwnerSid, FileSystemRights.FullControl, PropagationFlags.InheritOnly));
            Assert.False(WritableLocationAcl.GrantsNonAdminWrite(security, out _));
        }

        [Fact]
        public void WritableTempFile_IsReported()
        {
            var dir = Path.Combine(Path.GetTempPath(), "gnyida_acl_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var file = Path.Combine(dir, "x.dll");
                File.WriteAllText(file, "x");
                Assert.True(WritableLocationAcl.IsWritableByNonAdmin(file));
                // A not-yet-existing file resolves to its nearest existing directory.
                Assert.True(WritableLocationAcl.IsWritableByNonAdmin(Path.Combine(dir, "sub", "missing.dll")));
            }
            finally { Directory.Delete(dir, true); }
        }

        [Fact]
        public void EmptyPath_FailsClosed()
        {
            Assert.True(WritableLocationAcl.IsWritableByNonAdmin(null));
            Assert.True(WritableLocationAcl.IsWritableByNonAdmin("  "));
        }

        [Fact]
        public void SystemDirectory_IsProtected()
        {
            var kernel32 = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
            Assert.True(File.Exists(kernel32));
            Assert.False(WritableLocationAcl.IsWritableByNonAdmin(kernel32));
        }
    }
}
