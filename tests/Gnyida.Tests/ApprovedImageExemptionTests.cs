using System;
using Gnyida.Core;
using Xunit;

namespace Gnyida.Tests
{
    /// <summary>
    /// An administrator-approved image skips the ransomware rename rule only when the exact path,
    /// an admin-only location and a valid signature all hold. Any one missing means it does not.
    /// </summary>
    public class ApprovedImageExemptionTests
    {
        private const string Agent = @"C:\Program Files\Vendor\agent.exe";
        private static readonly string[] Approved = { Agent };

        private static bool Check(string? image, string[]? approved = null, bool protectedLoc = true, bool signed = true, string? final = null)
            => ApprovedImageExemption.Matches(image, approved ?? Approved, p => final ?? p, _ => protectedLoc, _ => signed);

        [Fact]
        public void ExactPathInProtectedLocationWithSignatureIsApproved() => Assert.True(Check(Agent));

        [Fact]
        public void PathComparisonIgnoresCase() => Assert.True(Check(@"c:\program files\vendor\AGENT.EXE"));

        [Fact]
        public void AnUnlistedImageIsNotApproved() => Assert.False(Check(@"C:\Program Files\Vendor\other.exe"));

        [Fact]
        public void ASameNameImageInAnotherFolderIsNotApproved()
            => Assert.False(Check(@"C:\Users\a\Downloads\agent.exe"));

        [Fact]
        public void ALinkThatResolvesElsewhereIsNotApproved()
            => Assert.False(Check(Agent, final: @"C:\Users\a\AppData\Local\Temp\agent.exe"));

        [Fact]
        public void AnApprovedPathInAUserWritableLocationIsNotApproved()
            => Assert.False(Check(Agent, protectedLoc: false));

        [Fact]
        public void AnApprovedPathWithoutAValidSignatureIsNotApproved()
            => Assert.False(Check(Agent, signed: false));

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void AnEmptyImagePathIsNotApproved(string? image) => Assert.False(Check(image));

        [Fact]
        public void AnEmptyApprovalListApprovesNothing() => Assert.False(Check(Agent, approved: Array.Empty<string>()));

        [Fact]
        public void BlankAndMalformedEntriesAreIgnoredAndFailClosed()
            => Assert.False(Check(Agent, approved: new[] { "", "   ", "C:\\bad\0path" }));

        [Fact]
        public void ALookupFailureFailsClosed()
            => Assert.False(ApprovedImageExemption.Matches(Agent, Approved, _ => throw new System.IO.IOException("boom"), _ => true, _ => true));

        [Fact]
        public void StoredListIsSplitOnPipeSoCommasInPathsSurvive()
        {
            var parsed = ApprovedImageExemption.Parse(@"C:\Program Files\A, Inc\a.exe|C:\Program Files\B\b.exe");
            Assert.Equal(new[] { @"C:\Program Files\A, Inc\a.exe", @"C:\Program Files\B\b.exe" }, parsed);
            Assert.Empty(ApprovedImageExemption.Parse(null));
            Assert.Empty(ApprovedImageExemption.Parse(" "));
        }

        [Fact]
        public void ApprovalOverrideIsAppliedFromTheProtectedConfigStore()
        {
            var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "gnyida-cfg-" + Guid.NewGuid().ToString("N") + ".enc");
            try
            {
                var store = new EncryptedConfigStore(null, path);
                store.SetOverride("RansomwareIoApprovedImages", Agent + "|" + @"C:\Program Files\B\b.exe");
                var config = new GnyidaConfig();
                store.ApplyOverrides(config);
                Assert.Equal(new[] { Agent, @"C:\Program Files\B\b.exe" }, config.RansomwareIoApprovedImages);
            }
            finally { if (System.IO.File.Exists(path)) System.IO.File.Delete(path); }
        }
    }
}
