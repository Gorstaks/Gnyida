using System.Collections.Generic;
using System.Linq;
using Gnyida.Core;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Gnyida.Tests
{
    /// <summary>
    /// A rename burst only gets kill authority when it shows a file-damage pattern.
    /// Bursts from installers, builds, OS-image tools and backup jobs stay Tier2 LogOnly.
    /// </summary>
    public class RansomwareRenameEvidenceTests
    {
        private static List<(string, string)> Renames(int count, System.Func<int, (string, string)> make)
            => Enumerable.Range(0, count).Select(make).ToList();

        private static readonly string[] DocExts = { ".docx", ".xlsx", ".pdf", ".jpg", ".pptx" };

        private static (string, string) Encrypt(int i)
        {
            var ext = DocExts[i % DocExts.Length];
            return ($@"C:\Users\a\Documents\d{i % 7}\file{i}{ext}", $@"C:\Users\a\Documents\d{i % 7}\file{i}{ext}.locked");
        }

        [Fact]
        public void Funnel_ManyTypesToOneNewExtension()
        {
            var e = RansomwareRenameEvidence.Evaluate(Renames(60, Encrypt));
            Assert.True(e.Funnel);
            Assert.Equal(".locked", e.DominantNewExtension);
            Assert.True(e.HasDamagePattern);
        }

        [Fact]
        public void TypeChange_RandomPerFileExtensionStillDetected()
        {
            // No shared new extension, so the funnel cannot match. Documents all lose their type.
            var list = Renames(60, i => ($@"C:\Users\a\Documents\f{i}{DocExts[i % DocExts.Length]}", $@"C:\Users\a\Documents\f{i}.x{i:x4}z"));
            var e = RansomwareRenameEvidence.Evaluate(list);
            Assert.False(e.Funnel);
            Assert.True(e.TypeChange);
        }

        [Fact]
        public void InstallerFinalisation_TmpToManyExtensions_IsNotDamage()
        {
            var finals = new[] { ".dll", ".exe", ".xml", ".dat", ".json" };
            var list = Renames(300, i => ($@"C:\Program Files\App\f{i}.tmp", $@"C:\Program Files\App\f{i}{finals[i % finals.Length]}"));
            Assert.False(RansomwareRenameEvidence.Evaluate(list).HasDamagePattern);
        }

        [Fact]
        public void BuildOutput_OneSourceTypeToOneTarget_IsNotDamage()
        {
            // Many files, one dominant target, but a single source type: not a funnel of file types.
            var list = Renames(300, i => ($@"C:\src\obj\f{i}.new", $@"C:\src\obj\f{i}.dll"));
            Assert.False(RansomwareRenameEvidence.Evaluate(list).HasDamagePattern);
        }

        [Fact]
        public void MovesThatKeepTheExtension_AreNotDamage()
        {
            var list = Renames(500, i => ($@"C:\Users\a\Documents\f{i}{DocExts[i % DocExts.Length]}", $@"C:\Users\a\Archive\f{i}{DocExts[i % DocExts.Length]}"));
            Assert.False(RansomwareRenameEvidence.Evaluate(list).HasDamagePattern);
        }

        [Fact]
        public void BackupRotation_ToBakExtension_IsNotDamage()
        {
            var list = Renames(300, i => ($@"D:\Data\f{i}{DocExts[i % DocExts.Length]}", $@"D:\Data\f{i}{DocExts[i % DocExts.Length]}.bak"));
            Assert.False(RansomwareRenameEvidence.Evaluate(list).HasDamagePattern);
        }

        [Fact]
        public void BelowMinimum_NeverAuthorisesEvidence()
        {
            var e = RansomwareRenameEvidence.Evaluate(Renames(RansomwareRenameEvidence.MinRenamesForEvidence - 1, Encrypt));
            Assert.False(e.HasDamagePattern);
        }

        [Fact]
        public void MixedTraffic_DilutesBelowThreshold()
        {
            var list = Renames(30, Encrypt);
            list.AddRange(Renames(200, i => ($@"C:\x\a{i}.tmp", $@"C:\x\a{i}.dll")));
            Assert.False(RansomwareRenameEvidence.Evaluate(list).HasDamagePattern);
        }
    }

    public class RansomwareIoMonitorEvidenceTests
    {
        private static RansomwareIoMonitor Create() => new(null!, NullLogger<RansomwareIoMonitor>.Instance);

        private static void Feed(RansomwareIoMonitor m, int pid, string name, int count, System.Func<int, (string, string)> make)
        {
            for (int i = 0; i < count; i++) { var (o, n) = make(i); m.RecordRename(pid, name, o, n); }
        }

        private static readonly string[] Exts = { ".docx", ".xlsx", ".pdf", ".jpg" };
        private static (string, string) Encrypt(int i) =>
            ($@"C:\Users\a\Documents\f{i}{Exts[i % 4]}", $@"C:\Users\a\Documents\f{i}{Exts[i % 4]}.crypted");

        [Fact]
        public void AttributedBurstWithDamagePattern_IsTier1Kill()
        {
            var m = Create();
            Feed(m, 91001, "evil", 80, Encrypt);
            var d = Assert.Single(m.EvaluateWindowAndReset());
            Assert.Equal(DetectionTier.Tier1Behavioral, d.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, d.AuthorizedResponse);
            Assert.Equal(91001, d.ProcessId);
            Assert.Equal("Ransomware: Mass File Rename", d.RuleName);
        }

        [Fact]
        public void AttributedBurstWithoutPattern_IsTier2LogOnly()
        {
            var m = Create();
            var finals = new[] { ".dll", ".exe", ".xml" };
            Feed(m, 91002, "ntlite", 500, i => ($@"C:\Mount\f{i}.tmp", $@"C:\Mount\f{i}{finals[i % 3]}"));
            var d = Assert.Single(m.EvaluateWindowAndReset());
            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
        }

        [Fact]
        public void BurstWithoutPattern_SurvivesTierLaw_AsObserve()
        {
            var m = Create();
            Feed(m, 91003, "tool", 200, i => ($@"C:\a\f{i}.tmp", $@"C:\a\f{i}.dll"));
            var d = Assert.Single(m.EvaluateWindowAndReset());
            ResponsePolicy.ApplyTierLaw(d);
            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
        }

        [Fact]
        public void UnattributedDamage_KillsOnlyWhenSamplesAgreeOnOneProcess()
        {
            var m = Create();
            m.Attributor = _ => (91004, "evil");
            Feed(m, 0, "unknown", 80, Encrypt);
            var d = Assert.Single(m.EvaluateWindowAndReset());
            Assert.Equal(DetectionTier.Tier1Behavioral, d.Tier);
            Assert.Equal(91004, d.ProcessId);
        }

        [Fact]
        public void UnattributedDamage_WithSplitHolders_IsNotKilled()
        {
            var m = Create();
            int n = 0;
            m.Attributor = _ => (91010 + (n++ % 4), "holder");
            Feed(m, 0, "unknown", 80, Encrypt);
            var d = Assert.Single(m.EvaluateWindowAndReset());
            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
            Assert.Equal(0, d.ProcessId);
        }

        [Fact]
        public void UnattributedDamage_WithoutAttributor_IsNotKilled()
        {
            var m = Create();
            Feed(m, 0, "unknown", 80, Encrypt);
            var d = Assert.Single(m.EvaluateWindowAndReset());
            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
        }

        [Fact]
        public void CountOnlyCalls_NeverCarryKillEvidence()
        {
            var m = Create();
            for (int i = 0; i < 500; i++) m.RecordRename(91005, "evil");
            var d = Assert.Single(m.EvaluateWindowAndReset());
            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
        }

        [Fact]
        public void WindowResetsAfterEvaluation()
        {
            var m = Create();
            Feed(m, 91006, "evil", 80, Encrypt);
            Assert.Single(m.EvaluateWindowAndReset());
            Assert.Empty(m.EvaluateWindowAndReset());
        }
    }
}
