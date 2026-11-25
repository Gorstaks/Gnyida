using System.Collections.Generic;
using Gnyida.Core;
using Xunit;

namespace Gnyida.Tests
{
    public class BrowserSandboxPolicyTests
    {
        private static FusedTelemetryContext Context(string caller, int pid, int target, string api = "ThreatIntel_EventId_4") =>
            new FusedTelemetryContext
            {
                TriggeringEvent = new ThreatIntelTelemetry
                {
                    ProcessName = caller, ProcessId = pid, TargetProcessId = target, ApiName = api,
                },
            };

        // ---- rule behavior ----

        [Fact]
        public void BrowserNamedBinaryThatIsNotTheRealBrowser_StillGetsTheKillGradeVerdict()
        {
            // A malware binary called chrome.exe used to be exempt on its name alone.
            var rule = new ThreatIntelInjectionRule((_, _) => { }, _ => BrowserSandboxPolicy.Verdict.Masquerade);
            var result = rule.Evaluate(Context("chrome.exe", 5001, 5002));
            Assert.NotNull(result);
            Assert.Equal("ThreatIntelInjectionRule", result!.RuleName);
            Assert.Equal(DetectionTier.Tier1Behavioral, result.Tier);
            Assert.Equal(ResponseAction.QuarantineAndKill, result.AuthorizedResponse);
        }

        [Fact]
        public void GenuineBrowserWritingIntoAnUnrelatedProcess_IsVisibleButNotKilled()
        {
            var rule = new ThreatIntelInjectionRule((_, _) => { }, _ => BrowserSandboxPolicy.Verdict.GenuineBrowserForeignTarget);
            var result = rule.Evaluate(Context("chrome", 5001, 5002));
            // PID 5002 does not resolve to a sensitive process, so the foreign-target path applies.
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
            Assert.Equal(ResponseAction.LogOnly, result.AuthorizedResponse);
            Assert.False(result.KillAuthorized);
            Assert.Equal("5002", result.Metadata["TargetProcessId"]);
        }

        [Fact]
        public void GenuineBrowserAimedAtSystem_KeepsTheKillGradeVerdict()
        {
            // Target PID 4 (System) was never covered by the exemption and still is not.
            var rule = new ThreatIntelInjectionRule((_, _) => { }, _ => BrowserSandboxPolicy.Verdict.GenuineBrowserForeignTarget);
            var result = rule.Evaluate(Context("msedge", 5001, 4));
            Assert.NotNull(result);
            Assert.Equal(ResponseAction.QuarantineAndKill, result!.AuthorizedResponse);
        }

        [Fact]
        public void UnsignedChromiumBuildTalkingToItself_IsVisibleButNeverKilled()
        {
            // Puppeteer, Playwright and developer builds are unsigned chrome.exe making same-family sandbox calls.
            var rule = new ThreatIntelInjectionRule((_, _) => { }, _ => BrowserSandboxPolicy.Verdict.UnverifiedSameFamily);
            var result = rule.Evaluate(Context("chrome.exe", 5001, 5002));
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
            Assert.Equal(ResponseAction.LogOnly, result.AuthorizedResponse);
            Assert.False(result.KillAuthorized);
            Assert.Contains("Unverified Browser-Named", result.RuleName);
        }

        [Fact]
        public void UnverifiedBrowserAimedAtSystem_KeepsTheKillGradeVerdict()
        {
            var rule = new ThreatIntelInjectionRule((_, _) => { }, _ => BrowserSandboxPolicy.Verdict.UnverifiedSameFamily);
            var result = rule.Evaluate(Context("chrome.exe", 5001, 4));
            Assert.NotNull(result);
            Assert.Equal(ResponseAction.QuarantineAndKill, result!.AuthorizedResponse);
        }

        [Fact]
        public void SandboxModel_IsStillExempt_AndStillQueuesTheTargetForInspection()
        {
            var queued = new List<int>();
            var rule = new ThreatIntelInjectionRule((pid, payloadOnly) => queued.Add(pid), _ => BrowserSandboxPolicy.Verdict.SandboxModel);
            Assert.Null(rule.Evaluate(Context("chrome", 5001, 5002)));
            Assert.Contains(5001, queued);
            Assert.Contains(5002, queued);
        }

        [Fact]
        public void NonBrowserCaller_NeverReachesTheBrowserClassifier()
        {
            bool asked = false;
            var rule = new ThreatIntelInjectionRule((_, _) => { }, _ => { asked = true; return BrowserSandboxPolicy.Verdict.SandboxModel; });
            var result = rule.Evaluate(Context("injector.exe", 5001, 5002));
            Assert.False(asked);
            Assert.NotNull(result);
            Assert.Equal(ResponseAction.QuarantineAndKill, result!.AuthorizedResponse);
        }

        // ---- policy helpers ----

        [Theory]
        [InlineData("chrome", "chrome.exe", true)]
        [InlineData("CHROME.EXE", "chrome", true)]
        [InlineData("msedge", "msedgewebview2", true)]
        [InlineData("msedgewebview2.exe", "msedge.exe", true)]
        [InlineData("chrome", "msedge", false)]
        [InlineData("chrome", "powershell", false)]
        [InlineData("chrome", "", false)]
        [InlineData("notepad", "notepad", false)]
        public void SameFamily_MatchesOnlyTheSameBrowser(string caller, string target, bool expected) =>
            Assert.Equal(expected, BrowserSandboxPolicy.SameFamily(caller, target));

        [Theory]
        [InlineData("chrome", "Google LLC", true)]
        [InlineData("chrome", "google llc", true)]
        [InlineData("chrome", "Google Updater Ltd", false)]
        [InlineData("chrome", "Microsoft Corporation", false)]
        [InlineData("chrome", null, false)]
        [InlineData("msedge", "Microsoft Corporation", true)]
        [InlineData("firefox", "Mozilla Corporation", true)]
        [InlineData("firefox", "Mozilla Corp", false)]
        [InlineData("electron", "Any Vendor Inc.", true)]
        [InlineData("electron", "", false)]
        [InlineData("notabrowser", "Google LLC", false)]
        public void PublisherMatches_RequiresTheBrowsersOwnPublisher(string caller, string? publisher, bool expected) =>
            Assert.Equal(expected, BrowserSandboxPolicy.PublisherMatches(caller, publisher));

        [Fact]
        public void IsGenuineImage_RejectsAProcessThatCannotBeResolved() =>
            Assert.False(BrowserSandboxPolicy.IsGenuineImage(int.MaxValue, "chrome"));

        [Fact]
        public void IsGenuineImage_RejectsARealProcessWhoseFileNameIsNotTheBrowser()
        {
            // The test host is a real, running process, but its image is not chrome.exe.
            Assert.False(BrowserSandboxPolicy.IsGenuineImage(ProcessInstanceTable.CurrentPid, "chrome"));
        }

        [Fact]
        public void Classify_ForAProcessThatOnlyCarriesABrowsersName_IsMasquerade()
        {
            var verdict = BrowserSandboxPolicy.Classify(new ThreatIntelTelemetry
            {
                ProcessName = "chrome.exe", ProcessId = ProcessInstanceTable.CurrentPid, TargetProcessId = 12345,
            });
            Assert.Equal(BrowserSandboxPolicy.Verdict.Masquerade, verdict);
        }
    }
}
