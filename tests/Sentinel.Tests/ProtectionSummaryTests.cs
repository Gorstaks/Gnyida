using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using Sentinel.Agent;
using Xunit;

namespace Sentinel.Tests
{
    public class ProtectionSummaryTests
    {
        private static readonly DateTime Now = new DateTime(2026, 11, 20, 12, 0, 0, DateTimeKind.Utc);

        private static string Result(DateTime at, string action, string status) =>
            "{\"type\":\"response_result\",\"timestamp\":\"" + at.ToString("o") + "\",\"data\":{\"EffectiveAction\":\"" + action +
            "\",\"Status\":\"" + status + "\"}}";

        private static string Detection(DateTime at) =>
            "{\"type\":\"detection\",\"timestamp\":\"" + at.ToString("o") + "\",\"data\":{\"RuleName\":\"X\"}}";

        [Fact]
        public void CountsOnlyVerifiedStoppingActionsInsideTheWindow()
        {
            var lines = new List<string>
            {
                Detection(Now.AddDays(-9)),                                     // makes the window complete
                Result(Now.AddDays(-1), "KillProcessTree", "Verified"),         // counted
                Result(Now.AddHours(-2), "QuarantineAndKill", "Verified"),      // counted, latest
                Result(Now.AddHours(-3), "QuarantineAndKill", "Failed"),        // attempt, not a stop
                Result(Now.AddHours(-4), "KillProcessTree", "Refused"),         // attempt, not a stop
                Result(Now.AddHours(-5), "LogOnly", "NotRequested"),            // observation
                Result(Now.AddDays(-8), "KillProcess", "Verified"),             // outside the window
                Detection(Now.AddMinutes(-1)),
            };
            var s = ProtectionSummary.Count(lines, Now);
            Assert.Equal(2, s.ThreatsStopped);
            Assert.Equal(2, s.ResponsesFailed);
            Assert.Equal(Now.AddHours(-2), s.LastThreatStoppedUtc);
            Assert.True(s.WindowComplete);
        }

        [Fact]
        public void ALogThatStartsInsideTheWindow_IsReportedIncomplete()
        {
            var s = ProtectionSummary.Count(new[] { Result(Now.AddDays(-2), "KillProcess", "Verified") }, Now);
            Assert.Equal(1, s.ThreatsStopped);
            Assert.False(s.WindowComplete);
        }

        [Fact]
        public void TornAndForeignLinesAreSkipped()
        {
            var lines = new[] { "", "not json", "{\"type\":\"response_result\",\"timestamp\":\"" + Now.AddHours(-1).ToString("o") + "\",\"data\":", "{}" };
            var s = ProtectionSummary.Count(lines, Now);
            Assert.Equal(0, s.ThreatsStopped);
            Assert.Equal(0, s.ResponsesFailed);
        }

        [Fact]
        public void FutureTimestampsDoNotInflateTheCount()
        {
            var s = ProtectionSummary.Count(new[] { Result(Now.AddDays(3), "KillProcess", "Verified") }, Now);
            Assert.Equal(0, s.ThreatsStopped);
        }

        [Theory]
        [InlineData("{\"type\":\"x\",\"timestamp\":\"2026-11-19T21:56:41.2397547Z\"}", true)]
        [InlineData("{\"type\":\"x\"}", false)]
        [InlineData("{\"timestamp\":\"garbage\"}", false)]
        public void FastTimestamp_ReadsTheTopLevelStamp(string line, bool found) =>
            Assert.Equal(found, ProtectionSummary.FastTimestamp(line).HasValue);

        [Fact]
        public void LiveLog_IsSummarizedQuickly()
        {
            string log = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel", "events.jsonl");
            if (!File.Exists(log)) return;
            var clock = Stopwatch.StartNew();
            var s = ProtectionSummary.Read(new[] { log });
            clock.Stop();
            Assert.True(s.ThreatsStopped >= 0);
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), "summary took " + clock.Elapsed);
        }
    }
}
