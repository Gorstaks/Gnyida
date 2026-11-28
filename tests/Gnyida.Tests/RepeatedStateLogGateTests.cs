using System;
using System.Text.Json;
using Gnyida.Core;
using Xunit;

namespace Gnyida.Tests
{
    public class RepeatedStateLogGateTests
    {
        private static readonly DateTimeOffset T0 = new(2026, 11, 28, 0, 0, 0, TimeSpan.Zero);
        private static readonly TimeSpan Reminder = TimeSpan.FromMinutes(15);

        [Fact]
        public void FirstObservationLogs()
            => Assert.True(new RepeatedStateLogGate().ShouldLog("a", T0, Reminder));

        [Fact]
        public void UnchangedStateIsSilentUntilTheReminder()
        {
            var g = new RepeatedStateLogGate();
            Assert.True(g.ShouldLog("a", T0, Reminder));
            for (int s = 22; s < 15 * 60; s += 22) Assert.False(g.ShouldLog("a", T0.AddSeconds(s), Reminder));
            Assert.True(g.ShouldLog("a", T0.AddMinutes(15), Reminder));
            Assert.False(g.ShouldLog("a", T0.AddMinutes(16), Reminder));
        }

        [Fact]
        public void AChangeLogsImmediatelyAndSoDoesTheChangeBack()
        {
            var g = new RepeatedStateLogGate();
            Assert.True(g.ShouldLog("conflict", T0, Reminder));
            Assert.True(g.ShouldLog("ok", T0.AddSeconds(5), Reminder));
            Assert.True(g.ShouldLog("conflict", T0.AddSeconds(10), Reminder));
        }

        [Fact]
        public void FirewallSignatureTracksComplianceConflictsAndChanges()
        {
            string Sig(string json, bool ok) { using var d = JsonDocument.Parse(json); return LocalFirewallPolicyService.StateSignature(d.RootElement, ok); }
            var same1 = Sig("{\"Changed\":0,\"PolicyCompliant\":false,\"Conflicts\":[\"a\"],\"Notes\":[\"n1\"]}", false);
            var same2 = Sig("{\"Changed\":0,\"PolicyCompliant\":false,\"Conflicts\":[\"a\"],\"Notes\":[\"n2\"]}", false);
            Assert.Equal(same1, same2);
            Assert.NotEqual(same1, Sig("{\"Changed\":0,\"PolicyCompliant\":false,\"Conflicts\":[\"a\",\"b\"]}", false));
            Assert.NotEqual(same1, Sig("{\"Changed\":1,\"PolicyCompliant\":false,\"Conflicts\":[\"a\"]}", false));
            Assert.NotEqual(same1, Sig("{\"Changed\":0,\"PolicyCompliant\":true,\"Conflicts\":[]}", true));
        }
    }
}
