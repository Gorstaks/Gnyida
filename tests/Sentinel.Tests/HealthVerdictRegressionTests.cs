using System;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Sentinel.Core.Monitors;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// Regression tests for the health verdict: a monitor that is off by policy must be reported
    /// as Completed (not Unavailable), sensors that expose no progress contract must not hold the
    /// dashboard at "limited", and the firewall registry watcher must attach to an existing key.
    /// </summary>
    public class HealthVerdictRegressionTests
    {
        [Fact]
        public void AggressiveSweep_IsStartupTask_SoPolicyOffIsCompletedNotUnavailable()
        {
            Assert.True(typeof(IMonitorStartupTask).IsAssignableFrom(typeof(AggressiveUnsignedDllSweepMonitor)));
        }

        [Fact]
        public void SensorWithoutProgressContract_IsNotCountedUnverified()
        {
            using var reg = new MonitorRegistry(null!, null!, NullLogger<MonitorRegistry>.Instance);
            reg.Register("NoProgressSensor", MonitorCategory.ThreatIntel, null);
            reg.MarkStarted("NoProgressSensor");
            reg.Heartbeat("NoProgressSensor");

            var stats = reg.GetStats();
            Assert.Equal(1, stats.Running);
            Assert.Equal(0, stats.CollectionUnverified);
            Assert.Equal(0, stats.Unhealthy);
        }

        [Fact]
        public void CompletedByPolicyMonitor_IsNotUnhealthy()
        {
            using var reg = new MonitorRegistry(null!, null!, NullLogger<MonitorRegistry>.Instance);
            reg.Register("OffByPolicy", MonitorCategory.ThreatIntel, null);
            reg.MarkStarted("OffByPolicy");
            reg.MarkCompleted("OffByPolicy", "off by policy");

            Assert.Equal(1, reg.GetStats().Completed);
            Assert.DoesNotContain(reg.GetUnhealthyMonitors(), m => m.Name == "OffByPolicy");
        }

        [Fact]
        public void FirewallPolicyWatcher_FallsBackToNearestExistingAncestor()
        {
            string missing = @"SOFTWARE\Microsoft\Windows\SentinelMissing_" + Guid.NewGuid().ToString("N") + @"\Child";
            Assert.Equal(@"SOFTWARE\Microsoft\Windows", LocalFirewallPolicyService.NearestExistingKey(missing));
            Assert.Equal(@"SOFTWARE\Microsoft\Windows", LocalFirewallPolicyService.NearestExistingKey(@"SOFTWARE\Microsoft\Windows"));
        }
    }
}
