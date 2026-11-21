using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// Environment.TickCount wraps from int.MaxValue to int.MinValue after ~24.9 days. The stale-PID
    /// sweep interval must keep measuring correctly across that wrap (it previously went negative and
    /// stopped sweeping, letting recycled PIDs inherit stale chain signals).
    /// </summary>
    public class ResponsePolicyTickWrapTests
    {
        [Fact]
        public void ElapsedTickMs_NoWrap_IsPlainDifference()
        {
            Assert.Equal(120_000u, ResponsePolicy.ElapsedTickMs(1_120_000, 1_000_000));
        }

        [Fact]
        public void ElapsedTickMs_AcrossWrap_IsPositiveAndExact()
        {
            int last = int.MaxValue - 50_000;
            int now = unchecked(last + 120_000); // wrapped negative
            Assert.True(now < 0);
            Assert.Equal(120_000u, ResponsePolicy.ElapsedTickMs(now, last));
        }

        [Fact]
        public void ElapsedTickMs_AcrossWrap_ShortInterval_DoesNotTriggerSweep()
        {
            int last = int.MaxValue - 10;
            int now = unchecked(last + 100);
            Assert.True(ResponsePolicy.ElapsedTickMs(now, last) < 120_000u);
        }
    }
}
