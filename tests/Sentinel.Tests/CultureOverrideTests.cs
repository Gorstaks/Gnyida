using System;
using System.Globalization;
using Xunit;

namespace Sentinel.Tests
{
    public class CultureOverrideTests
    {
        [Fact]
        public void WhenRequested_TheSuiteReallyRunsUnderThatCulture()
        {
            string? requested = Environment.GetEnvironmentVariable("SENTINEL_TEST_CULTURE");
            if (string.IsNullOrWhiteSpace(requested)) return;
            Assert.Equal(requested!.Trim(), CultureInfo.CurrentCulture.Name, ignoreCase: true);
            // and on a pool thread, which is where most of the product's code runs
            string pooled = System.Threading.Tasks.Task.Run(() => CultureInfo.CurrentCulture.Name).GetAwaiter().GetResult();
            Assert.Equal(requested.Trim(), pooled, ignoreCase: true);
        }
    }
}
