using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// Serializes tests that read or write the live HKLM\SOFTWARE\Policies hive. On an elevated runner
    /// HardeningModule.ApplyBrowserHardening writes browser policy keys (for example BraveSoftware\Brave),
    /// and WmiPolicyRewriteMonitor.FingerprintPolicyHives read the hive twice around that write in a
    /// parallel test class, so the "stable across calls" assertion failed intermittently.
    /// </summary>
    [CollectionDefinition(Name)]
    public sealed class PolicyHiveCollection
    {
        public const string Name = "PolicyHive";
    }
}
