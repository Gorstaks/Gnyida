using Xunit;
using Gnyida.Core;

namespace Gnyida.Tests
{
    public class OpsMetricsPublisherTests
    {
        [Fact]
        public void ProductInfo_Version_IsNotEmpty()
        {
            Assert.False(string.IsNullOrWhiteSpace(ProductInfo.Version));
        }

        [Fact]
        public void ProductInfo_Version_MatchesExpectedFormat()
        {
            var parts = ProductInfo.Version.Split('.');
            Assert.True(parts.Length >= 2, "Version should have at least major.minor");
            Assert.True(int.TryParse(parts[0], out _), "Major version should be numeric");
            Assert.True(int.TryParse(parts[1], out _), "Minor version should be numeric");
        }

        [Fact]
        public void GnyidaMetrics_CreateSnapshot_ReturnsNonNull()
        {
            var metrics = new GnyidaMetrics();
            metrics.TickRates();
            var snapshot = metrics.CreateSnapshot();

            Assert.NotNull(snapshot);
        }

        [Fact]
        public void GnyidaMetrics_RecordDetection_TracksCount()
        {
            var metrics = new GnyidaMetrics();
            metrics.RecordDetection(1.0);
            metrics.RecordDetection(2.0);
            metrics.RecordDetection(3.0);

            Assert.Equal(3, metrics.GetDetectionsCount());
        }

        [Fact]
        public void GnyidaMetrics_RecordResponse_TracksCount()
        {
            var metrics = new GnyidaMetrics();
            metrics.RecordResponse(5.0);
            metrics.RecordResponse(10.0);

            Assert.Equal(2, metrics.GetResponsesCount());
        }

        [Fact]
        public void GnyidaMetrics_RecordFalsePositive_TracksCount()
        {
            var metrics = new GnyidaMetrics();
            metrics.RecordFalsePositive();
            Assert.Equal(1, metrics.GetFalsePositivesCount());
        }

        [Fact]
        public void OpsMetricsSnapshot_DefaultProductVersion_IsSet()
        {
            var snapshot = new OpsMetricsSnapshot();
            Assert.Equal(ProductInfo.Version, snapshot.ProductVersion);
        }

        [Fact]
        public void GnyidaMetrics_TickRates_DoesNotThrow()
        {
            var metrics = new GnyidaMetrics();
            metrics.RecordTelemetryReceived();
            metrics.RecordDetection(1.0);
            metrics.TickRates();
            // Should not throw
        }

        [Fact]
        public void GnyidaMetrics_Snapshot_IncludesAllFields()
        {
            var metrics = new GnyidaMetrics();
            metrics.RecordDetection(5.0);
            metrics.RecordResponse(2.0);
            metrics.RecordTelemetryReceived();
            metrics.RecordCompositeEmitted();
            metrics.RecordWeightedEmitted();
            metrics.RecordChainConfirmed();
            metrics.TickRates();

            var snap = metrics.CreateSnapshot();
            Assert.Equal(1, snap.DetectionsTotal);
            Assert.Equal(1, snap.ResponsesTotal);
            Assert.Equal(1, snap.TelemetryReceived);
            Assert.Equal(1, snap.CompositesEmitted);
            Assert.Equal(1, snap.WeightedCompositesEmitted);
            Assert.Equal(1, snap.ChainConfirmed);
        }
    }
}
