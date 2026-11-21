using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// The cuckoo-egg impostor kill matches the running image to the replaced executable path. Windows
    /// paths are case-insensitive, so a casing difference must still match; a different file must not.
    /// </summary>
    public class ApplicationIntegrityImagePathTests
    {
        [Fact]
        public void SamePathDifferentCasing_Matches()
        {
            Assert.True(ApplicationIntegrityMonitor.IsSameImagePath(
                @"C:\Program Files\App\App.exe", @"c:\program files\app\APP.EXE"));
        }

        [Fact]
        public void EquivalentPathAfterNormalization_Matches()
        {
            Assert.True(ApplicationIntegrityMonitor.IsSameImagePath(
                @"C:\Program Files\App\.\App.exe", @"C:\Program Files\App\App.exe"));
        }

        [Fact]
        public void DifferentFile_DoesNotMatch()
        {
            Assert.False(ApplicationIntegrityMonitor.IsSameImagePath(
                @"C:\Program Files\App\App.exe", @"C:\Users\x\Downloads\App.exe"));
        }

        [Theory]
        [InlineData(null, @"C:\a.exe")]
        [InlineData(@"C:\a.exe", null)]
        [InlineData("", @"C:\a.exe")]
        public void MissingPath_DoesNotMatch(string? a, string? b)
        {
            Assert.False(ApplicationIntegrityMonitor.IsSameImagePath(a, b));
        }
    }
}
