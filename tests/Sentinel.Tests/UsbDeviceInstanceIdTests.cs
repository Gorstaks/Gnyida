using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    /// <summary>
    /// Device instance IDs embed device-reported strings and are interpolated into a quoted pnputil
    /// argument. Characters that could break the quoting must be rejected before the command line is built.
    /// </summary>
    public class UsbDeviceInstanceIdTests
    {
        [Theory]
        [InlineData(@"USB\VID_0781&PID_5581\4C530001230118115314")]
        [InlineData(@"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\4C530001230118115314&0")]
        [InlineData(@"HID\VID_046D&PID_C52B&MI_00\7&2A6B5C2E&0&0000")]
        [InlineData(@"SWD\WPDBUSENUM\{8D5B1E3A-1234-5678-9ABC-DEF012345678}#0000000000100000")]
        public void RealInstanceIds_AreAccepted(string id)
        {
            Assert.True(UsbDeviceFingerprinter.IsSafeDeviceInstanceId(id));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("USB\\VID_1\\abc\" /add-driver evil.inf \"")]
        [InlineData("USB\\VID_1\\abc def")]
        [InlineData("USB\\VID_1\\abc,def")]
        [InlineData("USB\\VID_1\\abc\tdef")]
        [InlineData("USB\\VID_1\\abc\u00e9")]
        public void MaliciousOrInvalidInstanceIds_AreRejected(string? id)
        {
            Assert.False(UsbDeviceFingerprinter.IsSafeDeviceInstanceId(id));
        }

        [Fact]
        public void OverlongInstanceId_IsRejected()
        {
            Assert.False(UsbDeviceFingerprinter.IsSafeDeviceInstanceId("USB\\" + new string('A', 600)));
        }
    }
}
