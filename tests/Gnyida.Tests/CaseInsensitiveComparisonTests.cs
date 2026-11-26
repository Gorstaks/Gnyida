using System;
using Microsoft.Extensions.Logging.Abstractions;
using Gnyida.Core;
using Xunit;

namespace Gnyida.Tests
{
    /// <summary>
    /// 3.7.9 comparison audit: Windows file names, extensions, process names and paths are
    /// case-insensitive, so re-casing one must neither evade a detection nor defeat an exemption.
    /// Pure logic only: no elevation, network or file state.
    /// </summary>
    public class CaseInsensitiveComparisonTests
    {
        private static FusedTelemetryContext Ctx(ProcessTelemetry pt) => new()
        {
            ProcessId = pt.ProcessId,
            ProcessName = pt.ProcessName,
            TriggeringEvent = pt
        };

        [Theory]
        [InlineData("cmd.exe", "cmd")]
        [InlineData("CMD.EXE", "CMD")]
        [InlineData("Explorer.EXE", "Explorer")]
        [InlineData("noext", "noext")]
        public void ReplaceIgnoreCase_StripsExtensionInAnyCase(string input, string expected)
        {
            Assert.Equal(expected, StringNet48.ReplaceIgnoreCase(input, ".exe", ""));
        }

        [Theory]
        [InlineData(".exe", true)]
        [InlineData(".EXE", true)]
        [InlineData(".Dll", true)]
        [InlineData(".PS1", true)]
        [InlineData(".txt", false)]
        [InlineData("", false)]
        [InlineData(null, false)]
        public void ReinfectionCorrelator_ExecutableExtension_IgnoresCase(string? ext, bool expected)
        {
            Assert.Equal(expected, ReinfectionCorrelator.IsExecutableExtension(ext));
        }

        [Theory]
        [InlineData("beacon.exe", @"C:\temp\beacon.exe")]
        [InlineData("Beacon.EXE", @"C:\temp\Beacon.EXE")]
        [InlineData("BEACON.exe", @"C:\TEMP\BEACON.exe")]
        public void CampaignRule_FileNameIoc_MatchesAnyCasing(string name, string path)
        {
            var rule = new CampaignDetectionRule(NullLogger<CampaignDetectionRule>.Instance);
            var result = rule.Evaluate(Ctx(new ProcessTelemetry { ProcessName = name, ProcessId = 1000, ImagePath = path, CommandLine = "" }));
            Assert.NotNull(result);
            Assert.Contains("Cobalt Strike", result!.RuleName);
        }

        [Theory]
        [InlineData("OneDrive.exe", @"C:\Users\Admin\AppData\Local\Temp\x\OneDrive.exe")]
        [InlineData("WINWORD.EXE", @"C:\Users\Admin\Downloads\WINWORD.EXE")]
        [InlineData("PowerShell.exe", @"C:\Users\Admin\AppData\Roaming\PowerShell.exe")]
        public void SideloadingRule_SystemToolNameWithRealCasing_Fires(string name, string path)
        {
            // The fixture paths do not exist, so they carry no Microsoft signature.
            var result = new DllSideloadingDetectionRule().Evaluate(Ctx(new ProcessTelemetry
            {
                ProcessName = name, ImagePath = path, CommandLine = name, ProcessId = 1500
            }));
            Assert.NotNull(result);
            Assert.Equal(ResponseAction.KillProcessTree, result!.AuthorizedResponse);
        }

        [Theory]
        [InlineData("CONHOST.EXE", @"C:\Windows\System32\conhost.exe", true)]
        [InlineData("Conhost", null, true)]
        [InlineData("OpenConsole", @"C:\Windows\System32\OpenConsole.exe", true)]
        [InlineData("CONHOST.EXE", @"C:\Users\Alice\AppData\Local\Temp\conhost.exe", false)]
        public void StockConsoleHost_IgnoresNameCasing(string name, string? path, bool expected)
        {
            Assert.Equal(expected, ParentPidSpoofDetector.IsStockWindowsConsoleHost(name, path));
        }

        [Theory]
        [InlineData("Contains", "powershell.exe -enc", "POWERSHELL.EXE -ENC AAAA", true)]
        [InlineData("Equals", "c:\\temp\\evil.exe", "C:\\Temp\\Evil.exe", true)]
        [InlineData("StartsWith", "c:\\users\\", "C:\\Users\\bob\\a.exe", true)]
        [InlineData("EndsWith", ".EXE", "C:\\Users\\bob\\a.exe", true)]
        [InlineData("NotContains", "mimikatz", "MIMIKATZ sekurlsa", false)]
        [InlineData("NotEquals", "cmd.exe", "CMD.EXE", false)]
        public void DynamicCondition_StringOperators_IgnoreCase(string op, string value, string actual, bool expected)
        {
            var field = op is "Equals" or "NotEquals" or "StartsWith" or "EndsWith" ? "ImagePath" : "CommandLine";
            var cond = new DynamicCondition { Field = field, Operator = op, Value = value };
            var pt = new ProcessTelemetry { ProcessName = "x", ProcessId = 1, ImagePath = actual, CommandLine = actual };
            Assert.Equal(expected, cond.Evaluate(pt));
        }

        [Fact]
        public void DynamicCondition_NumericField_UsesInvariantText()
        {
            var cond = new DynamicCondition { Field = "ParentProcessId", Operator = "Equals", Value = "1234" };
            Assert.True(cond.Evaluate(new ProcessTelemetry { ProcessId = 1, ParentProcessId = 1234 }));
        }
    }
}
