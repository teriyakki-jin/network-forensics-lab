[CmdletBinding()]
param(
    [string]$PythonCommand = 'python'
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $LabRoot

$CatalogPath = Join-Path $LabRoot 'detection\rule-catalog.json'
$SnortPath = Join-Path $LabRoot 'alerts\alert_json.txt'
$SuricataPath = Join-Path $LabRoot 'alerts\suricata\eve.json'
$NormalisedPath = Join-Path $LabRoot 'alerts\normalized-alerts.jsonl'
$ReportPath = Join-Path $LabRoot 'evidence\ids-comparison.json'
$FixtureReportPath = Join-Path $LabRoot 'evidence\pcap-regression.json'
$SigmaReportPath = Join-Path $LabRoot 'evidence\sigma-validation.json'

foreach ($RequiredPath in @($CatalogPath, $SnortPath, $SuricataPath)) {
    if (-not (Test-Path -LiteralPath $RequiredPath)) {
        throw "Required comparison input is missing: $RequiredPath"
    }
}

& $PythonCommand -m forensics.cli compare `
    --catalog $CatalogPath `
    --snort $SnortPath `
    --suricata $SuricataPath `
    --normalised $NormalisedPath `
    --report $ReportPath | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw 'IDS comparison failed.'
}

& $PythonCommand -m forensics.cli verify-fixture `
    --pcap (Join-Path $LabRoot 'evidence\lab-traffic.pcap') `
    --checksum (Join-Path $LabRoot 'evidence\lab-traffic.pcap.sha256') `
    --output $FixtureReportPath | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw 'PCAP regression verification failed.'
}

& $PythonCommand -m forensics.cli validate-sigma `
    --directory (Join-Path $LabRoot 'detection\sigma') `
    --output $SigmaReportPath | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw 'Sigma validation failed.'
}

$Comparison = Get-Content -LiteralPath $ReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
$MissingDetections = @($Comparison.scenarios | Where-Object { -not $_.detected_by_both })
if ($MissingDetections.Count -gt 0) {
    $Names = ($MissingDetections.scenario -join ', ')
    throw "One or more scenarios were not detected by both engines: $Names"
}

Write-Host "Snort alerts: $($Comparison.totals.snort)"
Write-Host "Suricata alerts: $($Comparison.totals.suricata)"
Write-Host "Comparison evidence: $ReportPath"
