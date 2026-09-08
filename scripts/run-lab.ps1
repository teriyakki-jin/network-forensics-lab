[CmdletBinding()]
param(
    [switch]$SkipElastic
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $LabRoot

function Invoke-Compose {
    & docker compose @args
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed: $($args -join ' ')"
    }
}

function Wait-Elasticsearch {
    param([int]$TimeoutSeconds = 300)

    $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $Health = Invoke-RestMethod `
                -Uri 'http://127.0.0.1:9200/_cluster/health?wait_for_status=yellow&timeout=5s' `
                -TimeoutSec 10
            if ($Health.status -in @('yellow', 'green')) {
                Write-Host "    Elasticsearch status: $($Health.status)"
                return
            }
        } catch {
            # Elasticsearch can close the connection while the JVM is still booting.
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $Deadline)

    throw "Elasticsearch did not become ready within $TimeoutSeconds seconds."
}

function Clear-LabIndices {
    $Indices = @()
    try {
        $Indices = @(
            Invoke-RestMethod `
                -Uri 'http://127.0.0.1:9200/_cat/indices/ids-alerts-*?format=json&h=index' `
                -TimeoutSec 15
        )
    } catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        if ($StatusCode -ne 404) {
            throw
        }
    }

    foreach ($Index in $Indices) {
        $ExactName = [string]$Index.index
        if ([string]::IsNullOrWhiteSpace($ExactName)) {
            continue
        }
        if ($ExactName -notlike 'ids-alerts-*') {
            throw "Refusing to delete unexpected index: $ExactName"
        }
        $EncodedName = [Uri]::EscapeDataString($ExactName)
        Invoke-RestMethod `
            -Method Delete `
            -Uri "http://127.0.0.1:9200/$EncodedName" `
            -TimeoutSec 15 | Out-Null
        Write-Host "    Cleared prior index: $ExactName"
    }
}

Write-Host '[1/10] Checking Docker engine'
& cmd.exe /d /c 'docker info >nul 2>&1'
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Desktop is not running.'
}

Write-Host '[2/10] Starting isolated network, DNS, Kali, victim, and vehicle gateway'
Invoke-Compose up -d --build victim dns vehicle-gateway kali

Write-Host '[3/10] Starting packet capture on Kali'
Invoke-Compose exec -T kali sh -lc 'rm -f /evidence/lab-traffic.pcap /tmp/tcpdump.pid; tcpdump -i eth0 -nn -U -w /evidence/lab-traffic.pcap >/tmp/tcpdump.log 2>&1 & echo $! >/tmp/tcpdump.pid'
Start-Sleep -Seconds 2

Write-Host '[4/10] Generating authorized scenarios: ICMP, HTTP admin probe, SYN scan, brute force, DNS tunneling, web exploit, DoIP unauthorized diagnostic, SOME/IP service discovery'
Invoke-Compose exec -T kali sh /lab/generate-traffic.sh
Start-Sleep -Seconds 2
Invoke-Compose exec -T kali sh -lc 'kill -2 $(cat /tmp/tcpdump.pid) 2>/dev/null || true; sleep 2; capinfos /evidence/lab-traffic.pcap'

$PcapPath = Join-Path $LabRoot 'evidence\lab-traffic.pcap'
if (-not (Test-Path -LiteralPath $PcapPath)) {
    throw "PCAP was not created: $PcapPath"
}
$Hash = Get-FileHash -Algorithm SHA256 -LiteralPath $PcapPath
$HashLine = "$($Hash.Hash.ToLowerInvariant())  lab-traffic.pcap"
Set-Content -LiteralPath (Join-Path $LabRoot 'evidence\lab-traffic.pcap.sha256') -Value $HashLine -Encoding ascii
Write-Host "    SHA-256: $($Hash.Hash)"

Write-Host '[5/10] Running Snort 3 offline analysis'
Remove-Item -LiteralPath (Join-Path $LabRoot 'alerts\alert_json.txt') -Force -ErrorAction SilentlyContinue
Invoke-Compose --profile tools run --rm snort

$AlertPath = Join-Path $LabRoot 'alerts\alert_json.txt'
if (-not (Test-Path -LiteralPath $AlertPath)) {
    throw "Snort alert file was not created: $AlertPath"
}
$Alerts = Get-Content -LiteralPath $AlertPath
Write-Host "    Snort alert count: $($Alerts.Count)"
$Alerts |
    ForEach-Object { $_ | ConvertFrom-Json } |
    Group-Object sid |
    Sort-Object Name |
    ForEach-Object { Write-Host "    SID $($_.Name): $($_.Count)" }

Write-Host '[6/10] Running Suricata 8 offline analysis'
Remove-Item -LiteralPath (Join-Path $LabRoot 'alerts\suricata') -Recurse -Force -ErrorAction SilentlyContinue
Invoke-Compose --profile tools run --rm suricata

$SuricataAlertPath = Join-Path $LabRoot 'alerts\suricata\eve.json'
if (-not (Test-Path -LiteralPath $SuricataAlertPath)) {
    throw "Suricata EVE file was not created: $SuricataAlertPath"
}

Write-Host '[7/10] Normalising alerts and comparing IDS coverage'
& (Join-Path $PSScriptRoot 'run-comparison.ps1')

$NormalisedPath = Join-Path $LabRoot 'alerts\normalized-alerts.jsonl'
$ExpectedCount = @(Get-Content -LiteralPath $NormalisedPath).Count
$AcquiredAt = (Get-Item -LiteralPath $PcapPath).LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
$CaseArguments = @(
    '-m', 'forensics.cli', 'build-case',
    '--case-id', 'NF-AUTO-LAB',
    '--evidence-root', $LabRoot,
    '--artifact', $PcapPath,
    '--artifact', (Join-Path $LabRoot 'evidence\lab-traffic.pcap.sha256'),
    '--artifact', $NormalisedPath,
    '--artifact', (Join-Path $LabRoot 'evidence\ids-comparison.json'),
    '--artifact', (Join-Path $LabRoot 'evidence\sigma-validation.json'),
    '--normalised', $NormalisedPath,
    '--acquired-at', $AcquiredAt,
    '--sensor-id', 'sensor-vehicle-gateway',
    '--tool-version', 'snort=3',
    '--tool-version', 'suricata=8.0.6',
    '--manifest', (Join-Path $LabRoot 'evidence\case-manifest.json'),
    '--timeline', (Join-Path $LabRoot 'evidence\incident-timeline.json')
)
& python @CaseArguments | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw 'Case manifest and incident timeline generation failed.'
}

if (-not $SkipElastic) {
    Write-Host '[8/10] Starting Elasticsearch and clearing the previous lab index'
    Invoke-Compose up -d elasticsearch
    Wait-Elasticsearch
    Clear-LabIndices

    Invoke-Compose up -d --force-recreate logstash kibana

    Write-Host '[9/10] Verifying Elasticsearch ingestion'
    $Deadline = (Get-Date).AddMinutes(5)
    $Count = 0
    do {
        Start-Sleep -Seconds 5
        try {
            $Response = Invoke-RestMethod -Uri 'http://127.0.0.1:9200/ids-alerts-*/_count' -TimeoutSec 5
            $Count = [int]$Response.count
        } catch {
            $Count = 0
        }
    } while ($Count -lt $ExpectedCount -and (Get-Date) -lt $Deadline)

    if ($Count -ne $ExpectedCount) {
        throw 'Elasticsearch ingestion was not confirmed within 5 minutes. Check docker compose logs logstash.'
    }
    Write-Host "    Elasticsearch document count: $Count"

    Write-Host '[10/10] Configuring the Kibana data view and Lens dashboard'
    & (Join-Path $PSScriptRoot 'setup-kibana.ps1')
} else {
    Write-Host '[8/10] -SkipElastic: Elastic Stack startup skipped'
    Write-Host '[9/10] Elasticsearch ingestion check skipped'
    Write-Host '[10/10] Kibana dashboard setup skipped'
}

Write-Host 'Lab completed.'
