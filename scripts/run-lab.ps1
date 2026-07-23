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

Write-Host '[1/8] Checking Docker engine'
& cmd.exe /d /c 'docker info >nul 2>&1'
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Desktop is not running.'
}

Write-Host '[2/8] Starting isolated network, Kali, and victim'
Invoke-Compose up -d --build victim kali

Write-Host '[3/8] Starting packet capture on Kali'
Invoke-Compose exec -T kali sh -lc 'rm -f /evidence/lab-traffic.pcap /tmp/tcpdump.pid; tcpdump -i eth0 -nn -U -w /evidence/lab-traffic.pcap >/tmp/tcpdump.log 2>&1 & echo $! >/tmp/tcpdump.pid'
Start-Sleep -Seconds 2

Write-Host '[4/8] Generating authorized lab traffic: ICMP, HTTP, SYN scan'
Invoke-Compose exec -T kali sh -lc 'ping -c 3 10.77.0.10 >/dev/null || true; curl -sS "http://10.77.0.10/admin?cmd=id" >/dev/null || true; nmap -n -sS -p 1-30 10.77.0.10 >/evidence/nmap-result.txt'
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

Write-Host '[5/8] Running Snort 3 offline analysis'
Remove-Item -LiteralPath (Join-Path $LabRoot 'alerts\alert_json.txt') -Force -ErrorAction SilentlyContinue
Invoke-Compose --profile tools run --rm snort

$AlertPath = Join-Path $LabRoot 'alerts\alert_json.txt'
if (-not (Test-Path -LiteralPath $AlertPath)) {
    throw "Snort alert file was not created: $AlertPath"
}
$Alerts = Get-Content -LiteralPath $AlertPath
Write-Host "    Snort alert count: $($Alerts.Count)"
$Alerts | ForEach-Object { Write-Host "    $_" }

if (-not $SkipElastic) {
    Write-Host '[6/8] Starting Elasticsearch, Logstash, and Kibana'
    Invoke-Compose up -d elasticsearch logstash kibana

    Write-Host '[7/8] Verifying Elasticsearch ingestion'
    $Deadline = (Get-Date).AddMinutes(5)
    $Count = 0
    do {
        Start-Sleep -Seconds 5
        try {
            $Response = Invoke-RestMethod -Uri 'http://127.0.0.1:9200/snort-alerts-*/_count' -TimeoutSec 5
            $Count = [int]$Response.count
        } catch {
            $Count = 0
        }
    } while ($Count -lt 1 -and (Get-Date) -lt $Deadline)

    if ($Count -lt 1) {
        throw 'Elasticsearch ingestion was not confirmed within 5 minutes. Check docker compose logs logstash.'
    }
    Write-Host "    Elasticsearch document count: $Count"

    Write-Host '[8/8] Configuring the Kibana data view'
    & (Join-Path $PSScriptRoot 'setup-kibana.ps1')
} else {
    Write-Host '[6/8] -SkipElastic: Elastic Stack startup skipped'
    Write-Host '[7/8] Elasticsearch ingestion check skipped'
    Write-Host '[8/8] Kibana data view setup skipped'
}

Write-Host 'Lab completed.'
