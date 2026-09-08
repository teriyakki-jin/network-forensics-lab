[CmdletBinding()]
param(
    [ValidateRange(1, 20)]
    [int]$RepeatCount = 5,
    [string]$PythonCommand = 'python',
    [switch]$UseCommittedFixtures
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $LabRoot

$EvidenceRoot = Join-Path $LabRoot 'evidence\evaluation'
$AlertRoot = Join-Path $LabRoot 'alerts\evaluation'
$GroundTruth = Join-Path $LabRoot 'evaluation\ground-truth.json'
$Catalog = Join-Path $LabRoot 'detection\rule-catalog.json'
$AggregateOutput = Join-Path $EvidenceRoot 'detection-metrics.json'
$FixturePcaps = @{
    attack = 'attack-traffic.pcap'
    benign = 'benign-traffic.pcap'
}

function Invoke-Compose {
    & docker compose @args
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed: $($args -join ' ')"
    }
}

function Invoke-Forensics {
    & $PythonCommand -m forensics.cli @args
    if ($LASTEXITCODE -ne 0) {
        throw "forensics CLI failed: $($args -join ' ')"
    }
}

New-Item -ItemType Directory -Path $EvidenceRoot -Force | Out-Null
if (Test-Path -LiteralPath $AlertRoot) {
    Remove-Item -LiteralPath $AlertRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $AlertRoot -Force | Out-Null

if (-not $UseCommittedFixtures) {
    Write-Host '[1/4] Starting isolated fixture network'
    Invoke-Compose up -d --build victim dns vehicle-gateway kali

    Write-Host '[2/4] Capturing paired attack and benign fixtures'
    foreach ($Fixture in @('attack', 'benign')) {
        $PcapName = $FixturePcaps[$Fixture]
        $PcapPath = Join-Path $EvidenceRoot $PcapName
        Remove-Item -LiteralPath $PcapPath -Force -ErrorAction SilentlyContinue
        Invoke-Compose exec -T kali sh -lc "rm -f /evidence/evaluation/$PcapName /tmp/tcpdump-evaluation.pid; tcpdump -i eth0 -nn -U -w /evidence/evaluation/$PcapName >/tmp/tcpdump-evaluation.log 2>&1 & echo `$! >/tmp/tcpdump-evaluation.pid"
        Start-Sleep -Seconds 2
        Invoke-Compose exec -T kali sh /lab/generate-traffic.sh $Fixture
        Start-Sleep -Seconds 2
        Invoke-Compose exec -T kali sh -lc 'kill -2 $(cat /tmp/tcpdump-evaluation.pid) 2>/dev/null || true; sleep 2'
        if (-not (Test-Path -LiteralPath $PcapPath)) {
            throw "Fixture capture was not created: $PcapPath"
        }
        Write-Host "    $Fixture fixture: $((Get-Item -LiteralPath $PcapPath).Length) bytes"
    }
} else {
    Write-Host '[1/4] Using committed paired fixtures'
    Write-Host '[2/4] Validating fixture availability'
}

foreach ($PcapName in $FixturePcaps.Values) {
    $PcapPath = Join-Path $EvidenceRoot $PcapName
    if (-not (Test-Path -LiteralPath $PcapPath)) {
        throw "Fixture is missing: $PcapPath"
    }
    $ActualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $PcapPath).Hash.ToLowerInvariant()
    $ChecksumPath = "$PcapPath.sha256"
    $HashLine = "$ActualHash  $PcapName"
    if ($UseCommittedFixtures) {
        if (-not (Test-Path -LiteralPath $ChecksumPath)) {
            throw "Fixture checksum is missing: $ChecksumPath"
        }
        $ExpectedHash = ((Get-Content -LiteralPath $ChecksumPath -Raw -Encoding ascii).Trim() -split '\s+')[0]
        if ($ActualHash -ne $ExpectedHash) {
            throw "Fixture checksum mismatch: $PcapName"
        }
    } else {
        Set-Content -LiteralPath $ChecksumPath -Value $HashLine -Encoding ascii
    }
}

Write-Host "[3/4] Running Snort and Suricata $RepeatCount times"
$EvaluationReports = @()
foreach ($Run in 1..$RepeatCount) {
    $RunNormalised = @()
    foreach ($Fixture in @('attack', 'benign')) {
        $PcapName = $FixturePcaps[$Fixture]
        $RelativeOutput = "evaluation/run-$Run/$Fixture"
        $HostOutput = Join-Path $AlertRoot "run-$Run\$Fixture"
        New-Item -ItemType Directory -Path $HostOutput -Force | Out-Null

        Invoke-Compose --profile tools run --rm `
            -e "PCAP_FILE=evaluation/$PcapName" `
            -e "OUTPUT_DIR=/alerts/$RelativeOutput/snort" snort
        Invoke-Compose --profile tools run --rm `
            -e "PCAP_FILE=evaluation/$PcapName" `
            -e "OUTPUT_DIR=/alerts/$RelativeOutput/suricata" suricata

        $NormalisedPath = Join-Path $HostOutput 'normalized-alerts.jsonl'
        Invoke-Forensics compare `
            --catalog $Catalog `
            --snort (Join-Path $HostOutput 'snort\alert_json.txt') `
            --suricata (Join-Path $HostOutput 'suricata\eve.json') `
            --normalised $NormalisedPath `
            --report (Join-Path $HostOutput 'ids-comparison.json') `
            --fixture-id $Fixture | Out-Host
        $RunNormalised += $NormalisedPath
    }

    $CombinedPath = Join-Path $AlertRoot "run-$Run\normalized-alerts.jsonl"
    Get-Content -LiteralPath $RunNormalised -Encoding UTF8 | Set-Content -LiteralPath $CombinedPath -Encoding UTF8
    foreach ($Engine in @('snort', 'suricata')) {
        $ReportPath = Join-Path $EvidenceRoot "run-$Run-$Engine.json"
        Invoke-Forensics evaluate `
            --alerts $CombinedPath `
            --ground-truth $GroundTruth `
            --engine $Engine `
            --run-id $Run `
            --output $ReportPath | Out-Host
        $EvaluationReports += $ReportPath
    }
}

Write-Host '[4/4] Aggregating transparent scenario-level metrics'
$AggregateArguments = @('aggregate-evaluations')
foreach ($ReportPath in $EvaluationReports) {
    $AggregateArguments += @('--input', $ReportPath)
}
$AggregateArguments += @('--output', $AggregateOutput)
Invoke-Forensics @AggregateArguments | Out-Host

Write-Host "Evaluation completed: $AggregateOutput"
