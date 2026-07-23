[CmdletBinding()]
param(
    [ValidateRange(1, 30)]
    [int]$TimeoutMinutes = 8
)

$ErrorActionPreference = 'Stop'
$KibanaBaseUrl = 'http://127.0.0.1:5601'
$Headers = @{ 'kbn-xsrf' = 'network-forensics-lab' }
$Deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$Ready = $false

Write-Host "Waiting for Kibana (timeout: $TimeoutMinutes minutes)"
do {
    try {
        $Status = Invoke-RestMethod -Uri "$KibanaBaseUrl/api/status" -TimeoutSec 10
        $Ready = $Status.status.overall.level -eq 'available'
    } catch {
        $Ready = $false
    }

    if (-not $Ready) {
        Start-Sleep -Seconds 5
    }
} while (-not $Ready -and (Get-Date) -lt $Deadline)

if (-not $Ready) {
    throw "Kibana did not become available within $TimeoutMinutes minutes."
}

$DataViewId = 'snort-alerts'
$DataViewExists = $false
try {
    Invoke-RestMethod `
        -Uri "$KibanaBaseUrl/api/data_views/data_view/$DataViewId" `
        -Headers $Headers `
        -TimeoutSec 15 | Out-Null
    $DataViewExists = $true
} catch {
    $StatusCode = $_.Exception.Response.StatusCode.value__
    if ($StatusCode -ne 404) {
        throw
    }
}

if (-not $DataViewExists) {
    $CreateBody = @{
        data_view = @{
            id            = $DataViewId
            title         = 'snort-alerts-*'
            timeFieldName = '@timestamp'
        }
    } | ConvertTo-Json -Depth 5

    Invoke-RestMethod `
        -Method Post `
        -Uri "$KibanaBaseUrl/api/data_views/data_view" `
        -Headers $Headers `
        -ContentType 'application/json' `
        -Body $CreateBody `
        -TimeoutSec 30 | Out-Null
    Write-Host "Created Kibana data view: $DataViewId"
} else {
    Write-Host "Kibana data view already exists: $DataViewId"
}

$DefaultBody = @{
    data_view_id = $DataViewId
    force        = $true
} | ConvertTo-Json

Invoke-RestMethod `
    -Method Post `
    -Uri "$KibanaBaseUrl/api/data_views/default" `
    -Headers $Headers `
    -ContentType 'application/json' `
    -Body $DefaultBody `
    -TimeoutSec 30 | Out-Null

Write-Host 'Kibana is ready: http://127.0.0.1:5601/app/discover'
