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

$DataViewId = 'ids-alerts'
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
            title         = 'ids-alerts-*'
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

$DataSource = @{
    type          = 'data_view_spec'
    index_pattern = 'ids-alerts-*'
    time_field    = '@timestamp'
}

$DashboardId = 'network-forensics-overview'
$Dashboard = @{
    title  = 'Network Forensics Lab | Snort vs Suricata'
    panels = @(
        @{
            grid   = @{ x = 0; y = 0; w = 48; h = 4 }
            type   = 'markdown'
            config = @{
                content = @'
## Network Forensics Lab

Cross-engine evidence for six authorized attack scenarios in an isolated lab. Snort 3 and Suricata 8 alerts are normalized and mapped to MITRE ATT&CK techniques.
'@
            }
        }
        @{
            grid          = @{ x = 0; y = 4; w = 12; h = 6 }
            type          = 'vis'
            config        = @{
                type        = 'metric'
                title       = 'Total IDS alerts'
                data_source = $DataSource
                metrics     = @(@{ type = 'primary'; operation = 'count' })
            }
        }
        @{
            grid          = @{ x = 12; y = 4; w = 12; h = 6 }
            type          = 'vis'
            config        = @{
                type        = 'metric'
                title       = 'Detected scenarios'
                data_source = $DataSource
                metrics     = @(
                    @{ type = 'primary'; operation = 'unique_count'; field = 'scenario.keyword' }
                )
            }
        }
        @{
            grid          = @{ x = 24; y = 4; w = 12; h = 10 }
            type          = 'vis'
            config        = @{
                type        = 'pie'
                title       = 'Alerts by IDS engine'
                data_source = $DataSource
                metrics     = @(@{ operation = 'count' })
                group_by    = @(
                    @{ operation = 'terms'; fields = @('engine.keyword'); limit = 5 }
                )
                styling     = @{ donut_hole = 'm' }
            }
        }
        @{
            grid          = @{ x = 36; y = 4; w = 12; h = 10 }
            type          = 'vis'
            config        = @{
                type        = 'pie'
                title       = 'MITRE ATT&CK techniques'
                data_source = $DataSource
                metrics     = @(@{ operation = 'count' })
                group_by    = @(
                    @{
                        operation = 'terms'
                        fields    = @('threat.technique.id.keyword')
                        limit     = 10
                    }
                )
                styling     = @{ donut_hole = 's' }
            }
        }
        @{
            grid          = @{ x = 0; y = 14; w = 24; h = 12 }
            type          = 'vis'
            config        = @{
                type        = 'data_table'
                title       = 'Scenario detection matrix'
                data_source = $DataSource
                metrics     = @(@{ operation = 'count' })
                rows        = @(
                    @{ operation = 'terms'; fields = @('scenario.keyword'); limit = 10 },
                    @{ operation = 'terms'; fields = @('engine.keyword'); limit = 5 }
                )
            }
        }
        @{
            grid          = @{ x = 24; y = 14; w = 24; h = 12 }
            type          = 'vis'
            config        = @{
                type        = 'data_table'
                title       = 'Source to destination evidence'
                data_source = $DataSource
                metrics     = @(@{ operation = 'count' })
                rows        = @(
                    @{ operation = 'terms'; fields = @('source.ip.keyword'); limit = 10 },
                    @{ operation = 'terms'; fields = @('destination.ip.keyword'); limit = 10 }
                )
            }
        }
    )
}

$DashboardBody = $Dashboard | ConvertTo-Json -Depth 20
$DashboardResponse = Invoke-RestMethod `
    -Method Put `
    -Uri "$KibanaBaseUrl/api/dashboards/$DashboardId" `
    -Headers $Headers `
    -ContentType 'application/json' `
    -Body $DashboardBody `
    -TimeoutSec 60

if ($DashboardResponse.id -ne $DashboardId -or $DashboardResponse.data.panels.Count -ne 7) {
    throw 'Kibana dashboard response did not match the requested dashboard.'
}

$DashboardUrl = "$KibanaBaseUrl/app/dashboards#/view/$DashboardId"
Write-Host "Kibana Lens dashboard is ready: $DashboardUrl"
