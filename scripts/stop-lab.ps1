[CmdletBinding()]
param(
    [switch]$DeleteElasticData
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $LabRoot

if ($DeleteElasticData) {
    docker compose --profile tools down --volumes
} else {
    docker compose --profile tools down
}

if ($LASTEXITCODE -ne 0) {
    throw 'Failed to stop the lab.'
}
