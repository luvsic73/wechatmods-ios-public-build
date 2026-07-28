param(
    [Parameter(Mandatory = $true)]
    [string]$InputIpa,
    [Parameter(Mandatory = $true)]
    [string]$OutputIpa,
    [string]$MasterPng,
    [string]$IconDocument,
    [string]$Report
)

$ErrorActionPreference = "Stop"
$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$env:PYTHONPATH = Join-Path $projectRoot "src"
if (-not $MasterPng) {
    $MasterPng = Join-Path $projectRoot "assets\app-icon-liquid-glass-1024.png"
}
if (-not $IconDocument) {
    $IconDocument = Join-Path $projectRoot "assets\AppIcon.icon"
}

$arguments = @(
    "-3", "-m", "wechat_ipa_audit.cli", "icon",
    [IO.Path]::GetFullPath($InputIpa),
    [IO.Path]::GetFullPath($MasterPng),
    [IO.Path]::GetFullPath($IconDocument),
    [IO.Path]::GetFullPath($OutputIpa)
)
if ($Report) {
    $arguments += @("--report", [IO.Path]::GetFullPath($Report))
}
& py @arguments
if ($LASTEXITCODE -ne 0) {
    throw "App icon packaging failed"
}

py -3 -m wechat_ipa_audit.cli verify ([IO.Path]::GetFullPath($OutputIpa))
if ($LASTEXITCODE -ne 0) {
    throw "App icon package verification failed"
}
