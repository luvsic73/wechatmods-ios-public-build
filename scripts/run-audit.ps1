param(
    [Parameter(Mandatory = $true)]
    [string]$SampleDirectory,
    [string]$ReportDirectory = "reports"
)

$ErrorActionPreference = "Stop"
$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$sampleRoot = (Resolve-Path -LiteralPath $SampleDirectory).Path
$reportRoot = Join-Path $projectRoot $ReportDirectory
New-Item -ItemType Directory -Force -Path $reportRoot | Out-Null
$env:PYTHONPATH = Join-Path $projectRoot "src"

Get-ChildItem -LiteralPath $sampleRoot -Filter "*.ipa" |
    Sort-Object Name |
    ForEach-Object {
        $output = Join-Path $reportRoot ($_.BaseName + ".json")
        py -3 -m wechat_ipa_audit.cli audit $_.FullName --output $output
        if ($LASTEXITCODE -ne 0) {
            throw "Audit failed: $($_.FullName)"
        }
    }
