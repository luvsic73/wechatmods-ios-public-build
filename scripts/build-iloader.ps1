param(
    [Parameter(Mandatory = $true)]
    [string]$BaseIpa,
    [Parameter(Mandatory = $true)]
    [string]$OutputIpa,
    [string]$Loader,
    [string]$SafetyReport
)

$ErrorActionPreference = "Stop"
$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$env:PYTHONPATH = Join-Path $projectRoot "src"
$modules = Join-Path $projectRoot "data\modules.json"
if (-not $Loader) {
    $Loader = Join-Path $projectRoot "dist\WeChatMods.dylib"
}
& (Join-Path $PSScriptRoot "assert-loader-current.ps1") -Loader $Loader
$outputPath = [IO.Path]::GetFullPath($OutputIpa)
if (-not $SafetyReport) {
    $SafetyReport = "$outputPath.account-safety.json"
}
$safetyReportPath = [IO.Path]::GetFullPath($SafetyReport)
$stagedIpa = Join-Path ([IO.Path]::GetDirectoryName($outputPath)) (
    ".wechatmods.{0}.staged.ipa" -f [guid]::NewGuid().ToString("N")
)

try {
    py -3 -m wechat_ipa_audit.cli package $BaseIpa $stagedIpa --modules $modules
    if ($LASTEXITCODE -ne 0) {
        throw "Packaging failed"
    }
    py -3 -m wechat_ipa_audit.cli inject $stagedIpa $Loader $outputPath
    if ($LASTEXITCODE -ne 0) {
        throw "Loader injection failed"
    }
    py -3 -m wechat_ipa_audit.cli account-safety `
        $BaseIpa $outputPath `
        --trusted-loader $Loader `
        --output $safetyReportPath
    if ($LASTEXITCODE -ne 0) {
        Remove-Item -LiteralPath $outputPath -Force `
            -ErrorAction SilentlyContinue
        throw "Account safety gate blocked the package; report: $safetyReportPath"
    }
    py -3 -m wechat_ipa_audit.cli verify $outputPath
    if ($LASTEXITCODE -ne 0) {
        throw "Verification failed"
    }
}
finally {
    Remove-Item -LiteralPath $stagedIpa -Force -ErrorAction SilentlyContinue
}
