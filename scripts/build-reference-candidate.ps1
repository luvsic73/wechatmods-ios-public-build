param(
    [Parameter(Mandatory = $true)]
    [string]$BaseIpa,
    [Parameter(Mandatory = $true)]
    [string]$OutputIpa,
    [string]$ReportDirectory,
    [string]$DisplayName
)

$ErrorActionPreference = "Stop"
$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$env:PYTHONPATH = Join-Path $projectRoot "src"
$basePath = [IO.Path]::GetFullPath($BaseIpa)
$outputPath = [IO.Path]::GetFullPath($OutputIpa)
if (-not $ReportDirectory) {
    $ReportDirectory = Join-Path (
        [IO.Path]::GetDirectoryName($outputPath)
    ) "reports"
}
$reportPath = [IO.Path]::GetFullPath($ReportDirectory)
if (-not $DisplayName) {
    $DisplayName = ([char]0x5FAE).ToString() +
        ([char]0x4FE1).ToString() + " Glass"
}

$staging = Join-Path ([IO.Path]::GetTempPath()) (
    "wechat-reference-{0}" -f [guid]::NewGuid().ToString("N")
)
New-Item -ItemType Directory -Path $staging | Out-Null
New-Item -ItemType Directory -Force -Path $reportPath | Out-Null

try {
    $modules = Join-Path $projectRoot "data\modules.json"
    $loader = Join-Path $projectRoot "dist\WeChatMods.dylib"
    $coexistBase = Join-Path $staging "00-coexist-base.ipa"
    $manifestIpa = Join-Path $staging "01-manifest.ipa"
    $injectedIpa = Join-Path $staging "02-injected.ipa"
    $candidateIpa = Join-Path $staging "03-candidate.ipa"

    & (Join-Path $PSScriptRoot "assert-loader-current.ps1") -Loader $loader

    py -3 -m wechat_ipa_audit.cli loader-policy `
        $loader `
        --output (Join-Path $reportPath "loader-policy.json")
    if ($LASTEXITCODE -ne 0) {
        throw "Reference loader policy failed"
    }

    py -3 -m wechat_ipa_audit.cli coexist `
        $basePath $coexistBase `
        --bundle-id "com.tencent.qy.xin" `
        --bundle-name "WeChatGlass" `
        --display-name $DisplayName `
        --scheme-prefix "wechatglass" `
        --report (Join-Path $reportPath "coexist-baseline.json")
    if ($LASTEXITCODE -ne 0) {
        throw "Reference coexist baseline packaging failed"
    }

    py -3 -m wechat_ipa_audit.cli package `
        $coexistBase $manifestIpa --modules $modules
    if ($LASTEXITCODE -ne 0) {
        throw "Reference manifest packaging failed"
    }

    py -3 -m wechat_ipa_audit.cli inject `
        $manifestIpa `
        $loader `
        $injectedIpa
    if ($LASTEXITCODE -ne 0) {
        throw "Reference loader injection failed"
    }

    py -3 -m wechat_ipa_audit.cli icon `
        $injectedIpa `
        (Join-Path $projectRoot "assets\app-icon-liquid-glass-1024.png") `
        (Join-Path $projectRoot "assets\AppIcon.icon") `
        $candidateIpa `
        --report (Join-Path $reportPath "app-icon.json")
    if ($LASTEXITCODE -ne 0) {
        throw "Reference app icon replacement failed"
    }

    py -3 -m wechat_ipa_audit.cli inspect-coexist `
        $candidateIpa `
        --output (Join-Path $reportPath "coexist-readiness.json")
    if ($LASTEXITCODE -ne 0) {
        throw "Reference coexist inspection failed"
    }

    py -3 -m wechat_ipa_audit.cli account-safety `
        $coexistBase $candidateIpa `
        --trusted-loader $loader `
        --output (Join-Path $reportPath "candidate-delta.json")
    if ($LASTEXITCODE -ne 0) {
        throw "Reference candidate delta gate failed"
    }

    py -3 -m wechat_ipa_audit.cli candidate-policy `
        $basePath $candidateIpa `
        --output (Join-Path $reportPath "candidate-policy.json")
    if ($LASTEXITCODE -ne 0) {
        throw "Reference candidate component policy failed"
    }

    py -3 -m wechat_ipa_audit.cli audit `
        $candidateIpa `
        --output (Join-Path $reportPath "candidate-audit.json")
    if ($LASTEXITCODE -ne 0) {
        throw "Reference candidate audit failed"
    }

    py -3 -m wechat_ipa_audit.cli verify `
        $candidateIpa `
        --output (Join-Path $reportPath "candidate-verify.json")
    if ($LASTEXITCODE -ne 0) {
        throw "Reference candidate verification failed"
    }

    $temporaryOutput = "$outputPath.tmp-$([guid]::NewGuid().ToString('N'))"
    Copy-Item -LiteralPath $candidateIpa -Destination $temporaryOutput
    Move-Item -LiteralPath $temporaryOutput -Destination $outputPath -Force
}
finally {
    Remove-Item -LiteralPath $staging -Recurse -Force `
        -ErrorAction SilentlyContinue
}
