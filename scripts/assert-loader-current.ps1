param(
    [Parameter(Mandatory = $true)]
    [string]$Loader
)

$ErrorActionPreference = "Stop"
$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$env:PYTHONPATH = Join-Path $projectRoot "src"
$loaderPath = [IO.Path]::GetFullPath($Loader)
$provenancePath = "$loaderPath.provenance.json"
if (-not (Test-Path -LiteralPath $loaderPath -PathType Leaf)) {
    throw "Loader is missing: $loaderPath"
}
if (-not (Test-Path -LiteralPath $provenancePath -PathType Leaf)) {
    throw "Loader provenance is missing: $provenancePath"
}

py -3 -m wechat_ipa_audit.cli verify-loader-provenance `
    $loaderPath $provenancePath
if ($LASTEXITCODE -ne 0) {
    throw (
        "Loader is stale or has no matching provenance: {0}" -f
        $provenancePath
    )
}
