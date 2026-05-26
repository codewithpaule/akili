Param(
  [string]$ApiBase = $env:API_BASE
)

if (-not $ApiBase) {
  Write-Error "API_BASE environment variable not set."
  exit 1
}

$outDir = Join-Path -Path (Get-Location) -ChildPath "frontend/js"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
$outFile = Join-Path $outDir 'config.runtime.js'
"window.AKILI_RUNTIME = { API_BASE: '$ApiBase' };" | Out-File -FilePath $outFile -Encoding utf8
Write-Host "Wrote $outFile"
