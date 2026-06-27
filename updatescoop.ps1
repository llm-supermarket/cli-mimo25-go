param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$exePath = Join-Path $PSScriptRoot "artifacts" "cli-mimo25-go-windows-amd64.exe"

if (-not (Test-Path $exePath)) {
    throw "Unable to locate cli-mimo25-go-windows-amd64.exe at $exePath"
}

$hash = (Get-FileHash -Path $exePath -Algorithm SHA256).Hash.ToLower()

Write-Host "Hash: $hash"

$url = "https://github.com/llm-supermarket/cli-mimo25-go/releases/download/v$Version/cli-mimo25-go-windows-amd64.exe"

$manifestPath = Join-Path $PSScriptRoot "cli-mimo25-go.json"

$manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json

$manifest.version = $Version
$manifest.architecture."64bit".url = $url
$manifest.architecture."64bit".hash = $hash

$manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestPath -NoNewline

Write-Host "Updated cli-mimo25-go.json to v$Version"
