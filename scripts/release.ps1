# scripts/release.ps1 — build wheel + sdist and write SHA256SUMS.txt.
#
# Usage:
#   pwsh -File scripts/release.ps1               # full build + checksums
#   pwsh -File scripts/release.ps1 -SkipBuild    # only refresh checksums
#
# Requires `python -m build`. Install with: python -m pip install build
[CmdletBinding()]
param(
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

if (-not $SkipBuild) {
    Write-Host "==> Cleaning dist/"
    if (Test-Path dist) { Remove-Item dist -Recurse -Force }
    New-Item -ItemType Directory -Path dist | Out-Null

    Write-Host "==> Building wheel + sdist"
    & python -m build
    if ($LASTEXITCODE -ne 0) { throw "python -m build failed (exit $LASTEXITCODE)" }
}

if (-not (Test-Path dist)) { throw "dist/ is missing; run without -SkipBuild first" }

Write-Host "==> Computing SHA256 checksums"
$lines = Get-ChildItem dist -File |
    Where-Object { $_.Name -ne "SHA256SUMS.txt" } |
    Sort-Object Name |
    ForEach-Object {
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "{0}  {1}" -f $hash, $_.Name
    }
$lines | Set-Content -Path "dist/SHA256SUMS.txt" -Encoding ascii

Write-Host "==> dist/ contents:"
Get-ChildItem dist | Format-Table Name, Length -AutoSize
Write-Host "==> SHA256SUMS.txt:"
Get-Content dist/SHA256SUMS.txt
