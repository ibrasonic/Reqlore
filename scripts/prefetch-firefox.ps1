# Pre-download the official Firefox portable archive into Reqlore's cache,
# so the first `reqlore browser` launch on this machine (or one we ship
# this folder to) is instant and offline-safe.
#
# Usage:
#   .\scripts\prefetch-firefox.ps1                    # latest version
#   .\scripts\prefetch-firefox.ps1 -Version 127.0
#   .\scripts\prefetch-firefox.ps1 -Force             # re-download

[CmdletBinding()]
param(
    [string]$Version,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$argsList = @("-m", "reqlore.cli", "prefetch-firefox")
if ($Version) { $argsList += @("--firefox-version", $Version) }
if ($Force)   { $argsList += "--force" }

# Use the same Python that has reqlore installed; fall back to `py`.
$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) { $python = (Get-Command py -ErrorAction SilentlyContinue).Source }
if (-not $python) { throw "Python not found on PATH." }

& $python @argsList
