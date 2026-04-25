# beamdrop CLI installer (Windows PowerShell).
#
# Usage (install only):
#   irm https://raw.githubusercontent.com/s-saga011/beamdrop-cli/main/install.ps1 | iex
#
# Usage (install if needed + run a command):
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/s-saga011/beamdrop-cli/main/install.ps1))) recv ROOM
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/s-saga011/beamdrop-cli/main/install.ps1))) send C:\path\to\file
#
# Reuses an existing install unless $env:BEAMDROP_FORCE_INSTALL is set.

param([Parameter(ValueFromRemainingArguments=$true)] $RestArgs)

$ErrorActionPreference = "Stop"

$Repo       = "s-saga011/beamdrop-cli"
$InstallDir = if ($env:BEAMDROP_INSTALL_DIR) { $env:BEAMDROP_INSTALL_DIR } else { "$env:USERPROFILE\.beamdrop" }
$BinName    = "beamdrop.exe"
$Target     = Join-Path $InstallDir $BinName

# 1. Find existing
$Existing = $null
$cmd = Get-Command beamdrop -ErrorAction SilentlyContinue
if ($cmd) { $Existing = $cmd.Path }
elseif (Test-Path $Target) { $Existing = $Target }

if ($Existing -and -not $env:BEAMDROP_FORCE_INSTALL) {
    Write-Host "beamdrop already installed: $Existing"
    $Target = $Existing
} else {
    $Asset = "beamdrop-windows-amd64.exe"
    $Url   = "https://github.com/$Repo/releases/latest/download/$Asset"
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Write-Host "Downloading $Asset ..."
    Invoke-WebRequest -Uri $Url -OutFile $Target -UseBasicParsing
    Write-Host "Installed: $Target"

    # Add to current process PATH so subsequent commands find it
    if ($env:Path -notlike "*$InstallDir*") {
        $env:Path = "$env:Path;$InstallDir"
    }
    # Persist on user PATH
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not ($userPath -split ";" | Where-Object { $_ -eq $InstallDir })) {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
        Write-Host "Added $InstallDir to your User PATH (open a new terminal to pick it up persistently)."
    }
}

# 2. If extra args were supplied (e.g. recv ROOM), run beamdrop with them.
if ($RestArgs -and $RestArgs.Count -gt 0) {
    Write-Host ""
    & $Target @RestArgs
}
