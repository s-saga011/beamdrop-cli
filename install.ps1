# beamdrop CLI installer + auto-updater (Windows PowerShell).
#
# Usage (install or update only):
#   irm https://raw.githubusercontent.com/s-saga011/beamdrop-cli/main/install.ps1 | iex
#
# Usage (install/update if needed + run a command):
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/s-saga011/beamdrop-cli/main/install.ps1))) recv ROOM
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/s-saga011/beamdrop-cli/main/install.ps1))) send C:\path\to\file
#
# $env:BEAMDROP_FORCE_INSTALL=1   forces re-download regardless of version.
# $env:BEAMDROP_INSTALL_DIR=...   override install location.

param([Parameter(ValueFromRemainingArguments=$true)] $RestArgs)

$ErrorActionPreference = "Stop"

$Repo       = "s-saga011/beamdrop-cli"
$InstallDir = if ($env:BEAMDROP_INSTALL_DIR) { $env:BEAMDROP_INSTALL_DIR } else { "$env:USERPROFILE\.beamdrop" }
$BinName    = "beamdrop.exe"
$Target     = Join-Path $InstallDir $BinName

# 1. Find existing install
$Existing = $null
$cmd = Get-Command beamdrop -ErrorAction SilentlyContinue
if ($cmd) { $Existing = $cmd.Path }
elseif (Test-Path $Target) { $Existing = $Target }

# 2. Read installed version (if any)
$InstalledVer = $null
if ($Existing) {
    try {
        $InstalledVer = (& $Existing --version 2>$null | Select-Object -First 1).Trim()
    } catch {
        $InstalledVer = $null
    }
}

# 3. Query latest release tag from GitHub API
$LatestVer = $null
try {
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
    $LatestVer = $rel.tag_name
} catch {
    $LatestVer = $null
}

# 4. Decide whether to (re)install
$needInstall = $true
if ($Existing -and -not $env:BEAMDROP_FORCE_INSTALL) {
    if ($InstalledVer -and $LatestVer -and ($InstalledVer -eq $LatestVer)) {
        Write-Host "beamdrop $InstalledVer already at latest ($Existing)"
        $needInstall = $false
        $Target = $Existing
    } elseif (-not $LatestVer) {
        Write-Host "beamdrop installed ($Existing); skipping (could not check latest version)"
        $needInstall = $false
        $Target = $Existing
    } else {
        $shown = if ($InstalledVer) { $InstalledVer } else { "<unknown>" }
        Write-Host "beamdrop $shown -> $LatestVer (updating)"
    }
}

if ($needInstall) {
    $Asset = "beamdrop-windows-amd64.exe"
    $Url   = "https://github.com/$Repo/releases/latest/download/$Asset"
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Write-Host "Downloading $Asset ..."
    Invoke-WebRequest -Uri $Url -OutFile $Target -UseBasicParsing

    $newVer = ""
    try { $newVer = (& $Target --version 2>$null | Select-Object -First 1).Trim() } catch {}
    Write-Host "Installed: $Target ($newVer)"

    # Add to current process PATH so subsequent calls find it
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

# 5. If extra args were supplied (e.g. recv ROOM, send file.mp4), run beamdrop with them.
if ($RestArgs -and $RestArgs.Count -gt 0) {
    Write-Host ""
    & $Target @RestArgs
}
