# beamdrop CLI installer (Windows PowerShell).
# Run via:
#   irm https://raw.githubusercontent.com/s-saga011/beamdrop-cli/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo      = "s-saga011/beamdrop-cli"
$InstallDir = if ($env:BEAMDROP_INSTALL_DIR) { $env:BEAMDROP_INSTALL_DIR } else { "$env:USERPROFILE\.beamdrop" }
$Asset     = "beamdrop-windows-amd64.exe"
$Url       = "https://github.com/$Repo/releases/latest/download/$Asset"
$Target    = Join-Path $InstallDir "beamdrop.exe"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "Downloading $Asset ..."
Invoke-WebRequest -Uri $Url -OutFile $Target -UseBasicParsing

Write-Host "Installed: $Target"

# Add to user PATH if missing
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not ($userPath -split ";" | Where-Object { $_ -eq $InstallDir })) {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
    Write-Host ""
    Write-Host "Added $InstallDir to your User PATH."
    Write-Host "Open a NEW terminal to pick it up."
}

Write-Host ""
Write-Host "Try:"
Write-Host "  beamdrop send <file>"
Write-Host "  beamdrop recv <share-url-or-room-id>"
