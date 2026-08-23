#!/usr/bin/env bash
# Idempotent Cloud Agent setup for the PowershellTools repository.
# Installs PowerShell 7 (pwsh) and the PSScriptAnalyzer linter so the
# DHCP Manager PowerShell scripts can be parsed, linted, and run.
set -euo pipefail

echo "==> PowershellTools environment setup"

# --- PowerShell 7 (pwsh) ---------------------------------------------------
if command -v pwsh >/dev/null 2>&1; then
  echo "==> pwsh already installed: $(pwsh --version)"
else
  echo "==> Installing PowerShell 7 from the Microsoft package repository"
  source /etc/os-release
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends wget apt-transport-https ca-certificates

  tmp_deb="$(mktemp --suffix=.deb)"
  wget -q "https://packages.microsoft.com/config/ubuntu/${VERSION_ID}/packages-microsoft-prod.deb" -O "$tmp_deb"
  sudo dpkg -i "$tmp_deb"
  rm -f "$tmp_deb"

  sudo apt-get update
  sudo apt-get install -y powershell
  echo "==> Installed $(pwsh --version)"
fi

# --- PSScriptAnalyzer (PowerShell linter) ----------------------------------
echo "==> Ensuring PSScriptAnalyzer module is available"
pwsh -NoProfile -NonInteractive -Command '
  $ErrorActionPreference = "Stop"
  if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {
    $v = (Get-Module -ListAvailable -Name PSScriptAnalyzer | Select-Object -First 1).Version
    Write-Host "==> PSScriptAnalyzer already installed: $v"
  } else {
    Write-Host "==> Installing PSScriptAnalyzer for current user"
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -AcceptLicense
    $v = (Get-Module -ListAvailable -Name PSScriptAnalyzer | Select-Object -First 1).Version
    Write-Host "==> Installed PSScriptAnalyzer $v"
  }
'

echo "==> Setup complete"
