#!/usr/bin/env bash
# Idempotent Cloud Agent bootstrap for the PowershellTools repository.
# Ensures PowerShell 7 (pwsh) plus the PSScriptAnalyzer (lint) and Pester
# (test) modules are available so the scripts can be linted and self-tested.
set -euo pipefail

install_powershell() {
    if command -v pwsh >/dev/null 2>&1; then
        echo "pwsh already installed: $(pwsh --version)"
        return
    fi

    echo "Installing PowerShell 7..."
    source /etc/os-release
    sudo apt-get update -y
    sudo apt-get install -y wget apt-transport-https software-properties-common ca-certificates
    local deb="/tmp/packages-microsoft-prod.deb"
    wget -q "https://packages.microsoft.com/config/ubuntu/${VERSION_ID}/packages-microsoft-prod.deb" -O "$deb"
    sudo dpkg -i "$deb"
    sudo apt-get update -y
    sudo apt-get install -y powershell
    echo "Installed: $(pwsh --version)"
}

install_ps_modules() {
    echo "Ensuring PowerShell dev modules (PSScriptAnalyzer, Pester)..."
    pwsh -NoProfile -Command '
        $ProgressPreference = "SilentlyContinue"
        if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne "Trusted") {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }
        foreach ($m in "PSScriptAnalyzer", "Pester") {
            if (-not (Get-Module -ListAvailable -Name $m)) {
                Write-Host "Installing $m..."
                Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
            } else {
                Write-Host "$m already available."
            }
        }
        Get-Module -ListAvailable PSScriptAnalyzer, Pester |
            Select-Object Name, Version | Format-Table -AutoSize | Out-String | Write-Host
    '
}

install_powershell
install_ps_modules

echo "Cloud Agent environment ready."
