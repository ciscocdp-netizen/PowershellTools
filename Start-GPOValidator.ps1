# Quick Start Script for GPO Drive Mapping Validator

Write-Host @"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║        GPO Drive Mapping Validator - Quick Start              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Host ""

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow

$issues = @()

# PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    $issues += "PowerShell 5.1 or later required (current: $($PSVersionTable.PSVersion))"
}
else {
    Write-Host "✓ PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Green
}

# ActiveDirectory module
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Write-Host "✓ ActiveDirectory module installed" -ForegroundColor Green
}
else {
    $issues += "ActiveDirectory module not found (install RSAT)"
}

# GroupPolicy module
if (Get-Module -ListAvailable -Name GroupPolicy) {
    Write-Host "✓ GroupPolicy module installed" -ForegroundColor Green
}
else {
    $issues += "GroupPolicy module not found (install RSAT)"
}

# Check for script files
$backendScript = Join-Path $PSScriptRoot "Test-GpoDriveMapTargeting.ps1"
$guiScript = Join-Path $PSScriptRoot "GPO-DriveMap-Validator-GUI.ps1"

if (Test-Path $backendScript) {
    Write-Host "✓ Backend validation script found" -ForegroundColor Green
}
else {
    $issues += "Backend script not found: $backendScript"
}

if (Test-Path $guiScript) {
    Write-Host "✓ GUI script found" -ForegroundColor Green
}
else {
    $issues += "GUI script not found: $guiScript"
}

Write-Host ""

# Report issues
if ($issues.Count -gt 0) {
    Write-Host "⚠ Issues detected:" -ForegroundColor Red
    foreach ($issue in $issues) {
        Write-Host "  - $issue" -ForegroundColor Red
    }
    Write-Host ""
    
    # Offer to install RSAT
    if ($issues -like "*RSAT*") {
        Write-Host "Would you like to install RSAT modules now? (requires admin rights)" -ForegroundColor Yellow
        $response = Read-Host "[Y/N]"
        
        if ($response -eq 'Y' -or $response -eq 'y') {
            Write-Host "Installing RSAT modules..." -ForegroundColor Cyan
            
            try {
                # Check if running as admin
                $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                
                if (-not $isAdmin) {
                    Write-Host "ERROR: Admin rights required. Please restart PowerShell as Administrator." -ForegroundColor Red
                }
                else {
                    Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
                    Add-WindowsCapability -Online -Name "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
                    Write-Host "✓ RSAT modules installed successfully" -ForegroundColor Green
                    $issues = $issues | Where-Object { $_ -notlike "*RSAT*" }
                }
            }
            catch {
                Write-Host "ERROR: RSAT installation failed: $_" -ForegroundColor Red
            }
        }
    }
    
    if ($issues.Count -gt 0) {
        Write-Host ""
        Write-Host "Please resolve the issues above before continuing." -ForegroundColor Yellow
        Read-Host "Press Enter to exit"
        exit
    }
}

# All good - show options
Write-Host "All prerequisites met! Choose an option:" -ForegroundColor Green
Write-Host ""
Write-Host "  [1] Launch GUI (recommended for first-time users)" -ForegroundColor Cyan
Write-Host "  [2] Quick CLI validation example" -ForegroundColor Cyan
Write-Host "  [3] View documentation" -ForegroundColor Cyan
Write-Host "  [4] Run demo with simulated users" -ForegroundColor Cyan
Write-Host "  [5] Exit" -ForegroundColor Cyan
Write-Host ""

$choice = Read-Host "Enter choice (1-5)"

switch ($choice) {
    "1" {
        Write-Host ""
        Write-Host "Launching GUI..." -ForegroundColor Cyan
        & $guiScript
    }
    
    "2" {
        Write-Host ""
        Write-Host "Quick CLI Example:" -ForegroundColor Yellow
        Write-Host ""
        
        # Get domain
        $domain = $env:USERDNSDOMAIN
        if (-not $domain) {
            Write-Host "Enter your domain FQDN (e.g., corp.contoso.com):" -ForegroundColor Cyan
            $domain = Read-Host
        }
        else {
            Write-Host "Detected domain: $domain" -ForegroundColor Green
        }
        
        # Get GPO name
        Write-Host ""
        Write-Host "Enter GPO name (or press Enter to browse):" -ForegroundColor Cyan
        $gpoName = Read-Host
        
        if (-not $gpoName) {
            Write-Host "Loading GPOs..." -ForegroundColor Cyan
            try {
                Import-Module GroupPolicy
                $gpos = Get-GPO -All -Domain $domain | Select-Object DisplayName | Sort-Object DisplayName
                Write-Host ""
                Write-Host "Available GPOs:" -ForegroundColor Yellow
                for ($i = 0; $i -lt $gpos.Count -and $i -lt 20; $i++) {
                    Write-Host "  [$($i+1)] $($gpos[$i].DisplayName)"
                }
                if ($gpos.Count -gt 20) {
                    Write-Host "  ... and $($gpos.Count - 20) more"
                }
                Write-Host ""
                $selection = Read-Host "Select GPO number (1-$([Math]::Min(20, $gpos.Count)))"
                $gpoName = $gpos[[int]$selection - 1].DisplayName
            }
            catch {
                Write-Host "ERROR: Failed to load GPOs: $_" -ForegroundColor Red
                Read-Host "Press Enter to exit"
                exit
            }
        }
        
        # Get users
        Write-Host ""
        Write-Host "Enter usernames to test (comma-separated):" -ForegroundColor Cyan
        $users = Read-Host
        
        if (-not $users) {
            Write-Host "No users specified. Exiting." -ForegroundColor Red
            exit
        }
        
        # Run validation
        Write-Host ""
        Write-Host "Running validation..." -ForegroundColor Cyan
        Write-Host ""
        
        $userArray = $users -split ',' | ForEach-Object { $_.Trim() }
        
        & $backendScript -GpoName $gpoName -Domain $domain -TargetUsers $userArray
        
        Write-Host ""
        Read-Host "Press Enter to continue"
    }
    
    "3" {
        Write-Host ""
        Write-Host "Opening documentation..." -ForegroundColor Cyan
        
        $readme = Join-Path $PSScriptRoot "GPO-DRIVEMAP-VALIDATOR-README.md"
        $userGuide = Join-Path $PSScriptRoot "GPO-DRIVEMAP-VALIDATOR-USERGUIDE.md"
        
        if (Test-Path $readme) {
            Start-Process notepad.exe $readme
        }
        if (Test-Path $userGuide) {
            Start-Process notepad.exe $userGuide
        }
    }
    
    "4" {
        Write-Host ""
        Write-Host "Running demo with simulated users..." -ForegroundColor Cyan
        Write-Host ""
        
        # Create example simulated users
        $simulatedUsers = @(
            @{
                Name = "Alice (Finance Employee)"
                DistinguishedName = "CN=Alice Smith,OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com"
                MemberOfGroups = @(
                    "CN=Finance-Users,OU=Groups,DC=corp,DC=contoso,DC=com",
                    "CN=Domain Users,CN=Users,DC=corp,DC=contoso,DC=com"
                )
                ComputerName = "DESKTOP-FIN-01"
                Site = "HQ"
            },
            @{
                Name = "Bob (Finance Contractor)"
                DistinguishedName = "CN=Bob Johnson,OU=Contractors,OU=Users,DC=corp,DC=contoso,DC=com"
                MemberOfGroups = @(
                    "CN=Finance-Users,OU=Groups,DC=corp,DC=contoso,DC=com",
                    "CN=Contractors,OU=Groups,DC=corp,DC=contoso,DC=com",
                    "CN=Domain Users,CN=Users,DC=corp,DC=contoso,DC=com"
                )
                ComputerName = "LAPTOP-CTR-01"
                Site = "Remote"
            },
            @{
                Name = "Charlie (HR Employee)"
                DistinguishedName = "CN=Charlie Brown,OU=HR,OU=Users,DC=corp,DC=contoso,DC=com"
                MemberOfGroups = @(
                    "CN=HR-Users,OU=Groups,DC=corp,DC=contoso,DC=com",
                    "CN=Domain Users,CN=Users,DC=corp,DC=contoso,DC=com"
                )
                ComputerName = "DESKTOP-HR-01"
                Site = "HQ"
            }
        )
        
        Write-Host "Demo Scenario:" -ForegroundColor Yellow
        Write-Host "  - Testing 3 simulated users (Finance employees/contractor, HR employee)"
        Write-Host "  - Using fictional GPO and domain"
        Write-Host "  - This demonstrates the tool without requiring real AD access"
        Write-Host ""
        
        # Create a demo Drives.xml file
        $demoXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">
    <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="H:" status="H:" image="2" changed="2024-01-15 10:00:00" uid="{12345678-1234-1234-1234-123456789001}">
        <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" path="\\fileserver\home\%USERNAME%" label="Home Drive" persistent="1" useLetter="1" letter="H"/>
    </Drive>
    <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="S:" status="S:" image="2" changed="2024-01-15 10:00:00" uid="{12345678-1234-1234-1234-123456789002}">
        <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" path="\\fileserver\shared" label="Shared Drive" persistent="1" useLetter="1" letter="S"/>
    </Drive>
    <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="F:" status="F:" image="2" changed="2024-01-15 10:00:00" uid="{12345678-1234-1234-1234-123456789003}">
        <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" path="\\fileserver\finance" label="Finance Drive" persistent="1" useLetter="1" letter="F"/>
        <Filters>
            <FilterGroup bool="AND" not="0" name="CN=Finance-Users,OU=Groups,DC=corp,DC=contoso,DC=com"/>
            <FilterGroup bool="AND" not="1" name="CN=Contractors,OU=Groups,DC=corp,DC=contoso,DC=com"/>
        </Filters>
    </Drive>
    <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="X:" status="X:" image="2" changed="2024-01-15 10:00:00" uid="{12345678-1234-1234-1234-123456789004}">
        <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" path="\\fileserver\hr" label="HR Drive" persistent="1" useLetter="1" letter="X"/>
        <Filters>
            <FilterGroup bool="AND" not="0" name="CN=HR-Users,OU=Groups,DC=corp,DC=contoso,DC=com"/>
        </Filters>
    </Drive>
</Drives>
"@
        
        $demoXmlPath = "$env:TEMP\Demo-Drives.xml"
        $demoXml | Out-File $demoXmlPath -Encoding UTF8
        
        Write-Host "Running validation..." -ForegroundColor Cyan
        Write-Host ""
        
        & $backendScript -DrivesXmlPath $demoXmlPath -SimulatedUsers $simulatedUsers -ShowFilterTrace
        
        Write-Host ""
        Write-Host "Demo complete!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Expected Results:" -ForegroundColor Yellow
        Write-Host "  - Alice: H:, S:, F: (Finance employee - gets Finance drive)"
        Write-Host "  - Bob: H:, S: (Finance contractor - excluded from Finance drive by NOT Contractors filter)"
        Write-Host "  - Charlie: H:, S:, X: (HR employee - gets HR drive)"
        Write-Host ""
        
        Read-Host "Press Enter to continue"
    }
    
    "5" {
        Write-Host "Exiting..." -ForegroundColor Cyan
        exit
    }
    
    default {
        Write-Host "Invalid choice. Exiting." -ForegroundColor Red
        exit
    }
}

Write-Host ""
Write-Host "Thank you for using GPO Drive Mapping Validator!" -ForegroundColor Green
