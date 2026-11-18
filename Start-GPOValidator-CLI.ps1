#Requires -Version 5.1
<#
.SYNOPSIS
    Interactive CLI launcher for GPO Drive Mapping Validator (Server-friendly)

.DESCRIPTION
    Provides a text-based menu interface for running GPO validations.
    Works on all Windows versions including Server Core.
    
.NOTES
    This is the recommended launcher for Windows Server environments.
#>

$ErrorActionPreference = 'Stop'
$script:BackendScript = Join-Path $PSScriptRoot "Test-GpoDriveMapTargeting.ps1"

function Show-Banner {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "       GPO Drive Mapping Validator - CLI Interface         " -ForegroundColor Cyan  
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
}

function Test-Prerequisites {
    Write-Host "Checking prerequisites..." -ForegroundColor Yellow
    Write-Host ""
    
    $issues = @()
    
    # Check backend script
    if (-not (Test-Path $script:BackendScript)) {
        $issues += "Backend script not found: $script:BackendScript"
    } else {
        Write-Host "✓ Backend script found" -ForegroundColor Green
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        Write-Host "✓ PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Green
    } else {
        $issues += "PowerShell 5.1+ required (current: $($PSVersionTable.PSVersion))"
    }
    
    # Check AD module (soft check)
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Write-Host "✓ ActiveDirectory module available" -ForegroundColor Green
    } else {
        Write-Host "⚠ ActiveDirectory module not found (you can still use simulated users)" -ForegroundColor Yellow
    }
    
    # Check GP module (soft check)
    if (Get-Module -ListAvailable -Name GroupPolicy) {
        Write-Host "✓ GroupPolicy module available" -ForegroundColor Green
    } else {
        Write-Host "⚠ GroupPolicy module not found (you can use -DrivesXmlPath instead)" -ForegroundColor Yellow
    }
    
    Write-Host ""
    
    if ($issues.Count -gt 0) {
        Write-Host "❌ Critical issues found:" -ForegroundColor Red
        foreach ($issue in $issues) {
            Write-Host "   $issue" -ForegroundColor Red
        }
        return $false
    }
    
    return $true
}

function Get-UserInput {
    param(
        [string]$Prompt,
        [string]$Default = ""
    )
    
    if ($Default) {
        $input = Read-Host "$Prompt [$Default]"
        if ([string]::IsNullOrWhiteSpace($input)) {
            return $Default
        }
        return $input
    }
    else {
        return Read-Host $Prompt
    }
}

function Invoke-QuickValidation {
    Write-Host ""
    Write-Host "═══ Quick Validation ═══" -ForegroundColor Cyan
    Write-Host ""
    
    # Get domain
    $domain = $env:USERDNSDOMAIN
    if ($domain) {
        Write-Host "Auto-detected domain: $domain" -ForegroundColor Green
        $customDomain = Get-UserInput "Use different domain? (leave blank to use detected)" ""
        if ($customDomain) { $domain = $customDomain }
    } else {
        $domain = Get-UserInput "Enter domain FQDN (e.g., corp.contoso.com)"
    }
    
    if (-not $domain) {
        Write-Host "Domain is required. Aborting." -ForegroundColor Red
        return
    }
    
    # Get GPO name
    Write-Host ""
    $gpoName = Get-UserInput "Enter GPO name"
    
    if (-not $gpoName) {
        Write-Host "GPO name is required. Aborting." -ForegroundColor Red
        return
    }
    
    # Get target users
    Write-Host ""
    Write-Host "Enter test users (comma-separated, e.g., alice,bob,charlie):"
    $usersInput = Read-Host "Users"
    
    if (-not $usersInput) {
        Write-Host "At least one user is required. Aborting." -ForegroundColor Red
        return
    }
    
    $users = $usersInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    
    # Show filter trace?
    Write-Host ""
    $showTrace = Get-UserInput "Show detailed filter trace? (Y/N)" "N"
    
    # Export CSV?
    Write-Host ""
    $exportCsv = Get-UserInput "Export to CSV? (Y/N)" "N"
    $csvPath = $null
    if ($exportCsv -eq 'Y' -or $exportCsv -eq 'y') {
        $csvPath = Get-UserInput "CSV file path" "C:\GPO-Validation-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    }
    
    # Build command
    Write-Host ""
    Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Running validation..." -ForegroundColor Cyan
    Write-Host "  GPO: $gpoName" -ForegroundColor Gray
    Write-Host "  Domain: $domain" -ForegroundColor Gray
    Write-Host "  Users: $($users -join ', ')" -ForegroundColor Gray
    Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    $params = @{
        GpoName = $gpoName
        Domain = $domain
        TargetUsers = $users
    }
    
    if ($showTrace -eq 'Y' -or $showTrace -eq 'y') {
        $params.ShowFilterTrace = $true
    }
    
    if ($csvPath) {
        $params.ExportCsvPath = $csvPath
    }
    
    try {
        & $script:BackendScript @params
        
        Write-Host ""
        Write-Host "✓ Validation complete!" -ForegroundColor Green
        
        if ($csvPath) {
            Write-Host "  Results exported to: $csvPath" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host ""
        Write-Host "✗ Validation failed:" -ForegroundColor Red
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-OUValidation {
    Write-Host ""
    Write-Host "═══ Validate Entire OU ═══" -ForegroundColor Cyan
    Write-Host ""
    
    # Get domain
    $domain = $env:USERDNSDOMAIN
    if ($domain) {
        Write-Host "Auto-detected domain: $domain" -ForegroundColor Green
        $customDomain = Get-UserInput "Use different domain? (leave blank to use detected)" ""
        if ($customDomain) { $domain = $customDomain }
    } else {
        $domain = Get-UserInput "Enter domain FQDN (e.g., corp.contoso.com)"
    }
    
    if (-not $domain) {
        Write-Host "Domain is required. Aborting." -ForegroundColor Red
        return
    }
    
    # Get GPO name
    Write-Host ""
    $gpoName = Get-UserInput "Enter GPO name"
    
    if (-not $gpoName) {
        Write-Host "GPO name is required. Aborting." -ForegroundColor Red
        return
    }
    
    # Get OU DN
    Write-Host ""
    Write-Host "Enter OU Distinguished Name (e.g., OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com):"
    $ouDN = Read-Host "OU DN"
    
    if (-not $ouDN) {
        Write-Host "OU DN is required. Aborting." -ForegroundColor Red
        return
    }
    
    # Export CSV (recommended for OU validation)
    Write-Host ""
    $csvPath = Get-UserInput "CSV export path (recommended)" "C:\GPO-Validation-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    
    # Build command
    Write-Host ""
    Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Running OU validation..." -ForegroundColor Cyan
    Write-Host "  GPO: $gpoName" -ForegroundColor Gray
    Write-Host "  Domain: $domain" -ForegroundColor Gray
    Write-Host "  OU: $ouDN" -ForegroundColor Gray
    Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This may take a while for large OUs..." -ForegroundColor Yellow
    Write-Host ""
    
    $params = @{
        GpoName = $gpoName
        Domain = $domain
        TargetOU = $ouDN
    }
    
    if ($csvPath) {
        $params.ExportCsvPath = $csvPath
    }
    
    try {
        & $script:BackendScript @params
        
        Write-Host ""
        Write-Host "✓ Validation complete!" -ForegroundColor Green
        
        if ($csvPath) {
            Write-Host "  Results exported to: $csvPath" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host ""
        Write-Host "✗ Validation failed:" -ForegroundColor Red
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Show-Help {
    Write-Host ""
    Write-Host "═══ Quick Help ═══" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "BASIC USAGE:" -ForegroundColor Yellow
    Write-Host "  Use the menu to run validations interactively" -ForegroundColor Gray
    Write-Host ""
    Write-Host "DIRECT CLI USAGE:" -ForegroundColor Yellow
    Write-Host "  .\Test-GpoDriveMapTargeting.ps1 -GpoName `"GPO Name`" -TargetUsers alice,bob" -ForegroundColor White
    Write-Host ""
    Write-Host "COMMON PARAMETERS:" -ForegroundColor Yellow
    Write-Host "  -GpoName              GPO display name" -ForegroundColor Gray
    Write-Host "  -Domain               Domain FQDN (auto-detected if omitted)" -ForegroundColor Gray
    Write-Host "  -TargetUsers          Comma-separated usernames" -ForegroundColor Gray
    Write-Host "  -TargetOU             OU Distinguished Name (tests all users in OU)" -ForegroundColor Gray
    Write-Host "  -DrivesXmlPath        Direct path to Drives.xml (instead of GPO name)" -ForegroundColor Gray
    Write-Host "  -ShowFilterTrace      Show step-by-step filter evaluation" -ForegroundColor Gray
    Write-Host "  -ExportCsvPath        Export results to CSV" -ForegroundColor Gray
    Write-Host ""
    Write-Host "EXAMPLES:" -ForegroundColor Yellow
    Write-Host "  See EXAMPLES.md for 13 detailed usage examples" -ForegroundColor Gray
    Write-Host ""
    Write-Host "DOCUMENTATION:" -ForegroundColor Yellow
    Write-Host "  README.md                          Quick start and overview" -ForegroundColor Gray
    Write-Host "  GPO-DRIVEMAP-VALIDATOR-USERGUIDE.md   Detailed user guide" -ForegroundColor Gray
    Write-Host "  EXAMPLES.md                        Practical examples" -ForegroundColor Gray
    Write-Host ""
}

# ═══════════════════════════════════════════════════════════════════
# Main Menu
# ═══════════════════════════════════════════════════════════════════

Show-Banner

# Check prerequisites
if (-not (Test-Prerequisites)) {
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Main loop
$continue = $true
while ($continue) {
    Write-Host ""
    Write-Host "═══ Main Menu ═══" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Quick Validation (specific users)" -ForegroundColor White
    Write-Host "  [2] Validate Entire OU" -ForegroundColor White
    Write-Host "  [3] Show Help / CLI Usage" -ForegroundColor White
    Write-Host "  [4] Open Documentation Folder" -ForegroundColor White
    Write-Host "  [5] Try GUI (if supported)" -ForegroundColor White
    Write-Host "  [Q] Quit" -ForegroundColor White
    Write-Host ""
    
    $choice = Read-Host "Select option"
    
    switch ($choice.ToUpper()) {
        "1" {
            Invoke-QuickValidation
            Write-Host ""
            Read-Host "Press Enter to continue"
        }
        
        "2" {
            Invoke-OUValidation
            Write-Host ""
            Read-Host "Press Enter to continue"
        }
        
        "3" {
            Show-Help
            Write-Host ""
            Read-Host "Press Enter to continue"
        }
        
        "4" {
            $docsPath = $PSScriptRoot
            if (Test-Path $docsPath) {
                Start-Process explorer.exe $docsPath
                Write-Host "Opened: $docsPath" -ForegroundColor Green
            } else {
                Write-Host "Documentation folder not found" -ForegroundColor Red
            }
            Write-Host ""
            Read-Host "Press Enter to continue"
        }
        
        "5" {
            Write-Host ""
            Write-Host "Attempting to launch GUI..." -ForegroundColor Cyan
            Write-Host "Note: This may not work on Server Core or remote sessions" -ForegroundColor Yellow
            Write-Host ""
            
            $guiScript = Join-Path $PSScriptRoot "GPO-DriveMap-Validator-GUI.ps1"
            if (Test-Path $guiScript) {
                try {
                    & $guiScript
                }
                catch {
                    Write-Host ""
                    Write-Host "✗ GUI failed to launch:" -ForegroundColor Red
                    Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
                    Write-Host ""
                    Write-Host "Use the CLI options instead (options 1-2)" -ForegroundColor Cyan
                }
            } else {
                Write-Host "GUI script not found: $guiScript" -ForegroundColor Red
            }
            Write-Host ""
            Read-Host "Press Enter to continue"
        }
        
        "Q" {
            $continue = $false
        }
        
        default {
            Write-Host "Invalid option. Please try again." -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "Thank you for using GPO Drive Mapping Validator!" -ForegroundColor Green
Write-Host ""
