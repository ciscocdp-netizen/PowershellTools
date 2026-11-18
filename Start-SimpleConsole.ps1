#Requires -Version 5.1
<#
.SYNOPSIS
    Simple console-based validator with colored output (no GUI needed)

.DESCRIPTION
    Provides an easy-to-use console interface with prompts and colored output.
    Works everywhere - no GUI, no browser, no WPF, nothing fancy.
    Just PowerShell and color output.
#>

$ErrorActionPreference = 'Stop'
$BackendScript = Join-Path $PSScriptRoot "Test-GpoDriveMapTargeting.ps1"

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                           ║" -ForegroundColor Cyan
    Write-Host "║        GPO Drive Mapping Validator                        ║" -ForegroundColor Cyan
    Write-Host "║        Simple Console Edition                             ║" -ForegroundColor Cyan
    Write-Host "║                                                           ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Get-Input {
    param(
        [string]$Prompt,
        [string]$Default = "",
        [switch]$Required
    )
    
    $displayPrompt = if ($Default) {
        "$Prompt [$Default]"
    } else {
        "$Prompt"
    }
    
    do {
        $input = Read-Host $displayPrompt
        
        if ([string]::IsNullOrWhiteSpace($input) -and $Default) {
            return $Default
        }
        
        if ([string]::IsNullOrWhiteSpace($input) -and $Required) {
            Write-Host "  ⚠ This field is required!" -ForegroundColor Yellow
            continue
        }
        
        return $input
    } while ($Required)
    
    return $input
}

function Show-Menu {
    Write-Host ""
    Write-Host "What would you like to do?" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Quick Validation (test specific users)" -ForegroundColor White
    Write-Host "  [2] Validate Entire OU" -ForegroundColor White
    Write-Host "  [3] Help / Examples" -ForegroundColor White
    Write-Host "  [Q] Quit" -ForegroundColor White
    Write-Host ""
}

function Invoke-QuickValidation {
    Write-Banner
    Write-Host "Quick Validation - Test Specific Users" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Get domain
    $domain = $env:USERDNSDOMAIN
    if ($domain) {
        Write-Host "Auto-detected domain: $domain" -ForegroundColor Green
        $customDomain = Get-Input "Use different domain? (press Enter to use detected)" ""
        if ($customDomain) { $domain = $customDomain }
    } else {
        $domain = Get-Input "Enter domain FQDN (e.g., corp.contoso.com)" "" -Required
    }
    
    # Get GPO name
    Write-Host ""
    $gpoName = Get-Input "Enter GPO name" "" -Required
    
    # Get users
    Write-Host ""
    Write-Host "Enter usernames to test (comma-separated):" -ForegroundColor White
    Write-Host "Example: alice, bob, charlie" -ForegroundColor Gray
    $usersInput = Get-Input "Users" "" -Required
    $users = $usersInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    
    # Show trace?
    Write-Host ""
    $showTrace = (Get-Input "Show detailed filter trace? (y/N)" "N").ToLower() -eq 'y'
    
    # Export?
    Write-Host ""
    $export = (Get-Input "Export to CSV? (y/N)" "N").ToLower() -eq 'y'
    $csvPath = $null
    if ($export) {
        $defaultPath = "GPO-Validation-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        $csvPath = Get-Input "CSV file path" $defaultPath
    }
    
    # Confirm
    Write-Host ""
    Write-Host "═══════════════════════════════════════" -ForegroundColor Yellow
    Write-Host "Ready to validate:" -ForegroundColor Yellow
    Write-Host "  Domain:  $domain" -ForegroundColor White
    Write-Host "  GPO:     $gpoName" -ForegroundColor White
    Write-Host "  Users:   $($users -join ', ')" -ForegroundColor White
    Write-Host "  Trace:   $showTrace" -ForegroundColor White
    if ($csvPath) {
        Write-Host "  Export:  $csvPath" -ForegroundColor White
    }
    Write-Host "═══════════════════════════════════════" -ForegroundColor Yellow
    Write-Host ""
    
    $confirm = Get-Input "Proceed? (Y/n)" "Y"
    if ($confirm.ToLower() -eq 'n') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }
    
    # Build parameters
    $params = @{
        GpoName = $gpoName
        Domain = $domain
        TargetUsers = $users
    }
    
    if ($showTrace) { $params.ShowFilterTrace = $true }
    if ($csvPath) { $params.ExportCsvPath = $csvPath }
    
    # Execute
    Write-Host ""
    Write-Host "Running validation..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    
    try {
        & $BackendScript @params
        
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "✓ Validation completed successfully!" -ForegroundColor Green
        
        if ($csvPath) {
            Write-Host "✓ Results exported to: $csvPath" -ForegroundColor Green
        }
    }
    catch {
        Write-Host ""
        Write-Host "✗ Validation failed!" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-OUValidation {
    Write-Banner
    Write-Host "OU Validation - Test All Users in OU" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Get domain
    $domain = $env:USERDNSDOMAIN
    if ($domain) {
        Write-Host "Auto-detected domain: $domain" -ForegroundColor Green
        $customDomain = Get-Input "Use different domain? (press Enter to use detected)" ""
        if ($customDomain) { $domain = $customDomain }
    } else {
        $domain = Get-Input "Enter domain FQDN (e.g., corp.contoso.com)" "" -Required
    }
    
    # Get GPO name
    Write-Host ""
    $gpoName = Get-Input "Enter GPO name" "" -Required
    
    # Get OU
    Write-Host ""
    Write-Host "Enter OU Distinguished Name:" -ForegroundColor White
    Write-Host "Example: OU=Finance,OU=Users,DC=corp,DC=contoso,DC=com" -ForegroundColor Gray
    $ouDN = Get-Input "OU DN" "" -Required
    
    # Export (recommended for OUs)
    Write-Host ""
    Write-Host "CSV export is recommended for OU validations (can be large)" -ForegroundColor Yellow
    $defaultPath = "GPO-Validation-OU-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    $csvPath = Get-Input "CSV file path (or blank to skip)" $defaultPath
    
    # Confirm
    Write-Host ""
    Write-Host "═══════════════════════════════════════" -ForegroundColor Yellow
    Write-Host "Ready to validate:" -ForegroundColor Yellow
    Write-Host "  Domain:  $domain" -ForegroundColor White
    Write-Host "  GPO:     $gpoName" -ForegroundColor White
    Write-Host "  OU:      $ouDN" -ForegroundColor White
    if ($csvPath) {
        Write-Host "  Export:  $csvPath" -ForegroundColor White
    }
    Write-Host "═══════════════════════════════════════" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "⚠ This may take a while for large OUs..." -ForegroundColor Yellow
    Write-Host ""
    
    $confirm = Get-Input "Proceed? (Y/n)" "Y"
    if ($confirm.ToLower() -eq 'n') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }
    
    # Build parameters
    $params = @{
        GpoName = $gpoName
        Domain = $domain
        TargetOU = $ouDN
    }
    
    if ($csvPath) { $params.ExportCsvPath = $csvPath }
    
    # Execute
    Write-Host ""
    Write-Host "Running validation..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    
    try {
        & $BackendScript @params
        
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "✓ Validation completed successfully!" -ForegroundColor Green
        
        if ($csvPath) {
            Write-Host "✓ Results exported to: $csvPath" -ForegroundColor Green
        }
    }
    catch {
        Write-Host ""
        Write-Host "✗ Validation failed!" -ForegroundColor Red
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Show-Help {
    Write-Banner
    Write-Host "Help & Examples" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "BASIC USAGE:" -ForegroundColor Yellow
    Write-Host "  Just follow the prompts in the menu!" -ForegroundColor White
    Write-Host ""
    
    Write-Host "DIRECT COMMAND LINE:" -ForegroundColor Yellow
    Write-Host "  .\Test-GpoDriveMapTargeting.ps1 -GpoName `"Your GPO`" -TargetUsers alice,bob" -ForegroundColor White
    Write-Host ""
    
    Write-Host "COMMON EXAMPLES:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Test specific users:" -ForegroundColor Cyan
    Write-Host "    .\Test-GpoDriveMapTargeting.ps1 -GpoName `"Corporate Drives`" -TargetUsers alice,bob,charlie" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Test entire OU:" -ForegroundColor Cyan
    Write-Host "    .\Test-GpoDriveMapTargeting.ps1 -GpoName `"Corporate Drives`" -TargetOU `"OU=Finance,DC=...`"" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Show debug trace:" -ForegroundColor Cyan
    Write-Host "    .\Test-GpoDriveMapTargeting.ps1 -GpoName `"Corporate Drives`" -TargetUsers alice -ShowFilterTrace" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Export to CSV:" -ForegroundColor Cyan
    Write-Host "    .\Test-GpoDriveMapTargeting.ps1 -GpoName `"Corporate Drives`" -TargetUsers alice -ExportCsvPath C:\report.csv" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "DOCUMENTATION:" -ForegroundColor Yellow
    Write-Host "  EXAMPLES.md                        - 13 detailed examples" -ForegroundColor White
    Write-Host "  GPO-DRIVEMAP-VALIDATOR-USERGUIDE.md  - Complete guide" -ForegroundColor White
    Write-Host "  README.md                          - Quick start" -ForegroundColor White
    Write-Host ""
}

# ═══════════════════════════════════════════════════════════════════
# Main Program
# ═══════════════════════════════════════════════════════════════════

# Check backend script
if (-not (Test-Path $BackendScript)) {
    Write-Host ""
    Write-Host "✗ Error: Backend script not found!" -ForegroundColor Red
    Write-Host "  Expected: $BackendScript" -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Main loop
$continue = $true
while ($continue) {
    Write-Banner
    Show-Menu
    
    $choice = (Read-Host "Select option").ToUpper()
    
    switch ($choice) {
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
        
        "Q" {
            $continue = $false
        }
        
        default {
            Write-Host ""
            Write-Host "Invalid option. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}

Write-Host ""
Write-Host "Thank you for using GPO Drive Mapping Validator!" -ForegroundColor Green
Write-Host ""
