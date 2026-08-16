#Requires -Version 5.1
<#
.SYNOPSIS
    DHCP Manager - Production-Ready WPF GUI for Managing Windows DHCP Server
.DESCRIPTION
    Complete DHCP management tool with full visibility and robust error handling.
.NOTES
    Version: 2.0 (Production Ready with All Fixes)
    Date: 2026-08-16
    Compatible with: PowerShell 5.1+ and Windows Server 2016-2022 DHCP
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "This script requires PowerShell 5.1 or later."
    exit 1
}

try {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms, System.Drawing -ErrorAction Stop
} catch {
    Write-Error "Failed to load required .NET assemblies: $_"
    exit 1
}

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  DHCP Manager v2.0 - Production Ready" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────────────────────
#  GLOBAL STATE
# ─────────────────────────────────────────────────────────────────────────────
$Global:DHCPServer    = $null
$Global:SelectedScope = $null
$Global:ActionLog     = [System.Collections.Generic.List[string]]::new()

# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
function Write-ActionLog {
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'HH:mm:ss.fff'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    try {
        $Global:ActionLog.Add($logEntry)
        if ($Global:ActionLog.Count -gt 1000) {
            $Global:ActionLog.RemoveAt(0)
        }
    } catch {}
    
    $color = switch ($Level) {
        'SUCCESS' { 'Green' }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        default   { 'Cyan' }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Update-LogDisplay {
    if ($null -eq $script:TxtLog) { return }
    
    try {
        $script:TxtLog.Dispatcher.Invoke([action]{
            $script:TxtLog.Text = ($Global:ActionLog | Select-Object -Last 500) -join "`r`n"
            if ($null -ne $script:LogScrollViewer) {
                $script:LogScrollViewer.ScrollToEnd()
            }
        }, [System.Windows.Threading.DispatcherPriority]::Background)
    } catch {}
}

Write-ActionLog "Application starting..." "INFO"

