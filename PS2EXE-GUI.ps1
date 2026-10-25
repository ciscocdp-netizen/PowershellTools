#Requires -Version 5.1
<#
.SYNOPSIS
    PS2EXE Studio - interactive GUI for compiling PowerShell scripts to standalone executables.

.DESCRIPTION
    Fully interactive WinForms front end for Invoke-ps2exe. Covers every compiler switch from
    PS2EXE 0.5.0.31+ (including later 0.5.0.34 additions -conHost and -embedFiles):

      files, architecture, apartment, culture, application type, I/O, manifests, metadata,
      embedded resources, live validation, command preview, compile profiles, and a captured log.

    The bundled engine is the PS2EXE compiler by Ingo Karstein and Markus Scholtes (Ms-PL).

.PARAMETER InputFile
    Optional script path to load on startup.
.PARAMETER ProfilePath
    Optional compile profile (.json) to restore on startup.
.PARAMETER NoGui
    Dot-source mode for tests. Loads the shared core and exits without showing a window.
.PARAMETER CommandLineOnly
    Print the Invoke-ps2exe command for the current / supplied options and exit.

.EXAMPLE
    .\PS2EXE-GUI.ps1
.EXAMPLE
    .\PS2EXE-GUI.ps1 -InputFile C:\Tools\Backup.ps1
.NOTES
    Version: 1.0.0
    Requires: Windows PowerShell 5.1+ or PowerShell 7+ on Windows
    Engine:   bundled ps2exe/Invoke-ps2exe.ps1 (PS2EXE-GUI v0.5.0.34)
#>

[CmdletBinding()]
param(
    [string]$InputFile,
    [string]$ProfilePath,
    [switch]$NoGui,
    [switch]$CommandLineOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:StudioRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $script:StudioRoot 'ps2exe\PS2EXE-StudioCore.ps1')

if ($NoGui) {
    return
}

function Test-PS2EXEIsWindows {
    if ($PSVersionTable.PSObject.Properties.Name -contains 'Platform') {
        return $PSVersionTable.Platform -eq 'Win32NT'
    }
    return $true
}

function Test-PS2EXEIsSTA {
    try {
        return [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
    }
    catch {
        return $true
    }
}

if (-not $CommandLineOnly -and (Test-PS2EXEIsWindows) -and -not (Test-PS2EXEIsSTA)) {
    $hostExe = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh' } else { 'powershell.exe' }
    $argList = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    if ($InputFile) { $argList += @('-InputFile', $InputFile) }
    if ($ProfilePath) { $argList += @('-ProfilePath', $ProfilePath) }
    & $hostExe @argList
    exit $LASTEXITCODE
}

function Import-PS2EXEEngine {
    if (Get-Command -Name Invoke-ps2exe -ErrorAction SilentlyContinue) {
        return $true
    }
    $engine = Join-Path $script:StudioRoot 'ps2exe\Invoke-ps2exe.ps1'
    if (Test-Path -LiteralPath $engine) {
        . $engine
        return [bool](Get-Command -Name Invoke-ps2exe -ErrorAction SilentlyContinue)
    }
    try {
        Import-Module ps2exe -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

# ------------------------------------------------------------
# Command-line only mode (no window)
# ------------------------------------------------------------
if ($CommandLineOnly) {
    $options = New-PS2EXEOptions
    if ($ProfilePath) { $options = Import-PS2EXEProfile -Path $ProfilePath }
    if ($InputFile) { $options.inputFile = $InputFile }
    Write-Output (New-PS2EXECommandLine -Options $options)
    $issues = Test-PS2EXEOptions -Options $options
    foreach ($issue in $issues) {
        Write-Output ('[{0}] {1}' -f $issue.Severity, $issue.Message)
    }
    if (-not (Test-PS2EXEReady -Issues $issues)) { exit 2 }
    exit 0
}

if (-not (Test-PS2EXEIsWindows)) {
    Write-Error "PS2EXE Studio's windowed UI requires Windows. Use -CommandLineOnly or -NoGui on this platform."
    exit 1
}

$uiPath = Join-Path $script:StudioRoot 'ps2exe\PS2EXE-StudioUI.ps1'
if (-not (Test-Path -LiteralPath $uiPath)) {
    Write-Error "UI script not found: $uiPath"
    exit 1
}
. $uiPath
