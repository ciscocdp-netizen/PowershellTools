#Requires -Version 5.1
<#
.SYNOPSIS
    Headless tests for PS2EXE Studio core: validation, presets, command line, profiles.
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repoRoot 'ps2exe\PS2EXE-StudioCore.ps1')

$script:Pass = 0
$script:Fail = 0
$script:Failures = New-Object System.Collections.Generic.List[string]

function Assert-True {
    param([bool]$Condition, [string]$Name, [string]$Detail = '')
    if ($Condition) {
        $script:Pass++
        Write-Host "  PASS  $Name"
    }
    else {
        $script:Fail++
        $msg = $Name
        if ($Detail) { $msg = "$Name -- $Detail" }
        $script:Failures.Add($msg)
        Write-Host "  FAIL  $msg"
    }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Name)
    $ok = [string]$Expected -eq [string]$Actual
    Assert-True -Condition $ok -Name $Name -Detail "expected '$Expected' got '$Actual'"
}

function Get-Issue {
    param($Issues, [string]$Code)
    @($Issues | Where-Object { $_ }) |
        Where-Object { $_.PSObject.Properties.Name -contains 'Code' -and $_.Code -eq $Code } |
        Select-Object -First 1
}

Write-Host ''
Write-Host 'PS2EXE Studio core tests'
Write-Host '========================'

# --- Version strings ---
Write-Host ''
Write-Host 'Version validation'
Assert-True (Test-PS2EXEVersionString '') 'empty version is valid'
Assert-True (Test-PS2EXEVersionString '1') 'single-digit version'
Assert-True (Test-PS2EXEVersionString '1.2') 'two-part version'
Assert-True (Test-PS2EXEVersionString '1.2.3') 'three-part version'
Assert-True (Test-PS2EXEVersionString '1.2.3.4') 'four-part version'
Assert-True (-not (Test-PS2EXEVersionString '1.2.3.4.5')) 'five-part version rejected'
Assert-True (-not (Test-PS2EXEVersionString 'v1.0')) 'v-prefix rejected'
Assert-True (-not (Test-PS2EXEVersionString '1.0-beta')) 'prerelease rejected'
Assert-True (-not (Test-PS2EXEVersionString 'abc')) 'letters rejected'

# --- Required input ---
Write-Host ''
Write-Host 'Required input and paths'
$opt = New-PS2EXEOptions
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'INPUT_REQUIRED')) 'missing input is an error'

$opt.inputFile = 'C:\Scripts\Backup.ps1'
$opt.outputFile = 'C:\Scripts\Backup.dll'
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'OUTPUT_EXT')) 'non exe/com output is an error'

$opt.outputFile = 'C:\Scripts\Backup.exe'
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True (-not (Get-Issue $issues 'OUTPUT_EXT')) 'exe output is accepted'
Assert-Equal 'C:\Scripts\Backup.exe' (Get-PS2EXEResolvedOutput -Options $opt) 'explicit output is unchanged'

$opt.outputFile = ''
Assert-Equal 'C:\Scripts\Backup.exe' (Get-PS2EXEResolvedOutput -Options $opt) 'blank output defaults to input.exe'

$opt.outputFile = 'C:\Out'
Assert-Equal 'C:\Out\Backup.exe' (Get-PS2EXEResolvedOutput -Options $opt) 'extensionless output treated as folder'

$opt.outputFile = 'C:\Scripts\Backup.ps1'
$opt.inputFile = 'C:\Scripts\Backup.ps1'
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
# SAME_PATH is skipped when SkipFileSystem is set (full-path compare still runs if both set)
# GetFullPath works on Linux too
$same = Get-Issue $issues 'SAME_PATH'
Assert-True ([bool]$same) 'identical input and output is an error'

# --- Conflicts ---
Write-Host ''
Write-Host 'Compiler conflicts'
$opt = New-PS2EXEOptions
$opt.inputFile = '/tmp/demo.ps1'
$opt.noConsole = $true
$opt.conHost = $true
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'CONHOST_GUI')) 'noConsole + conHost is an error'

$opt = New-PS2EXEOptions
$opt.inputFile = '/tmp/demo.ps1'
$opt.requireAdmin = $true
$opt.virtualize = $true
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'ADMIN_VIRT')) 'requireAdmin + virtualize is an error'

$opt = New-PS2EXEOptions
$opt.inputFile = '/tmp/demo.ps1'
$opt.supportOS = $true
$opt.virtualize = $true
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'OS_VIRT')) 'supportOS + virtualize is an error'

$opt = New-PS2EXEOptions
$opt.inputFile = '/tmp/demo.ps1'
$opt.longPaths = $true
$opt.virtualize = $true
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'PATH_VIRT')) 'longPaths + virtualize is an error'

$opt = New-PS2EXEOptions
$opt.inputFile = '/tmp/demo.ps1'
$opt.configFile = $true
$opt.noConfigFile = $true
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'CONFIG_CONFLICT')) 'configFile + noConfigFile is an error'

$opt = New-PS2EXEOptions
$opt.inputFile = '/tmp/demo.ps1'
$opt.longPaths = $true
$opt.noConfigFile = $true
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'LONGPATH_NOCONFIG')) 'longPaths + noConfigFile is an error'

$opt = New-PS2EXEOptions
$opt.inputFile = '/tmp/demo.ps1'
$opt.winFormsDPIAware = $true
$opt.noConfigFile = $true
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'WFDPI_NOCONFIG')) 'winFormsDPIAware + noConfigFile is an error'

$opt = New-PS2EXEOptions
$opt.inputFile = '/tmp/demo.ps1'
$opt.virtualize = $true
$opt.architecture = 'anycpu'
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'VIRT_X86')) 'virtualize on AnyCPU warns about x86'

$opt = New-PS2EXEOptions
$opt.inputFile = '/tmp/demo.ps1'
$opt.longPaths = $true
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'LONGPATH_CONFIG')) 'longPaths without configFile warns'

$opt = New-PS2EXEOptions
$opt.inputFile = '/tmp/demo.ps1'
$opt.winFormsDPIAware = $true
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'WFDPI_CONFIG')) 'winFormsDPIAware without configFile warns'
Assert-True ([bool](Get-Issue $issues 'WFDPI_OS')) 'winFormsDPIAware without supportOS warns'

$opt = New-PS2EXEOptions
$opt.inputFile = '/tmp/demo.ps1'
$opt.noVisualStyles = $true
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'VISUAL_GUI')) 'noVisualStyles without GUI is informational'

$opt = New-PS2EXEOptions
$opt.inputFile = '/tmp/demo.ps1'
$opt.exitOnCancel = $true
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'CANCEL_GUI')) 'exitOnCancel without GUI is informational'

$opt = New-PS2EXEOptions
$opt.inputFile = '/tmp/demo.ps1'
$opt.UNICODEEncoding = $true
$opt.noConsole = $true
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'UNICODE_CONSOLE')) 'UNICODEEncoding with GUI is informational'

$opt = New-PS2EXEOptions
$opt.inputFile = '/tmp/demo.ps1'
$opt.version = 'nope'
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'VERSION')) 'invalid version is an error'
Assert-True (-not (Test-PS2EXEReady -Issues $issues)) 'invalid version blocks compile'

$opt.version = '1.0.0'
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True (Test-PS2EXEReady -Issues $issues) 'valid options with missing files skipped are ready'

# --- Command line ---
Write-Host ''
Write-Host 'Command-line builder'
$opt = New-PS2EXEOptions
$opt.inputFile = 'C:\Data\My Script.ps1'
$opt.outputFile = 'C:\Data\MyScriptGUI.exe'
$opt.iconFile = 'C:\Data\Icon.ico'
$opt.noConsole = $true
$opt.title = "My Script"
$opt.version = '0.0.0.1'
$opt.architecture = 'x64'
$opt.apartment = 'STA'
$opt.lcid = 1033
$cmd = New-PS2EXECommandLine -Options $opt
Assert-True ($cmd -like 'Invoke-ps2exe*') 'command starts with Invoke-ps2exe'
Assert-True ($cmd -match "-inputFile 'C:\\Data\\My Script\.ps1'") 'input path is quoted'
Assert-True ($cmd -match "-outputFile 'C:\\Data\\MyScriptGUI\.exe'") 'output path is present'
Assert-True ($cmd -match "-iconFile 'C:\\Data\\Icon\.ico'") 'icon path is present'
Assert-True ($cmd -match '-noConsole') 'noConsole switch present'
Assert-True ($cmd -match '-x64') 'x64 switch present'
Assert-True ($cmd -notmatch '-x86') 'x86 switch absent for x64'
Assert-True ($cmd -match '-STA') 'STA switch present'
Assert-True ($cmd -match '-lcid 1033') 'lcid emitted as integer'
Assert-True ($cmd -match "-title 'My Script'") 'title quoted'
Assert-True ($cmd -match "-version '0.0.0.1'") 'version quoted'

$opt.verbose = $true
$cmd = New-PS2EXECommandLine -Options $opt
Assert-True ($cmd -match '-Verbose') 'verbose appended'

$opt = New-PS2EXEOptions
$opt.inputFile = '/tmp/a.ps1'
$opt.lcid = 0
$cmd = New-PS2EXECommandLine -Options $opt
Assert-True ($cmd -notmatch '-lcid') 'lcid 0 is omitted'
Assert-True ($cmd -notmatch '-noConsole') 'unset switches omitted'
Assert-True ($cmd -match '-STA') 'default apartment is STA'

$opt.apartment = 'MTA'
$cmd = New-PS2EXECommandLine -Options $opt
Assert-True ($cmd -match '-MTA') 'MTA emitted'
Assert-True ($cmd -notmatch '-STA') 'STA omitted when MTA selected'

$opt.architecture = 'x86'
$cmd = New-PS2EXECommandLine -Options $opt
Assert-True ($cmd -match '-x86') 'x86 emitted'
Assert-True ($cmd -notmatch '-x64') 'x64 omitted when x86 selected'

$opt.title = "O'Brien"
$cmd = New-PS2EXECommandLine -Options $opt
Assert-True ($cmd -match "-title 'O''Brien'") 'single quotes in metadata are escaped'

$opt = New-PS2EXEOptions
$opt.inputFile = '/tmp/a.ps1'
$opt.embedFiles = @(
    [pscustomobject]@{ Source = 'C:\src\config.xml'; Target = '.\assets\config.xml' }
)
$cmd = New-PS2EXECommandLine -Options $opt
Assert-True ($cmd -match '-embedFiles') 'embedFiles switch present'
Assert-True ($cmd -match "'\.\\assets\\config\.xml'='C:\\src\\config\.xml'") 'embedFiles hashtable uses target=source'

$opt.embedFiles = @(
    [pscustomobject]@{ Source = 'C:\src\a.xml'; Target = '.\a.xml' }
    [pscustomobject]@{ Source = 'C:\src\a.json'; Target = '.\b.json' }
)
# same filename a.xml vs a.json - unique
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True (-not (Get-Issue $issues 'EMBED_UNIQUE')) 'distinct source names are allowed'

$opt.embedFiles = @(
    [pscustomobject]@{ Source = 'C:\src\a.xml'; Target = '.\one.xml' }
    [pscustomobject]@{ Source = 'D:\other\a.xml'; Target = '.\two.xml' }
)
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'EMBED_UNIQUE')) 'duplicate source file names are rejected'

$opt.embedFiles = @(
    [pscustomobject]@{ Source = 'C:\src\a.xml'; Target = '' }
)
$issues = Test-PS2EXEOptions -Options $opt -SkipFileSystem
Assert-True ([bool](Get-Issue $issues 'EMBED_PAIR')) 'embed row missing target is an error'

# --- Presets ---
Write-Host ''
Write-Host 'Presets'
$opt = New-PS2EXEOptions
$opt.inputFile = 'C:\Tools\App.ps1'
$opt.title = 'KeepMe'
$gui = Apply-PS2EXEPreset -Options $opt -PresetName 'Windows GUI'
Assert-True $gui.noConsole 'Windows GUI sets noConsole'
Assert-True $gui.exitOnCancel 'Windows GUI sets exitOnCancel'
Assert-Equal 'KeepMe' $gui.title 'preset keeps existing metadata'
Assert-Equal 'C:\Tools\App.ps1' $gui.inputFile 'preset keeps input path'

$admin = Apply-PS2EXEPreset -Options $opt -PresetName 'Admin GUI'
Assert-True $admin.requireAdmin 'Admin GUI requires admin'
Assert-True $admin.DPIAware 'Admin GUI is DPI aware'
Assert-True $admin.supportOS 'Admin GUI sets supportOS'
Assert-True (-not $admin.virtualize) 'Admin GUI clears virtualize'

$virt = Apply-PS2EXEPreset -Options $opt -PresetName 'x86 virtualized'
Assert-Equal 'x86' $virt.architecture 'virtualized preset forces x86'
Assert-True $virt.virtualize 'virtualized preset sets virtualize'
Assert-True (-not $virt.requireAdmin) 'virtualized preset clears requireAdmin'
Assert-True (-not $virt.longPaths) 'virtualized preset clears longPaths'

$dpi = Apply-PS2EXEPreset -Options $opt -PresetName 'High-DPI WinForms'
Assert-True $dpi.winFormsDPIAware 'high-dpi preset sets winFormsDPIAware'
Assert-True $dpi.configFile 'high-dpi preset writes config'
Assert-True $dpi.supportOS 'high-dpi preset sets supportOS'

$conhost = Apply-PS2EXEPreset -Options $opt -PresetName 'Forced conhost'
Assert-True $conhost.conHost 'conhost preset sets conHost'
Assert-True (-not $conhost.noConsole) 'conhost preset is not GUI'

$names = @((Get-PS2EXEPresets).Keys)
Assert-True ($names.Count -ge 8) 'at least eight presets ship'

# --- Profiles ---
Write-Host ''
Write-Host 'Profiles'
$opt = New-PS2EXEOptions
$opt.inputFile = 'D:\a.ps1'
$opt.noConsole = $true
$opt.requireAdmin = $true
$opt.version = '2.3.4'
$opt.embedFiles = @([pscustomobject]@{ Source = 'D:\x.ini'; Target = '%TEMP%\x.ini' })
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ps2exe-profile-{0}.json" -f [guid]::NewGuid())
try {
    Export-PS2EXEProfile -Options $opt -Path $tmp -Name 'roundtrip' | Out-Null
    $loaded = Import-PS2EXEProfile -Path $tmp
    Assert-Equal 'D:\a.ps1' $loaded.inputFile 'profile restores input'
    Assert-True $loaded.noConsole 'profile restores noConsole'
    Assert-True $loaded.requireAdmin 'profile restores requireAdmin'
    Assert-Equal '2.3.4' $loaded.version 'profile restores version'
    Assert-Equal 'D:\x.ini' $loaded.embedFiles[0].Source 'profile restores embed source'
    Assert-Equal '%TEMP%\x.ini' $loaded.embedFiles[0].Target 'profile restores embed target'
}
finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
}

# --- Catalog / help surface ---
Write-Host ''
Write-Host 'Catalog completeness'
$catalogNames = @((Get-PS2EXEOptionCatalog).Name)
foreach ($expected in @(
        'noConsole', 'conHost', 'UNICODEEncoding', 'credentialGUI', 'prepareDebug',
        'configFile', 'noConfigFile', 'noOutput', 'noError', 'noVisualStyles',
        'exitOnCancel', 'DPIAware', 'winFormsDPIAware', 'requireAdmin',
        'supportOS', 'virtualize', 'longPaths'
    )) {
    Assert-True ($catalogNames -contains $expected) "catalog includes $expected"
}

$reserved = Get-PS2EXEReservedRuntimeParameters
Assert-True ($reserved.Count -eq 5) 'five reserved EXE parameters documented'

$cultures = Get-PS2EXECommonCultures
Assert-True ($cultures.Count -gt 10) 'culture list is populated'
Assert-Equal 0 $cultures[0].Lcid 'first culture is current-user (0)'

$meta = Get-PS2EXEDefaultMetadata -InputFile 'C:\Tools\Inventory.ps1'
Assert-Equal 'Inventory' $meta.title 'default title from file name'
Assert-Equal '1.0.0.0' $meta.version 'default version is 1.0.0.0'

# --- Script info ---
Write-Host ''
Write-Host 'Script inspection'
$sample = Join-Path ([System.IO.Path]::GetTempPath()) ("ps2exe-sample-{0}.ps1" -f [guid]::NewGuid())
@'
<#
.SYNOPSIS
    Demo backup helper.
.DESCRIPTION
    Copies files.
.PARAMETER Path
    Source path.
#>
param(
    [string]$Path
)
Write-Output $Path
'@ | Set-Content -LiteralPath $sample -Encoding UTF8
try {
    $info = Get-PS2EXEScriptInfo -Path $sample
    Assert-True $info.Exists 'sample script exists'
    Assert-True ($info.LineCount -gt 5) 'line count populated'
    Assert-True ($info.Synopsis -match 'Demo backup helper') 'synopsis parsed'
    Assert-True ($info.Parameters -contains 'Path') 'parameter name parsed'
    Assert-True ($info.Encoding -match 'UTF-8') 'utf8 encoding detected'
}
finally {
    Remove-Item -LiteralPath $sample -Force
}

$infoMissing = Get-PS2EXEScriptInfo -Path (Join-Path ([System.IO.Path]::GetTempPath()) 'does-not-exist-ps2exe.ps1')
Assert-True (-not $infoMissing.Exists) 'missing script reported as not exists'

# --- Copy options ---
Write-Host ''
Write-Host 'Options copy'
$opt = New-PS2EXEOptions
$opt.noConsole = $true
$opt.embedFiles = @([pscustomobject]@{ Source = 'a'; Target = 'b' })
$copy = Copy-PS2EXEOptions -Options $opt
$copy.noConsole = $false
$copy.embedFiles[0].Source = 'changed'
Assert-True $opt.noConsole 'copy is detached from bools'
Assert-Equal 'a' $opt.embedFiles[0].Source 'copy is detached from embed rows'

# --- CommandLineOnly exit path of GUI script is covered separately ---
Write-Host ''
Write-Host 'Splat conversion'
$opt = New-PS2EXEOptions
$opt.inputFile = 'in.ps1'
$opt.outputFile = 'out.exe'
$opt.noError = $true
$opt.prepareDebug = $true
$splat = ConvertTo-PS2EXESplat -Options $opt
Assert-True $splat.Contains('noError') 'splat includes noError'
Assert-True $splat.Contains('prepareDebug') 'splat includes prepareDebug'
Assert-True (-not $splat.Contains('noConsole')) 'splat omits false switches'
Assert-True $splat.Contains('STA') 'splat includes default STA'

Write-Host ''
Write-Host ("Results: {0} passed, {1} failed" -f $script:Pass, $script:Fail)
if ($script:Fail -gt 0) {
    Write-Host ''
    Write-Host 'Failures:'
    foreach ($item in $script:Failures) { Write-Host "  - $item" }
    exit 1
}
exit 0
