#Requires -Version 5.1
<#
.SYNOPSIS
    Shared validation, presets, profiles, and command-line builder for PS2EXE Studio.
.NOTES
    PowerShell 5.1 compatible. Safe to dot-source without loading WinForms.
#>

Set-StrictMode -Version Latest

$script:PS2EXEStudioVersion = '1.0.0'
$script:PS2EXEStudioAppName = 'PS2EXE Studio'

function Get-PS2EXEStudioVersion {
    return $script:PS2EXEStudioVersion
}

function Test-PS2EXEPathExists {
    param(
        [string]$LiteralPath,
        [ValidateSet('Any', 'Leaf', 'Container')]
        [string]$PathType = 'Any'
    )

    if ([string]::IsNullOrWhiteSpace($LiteralPath)) {
        return $false
    }
    try {
        if ($PathType -eq 'Any') {
            return [bool](Test-Path -LiteralPath $LiteralPath -ErrorAction Stop)
        }
        return [bool](Test-Path -LiteralPath $LiteralPath -PathType $PathType -ErrorAction Stop)
    }
    catch {
        return $false
    }
}

function Get-PS2EXEStudioAppData {
    $base = [string]$env:APPDATA
    if ([string]::IsNullOrWhiteSpace($base)) { $base = [string]$env:LOCALAPPDATA }
    if ([string]::IsNullOrWhiteSpace($base)) { $base = [System.IO.Path]::GetTempPath() }
    $root = Join-Path $base 'PS2EXE-Studio'
    $profiles = Join-Path $root 'profiles'
    if (-not (Test-PS2EXEPathExists -LiteralPath $profiles -PathType Container)) {
        New-Item -ItemType Directory -Path $profiles -Force | Out-Null
    }
    return [pscustomobject]@{
        Root         = $root
        Profiles     = $profiles
        LastSession  = Join-Path $root 'last-session.json'
        RecentFiles  = Join-Path $root 'recent.json'
    }
}

function New-PS2EXEOptions {
    [CmdletBinding()]
    param()

    return [pscustomobject]@{
        PSTypeName       = 'PS2EXE.Studio.Options'
        inputFile        = ''
        outputFile       = ''
        iconFile         = ''
        architecture     = 'anycpu'
        apartment        = 'STA'
        lcid             = 0
        noConsole        = $false
        conHost          = $false
        UNICODEEncoding  = $false
        credentialGUI    = $false
        prepareDebug     = $false
        configFile       = $false
        noConfigFile     = $false
        noOutput         = $false
        noError          = $false
        noVisualStyles   = $false
        exitOnCancel     = $false
        DPIAware         = $false
        winFormsDPIAware = $false
        requireAdmin     = $false
        supportOS        = $false
        virtualize       = $false
        longPaths        = $false
        title            = ''
        description      = ''
        company          = ''
        product          = ''
        copyright        = ''
        trademark        = ''
        version          = ''
        embedFiles       = @()
        verbose          = $false
    }
}

function Copy-PS2EXEOptions {
    param(
        [Parameter(Mandatory = $true)]
        $Options
    )

    $copy = New-PS2EXEOptions
    foreach ($prop in $copy.PSObject.Properties.Name) {
        if ($prop -eq 'PSTypeName') { continue }
        if ($Options.PSObject.Properties.Name -contains $prop) {
            $value = $Options.$prop
            if ($prop -eq 'embedFiles' -and $null -ne $value) {
                $copy.$prop = @(
                    foreach ($item in @($value)) {
                        [pscustomobject]@{
                            Source = [string]$item.Source
                            Target = [string]$item.Target
                        }
                    }
                )
            }
            else {
                $copy.$prop = $value
            }
        }
    }
    return $copy
}

function Get-PS2EXECommonCultures {
    return @(
        [pscustomobject]@{ Lcid = 0;    Name = '(Current user culture)';     Culture = '' }
        [pscustomobject]@{ Lcid = 1033; Name = 'en-US  English (United States)'; Culture = 'en-US' }
        [pscustomobject]@{ Lcid = 2057; Name = 'en-GB  English (United Kingdom)'; Culture = 'en-GB' }
        [pscustomobject]@{ Lcid = 3081; Name = 'en-AU  English (Australia)'; Culture = 'en-AU' }
        [pscustomobject]@{ Lcid = 1031; Name = 'de-DE  German (Germany)';    Culture = 'de-DE' }
        [pscustomobject]@{ Lcid = 1036; Name = 'fr-FR  French (France)';     Culture = 'fr-FR' }
        [pscustomobject]@{ Lcid = 3082; Name = 'es-ES  Spanish (Spain)';     Culture = 'es-ES' }
        [pscustomobject]@{ Lcid = 2058; Name = 'es-MX  Spanish (Mexico)';    Culture = 'es-MX' }
        [pscustomobject]@{ Lcid = 1040; Name = 'it-IT  Italian (Italy)';     Culture = 'it-IT' }
        [pscustomobject]@{ Lcid = 1041; Name = 'ja-JP  Japanese';            Culture = 'ja-JP' }
        [pscustomobject]@{ Lcid = 2052; Name = 'zh-CN  Chinese (Simplified)'; Culture = 'zh-CN' }
        [pscustomobject]@{ Lcid = 1028; Name = 'zh-TW  Chinese (Traditional)'; Culture = 'zh-TW' }
        [pscustomobject]@{ Lcid = 1042; Name = 'ko-KR  Korean';              Culture = 'ko-KR' }
        [pscustomobject]@{ Lcid = 1049; Name = 'ru-RU  Russian';             Culture = 'ru-RU' }
        [pscustomobject]@{ Lcid = 1046; Name = 'pt-BR  Portuguese (Brazil)'; Culture = 'pt-BR' }
        [pscustomobject]@{ Lcid = 2070; Name = 'pt-PT  Portuguese (Portugal)'; Culture = 'pt-PT' }
        [pscustomobject]@{ Lcid = 1030; Name = 'da-DK  Danish';              Culture = 'da-DK' }
        [pscustomobject]@{ Lcid = 1053; Name = 'sv-SE  Swedish';             Culture = 'sv-SE' }
        [pscustomobject]@{ Lcid = 1044; Name = 'nb-NO  Norwegian (Bokmal)';  Culture = 'nb-NO' }
        [pscustomobject]@{ Lcid = 1043; Name = 'nl-NL  Dutch';               Culture = 'nl-NL' }
        [pscustomobject]@{ Lcid = 1045; Name = 'pl-PL  Polish';              Culture = 'pl-PL' }
        [pscustomobject]@{ Lcid = 1055; Name = 'tr-TR  Turkish';             Culture = 'tr-TR' }
        [pscustomobject]@{ Lcid = 1029; Name = 'cs-CZ  Czech';               Culture = 'cs-CZ' }
        [pscustomobject]@{ Lcid = 1038; Name = 'hu-HU  Hungarian';           Culture = 'hu-HU' }
        [pscustomobject]@{ Lcid = 1054; Name = 'th-TH  Thai';                Culture = 'th-TH' }
        [pscustomobject]@{ Lcid = 1081; Name = 'hi-IN  Hindi';               Culture = 'hi-IN' }
        [pscustomobject]@{ Lcid = 1025; Name = 'ar-SA  Arabic (Saudi Arabia)'; Culture = 'ar-SA' }
        [pscustomobject]@{ Lcid = 1037; Name = 'he-IL  Hebrew';              Culture = 'he-IL' }
    )
}

function Get-PS2EXEOptionCatalog {
    return @(
        [pscustomobject]@{ Name = 'noConsole';        Category = 'Application'; Label = 'Windows GUI (no console)';     GuiOnly = $false; Tooltip = 'Compile as a Windows Forms app without a console window. Pipe output to Out-String to avoid a message box per line.' }
        [pscustomobject]@{ Name = 'conHost';          Category = 'Application'; Label = 'Force conhost console';        GuiOnly = $false; Tooltip = 'Force start with conhost instead of Windows Terminal. Disables redirection of input, output, and error. Cannot be combined with Windows GUI mode.' }
        [pscustomobject]@{ Name = 'UNICODEEncoding';  Category = 'Application'; Label = 'Unicode console output';       GuiOnly = $false; Tooltip = 'Encode console output as UNICODE so special characters display correctly. Console apps only.' }
        [pscustomobject]@{ Name = 'credentialGUI';    Category = 'Application'; Label = 'GUI credential prompt';        GuiOnly = $false; Tooltip = 'Use a graphical credential dialog in console mode instead of console input.' }
        [pscustomobject]@{ Name = 'prepareDebug';     Category = 'Compiler';    Label = 'Prepare debug artifacts';      GuiOnly = $false; Tooltip = 'Keep compiler temp files and copy the generated C# source next to the EXE for debugging. The EXE also accepts -debug.' }
        [pscustomobject]@{ Name = 'configFile';       Category = 'Compiler';    Label = 'Write .exe.config';            GuiOnly = $false; Tooltip = 'Write a .NET config file beside the EXE. Forced on by long paths and WinForms DPI awareness.' }
        [pscustomobject]@{ Name = 'noConfigFile';     Category = 'Compiler';    Label = 'Do not write config file';     GuiOnly = $false; Tooltip = 'Compatibility switch that forbids generating a config file. Conflicts with -configFile, -longPaths, and -winFormsDPIAware.' }
        [pscustomobject]@{ Name = 'noOutput';         Category = 'Runtime I/O'; Label = 'Suppress standard output';     GuiOnly = $false; Tooltip = 'The EXE generates no standard output, including verbose and information streams.' }
        [pscustomobject]@{ Name = 'noError';          Category = 'Runtime I/O'; Label = 'Suppress error output';        GuiOnly = $false; Tooltip = 'The EXE generates no error output, including warning and debug streams.' }
        [pscustomobject]@{ Name = 'noVisualStyles';   Category = 'GUI only';    Label = 'Disable visual styles';        GuiOnly = $true;  Tooltip = 'Disable Windows visual styles for a generated GUI application. Only applies with Windows GUI mode.' }
        [pscustomobject]@{ Name = 'exitOnCancel';     Category = 'GUI only';    Label = 'Exit when input is cancelled'; GuiOnly = $true;  Tooltip = 'Exit the program when Cancel or X is selected in a Read-Host input box. Only applies with Windows GUI mode.' }
        [pscustomobject]@{ Name = 'DPIAware';         Category = 'Manifest';    Label = 'DPI aware (manifest)';         GuiOnly = $false; Tooltip = 'Declare per-monitor DPI awareness in the win32 manifest so GUI controls scale with display scaling.' }
        [pscustomobject]@{ Name = 'winFormsDPIAware'; Category = 'Manifest';    Label = 'WinForms DPI scaling';         GuiOnly = $false; Tooltip = 'Add WinForms PerMonitorV2 DPI scaling to the config file. Forces -configFile and -supportOS. Requires Windows 10 and .NET 4.7+.' }
        [pscustomobject]@{ Name = 'requireAdmin';     Category = 'Manifest';    Label = 'Require administrator (UAC)';  GuiOnly = $false; Tooltip = 'If UAC is enabled, the EXE runs only elevated. Cannot be combined with application virtualization.' }
        [pscustomobject]@{ Name = 'supportOS';        Category = 'Manifest';    Label = 'Declare supported OS versions'; GuiOnly = $false; Tooltip = 'Embed a compatibility manifest so [Environment]::OSVersion reports the real Windows version. Cannot be combined with virtualization.' }
        [pscustomobject]@{ Name = 'virtualize';       Category = 'Manifest';    Label = 'Application virtualization';   GuiOnly = $false; Tooltip = 'Activate application virtualization and force the x86 runtime. Conflicts with requireAdmin, supportOS, and longPaths.' }
        [pscustomobject]@{ Name = 'longPaths';        Category = 'Manifest';    Label = 'Enable long paths (>260)';     GuiOnly = $false; Tooltip = 'Enable long paths when the OS allows them (Windows 10+). Forces a config file. Conflicts with virtualization.' }
        [pscustomobject]@{ Name = 'verbose';          Category = 'Compiler';    Label = 'Verbose compiler output';      GuiOnly = $false; Tooltip = 'Show detailed compiler errors if compilation fails (Invoke-ps2exe -Verbose).' }
    )
}

function Get-PS2EXEPresets {
    return [ordered]@{
        'Console EXE' = @{
            Description      = 'Standard console executable. AnyCPU, STA, current culture.'
            architecture     = 'anycpu'
            apartment        = 'STA'
            noConsole        = $false
            conHost          = $false
            requireAdmin     = $false
            virtualize       = $false
        }
        'Windows GUI' = @{
            Description      = 'WinForms app with no console. Recommended for scripts that already show forms or message boxes.'
            architecture     = 'anycpu'
            apartment        = 'STA'
            noConsole        = $true
            conHost          = $false
            exitOnCancel     = $true
            credentialGUI    = $false
        }
        'Admin GUI' = @{
            Description      = 'Elevated Windows GUI with DPI awareness and modern OS compatibility.'
            architecture     = 'anycpu'
            apartment        = 'STA'
            noConsole        = $true
            requireAdmin     = $true
            DPIAware         = $true
            supportOS        = $true
            exitOnCancel     = $true
            virtualize       = $false
        }
        'High-DPI WinForms' = @{
            Description      = 'GUI app with per-monitor v2 DPI scaling (.NET 4.7+ config + manifest).'
            architecture     = 'anycpu'
            apartment        = 'STA'
            noConsole        = $true
            DPIAware         = $true
            winFormsDPIAware = $true
            supportOS        = $true
            configFile       = $true
            noConfigFile     = $false
            exitOnCancel     = $true
        }
        'Unicode console' = @{
            Description      = 'Console EXE that emits UNICODE output and uses a GUI credential prompt.'
            architecture     = 'anycpu'
            apartment        = 'STA'
            noConsole        = $false
            UNICODEEncoding  = $true
            credentialGUI    = $true
        }
        'Forced conhost' = @{
            Description      = 'Console EXE that always starts through conhost.exe instead of Windows Terminal.'
            architecture     = 'anycpu'
            apartment        = 'STA'
            noConsole        = $false
            conHost          = $true
        }
        'Debug build' = @{
            Description      = 'Keep C# sources and compiler temp files beside the EXE.'
            prepareDebug     = $true
            configFile       = $true
            noConfigFile     = $false
            verbose          = $true
        }
        'x86 virtualized' = @{
            Description      = '32-bit EXE with application virtualization. Incompatible with admin/OS/long-path manifests.'
            architecture     = 'x86'
            virtualize       = $true
            requireAdmin     = $false
            supportOS        = $false
            longPaths        = $false
            DPIAware         = $false
            winFormsDPIAware = $false
            configFile       = $false
        }
        'Long-path console' = @{
            Description      = 'Console EXE that opts into Win10+ long paths and writes the required config file.'
            architecture     = 'anycpu'
            noConsole        = $false
            longPaths        = $true
            supportOS        = $true
            configFile       = $true
            noConfigFile     = $false
            virtualize       = $false
        }
    }
}

function Apply-PS2EXEPreset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Options,

        [Parameter(Mandatory = $true)]
        [string]$PresetName
    )

    $presets = Get-PS2EXEPresets
    if (-not $presets.Contains($PresetName)) {
        throw "Unknown preset '$PresetName'."
    }

    $result = Copy-PS2EXEOptions -Options $Options
    $values = $presets[$PresetName]
    foreach ($key in $values.Keys) {
        if ($key -eq 'Description') { continue }
        if ($result.PSObject.Properties.Name -contains $key) {
            $result.$key = $values[$key]
        }
    }
    return $result
}

function Get-PS2EXEFileName {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $normalized = $Path.Replace('\', '/')
    return [System.IO.Path]::GetFileName($normalized.TrimEnd('/'))
}

function Get-PS2EXEFileNameWithoutExtension {
    param([string]$Path)
    $name = Get-PS2EXEFileName -Path $Path
    if ([string]::IsNullOrWhiteSpace($name)) { return '' }
    return [System.IO.Path]::GetFileNameWithoutExtension($name)
}

function Get-PS2EXEExtension {
    param([string]$Path)
    $name = Get-PS2EXEFileName -Path $Path
    if ([string]::IsNullOrWhiteSpace($name)) { return '' }
    return [System.IO.Path]::GetExtension($name)
}

function Join-PS2EXEPath {
    param([string]$Parent, [string]$Child)
    if ([string]::IsNullOrWhiteSpace($Parent)) { return $Child }
    if ($Parent -match '\\' -and $Parent -notmatch '/') {
        return ($Parent.TrimEnd('\') + '\' + $Child.TrimStart('\'))
    }
    return [System.IO.Path]::Combine($Parent, $Child)
}

function Get-PS2EXENormalizedPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $trimmed = $Path.Trim().Trim('"')
    try {
        if ($trimmed -match '^[A-Za-z]:[\\/]' -or $trimmed.StartsWith('\\')) {
            return $trimmed.Replace('/', '\').TrimEnd('\').ToLowerInvariant()
        }
        return [System.IO.Path]::GetFullPath($trimmed).TrimEnd([System.IO.Path]::DirectorySeparatorChar).ToLowerInvariant()
    }
    catch {
        return $trimmed.Replace('/', '\').TrimEnd('\').ToLowerInvariant()
    }
}

function Test-PS2EXEVersionString {
    param([string]$Version)

    if ([string]::IsNullOrWhiteSpace($Version)) { return $true }
    return [bool]($Version -match '^(?:\d+\.){0,3}\d+$')
}

function ConvertTo-PS2EXEIssue {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Error', 'Warning', 'Info')][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Message,
        [string[]]$Fields = @()
    )

    return [pscustomobject]@{
        Severity = $Severity
        Code     = $Code
        Message  = $Message
        Fields   = @($Fields)
    }
}

function Get-PS2EXEResolvedOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Options,

        [switch]$RequireExistingPaths
    )

    $inputFile = [string]$Options.inputFile
    $outputFile = [string]$Options.outputFile

    if ([string]::IsNullOrWhiteSpace($inputFile)) {
        return ''
    }

    if ([string]::IsNullOrWhiteSpace($outputFile)) {
        $base = Get-PS2EXEFileNameWithoutExtension -Path $inputFile
        $parent = $inputFile.Substring(0, $inputFile.Length - (Get-PS2EXEFileName -Path $inputFile).Length).TrimEnd('\', '/')
        if ([string]::IsNullOrWhiteSpace($parent)) {
            return ($base + '.exe')
        }
        return (Join-PS2EXEPath -Parent $parent -Child ($base + '.exe'))
    }

    $outputLooksLikeDirectory = $false
    if ($RequireExistingPaths -and (Test-PS2EXEPathExists -LiteralPath $outputFile -PathType Container)) {
        $outputLooksLikeDirectory = $true
    }
    elseif (-not $RequireExistingPaths) {
        $ext = Get-PS2EXEExtension -Path $outputFile
        if ([string]::IsNullOrWhiteSpace($ext)) {
            $outputLooksLikeDirectory = $true
        }
    }

    if ($outputLooksLikeDirectory) {
        $name = (Get-PS2EXEFileNameWithoutExtension -Path $inputFile) + '.exe'
        return (Join-PS2EXEPath -Parent $outputFile -Child $name)
    }

    return $outputFile
}

function Test-PS2EXEOptions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Options,

        [switch]$SkipFileSystem
    )

    $issues = @()

    if ([string]::IsNullOrWhiteSpace([string]$Options.inputFile)) {
        $issues += ,(ConvertTo-PS2EXEIssue Error 'INPUT_REQUIRED' 'Select a PowerShell script to compile.' @('inputFile'))
    }
    elseif (-not $SkipFileSystem) {
        if (-not (Test-PS2EXEPathExists -LiteralPath $Options.inputFile -PathType Leaf)) {
            $issues += ,(ConvertTo-PS2EXEIssue Error 'INPUT_MISSING' "Input file not found: $($Options.inputFile)" @('inputFile'))
        }
        else {
            $ext = Get-PS2EXEExtension -Path $Options.inputFile
            if ($ext -notin @('.ps1', '.psm1')) {
                $issues += ,(ConvertTo-PS2EXEIssue Warning 'INPUT_EXT' 'Input is not a .ps1 or .psm1 file. PS2EXE expects a PowerShell script encoded as UTF-8 or UTF-16.' @('inputFile'))
            }
        }
    }

    $resolvedOutput = Get-PS2EXEResolvedOutput -Options $Options -RequireExistingPaths:(-not $SkipFileSystem)
    if (-not [string]::IsNullOrWhiteSpace($resolvedOutput)) {
        $outExt = Get-PS2EXEExtension -Path $resolvedOutput
        if ($outExt -notin @('.exe', '.com')) {
            $issues += ,(ConvertTo-PS2EXEIssue Error 'OUTPUT_EXT' "Output file must have extension '.exe' or '.com'." @('outputFile'))
        }

        if (-not [string]::IsNullOrWhiteSpace($Options.inputFile)) {
            $inFull = Get-PS2EXENormalizedPath -Path $Options.inputFile
            $outFull = Get-PS2EXENormalizedPath -Path $resolvedOutput
            if ($inFull -and $outFull -and $inFull -eq $outFull) {
                $issues += ,(ConvertTo-PS2EXEIssue Error 'SAME_PATH' 'Input file is identical to output file.' @('inputFile', 'outputFile'))
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$Options.iconFile)) {
        $iconExt = Get-PS2EXEExtension -Path $Options.iconFile
        if ($iconExt -and $iconExt -notin @('.ico', '.icon')) {
            $issues += ,(ConvertTo-PS2EXEIssue Warning 'ICON_EXT' 'Icon should be a .ico file. Other formats are usually rejected by the C# compiler.' @('iconFile'))
        }
        if (-not $SkipFileSystem -and -not (Test-PS2EXEPathExists -LiteralPath $Options.iconFile -PathType Leaf)) {
            $issues += ,(ConvertTo-PS2EXEIssue Error 'ICON_MISSING' "Icon file not found: $($Options.iconFile)" @('iconFile'))
        }
    }

    $arch = [string]$Options.architecture
    if ($arch -notin @('anycpu', 'x86', 'x64')) {
        $issues += ,(ConvertTo-PS2EXEIssue Error 'ARCH_INVALID' 'Architecture must be anycpu, x86, or x64.' @('architecture'))
    }

    $apt = [string]$Options.apartment
    if ($apt -notin @('STA', 'MTA')) {
        $issues += ,(ConvertTo-PS2EXEIssue Error 'APT_INVALID' 'Apartment mode must be STA or MTA.' @('apartment'))
    }

    if ($Options.noConsole -and $Options.conHost) {
        $issues += ,(ConvertTo-PS2EXEIssue Error 'CONHOST_GUI' '-noConsole cannot be combined with -conHost.' @('noConsole', 'conHost'))
    }

    if ($Options.requireAdmin -and $Options.virtualize) {
        $issues += ,(ConvertTo-PS2EXEIssue Error 'ADMIN_VIRT' '-requireAdmin cannot be combined with -virtualize.' @('requireAdmin', 'virtualize'))
    }

    if ($Options.supportOS -and $Options.virtualize) {
        $issues += ,(ConvertTo-PS2EXEIssue Error 'OS_VIRT' '-supportOS cannot be combined with -virtualize.' @('supportOS', 'virtualize'))
    }

    if ($Options.longPaths -and $Options.virtualize) {
        $issues += ,(ConvertTo-PS2EXEIssue Error 'PATH_VIRT' '-longPaths cannot be combined with -virtualize.' @('longPaths', 'virtualize'))
    }

    if ($Options.configFile -and $Options.noConfigFile) {
        $issues += ,(ConvertTo-PS2EXEIssue Error 'CONFIG_CONFLICT' '-configFile cannot be combined with -noConfigFile.' @('configFile', 'noConfigFile'))
    }

    if ($Options.virtualize -and $arch -ne 'x86') {
        $issues += ,(ConvertTo-PS2EXEIssue Warning 'VIRT_X86' 'Application virtualization forces the x86 platform at compile time.' @('architecture', 'virtualize'))
    }

    if ($Options.longPaths -and -not $Options.configFile) {
        $issues += ,(ConvertTo-PS2EXEIssue Warning 'LONGPATH_CONFIG' 'PS2EXE will force generation of a config file because -longPaths requires one.' @('longPaths', 'configFile'))
    }

    if ($Options.winFormsDPIAware -and -not $Options.configFile) {
        $issues += ,(ConvertTo-PS2EXEIssue Warning 'WFDPI_CONFIG' 'PS2EXE will force generation of a config file because -winFormsDPIAware requires one.' @('winFormsDPIAware', 'configFile'))
    }

    if ($Options.winFormsDPIAware -and -not $Options.supportOS) {
        $issues += ,(ConvertTo-PS2EXEIssue Warning 'WFDPI_OS' 'PS2EXE will force -supportOS because -winFormsDPIAware requires it.' @('winFormsDPIAware', 'supportOS'))
    }

    if ($Options.longPaths -and $Options.noConfigFile) {
        $issues += ,(ConvertTo-PS2EXEIssue Error 'LONGPATH_NOCONFIG' '-longPaths requires a config file and cannot be combined with -noConfigFile.' @('longPaths', 'noConfigFile'))
    }

    if ($Options.winFormsDPIAware -and $Options.noConfigFile) {
        $issues += ,(ConvertTo-PS2EXEIssue Error 'WFDPI_NOCONFIG' '-winFormsDPIAware requires a config file and cannot be combined with -noConfigFile.' @('winFormsDPIAware', 'noConfigFile'))
    }

    if ($Options.noVisualStyles -and -not $Options.noConsole) {
        $issues += ,(ConvertTo-PS2EXEIssue Info 'VISUAL_GUI' '-noVisualStyles only applies to Windows GUI (-noConsole) applications.' @('noVisualStyles'))
    }

    if ($Options.exitOnCancel -and -not $Options.noConsole) {
        $issues += ,(ConvertTo-PS2EXEIssue Info 'CANCEL_GUI' '-exitOnCancel only applies to Windows GUI (-noConsole) applications.' @('exitOnCancel'))
    }

    if ($Options.UNICODEEncoding -and $Options.noConsole) {
        $issues += ,(ConvertTo-PS2EXEIssue Info 'UNICODE_CONSOLE' '-UNICODEEncoding applies to console mode. It has no effect on Windows GUI executables.' @('UNICODEEncoding'))
    }

    if ($Options.conHost -and $Options.noOutput) {
        $issues += ,(ConvertTo-PS2EXEIssue Warning 'CONHOST_IO' '-conHost disables redirection of the output channel. Combined with -noOutput the EXE will be silent.' @('conHost', 'noOutput'))
    }

    $lcid = 0
    try { $lcid = [int]$Options.lcid } catch { $lcid = -1 }
    if ($lcid -lt 0) {
        $issues += ,(ConvertTo-PS2EXEIssue Error 'LCID_INVALID' 'LCID must be a non-negative integer. Use 0 for the current user culture.' @('lcid'))
    }

    if (-not (Test-PS2EXEVersionString -Version ([string]$Options.version))) {
        $issues += ,(ConvertTo-PS2EXEIssue Error 'VERSION' 'Version must be n, n.n, n.n.n, or n.n.n.n (digits only).' @('version'))
    }

    $embedIndex = 0
    foreach ($item in @($Options.embedFiles)) {
        $embedIndex++
        $src = [string]$item.Source
        $dst = [string]$item.Target
        if ([string]::IsNullOrWhiteSpace($src) -and [string]::IsNullOrWhiteSpace($dst)) { continue }
        if ([string]::IsNullOrWhiteSpace($src) -or [string]::IsNullOrWhiteSpace($dst)) {
            $issues += ,(ConvertTo-PS2EXEIssue Error 'EMBED_PAIR' "Embedded file #$embedIndex needs both a source path and a runtime target path." @('embedFiles'))
            continue
        }
        if (-not $SkipFileSystem -and -not (Test-PS2EXEPathExists -LiteralPath $src -PathType Leaf)) {
            $issues += ,(ConvertTo-PS2EXEIssue Error 'EMBED_MISSING' "Embedded source file not found: $src" @('embedFiles'))
        }
    }

    $names = @()
    foreach ($item in @($Options.embedFiles)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$item.Source)) {
            $names += (Get-PS2EXEFileName -Path $item.Source).ToLowerInvariant()
        }
    }
    $dupes = $names | Group-Object | Where-Object { $_.Count -gt 1 }
    foreach ($dupe in $dupes) {
        $issues += ,(ConvertTo-PS2EXEIssue Error 'EMBED_UNIQUE' "Embedded source file names must be unique. Duplicate: $($dupe.Name)" @('embedFiles'))
    }

    return ,$issues
}

function Test-PS2EXEReady {
    param($Issues)

    $list = @($Issues | Where-Object { $_ })
    return -not [bool]($list | Where-Object { $_.Severity -eq 'Error' })
}

function ConvertTo-PS2EXEQuoted {
    param([string]$Value)

    if ($null -eq $Value) { return "''" }
    return "'" + ($Value -replace "'", "''") + "'"
}

function Get-PS2EXEEmbedHashtableLiteral {
    param($Items)

    $pairs = @()
    foreach ($item in @($Items)) {
        $src = [string]$item.Source
        $dst = [string]$item.Target
        if ([string]::IsNullOrWhiteSpace($src) -or [string]::IsNullOrWhiteSpace($dst)) { continue }
        $pairs += ('{0}={1}' -f (ConvertTo-PS2EXEQuoted $dst), (ConvertTo-PS2EXEQuoted $src))
    }
    if ($pairs.Count -eq 0) { return $null }
    return '@{ ' + ($pairs -join '; ') + ' }'
}

function ConvertTo-PS2EXESplat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Options
    )

    $splat = [ordered]@{}

    if (-not [string]::IsNullOrWhiteSpace([string]$Options.inputFile)) {
        $splat['inputFile'] = [string]$Options.inputFile
    }

    $resolvedOutput = Get-PS2EXEResolvedOutput -Options $Options
    if (-not [string]::IsNullOrWhiteSpace($resolvedOutput)) {
        $splat['outputFile'] = $resolvedOutput
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$Options.iconFile)) {
        $splat['iconFile'] = [string]$Options.iconFile
    }

    switch ([string]$Options.architecture) {
        'x86' { $splat['x86'] = $true }
        'x64' { $splat['x64'] = $true }
    }

    switch ([string]$Options.apartment) {
        'MTA' { $splat['MTA'] = $true }
        default { $splat['STA'] = $true }
    }

    $lcid = 0
    try { $lcid = [int]$Options.lcid } catch { $lcid = 0 }
    if ($lcid -gt 0) {
        $splat['lcid'] = $lcid
    }

    $switchNames = @(
        'noConsole', 'conHost', 'UNICODEEncoding', 'credentialGUI', 'prepareDebug',
        'configFile', 'noConfigFile', 'noOutput', 'noError', 'noVisualStyles',
        'exitOnCancel', 'DPIAware', 'winFormsDPIAware', 'requireAdmin',
        'supportOS', 'virtualize', 'longPaths'
    )
    foreach ($name in $switchNames) {
        if ($Options.PSObject.Properties.Name -contains $name -and [bool]$Options.$name) {
            $splat[$name] = $true
        }
    }

    foreach ($meta in @('title', 'description', 'company', 'product', 'copyright', 'trademark', 'version')) {
        $value = [string]$Options.$meta
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $splat[$meta] = $value
        }
    }

    $embed = @{}
    foreach ($item in @($Options.embedFiles)) {
        $src = [string]$item.Source
        $dst = [string]$item.Target
        if (-not [string]::IsNullOrWhiteSpace($src) -and -not [string]::IsNullOrWhiteSpace($dst)) {
            $embed[$dst] = $src
        }
    }
    if ($embed.Count -gt 0) {
        $splat['embedFiles'] = $embed
    }

    return $splat
}

function New-PS2EXECommandLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Options,

        [string]$CommandName = 'Invoke-ps2exe'
    )

    $splat = ConvertTo-PS2EXESplat -Options $Options
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add($CommandName)

    foreach ($key in $splat.Keys) {
        $value = $splat[$key]
        if ($key -eq 'embedFiles') {
            $literal = Get-PS2EXEEmbedHashtableLiteral -Items $Options.embedFiles
            if ($literal) {
                $parts.Add('-embedFiles')
                $parts.Add($literal)
            }
            continue
        }

        if ($value -is [bool]) {
            if ($value) { $parts.Add("-$key") }
            continue
        }

        $parts.Add("-$key")
        if ($value -is [int] -or $value -is [long]) {
            $parts.Add([string]$value)
        }
        else {
            $parts.Add((ConvertTo-PS2EXEQuoted ([string]$value)))
        }
    }

    if ([bool]$Options.verbose) {
        $parts.Add('-Verbose')
    }

    return ($parts -join ' ')
}

function ConvertTo-PS2EXEProfile {
    param(
        [Parameter(Mandatory = $true)]
        $Options,

        [string]$Name = 'Untitled'
    )

    return [pscustomobject]@{
        schema     = 'ps2exe-studio-profile/v1'
        name       = $Name
        savedUtc   = (Get-Date).ToUniversalTime().ToString('o')
        studio     = $script:PS2EXEStudioVersion
        options    = Copy-PS2EXEOptions -Options $Options
    }
}

function ConvertFrom-PS2EXEProfile {
    param(
        [Parameter(Mandatory = $true)]
        $ProfileObject
    )

    $options = New-PS2EXEOptions
    $source = $ProfileObject
    if ($ProfileObject.PSObject.Properties.Name -contains 'options') {
        $source = $ProfileObject.options
    }

    foreach ($prop in $options.PSObject.Properties.Name) {
        if ($prop -eq 'PSTypeName') { continue }
        if ($source.PSObject.Properties.Name -contains $prop) {
            if ($prop -eq 'embedFiles') {
                $options.embedFiles = @(
                    foreach ($item in @($source.embedFiles)) {
                        [pscustomobject]@{
                            Source = [string]$item.Source
                            Target = [string]$item.Target
                        }
                    }
                )
            }
            else {
                $options.$prop = $source.$prop
            }
        }
    }
    return $options
}

function Export-PS2EXEProfile {
    param(
        [Parameter(Mandatory = $true)]
        $Options,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$Name = 'Untitled'
    )

    $profileObject = ConvertTo-PS2EXEProfile -Options $Options -Name $Name
    $json = $profileObject | ConvertTo-Json -Depth 6
    $dir = [System.IO.Path]::GetDirectoryName($Path)
    if ($dir -and -not (Test-PS2EXEPathExists -LiteralPath $dir -PathType Container)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
    return $Path
}

function Import-PS2EXEProfile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-PS2EXEPathExists -LiteralPath $Path -PathType Leaf)) {
        throw "Profile not found: $Path"
    }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $obj = $raw | ConvertFrom-Json
    return ConvertFrom-PS2EXEProfile -ProfileObject $obj
}

function Get-PS2EXEScriptInfo {
    [CmdletBinding()]
    param(
        [string]$Path
    )

    $info = [pscustomobject]@{
        Exists      = $false
        Path        = $Path
        Name        = ''
        Length      = 0
        Encoding    = 'Unknown'
        LineCount   = 0
        Synopsis    = ''
        Description = ''
        Parameters  = @()
        Preview     = ''
        LastWrite   = $null
    }

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-PS2EXEPathExists -LiteralPath $Path -PathType Leaf)) {
        return $info
    }

    $item = Get-Item -LiteralPath $Path
    $info.Exists = $true
    $info.Name = $item.Name
    $info.Length = [int]$item.Length
    $info.LastWrite = $item.LastWriteTime

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $info.Encoding = 'UTF-8 with BOM'
    }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $info.Encoding = 'UTF-16 LE'
    }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        $info.Encoding = 'UTF-16 BE'
    }
    else {
        $info.Encoding = 'UTF-8 (no BOM) or ANSI'
    }

    $text = [System.IO.File]::ReadAllText($Path)
    $lines = $text -split '\r\n|\n|\r'
    $info.LineCount = @($lines).Count
    $previewLines = @($lines | Select-Object -First 80)
    $info.Preview = $previewLines -join [Environment]::NewLine

    foreach ($line in $lines) {
        if ($line -match '^\s*\.SYNOPSIS\s*$') { continue }
        if ($line -match '^\s*\.SYNOPSIS\s+(.+)$') {
            $info.Synopsis = $Matches[1].Trim()
            break
        }
        if ($info.Synopsis -eq '' -and $line -match '^\s*\.SYNOPSIS') { continue }
    }

    $inSynopsis = $false
    $inDescription = $false
    $synopsisParts = New-Object System.Collections.Generic.List[string]
    $descriptionParts = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines) {
        if ($line -match '^\s*\.SYNOPSIS\s*$') { $inSynopsis = $true; $inDescription = $false; continue }
        if ($line -match '^\s*\.DESCRIPTION\s*$') { $inSynopsis = $false; $inDescription = $true; continue }
        if ($line -match '^\s*\.(PARAMETER|EXAMPLE|NOTES|LINK|INPUTS|OUTPUTS|COMPONENT|ROLE|FUNCTIONALITY)\b') {
            $inSynopsis = $false
            $inDescription = $false
            continue
        }
        if ($line -match '^\s*#>') { $inSynopsis = $false; $inDescription = $false; continue }
        if ($inSynopsis) { $synopsisParts.Add($line.Trim()) }
        if ($inDescription) { $descriptionParts.Add($line.Trim()) }
    }
    if ([string]::IsNullOrWhiteSpace($info.Synopsis) -and $synopsisParts.Count -gt 0) {
        $info.Synopsis = (($synopsisParts | Where-Object { $_ }) -join ' ').Trim()
    }
    if ($descriptionParts.Count -gt 0) {
        $info.Description = (($descriptionParts | Where-Object { $_ }) -join ' ').Trim()
    }

    $paramNames = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines) {
        if ($line -match '^\s*\[(?:Parameter[^\]]*\]\s*\[)*?(?:Alias\([^\]]*\)\]\s*)?(?:Validate[^\]]*\]\s*)?(?:\[[^\]]+\]\s*)?\$(?<name>[A-Za-z_][A-Za-z0-9_]*)') {
            $paramNames.Add($Matches['name'])
        }
        elseif ($line -match '^\s*\$ (?<name>[A-Za-z_][A-Za-z0-9_]*)') {
            # ignore
        }
    }
    # Simpler: comment-based help .PARAMETER plus param() block names
    foreach ($line in $lines) {
        if ($line -match '^\s*\.PARAMETER\s+(\S+)') {
            $paramNames.Add($Matches[1])
        }
    }
    $info.Parameters = @($paramNames | Select-Object -Unique)
    return $info
}

function Get-PS2EXEReservedRuntimeParameters {
    return @(
        [pscustomobject]@{ Name = '-? [<MODIFIER>]'; Description = 'Show comment-based help from the script inside the EXE. Combine with -detailed, -examples, or -full.' }
        [pscustomobject]@{ Name = '-debug';          Description = 'Force System.Diagnostics.Debugger.Launch() before the script runs.' }
        [pscustomobject]@{ Name = '-extract:<FILE>'; Description = 'Extract the embedded PowerShell script to FILE and exit without running it.' }
        [pscustomobject]@{ Name = '-wait';           Description = 'Pause after execution ("Hit any key to exit..." / OK dialog in GUI mode).' }
        [pscustomobject]@{ Name = '-end';            Description = 'Everything after -end is passed to the script. Everything before is consumed by the EXE host.' }
    )
}

function Format-PS2EXEByteSize {
    param([long]$Bytes)
    if ($Bytes -lt 1024) { return "$Bytes B" }
    if ($Bytes -lt 1048576) { return ('{0:N1} KB' -f ($Bytes / 1024)) }
    return ('{0:N2} MB' -f ($Bytes / 1048576))
}

function Get-PS2EXEDefaultMetadata {
    param([string]$InputFile)

    $result = [pscustomobject]@{
        title    = ''
        product  = ''
        version  = '1.0.0.0'
        copyright = ''
    }
    if ([string]::IsNullOrWhiteSpace($InputFile)) { return $result }

    $base = Get-PS2EXEFileNameWithoutExtension -Path $InputFile
    $result.title = $base
    $result.product = $base
    try {
        $year = (Get-Date).Year
        $user = [Environment]::UserName
        $result.copyright = "Copyright (c) $year $user"
    }
    catch {
        $result.copyright = "Copyright (c) $([DateTime]::Now.Year)"
    }
    return $result
}

function Add-PS2EXERecentFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$Keep = 12
    )

    $paths = Get-PS2EXEStudioAppData
    $list = @()
    if (Test-PS2EXEPathExists -LiteralPath $paths.RecentFiles -PathType Leaf) {
        try {
            $list = @((Get-Content -LiteralPath $paths.RecentFiles -Raw -Encoding UTF8 | ConvertFrom-Json))
        }
        catch {
            $list = @()
        }
    }
    $full = $Path
    try { $full = [System.IO.Path]::GetFullPath($Path) } catch { }
    $list = @($full) + @($list | Where-Object { $_ -and $_ -ne $full })
    $list = @($list | Select-Object -First $Keep)
    $dir = [System.IO.Path]::GetDirectoryName($paths.RecentFiles)
    if ($dir -and -not (Test-PS2EXEPathExists -LiteralPath $dir -PathType Container)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    ($list | ConvertTo-Json) | Set-Content -LiteralPath $paths.RecentFiles -Encoding UTF8
    return $list
}

function Get-PS2EXERecentFiles {
    $paths = Get-PS2EXEStudioAppData
    if (-not (Test-PS2EXEPathExists -LiteralPath $paths.RecentFiles -PathType Leaf)) { return @() }
    try {
        return @((Get-Content -LiteralPath $paths.RecentFiles -Raw -Encoding UTF8 | ConvertFrom-Json))
    }
    catch {
        return @()
    }
}
