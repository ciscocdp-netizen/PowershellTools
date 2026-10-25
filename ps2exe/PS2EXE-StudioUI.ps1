#Requires -Version 5.1
# WinForms surface for PS2EXE Studio. Dot-sourced by PS2EXE-GUI.ps1 after
# the launcher has loaded the core and confirmed a Windows STA session.

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

$script:EngineLoaded = Import-PS2EXEEngine
$script:Options = New-PS2EXEOptions
$script:Updating = $false
$script:Compiling = $false
$script:LastOutputPath = ''
$script:Theme = @{
    Header     = [System.Drawing.Color]::FromArgb(24, 42, 68)
    SubHeader  = [System.Drawing.Color]::FromArgb(32, 52, 80)
    Background = [System.Drawing.Color]::FromArgb(245, 247, 250)
    Splitter   = [System.Drawing.Color]::FromArgb(220, 225, 232)
    Text       = [System.Drawing.Color]::FromArgb(24, 42, 68)
    Muted      = [System.Drawing.Color]::FromArgb(100, 110, 125)
    Accent     = [System.Drawing.Color]::FromArgb(0, 120, 212)
    Teal       = [System.Drawing.Color]::FromArgb(0, 150, 136)
    Success    = [System.Drawing.Color]::FromArgb(16, 137, 62)
    Warning    = [System.Drawing.Color]::FromArgb(202, 131, 0)
    Error      = [System.Drawing.Color]::FromArgb(196, 43, 28)
    Info       = [System.Drawing.Color]::FromArgb(0, 99, 177)
    White      = [System.Drawing.Color]::White
    FieldBg    = [System.Drawing.Color]::White
    LogBg      = [System.Drawing.Color]::FromArgb(18, 22, 28)
}

function New-StudioFont {
    param([int]$Size = 9, [System.Drawing.FontStyle]$Style = [System.Drawing.FontStyle]::Regular, [string]$Family = 'Segoe UI')
    return New-Object System.Drawing.Font($Family, $Size, $Style)
}

function New-StudioButton {
    param(
        [string]$Text,
        [System.Drawing.Color]$BackColor,
        [int]$Width = 140,
        [int]$Height = 34
    )
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $Text
    $btn.Size = New-Object System.Drawing.Size($Width, $Height)
    $btn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btn.FlatAppearance.BorderSize = 0
    $btn.BackColor = $BackColor
    $btn.ForeColor = $script:Theme.White
    $btn.Font = New-StudioFont -Size 9 -Style Bold
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btn.TabStop = $true
    return $btn
}

function Set-StudioToolTip {
    param($Control, [string]$Text)
    if (-not $script:ToolTip) { return }
    $script:ToolTip.SetToolTip($Control, $Text)
}

function Write-StudioLog {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'CMD')]
        [string]$Level = 'INFO'
    )
    if (-not $script:txtLog) { return }
    $color = switch ($Level) {
        'WARN'    { $script:Theme.Warning }
        'ERROR'   { [System.Drawing.Color]::FromArgb(255, 120, 110) }
        'SUCCESS' { [System.Drawing.Color]::FromArgb(80, 220, 140) }
        'CMD'     { [System.Drawing.Color]::FromArgb(130, 190, 255) }
        default   { [System.Drawing.Color]::FromArgb(210, 220, 230) }
    }
    $stamp = Get-Date -Format 'HH:mm:ss.fff'
    $line = "[{0}] [{1}] {2}`r`n" -f $stamp, $Level, $Message
    $script:txtLog.SelectionStart = $script:txtLog.TextLength
    $script:txtLog.SelectionColor = $color
    $script:txtLog.AppendText($line)
    $script:txtLog.ScrollToCaret()
}

function Set-StudioStatus {
    param([string]$Text, [System.Drawing.Color]$Color = $null)
    if ($script:lblStatus) {
        $script:lblStatus.Text = $Text
        if ($Color) { $script:lblStatus.ForeColor = $Color } else { $script:lblStatus.ForeColor = $script:Theme.White }
    }
}

function Get-StudioCheckValue {
    param([string]$Name)
    if ($script:Checks.ContainsKey($Name)) {
        return [bool]$script:Checks[$Name].Checked
    }
    return $false
}

function Read-StudioOptionsFromUi {
    $opt = Copy-PS2EXEOptions -Options $script:Options
    $opt.inputFile = $script:txtInput.Text.Trim()
    $opt.outputFile = $script:txtOutput.Text.Trim()
    $opt.iconFile = $script:txtIcon.Text.Trim()
    if ($script:rbX86.Checked) { $opt.architecture = 'x86' }
    elseif ($script:rbX64.Checked) { $opt.architecture = 'x64' }
    else { $opt.architecture = 'anycpu' }
    $opt.apartment = $(if ($script:rbMTA.Checked) { 'MTA' } else { 'STA' })
    $lcidVal = 0
    [void][int]::TryParse($script:txtLcid.Text, [ref]$lcidVal)
    $opt.lcid = $lcidVal
    foreach ($name in $script:Checks.Keys) {
        $opt.$name = [bool]$script:Checks[$name].Checked
    }
    $opt.title = $script:txtTitle.Text
    $opt.description = $script:txtDescription.Text
    $opt.company = $script:txtCompany.Text
    $opt.product = $script:txtProduct.Text
    $opt.copyright = $script:txtCopyright.Text
    $opt.trademark = $script:txtTrademark.Text
    $opt.version = $script:txtVersion.Text.Trim()
    $embeds = @()
    foreach ($row in $script:dgvEmbed.Rows) {
        if ($row.IsNewRow) { continue }
        $src = [string]$row.Cells['Source'].Value
        $dst = [string]$row.Cells['Target'].Value
        if (-not [string]::IsNullOrWhiteSpace($src) -or -not [string]::IsNullOrWhiteSpace($dst)) {
            $embeds += [pscustomobject]@{ Source = $src; Target = $dst }
        }
    }
    $opt.embedFiles = $embeds
    return $opt
}

function Write-StudioOptionsToUi {
    param($Options)
    $script:Updating = $true
    try {
        $script:txtInput.Text = [string]$Options.inputFile
        $script:txtOutput.Text = [string]$Options.outputFile
        $script:txtIcon.Text = [string]$Options.iconFile
        switch ([string]$Options.architecture) {
            'x86' { $script:rbX86.Checked = $true }
            'x64' { $script:rbX64.Checked = $true }
            default { $script:rbAnyCpu.Checked = $true }
        }
        if ([string]$Options.apartment -eq 'MTA') { $script:rbMTA.Checked = $true } else { $script:rbSTA.Checked = $true }
        $script:txtLcid.Text = [string]([int]$Options.lcid)
        $lcidInt = [int]$Options.lcid
        $match = $false
        for ($i = 0; $i -lt $script:cmbLcid.Items.Count; $i++) {
            $item = $script:cmbLcid.Items[$i]
            if ([int]$item.Lcid -eq $lcidInt) {
                $script:cmbLcid.SelectedIndex = $i
                $match = $true
                break
            }
        }
        if (-not $match) { $script:cmbLcid.SelectedIndex = 0 }
        foreach ($name in $script:Checks.Keys) {
            $script:Checks[$name].Checked = [bool]$Options.$name
        }
        $script:txtTitle.Text = [string]$Options.title
        $script:txtDescription.Text = [string]$Options.description
        $script:txtCompany.Text = [string]$Options.company
        $script:txtProduct.Text = [string]$Options.product
        $script:txtCopyright.Text = [string]$Options.copyright
        $script:txtTrademark.Text = [string]$Options.trademark
        $script:txtVersion.Text = [string]$Options.version
        $script:dgvEmbed.Rows.Clear()
        foreach ($item in @($Options.embedFiles)) {
            [void]$script:dgvEmbed.Rows.Add([string]$item.Source, [string]$item.Target)
        }
    }
    finally {
        $script:Updating = $false
    }
}

function Update-StudioDependentControls {
    $gui = $script:Checks['noConsole'].Checked
    $conhost = $script:Checks['conHost'].Checked
    foreach ($name in @('noVisualStyles', 'exitOnCancel')) {
        $script:Checks[$name].Enabled = $gui
    }
    $script:Checks['UNICODEEncoding'].Enabled = -not $gui
    $script:Checks['conHost'].Enabled = -not $gui
    $script:Checks['noConsole'].Enabled = -not $conhost
    $virt = $script:Checks['virtualize'].Checked
    foreach ($name in @('requireAdmin', 'supportOS', 'longPaths', 'winFormsDPIAware', 'DPIAware')) {
        if ($virt -and $name -in @('requireAdmin', 'supportOS', 'longPaths')) {
            $script:Checks[$name].Enabled = $false
        }
        else {
            $script:Checks[$name].Enabled = $true
        }
    }
    if ($virt) {
        $script:rbX86.Checked = $true
        $script:rbX64.Enabled = $false
        $script:rbAnyCpu.Enabled = $false
    }
    else {
        $script:rbX64.Enabled = $true
        $script:rbAnyCpu.Enabled = $true
    }
}

function Update-StudioScriptInfo {
    $path = $script:txtInput.Text.Trim()
    $info = Get-PS2EXEScriptInfo -Path $path
    if (-not $info.Exists) {
        $script:txtPreview.Text = 'Select a PowerShell script to preview the first 80 lines, encoding, and comment-based help.'
        $script:lblScriptMeta.Text = 'No script loaded'
        return
    }
    $params = if ($info.Parameters.Count) { $info.Parameters -join ', ' } else { '(none documented)' }
    $synopsis = if ($info.Synopsis) { $info.Synopsis } else { '(no .SYNOPSIS)' }
    $script:lblScriptMeta.Text = "{0}  |  {1}  |  {2} lines  |  {3}  |  {4}" -f `
        $info.Name, (Format-PS2EXEByteSize $info.Length), $info.LineCount, $info.Encoding, $info.LastWrite
    $header = @(
        "Synopsis : $synopsis"
        "Parameters : $params"
        ''
    ) -join [Environment]::NewLine
    $script:txtPreview.Text = $header + $info.Preview
}

function Update-StudioIconPreview {
    if ($script:picIcon.Image) {
        $script:picIcon.Image.Dispose()
        $script:picIcon.Image = $null
    }
    $iconPath = $script:txtIcon.Text.Trim()
    if ($iconPath -and (Test-Path -LiteralPath $iconPath -PathType Leaf)) {
        try {
            $icon = New-Object System.Drawing.Icon($iconPath)
            $script:picIcon.Image = $icon.ToBitmap()
            $icon.Dispose()
        }
        catch {
            $script:picIcon.Image = [System.Drawing.SystemIcons]::Application.ToBitmap()
        }
    }
}

function Update-StudioValidation {
    if ($script:Updating) { return }
    $script:Options = Read-StudioOptionsFromUi
    Update-StudioDependentControls
    $issues = @(Test-PS2EXEOptions -Options $script:Options)
    $script:lstIssues.Items.Clear()
    $errors = 0; $warnings = 0; $infos = 0
    foreach ($issue in $issues) {
        switch ($issue.Severity) {
            'Error'   { $errors++ }
            'Warning' { $warnings++ }
            default   { $infos++ }
        }
        [void]$script:lstIssues.Items.Add(('[{0}] {1}' -f $issue.Severity, $issue.Message))
    }
    if ($issues.Count -eq 0) {
        [void]$script:lstIssues.Items.Add('[Ready] All checks passed. Compile is available.')
    }
    $script:txtCommand.Text = New-PS2EXECommandLine -Options $script:Options
    $ready = Test-PS2EXEReady -Issues $issues
    $script:btnCompile.Enabled = $ready -and $script:EngineLoaded -and -not $script:Compiling
    if (-not $script:EngineLoaded) {
        Set-StudioStatus 'Engine not loaded — command preview still works' $script:Theme.Warning
    }
    elseif ($script:Compiling) {
        Set-StudioStatus 'Compiling...' $script:Theme.Warning
    }
    elseif (-not $ready) {
        Set-StudioStatus ("{0} error(s), {1} warning(s) — fix errors to compile" -f $errors, $warnings) $script:Theme.Error
    }
    elseif ($warnings -gt 0) {
        Set-StudioStatus ("Ready with {0} warning(s), {1} note(s)" -f $warnings, $infos) $script:Theme.Warning
    }
    else {
        Set-StudioStatus 'Ready to compile' $script:Theme.Success
    }
    $resolved = Get-PS2EXEResolvedOutput -Options $script:Options
    if ($resolved) {
        $script:lblResolvedOut.Text = "Resolved output: $resolved"
    }
    else {
        $script:lblResolvedOut.Text = 'Resolved output: (select an input script)'
    }
}

function Use-StudioInputFile {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $script:txtInput.Text = $Path
    if ([string]::IsNullOrWhiteSpace($script:txtOutput.Text)) {
        $script:txtOutput.Text = [System.IO.Path]::ChangeExtension($Path, '.exe')
    }
    $meta = Get-PS2EXEDefaultMetadata -InputFile $Path
    if ([string]::IsNullOrWhiteSpace($script:txtTitle.Text)) { $script:txtTitle.Text = $meta.title }
    if ([string]::IsNullOrWhiteSpace($script:txtProduct.Text)) { $script:txtProduct.Text = $meta.product }
    if ([string]::IsNullOrWhiteSpace($script:txtVersion.Text)) { $script:txtVersion.Text = $meta.version }
    if ([string]::IsNullOrWhiteSpace($script:txtCopyright.Text)) { $script:txtCopyright.Text = $meta.copyright }
    [void](Add-PS2EXERecentFile -Path $Path)
    Refresh-StudioRecent
    Update-StudioScriptInfo
    Update-StudioValidation
}

function Refresh-StudioRecent {
    $script:cmbRecent.Items.Clear()
    foreach ($path in Get-PS2EXERecentFiles) {
        if ($path) { [void]$script:cmbRecent.Items.Add($path) }
    }
}

function Browse-StudioFile {
    param(
        [string]$Title,
        [string]$Filter,
        [string]$Current
    )
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title = $Title
    $dlg.Filter = $Filter
    $dlg.CheckFileExists = $true
    if ($Current -and (Test-Path -LiteralPath $Current)) {
        $dlg.InitialDirectory = [System.IO.Path]::GetDirectoryName($Current)
        $dlg.FileName = [System.IO.Path]::GetFileName($Current)
    }
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $dlg.FileName
    }
    return $null
}

function Browse-StudioSave {
    param(
        [string]$Title,
        [string]$Filter,
        [string]$Current,
        [string]$DefaultExt = 'exe'
    )
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Title = $Title
    $dlg.Filter = $Filter
    $dlg.AddExtension = $true
    $dlg.DefaultExt = $DefaultExt
    $dlg.OverwritePrompt = $true
    if ($Current) {
        try {
            $dlg.InitialDirectory = [System.IO.Path]::GetDirectoryName($Current)
            $dlg.FileName = [System.IO.Path]::GetFileName($Current)
        }
        catch { }
    }
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $dlg.FileName
    }
    return $null
}

function Invoke-StudioCompile {
    if ($script:Compiling) { return }
    Update-StudioValidation
    $issues = @(Test-PS2EXEOptions -Options $script:Options)
    if (-not (Test-PS2EXEReady -Issues $issues)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Fix the reported errors before compiling.`n`n" + (($issues | Where-Object Severity -eq Error | ForEach-Object { $_.Message }) -join "`n"),
            'Cannot compile',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return
    }
    if (-not $script:EngineLoaded) {
        [System.Windows.Forms.MessageBox]::Show(
            "The PS2EXE engine is not loaded. Place Invoke-ps2exe.ps1 in the ps2exe folder or install the ps2exe module.",
            'Engine missing',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        return
    }

    $script:Compiling = $true
    $script:btnCompile.Enabled = $false
    $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    $script:progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee
    $script:progressBar.MarqueeAnimationSpeed = 30
    Set-StudioStatus 'Compiling...' $script:Theme.Warning
    [System.Windows.Forms.Application]::DoEvents()

    $command = New-PS2EXECommandLine -Options $script:Options
    Write-StudioLog '========================================' 'INFO'
    Write-StudioLog 'Compile started' 'INFO'
    Write-StudioLog $command 'CMD'
    Write-StudioLog ("PowerShell {0} | {1}" -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition) 'INFO'

    $ok = $false
    $resolved = Get-PS2EXEResolvedOutput -Options $script:Options
    try {
        $splat = ConvertTo-PS2EXESplat -Options $script:Options
        if ($script:Options.verbose) {
            $splat['Verbose'] = $true
        }

        $output = $null
        $errRec = $null
        $warnRec = $null
        $output = Invoke-ps2exe @splat -ErrorVariable errRec -WarningVariable warnRec *>&1

        foreach ($item in @($output)) {
            $text = [string]$item
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            if ($item -is [System.Management.Automation.ErrorRecord]) {
                Write-StudioLog $text 'ERROR'
            }
            elseif ($item -is [System.Management.Automation.WarningRecord]) {
                Write-StudioLog $text 'WARN'
            }
            else {
                Write-StudioLog $text 'INFO'
            }
            [System.Windows.Forms.Application]::DoEvents()
        }
        foreach ($w in @($warnRec)) { Write-StudioLog ([string]$w) 'WARN' }
        foreach ($e in @($errRec)) { Write-StudioLog ([string]$e) 'ERROR' }

        if ($resolved -and (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            $ok = $true
            $script:LastOutputPath = $resolved
            $item = Get-Item -LiteralPath $resolved
            Write-StudioLog ("Output written: {0} ({1})" -f $resolved, (Format-PS2EXEByteSize $item.Length)) 'SUCCESS'
            Set-StudioStatus "Compiled: $($item.Name)" $script:Theme.Success
            $script:btnOpenFolder.Enabled = $true
            $script:btnRunExe.Enabled = $true
        }
        else {
            Write-StudioLog "Compiler finished but output file was not found: $resolved" 'ERROR'
            Set-StudioStatus 'Compile failed — see log' $script:Theme.Error
        }
    }
    catch {
        Write-StudioLog $_.Exception.Message 'ERROR'
        if ($_.ScriptStackTrace) { Write-StudioLog $_.ScriptStackTrace 'ERROR' }
        Set-StudioStatus 'Compile failed — see log' $script:Theme.Error
    }
    finally {
        $script:Compiling = $false
        $script:form.Cursor = [System.Windows.Forms.Cursors]::Default
        $script:progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
        $script:progressBar.MarqueeAnimationSpeed = 0
        $script:progressBar.Value = 0
        Update-StudioValidation
        if ($ok) { Set-StudioStatus "Compiled: $resolved" $script:Theme.Success }
    }
}

function Show-StudioAbout {
    $text = @"
PS2EXE Studio $($script:PS2EXEStudioVersion)

Interactive compiler workbench for Invoke-ps2exe.

Engine
  PS2EXE / PS2EXE-GUI by Ingo Karstein and Markus Scholtes
  Bundled: ps2exe\Invoke-ps2exe.ps1
  License: Microsoft Public License (Ms-PL)
  https://github.com/MScholtes/PS2EXE

A generated EXE reserves: -?, -debug, -extract:<FILE>, -wait, -end

Tips
  • Scripts must be UTF-8 or UTF-16.
  • In GUI mode, pipe output to Out-String to avoid a dialog per line.
  • -end separates host switches from script arguments.
  • F5 compiles, Ctrl+O opens a script, Ctrl+L copies the command.
"@
    [System.Windows.Forms.MessageBox]::Show($text, 'About PS2EXE Studio', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
}

# ------------------------------------------------------------
# BUILD UI
# ------------------------------------------------------------
$script:form = New-Object System.Windows.Forms.Form
$script:form.Text = "PS2EXE Studio v$($script:PS2EXEStudioVersion) - PowerShell to EXE"
$script:form.Size = New-Object System.Drawing.Size(1440, 960)
$script:form.MinimumSize = New-Object System.Drawing.Size(1120, 760)
$script:form.StartPosition = 'CenterScreen'
$script:form.Font = New-StudioFont 9
$script:form.BackColor = $script:Theme.Background
$script:form.KeyPreview = $true
$script:form.AllowDrop = $true
$script:form.Icon = [System.Drawing.SystemIcons]::Application

$script:ToolTip = New-Object System.Windows.Forms.ToolTip
$script:ToolTip.AutoPopDelay = 20000
$script:ToolTip.InitialDelay = 400
$script:ToolTip.ReshowDelay = 100
$script:ToolTip.ShowAlways = $true

# Header
$header = New-Object System.Windows.Forms.Panel
$header.Dock = 'Top'
$header.Height = 62
$header.BackColor = $script:Theme.Header
$script:form.Controls.Add($header)

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = 'PS2EXE Studio'
$lblTitle.Font = New-StudioFont 16 Bold
$lblTitle.ForeColor = $script:Theme.White
$lblTitle.AutoSize = $true
$lblTitle.Location = New-Object System.Drawing.Point(20, 14)
$header.Controls.Add($lblTitle)

$lblSubtitle = New-Object System.Windows.Forms.Label
$engineLabel = if ($script:EngineLoaded) { 'engine loaded' } else { 'engine missing' }
$lblSubtitle.Text = "v$($script:PS2EXEStudioVersion)  |  Interactive compiler for Invoke-ps2exe 0.5.0.31+  |  $engineLabel  |  $env:USERNAME"
$lblSubtitle.Font = New-StudioFont 9
$lblSubtitle.ForeColor = [System.Drawing.Color]::FromArgb(160, 185, 215)
$lblSubtitle.AutoSize = $true
$lblSubtitle.Location = New-Object System.Drawing.Point(250, 22)
$header.Controls.Add($lblSubtitle)

# Toolbar
$toolbar = New-Object System.Windows.Forms.Panel
$toolbar.Dock = 'Top'
$toolbar.Height = 54
$toolbar.BackColor = $script:Theme.SubHeader
$toolbar.Padding = New-Object System.Windows.Forms.Padding(16, 10, 16, 10)
$script:form.Controls.Add($toolbar)

$lblPreset = New-Object System.Windows.Forms.Label
$lblPreset.Text = 'Preset'
$lblPreset.ForeColor = $script:Theme.White
$lblPreset.AutoSize = $true
$lblPreset.Location = New-Object System.Drawing.Point(20, 18)
$toolbar.Controls.Add($lblPreset)

$script:cmbPreset = New-Object System.Windows.Forms.ComboBox
$script:cmbPreset.DropDownStyle = 'DropDownList'
$script:cmbPreset.Location = New-Object System.Drawing.Point(70, 14)
$script:cmbPreset.Size = New-Object System.Drawing.Size(200, 28)
$script:cmbPreset.Font = New-StudioFont 9
foreach ($name in (Get-PS2EXEPresets).Keys) { [void]$script:cmbPreset.Items.Add($name) }
$script:cmbPreset.SelectedIndex = 0
Set-StudioToolTip $script:cmbPreset 'Apply a curated set of compiler switches. Existing file paths and metadata are kept.'
$toolbar.Controls.Add($script:cmbPreset)

$btnApplyPreset = New-StudioButton 'Apply preset' $script:Theme.Accent 120 28
$btnApplyPreset.Location = New-Object System.Drawing.Point(280, 13)
$toolbar.Controls.Add($btnApplyPreset)

$lblRecent = New-Object System.Windows.Forms.Label
$lblRecent.Text = 'Recent'
$lblRecent.ForeColor = $script:Theme.White
$lblRecent.AutoSize = $true
$lblRecent.Location = New-Object System.Drawing.Point(415, 18)
$toolbar.Controls.Add($lblRecent)

$script:cmbRecent = New-Object System.Windows.Forms.ComboBox
$script:cmbRecent.DropDownStyle = 'DropDownList'
$script:cmbRecent.Location = New-Object System.Drawing.Point(470, 14)
$script:cmbRecent.Size = New-Object System.Drawing.Size(320, 28)
$script:cmbRecent.Font = New-StudioFont 8
$toolbar.Controls.Add($script:cmbRecent)

$btnSaveProfile = New-StudioButton 'Save profile' $script:Theme.Teal 110 28
$btnSaveProfile.Location = New-Object System.Drawing.Point(800, 13)
$toolbar.Controls.Add($btnSaveProfile)

$btnLoadProfile = New-StudioButton 'Load profile' $script:Theme.Teal 110 28
$btnLoadProfile.Location = New-Object System.Drawing.Point(916, 13)
$toolbar.Controls.Add($btnLoadProfile)

$btnReset = New-StudioButton 'Reset' $script:Theme.Muted 80 28
$btnReset.Location = New-Object System.Drawing.Point(1032, 13)
$toolbar.Controls.Add($btnReset)

$btnAbout = New-StudioButton 'About' $script:Theme.Muted 80 28
$btnAbout.Location = New-Object System.Drawing.Point(1118, 13)
$toolbar.Controls.Add($btnAbout)

# Footer first so Fill split sits between header/toolbar and footer
$footer = New-Object System.Windows.Forms.Panel
$footer.Dock = 'Bottom'
$footer.Height = 58
$footer.BackColor = $script:Theme.Header
$script:form.Controls.Add($footer)

$script:lblStatus = New-Object System.Windows.Forms.Label
$script:lblStatus.Text = 'Ready'
$script:lblStatus.ForeColor = $script:Theme.White
$script:lblStatus.AutoSize = $true
$script:lblStatus.Location = New-Object System.Drawing.Point(20, 20)
$script:lblStatus.Font = New-StudioFont 9
$footer.Controls.Add($script:lblStatus)

$script:progressBar = New-Object System.Windows.Forms.ProgressBar
$script:progressBar.Location = New-Object System.Drawing.Point(20, 40)
$script:progressBar.Size = New-Object System.Drawing.Size(280, 8)
$footer.Controls.Add($script:progressBar)

$script:btnCompile = New-StudioButton 'Compile  (F5)' $script:Theme.Success 150 34
$script:btnOpenFolder = New-StudioButton 'Open folder' $script:Theme.Accent 120 34
$script:btnRunExe = New-StudioButton 'Run EXE' $script:Theme.Teal 110 34
$script:btnCopyCmd = New-StudioButton 'Copy command' $script:Theme.Accent 140 34
$script:btnClearLog = New-StudioButton 'Clear log' $script:Theme.Muted 100 34
$script:btnOpenFolder.Enabled = $false
$script:btnRunExe.Enabled = $false

$footerButtons = @($script:btnCompile, $script:btnOpenFolder, $script:btnRunExe, $script:btnCopyCmd, $script:btnClearLog)
$fx = 980
foreach ($b in $footerButtons) {
    $b.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $footer.Controls.Add($b)
}
$script:form.Add_Resize({
    $x = $script:form.ClientSize.Width - 20
    foreach ($b in @($script:btnClearLog, $script:btnCopyCmd, $script:btnRunExe, $script:btnOpenFolder, $script:btnCompile)) {
        $x -= $b.Width + 8
        $b.Location = New-Object System.Drawing.Point($x, 12)
    }
})

# Main split: tabs / log
$split = New-Object System.Windows.Forms.SplitContainer
$split.Dock = 'Fill'
$split.Orientation = 'Horizontal'
$split.SplitterWidth = 6
$split.BackColor = $script:Theme.Splitter
$split.Panel1.BackColor = $script:Theme.Background
$split.Panel2.BackColor = $script:Theme.Background
$script:form.Controls.Add($split)
$split.BringToFront()
$header.BringToFront()
$toolbar.BringToFront()
$footer.SendToBack()

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$tabs.Font = New-StudioFont 10 Bold
$tabs.Padding = New-Object System.Drawing.Point(14, 6)
$split.Panel1.Controls.Add($tabs)

function New-StudioTab([string]$Text) {
    $tab = New-Object System.Windows.Forms.TabPage
    $tab.Text = "  $Text  "
    $tab.BackColor = $script:Theme.Background
    $tab.UseVisualStyleBackColor = $true
    [void]$tabs.TabPages.Add($tab)
    return $tab
}

$tabCompile = New-StudioTab 'Compile'
$tabRuntime = New-StudioTab 'Runtime'
$tabOptions = New-StudioTab 'Options'
$tabMeta = New-StudioTab 'Metadata'
$tabEmbed = New-StudioTab 'Embed files'
$tabHelp = New-StudioTab 'Help'

# ---- Compile tab ----
$compileLeft = New-Object System.Windows.Forms.Panel
$compileLeft.Dock = 'Fill'
$compileLeft.Padding = New-Object System.Windows.Forms.Padding(16)
$tabCompile.Controls.Add($compileLeft)

function Add-FileRow {
    param($Parent, [int]$Top, [string]$Label, [string]$Tip)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Label
    $lbl.Font = New-StudioFont 9 Bold
    $lbl.ForeColor = $script:Theme.Text
    $lbl.Location = New-Object System.Drawing.Point(16, $Top)
    $lbl.AutoSize = $true
    $Parent.Controls.Add($lbl)
    Set-StudioToolTip $lbl $Tip

    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Font = New-Object System.Drawing.Font('Consolas', 10)
    $txt.Location = New-Object System.Drawing.Point(16, ($Top + 20))
    $txt.Size = New-Object System.Drawing.Size(620, 26)
    $txt.Anchor = 'Top,Left,Right'
    $Parent.Controls.Add($txt)

    $btn = New-StudioButton 'Browse...' $script:Theme.Accent 100 26
    $btn.Anchor = 'Top,Right'
    $btn.Location = New-Object System.Drawing.Point(646, ($Top + 20))
    $Parent.Controls.Add($btn)

    $btnClear = New-StudioButton 'Clear' $script:Theme.Muted 70 26
    $btnClear.Anchor = 'Top,Right'
    $btnClear.Location = New-Object System.Drawing.Point(752, ($Top + 20))
    $Parent.Controls.Add($btnClear)
    return @{ Text = $txt; Browse = $btn; Clear = $btnClear }
}

$script:AllowDropHint = New-Object System.Windows.Forms.Label
$script:AllowDropHint.Text = 'Drag a .ps1, .ico, or .json profile onto this window. F5 compiles. Ctrl+O opens a script. Ctrl+L copies the command.'
$script:AllowDropHint.ForeColor = $script:Theme.Muted
$script:AllowDropHint.Location = New-Object System.Drawing.Point(16, 12)
$script:AllowDropHint.AutoSize = $true
$compileLeft.Controls.Add($script:AllowDropHint)

$inputRow = Add-FileRow $compileLeft 40 'Input script  (required)' 'PowerShell script to compile. Must be UTF-8 or UTF-16 encoded.'
$script:txtInput = $inputRow.Text
$outputRow = Add-FileRow $compileLeft 100 'Output executable' 'Destination .exe/.com path, or a folder. Defaults to the input name with a .exe extension.'
$script:txtOutput = $outputRow.Text
$iconRow = Add-FileRow $compileLeft 160 'Icon file  (.ico)' 'Optional Win32 icon embedded in the executable.'
$script:txtIcon = $iconRow.Text

$script:picIcon = New-Object System.Windows.Forms.PictureBox
$script:picIcon.Size = New-Object System.Drawing.Size(48, 48)
$script:picIcon.Location = New-Object System.Drawing.Point(830, 180)
$script:picIcon.Anchor = 'Top,Right'
$script:picIcon.SizeMode = 'Zoom'
$script:picIcon.BorderStyle = 'FixedSingle'
$compileLeft.Controls.Add($script:picIcon)

$script:lblResolvedOut = New-Object System.Windows.Forms.Label
$script:lblResolvedOut.Text = 'Resolved output: (select an input script)'
$script:lblResolvedOut.ForeColor = $script:Theme.Info
$script:lblResolvedOut.Location = New-Object System.Drawing.Point(16, 222)
$script:lblResolvedOut.AutoSize = $true
$compileLeft.Controls.Add($script:lblResolvedOut)

$script:lblScriptMeta = New-Object System.Windows.Forms.Label
$script:lblScriptMeta.Text = 'No script loaded'
$script:lblScriptMeta.ForeColor = $script:Theme.Muted
$script:lblScriptMeta.Location = New-Object System.Drawing.Point(16, 244)
$script:lblScriptMeta.AutoSize = $true
$compileLeft.Controls.Add($script:lblScriptMeta)

$lblIssues = New-Object System.Windows.Forms.Label
$lblIssues.Text = 'Live validation'
$lblIssues.Font = New-StudioFont 9 Bold
$lblIssues.ForeColor = $script:Theme.Text
$lblIssues.Location = New-Object System.Drawing.Point(16, 272)
$compileLeft.Controls.Add($lblIssues)

$script:lstIssues = New-Object System.Windows.Forms.ListBox
$script:lstIssues.Location = New-Object System.Drawing.Point(16, 294)
$script:lstIssues.Size = New-Object System.Drawing.Size(900, 90)
$script:lstIssues.Anchor = 'Top,Left,Right'
$script:lstIssues.Font = New-Object System.Drawing.Font('Consolas', 9)
$compileLeft.Controls.Add($script:lstIssues)

$lblCmd = New-Object System.Windows.Forms.Label
$lblCmd.Text = 'Command preview  (updates as you change options)'
$lblCmd.Font = New-StudioFont 9 Bold
$lblCmd.ForeColor = $script:Theme.Text
$lblCmd.Location = New-Object System.Drawing.Point(16, 394)
$compileLeft.Controls.Add($lblCmd)

$script:txtCommand = New-Object System.Windows.Forms.TextBox
$script:txtCommand.Multiline = $true
$script:txtCommand.ReadOnly = $true
$script:txtCommand.ScrollBars = 'Vertical'
$script:txtCommand.Font = New-Object System.Drawing.Font('Consolas', 10)
$script:txtCommand.Location = New-Object System.Drawing.Point(16, 416)
$script:txtCommand.Size = New-Object System.Drawing.Size(900, 70)
$script:txtCommand.Anchor = 'Top,Left,Right'
$script:txtCommand.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 22)
$script:txtCommand.ForeColor = [System.Drawing.Color]::FromArgb(0, 210, 106)
$compileLeft.Controls.Add($script:txtCommand)

$lblPreview = New-Object System.Windows.Forms.Label
$lblPreview.Text = 'Script preview'
$lblPreview.Font = New-StudioFont 9 Bold
$lblPreview.ForeColor = $script:Theme.Text
$lblPreview.Location = New-Object System.Drawing.Point(16, 496)
$compileLeft.Controls.Add($lblPreview)

$script:txtPreview = New-Object System.Windows.Forms.TextBox
$script:txtPreview.Multiline = $true
$script:txtPreview.ReadOnly = $true
$script:txtPreview.ScrollBars = 'Both'
$script:txtPreview.WordWrap = $false
$script:txtPreview.Font = New-Object System.Drawing.Font('Consolas', 9)
$script:txtPreview.Location = New-Object System.Drawing.Point(16, 518)
$script:txtPreview.Size = New-Object System.Drawing.Size(900, 130)
$script:txtPreview.Anchor = 'Top,Bottom,Left,Right'
$script:txtPreview.BackColor = $script:Theme.White
$compileLeft.Controls.Add($script:txtPreview)

# ---- Runtime tab ----
$grpArch = New-Object System.Windows.Forms.GroupBox
$grpArch.Text = ' Platform '
$grpArch.Font = New-StudioFont 10 Bold
$grpArch.ForeColor = $script:Theme.Text
$grpArch.Location = New-Object System.Drawing.Point(20, 20)
$grpArch.Size = New-Object System.Drawing.Size(420, 120)
$tabRuntime.Controls.Add($grpArch)

$script:rbAnyCpu = New-Object System.Windows.Forms.RadioButton
$script:rbAnyCpu.Text = 'AnyCPU  (default)'
$script:rbX86 = New-Object System.Windows.Forms.RadioButton
$script:rbX86.Text = 'x86  (32-bit only)'
$script:rbX64 = New-Object System.Windows.Forms.RadioButton
$script:rbX64.Text = 'x64  (64-bit only)'
$script:rbAnyCpu.Location = New-Object System.Drawing.Point(20, 30)
$script:rbX86.Location = New-Object System.Drawing.Point(20, 55)
$script:rbX64.Location = New-Object System.Drawing.Point(20, 80)
$script:rbAnyCpu.AutoSize = $true
$script:rbX86.AutoSize = $true
$script:rbX64.AutoSize = $true
$script:rbAnyCpu.Font = New-StudioFont 9
$script:rbX86.Font = New-StudioFont 9
$script:rbX64.Font = New-StudioFont 9
$script:rbAnyCpu.Checked = $true
$grpArch.Controls.AddRange(@($script:rbAnyCpu, $script:rbX86, $script:rbX64))
Set-StudioToolTip $script:rbAnyCpu 'Compile for any CPU. The EXE runs as 64-bit on 64-bit Windows and 32-bit on 32-bit Windows.'
Set-StudioToolTip $script:rbX86 'Force 32-bit runtime. Required when application virtualization is enabled.'
Set-StudioToolTip $script:rbX64 'Force 64-bit runtime only.'

$grpApt = New-Object System.Windows.Forms.GroupBox
$grpApt.Text = ' Thread apartment '
$grpApt.Font = New-StudioFont 10 Bold
$grpApt.ForeColor = $script:Theme.Text
$grpApt.Location = New-Object System.Drawing.Point(460, 20)
$grpApt.Size = New-Object System.Drawing.Size(420, 120)
$tabRuntime.Controls.Add($grpApt)

$script:rbSTA = New-Object System.Windows.Forms.RadioButton
$script:rbMTA = New-Object System.Windows.Forms.RadioButton
$script:rbSTA.Text = 'STA  — Single Thread Apartment (default, required for WinForms)'
$script:rbMTA.Text = 'MTA  — Multi Thread Apartment'
$script:rbSTA.Location = New-Object System.Drawing.Point(20, 35)
$script:rbMTA.Location = New-Object System.Drawing.Point(20, 70)
$script:rbSTA.AutoSize = $true
$script:rbMTA.AutoSize = $true
$script:rbSTA.Font = New-StudioFont 9
$script:rbMTA.Font = New-StudioFont 9
$script:rbSTA.Checked = $true
$grpApt.Controls.AddRange(@($script:rbSTA, $script:rbMTA))
Set-StudioToolTip $script:rbSTA 'Default apartment. Use STA for any script that creates Windows Forms or WPF windows.'
Set-StudioToolTip $script:rbMTA 'Multi-thread apartment. Rarely needed; incompatible with most UI frameworks.'

$grpCulture = New-Object System.Windows.Forms.GroupBox
$grpCulture.Text = ' Culture / LCID '
$grpCulture.Font = New-StudioFont 10 Bold
$grpCulture.ForeColor = $script:Theme.Text
$grpCulture.Location = New-Object System.Drawing.Point(20, 160)
$grpCulture.Size = New-Object System.Drawing.Size(860, 120)
$tabRuntime.Controls.Add($grpCulture)

$lblCulture = New-Object System.Windows.Forms.Label
$lblCulture.Text = 'Common cultures'
$lblCulture.Font = New-StudioFont 9
$lblCulture.Location = New-Object System.Drawing.Point(20, 32)
$lblCulture.AutoSize = $true
$grpCulture.Controls.Add($lblCulture)

$script:cmbLcid = New-Object System.Windows.Forms.ComboBox
$script:cmbLcid.DropDownStyle = 'DropDownList'
$script:cmbLcid.Location = New-Object System.Drawing.Point(20, 55)
$script:cmbLcid.Size = New-Object System.Drawing.Size(420, 28)
$script:cmbLcid.Font = New-StudioFont 9
$script:cmbLcid.DisplayMember = 'Name'
$script:cmbLcid.ValueMember = 'Lcid'
foreach ($c in Get-PS2EXECommonCultures) { [void]$script:cmbLcid.Items.Add($c) }
$script:cmbLcid.SelectedIndex = 0
$grpCulture.Controls.Add($script:cmbLcid)
Set-StudioToolTip $script:cmbLcid 'Sets Thread.CurrentCulture / CurrentUICulture inside the generated EXE. 0 = current user culture.'

$lblLcid = New-Object System.Windows.Forms.Label
$lblLcid.Text = 'LCID'
$lblLcid.Font = New-StudioFont 9
$lblLcid.Location = New-Object System.Drawing.Point(460, 32)
$lblLcid.AutoSize = $true
$grpCulture.Controls.Add($lblLcid)

$script:txtLcid = New-Object System.Windows.Forms.TextBox
$script:txtLcid.Text = '0'
$script:txtLcid.Location = New-Object System.Drawing.Point(460, 55)
$script:txtLcid.Size = New-Object System.Drawing.Size(80, 26)
$script:txtLcid.Font = New-Object System.Drawing.Font('Consolas', 10)
$grpCulture.Controls.Add($script:txtLcid)

$lblLcidHelp = New-Object System.Windows.Forms.Label
$lblLcidHelp.Text = '0 means "do not embed a culture". Any other LCID is written into the EXE host.'
$lblLcidHelp.Font = New-StudioFont 8
$lblLcidHelp.ForeColor = $script:Theme.Muted
$lblLcidHelp.Location = New-Object System.Drawing.Point(550, 58)
$lblLcidHelp.AutoSize = $true
$grpCulture.Controls.Add($lblLcidHelp)

$lblRuntimeNote = New-Object System.Windows.Forms.Label
$lblRuntimeNote.Text = "Virtualization forces x86. STA is the safe default. Windows GUI apps should stay on STA.`r`nPowerShell 7 hosts re-launch Windows PowerShell Desktop because the compiler requires System.Management.Automation from Desktop."
$lblRuntimeNote.Font = New-StudioFont 9
$lblRuntimeNote.ForeColor = $script:Theme.Muted
$lblRuntimeNote.Location = New-Object System.Drawing.Point(20, 300)
$lblRuntimeNote.Size = New-Object System.Drawing.Size(860, 60)
$tabRuntime.Controls.Add($lblRuntimeNote)

# ---- Options tab ----
$optScroll = New-Object System.Windows.Forms.Panel
$optScroll.Dock = 'Fill'
$optScroll.AutoScroll = $true
$optScroll.Padding = New-Object System.Windows.Forms.Padding(16)
$tabOptions.Controls.Add($optScroll)

$script:Checks = @{}
$catalog = Get-PS2EXEOptionCatalog
$grouped = $catalog | Group-Object Category
$optY = 16
foreach ($group in $grouped) {
    $box = New-Object System.Windows.Forms.GroupBox
    $box.Text = " $($group.Name) "
    $box.Font = New-StudioFont 10 Bold
    $box.ForeColor = $script:Theme.Text
    $box.Location = New-Object System.Drawing.Point(20, $optY)
    $height = 36 + ($group.Group.Count * 28)
    $box.Size = New-Object System.Drawing.Size(980, $height)
    $optScroll.Controls.Add($box)
    $iy = 28
    foreach ($item in $group.Group) {
        $chk = New-Object System.Windows.Forms.CheckBox
        $chk.Text = $item.Label
        $chk.Font = New-StudioFont 9
        $chk.AutoSize = $true
        $chk.Location = New-Object System.Drawing.Point(20, $iy)
        $chk.Tag = $item.Name
        Set-StudioToolTip $chk $item.Tooltip
        $box.Controls.Add($chk)
        $script:Checks[$item.Name] = $chk
        $iy += 28
    }
    $optY += $height + 12
}

# ---- Metadata tab ----
function Add-MetaField {
    param($Parent, [int]$Top, [string]$Label, [int]$Height = 26, [switch]$Multiline)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Label
    $lbl.Font = New-StudioFont 9 Bold
    $lbl.ForeColor = $script:Theme.Text
    $lbl.Location = New-Object System.Drawing.Point(20, $Top)
    $lbl.Size = New-Object System.Drawing.Size(160, 22)
    $Parent.Controls.Add($lbl)
    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Location = New-Object System.Drawing.Point(190, $Top)
    $txt.Size = New-Object System.Drawing.Size(620, $Height)
    $txt.Anchor = 'Top,Left,Right'
    if ($Multiline) {
        $txt.Multiline = $true
        $txt.ScrollBars = 'Vertical'
    }
    $Parent.Controls.Add($txt)
    return $txt
}

$script:txtTitle = Add-MetaField $tabMeta 24 'Title'
$script:txtProduct = Add-MetaField $tabMeta 60 'Product'
$script:txtVersion = Add-MetaField $tabMeta 96 'Version'
$script:txtCompany = Add-MetaField $tabMeta 132 'Company'
$script:txtCopyright = Add-MetaField $tabMeta 168 'Copyright'
$script:txtTrademark = Add-MetaField $tabMeta 204 'Trademark'
$script:txtDescription = Add-MetaField $tabMeta 240 'Description' 80 -Multiline

$lblVerHelp = New-Object System.Windows.Forms.Label
$lblVerHelp.Text = "Version must be n, n.n, n.n.n, or n.n.n.n. Title, product, copyright, and trademark appear on the EXE Details tab in Explorer.`r`nDescription and company are embedded but not shown in that dialog. Backslashes are escaped by the compiler."
$lblVerHelp.Font = New-StudioFont 8
$lblVerHelp.ForeColor = $script:Theme.Muted
$lblVerHelp.Location = New-Object System.Drawing.Point(190, 330)
$lblVerHelp.Size = New-Object System.Drawing.Size(620, 48)
$tabMeta.Controls.Add($lblVerHelp)

$btnFillMeta = New-StudioButton 'Fill from script name' $script:Theme.Accent 180 34
$btnFillMeta.Location = New-Object System.Drawing.Point(190, 380)
$tabMeta.Controls.Add($btnFillMeta)
Set-StudioToolTip $script:txtVersion 'File version written into AssemblyVersion / AssemblyFileVersion. Empty skips both attributes.'
Set-StudioToolTip $script:txtTitle 'AssemblyTitle — shown as File description / Title in Explorer.'

# ---- Embed tab ----
$lblEmbed = New-Object System.Windows.Forms.Label
$lblEmbed.Text = "Files to embed in the EXE and extract on startup. Source file names must be unique.`r`nTarget paths may use %TEMP% / %APPDATA%. A target starting with .\ is relative to the executable."
$lblEmbed.Font = New-StudioFont 9
$lblEmbed.ForeColor = $script:Theme.Text
$lblEmbed.Location = New-Object System.Drawing.Point(16, 16)
$lblEmbed.Size = New-Object System.Drawing.Size(900, 40)
$tabEmbed.Controls.Add($lblEmbed)

$script:dgvEmbed = New-Object System.Windows.Forms.DataGridView
$script:dgvEmbed.Location = New-Object System.Drawing.Point(16, 64)
$script:dgvEmbed.Size = New-Object System.Drawing.Size(900, 280)
$script:dgvEmbed.Anchor = 'Top,Left,Right'
$script:dgvEmbed.AllowUserToAddRows = $true
$script:dgvEmbed.AllowUserToDeleteRows = $true
$script:dgvEmbed.AutoSizeColumnsMode = 'Fill'
$script:dgvEmbed.RowHeadersVisible = $false
$script:dgvEmbed.SelectionMode = 'FullRowSelect'
$script:dgvEmbed.BackgroundColor = $script:Theme.White
$colSrc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colSrc.Name = 'Source'
$colSrc.HeaderText = 'Source file (on this PC)'
$colDst = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDst.Name = 'Target'
$colDst.HeaderText = 'Extract target (runtime path)'
[void]$script:dgvEmbed.Columns.Add($colSrc)
[void]$script:dgvEmbed.Columns.Add($colDst)
$tabEmbed.Controls.Add($script:dgvEmbed)

$btnAddEmbed = New-StudioButton 'Add file...' $script:Theme.Accent 120 34
$btnAddEmbed.Location = New-Object System.Drawing.Point(16, 356)
$btnRemoveEmbed = New-StudioButton 'Remove selected' $script:Theme.Error 150 34
$btnRemoveEmbed.Location = New-Object System.Drawing.Point(144, 356)
$tabEmbed.Controls.AddRange(@($btnAddEmbed, $btnRemoveEmbed))

# ---- Help tab ----
$helpText = New-Object System.Windows.Forms.TextBox
$helpText.Multiline = $true
$helpText.ReadOnly = $true
$helpText.ScrollBars = 'Vertical'
$helpText.Dock = 'Fill'
$helpText.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$helpText.BackColor = $script:Theme.White
$helpLines = New-Object System.Collections.Generic.List[string]
[void]$helpLines.Add('PS2EXE Studio')
[void]$helpLines.Add('=============')
[void]$helpLines.Add('')
[void]$helpLines.Add('Compile a UTF-8 or UTF-16 PowerShell script to a real Windows executable.')
[void]$helpLines.Add('The compiler embeds your script and hosts it in a small C# PowerShell host.')
[void]$helpLines.Add('')
[void]$helpLines.Add('Reserved parameters on every generated EXE')
[void]$helpLines.Add('------------------------------------------')
foreach ($p in Get-PS2EXEReservedRuntimeParameters) {
    [void]$helpLines.Add(('  {0,-18} {1}' -f $p.Name, $p.Description))
}
[void]$helpLines.Add('')
[void]$helpLines.Add('Option notes')
[void]$helpLines.Add('------------')
foreach ($item in Get-PS2EXEOptionCatalog) {
    [void]$helpLines.Add(('  {0}' -f $item.Label))
    [void]$helpLines.Add(('      {0}' -f $item.Tooltip))
}
[void]$helpLines.Add('')
[void]$helpLines.Add('Conflicts the compiler rejects')
[void]$helpLines.Add('------------------------------')
[void]$helpLines.Add('  STA + MTA')
[void]$helpLines.Add('  noConsole + conHost')
[void]$helpLines.Add('  requireAdmin + virtualize')
[void]$helpLines.Add('  supportOS + virtualize')
[void]$helpLines.Add('  longPaths + virtualize')
[void]$helpLines.Add('  configFile + noConfigFile')
[void]$helpLines.Add('  longPaths or winFormsDPIAware + noConfigFile')
[void]$helpLines.Add('')
[void]$helpLines.Add('Keyboard')
[void]$helpLines.Add('--------')
[void]$helpLines.Add('  F5        Compile')
[void]$helpLines.Add('  Ctrl+O    Browse for input script')
[void]$helpLines.Add('  Ctrl+L    Copy command preview')
[void]$helpLines.Add('  Ctrl+S    Save profile')
[void]$helpLines.Add('')
[void]$helpLines.Add('License')
[void]$helpLines.Add('-------')
[void]$helpLines.Add('  PS2EXE engine: Microsoft Public License (Ms-PL), Ingo Karstein & Markus Scholtes')
[void]$helpLines.Add('  https://github.com/MScholtes/PS2EXE')
$helpText.Text = $helpLines -join [Environment]::NewLine
$tabHelp.Controls.Add($helpText)

# ---- Log panel ----
$logHeader = New-Object System.Windows.Forms.Label
$logHeader.Text = '  Compile log'
$logHeader.Dock = 'Top'
$logHeader.Height = 24
$logHeader.Font = New-StudioFont 9 Bold
$logHeader.ForeColor = $script:Theme.Text
$split.Panel2.Controls.Add($logHeader)

$script:txtLog = New-Object System.Windows.Forms.RichTextBox
$script:txtLog.Dock = 'Fill'
$script:txtLog.ReadOnly = $true
$script:txtLog.Font = New-Object System.Drawing.Font('Consolas', 9)
$script:txtLog.BackColor = $script:Theme.LogBg
$script:txtLog.ForeColor = [System.Drawing.Color]::FromArgb(210, 220, 230)
$script:txtLog.HideSelection = $false
$split.Panel2.Controls.Add($script:txtLog)
$script:txtLog.BringToFront()

# ------------------------------------------------------------
# EVENTS
# ------------------------------------------------------------
$updateHandler = { Update-StudioValidation }
foreach ($ctrl in @($script:txtInput, $script:txtOutput, $script:txtIcon, $script:txtLcid, $script:txtTitle, $script:txtProduct, $script:txtVersion, $script:txtCompany, $script:txtCopyright, $script:txtTrademark, $script:txtDescription)) {
    $ctrl.Add_TextChanged($updateHandler)
}
foreach ($rb in @($script:rbAnyCpu, $script:rbX86, $script:rbX64, $script:rbSTA, $script:rbMTA)) {
    $rb.Add_CheckedChanged($updateHandler)
}
foreach ($chk in $script:Checks.Values) {
    $chk.Add_CheckedChanged($updateHandler)
}
$script:dgvEmbed.Add_CellValueChanged({ Update-StudioValidation })
$script:dgvEmbed.Add_RowsRemoved({ Update-StudioValidation })
$script:dgvEmbed.Add_UserDeletedRow({ Update-StudioValidation })

$script:txtInput.Add_Leave({ Update-StudioScriptInfo })
$script:txtIcon.Add_TextChanged({ Update-StudioIconPreview })

$script:cmbLcid.Add_SelectedIndexChanged({
    if ($script:Updating) { return }
    $item = $script:cmbLcid.SelectedItem
    if ($item) { $script:txtLcid.Text = [string]$item.Lcid }
})

$inputRow.Browse.Add_Click({
    $picked = Browse-StudioFile -Title 'Select PowerShell script' -Filter 'PowerShell (*.ps1;*.psm1)|*.ps1;*.psm1|All files (*.*)|*.*' -Current $script:txtInput.Text
    if ($picked) { Use-StudioInputFile -Path $picked }
})
$inputRow.Clear.Add_Click({ $script:txtInput.Clear(); Update-StudioScriptInfo; Update-StudioValidation })

$outputRow.Browse.Add_Click({
    $picked = Browse-StudioSave -Title 'Executable destination' -Filter 'Executable (*.exe)|*.exe|COM (*.com)|*.com|All files (*.*)|*.*' -Current $(if ($script:txtOutput.Text) { $script:txtOutput.Text } else { $script:txtInput.Text })
    if ($picked) { $script:txtOutput.Text = $picked; Update-StudioValidation }
})
$outputRow.Clear.Add_Click({ $script:txtOutput.Clear(); Update-StudioValidation })

$iconRow.Browse.Add_Click({
    $picked = Browse-StudioFile -Title 'Select icon' -Filter 'Icon (*.ico)|*.ico|All files (*.*)|*.*' -Current $script:txtIcon.Text
    if ($picked) { $script:txtIcon.Text = $picked; Update-StudioValidation }
})
$iconRow.Clear.Add_Click({ $script:txtIcon.Clear(); Update-StudioValidation })

$btnApplyPreset.Add_Click({
    $name = [string]$script:cmbPreset.SelectedItem
    if (-not $name) { return }
    $script:Options = Read-StudioOptionsFromUi
    $script:Options = Apply-PS2EXEPreset -Options $script:Options -PresetName $name
    Write-StudioOptionsToUi -Options $script:Options
    Update-StudioValidation
    $presets = Get-PS2EXEPresets
    Write-StudioLog ("Applied preset '{0}': {1}" -f $name, $presets[$name].Description) 'INFO'
})

$script:cmbRecent.Add_SelectedIndexChanged({
    if ($script:Updating) { return }
    $path = [string]$script:cmbRecent.SelectedItem
    if ($path -and (Test-Path -LiteralPath $path)) { Use-StudioInputFile -Path $path }
})

$btnSaveProfile.Add_Click({
    $paths = Get-PS2EXEStudioAppData
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Title = 'Save compile profile'
    $dlg.Filter = 'PS2EXE Studio profile (*.json)|*.json'
    $dlg.InitialDirectory = $paths.Profiles
    $dlg.FileName = 'compile-profile.json'
    if ($dlg.ShowDialog() -eq 'OK') {
        $script:Options = Read-StudioOptionsFromUi
        Export-PS2EXEProfile -Options $script:Options -Path $dlg.FileName -Name ([System.IO.Path]::GetFileNameWithoutExtension($dlg.FileName)) | Out-Null
        Write-StudioLog "Profile saved: $($dlg.FileName)" 'SUCCESS'
    }
})

$btnLoadProfile.Add_Click({
    $paths = Get-PS2EXEStudioAppData
    $picked = Browse-StudioFile -Title 'Load compile profile' -Filter 'PS2EXE Studio profile (*.json)|*.json|All files (*.*)|*.*' -Current $paths.Profiles
    if ($picked) {
        $script:Options = Import-PS2EXEProfile -Path $picked
        Write-StudioOptionsToUi -Options $script:Options
        Update-StudioScriptInfo
        Update-StudioIconPreview
        Update-StudioValidation
        Write-StudioLog "Profile loaded: $picked" 'SUCCESS'
    }
})

$btnReset.Add_Click({
    $keepInput = $script:txtInput.Text
    $script:Options = New-PS2EXEOptions
    $script:Options.inputFile = $keepInput
    Write-StudioOptionsToUi -Options $script:Options
    Update-StudioValidation
    Write-StudioLog 'Options reset to defaults (input path kept).' 'INFO'
})

$btnAbout.Add_Click({ Show-StudioAbout })
$script:btnCompile.Add_Click({ Invoke-StudioCompile })
$script:btnClearLog.Add_Click({ $script:txtLog.Clear() })
$script:btnCopyCmd.Add_Click({
    Update-StudioValidation
    [System.Windows.Forms.Clipboard]::SetText($script:txtCommand.Text)
    Write-StudioLog 'Command copied to clipboard.' 'SUCCESS'
    Set-StudioStatus 'Command copied' $script:Theme.Success
})
$script:btnOpenFolder.Add_Click({
    $target = $script:LastOutputPath
    if (-not $target) { $target = Get-PS2EXEResolvedOutput -Options $script:Options }
    if ($target -and (Test-Path -LiteralPath $target)) {
        Start-Process explorer.exe -ArgumentList "/select,`"$target`""
    }
    elseif ($target) {
        $dir = [System.IO.Path]::GetDirectoryName($target)
        if (Test-Path -LiteralPath $dir) { Start-Process explorer.exe -ArgumentList $dir }
    }
})
$script:btnRunExe.Add_Click({
    if ($script:LastOutputPath -and (Test-Path -LiteralPath $script:LastOutputPath)) {
        Start-Process -FilePath $script:LastOutputPath
    }
})

$btnFillMeta.Add_Click({
    $meta = Get-PS2EXEDefaultMetadata -InputFile $script:txtInput.Text
    $script:txtTitle.Text = $meta.title
    $script:txtProduct.Text = $meta.product
    $script:txtVersion.Text = $meta.version
    $script:txtCopyright.Text = $meta.copyright
    Update-StudioValidation
})

$btnAddEmbed.Add_Click({
    $picked = Browse-StudioFile -Title 'File to embed' -Filter 'All files (*.*)|*.*' -Current $script:txtInput.Text
    if ($picked) {
        $name = [System.IO.Path]::GetFileName($picked)
        [void]$script:dgvEmbed.Rows.Add($picked, ('.\' + $name))
        Update-StudioValidation
    }
})
$btnRemoveEmbed.Add_Click({
    foreach ($row in @($script:dgvEmbed.SelectedRows)) {
        if (-not $row.IsNewRow) { $script:dgvEmbed.Rows.Remove($row) }
    }
    Update-StudioValidation
})

$script:form.Add_KeyDown({
    if ($_.KeyCode -eq 'F5') { $_.Handled = $true; Invoke-StudioCompile }
    elseif ($_.Control -and $_.KeyCode -eq 'O') {
        $_.Handled = $true
        $picked = Browse-StudioFile -Title 'Select PowerShell script' -Filter 'PowerShell (*.ps1;*.psm1)|*.ps1;*.psm1|All files (*.*)|*.*' -Current $script:txtInput.Text
        if ($picked) { Use-StudioInputFile -Path $picked }
    }
    elseif ($_.Control -and $_.KeyCode -eq 'L') {
        $_.Handled = $true
        [System.Windows.Forms.Clipboard]::SetText($script:txtCommand.Text)
        Write-StudioLog 'Command copied to clipboard.' 'SUCCESS'
    }
    elseif ($_.Control -and $_.KeyCode -eq 'S') {
        $_.Handled = $true
        $btnSaveProfile.PerformClick()
    }
})

$script:form.Add_DragEnter({
    if ($_.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $_.Effect = [System.Windows.Forms.DragDropEffects]::Copy
    }
})
$script:form.Add_DragDrop({
    $files = @($_.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop))
    foreach ($file in $files) {
        $ext = [System.IO.Path]::GetExtension($file).ToLowerInvariant()
        switch ($ext) {
            '.ps1'  { Use-StudioInputFile -Path $file }
            '.psm1' { Use-StudioInputFile -Path $file }
            '.ico'  { $script:txtIcon.Text = $file; Update-StudioValidation }
            '.json' {
                try {
                    $script:Options = Import-PS2EXEProfile -Path $file
                    Write-StudioOptionsToUi -Options $script:Options
                    Update-StudioScriptInfo
                    Update-StudioIconPreview
                    Update-StudioValidation
                    Write-StudioLog "Profile loaded: $file" 'SUCCESS'
                }
                catch {
                    Write-StudioLog "Not a studio profile: $file ($($_.Exception.Message))" 'WARN'
                }
            }
            default {
                [void]$script:dgvEmbed.Rows.Add($file, ('.\' + [System.IO.Path]::GetFileName($file)))
                Update-StudioValidation
            }
        }
    }
})

$script:form.Add_FormClosing({
    try {
        $script:Options = Read-StudioOptionsFromUi
        $paths = Get-PS2EXEStudioAppData
        Export-PS2EXEProfile -Options $script:Options -Path $paths.LastSession -Name 'last-session' | Out-Null
    }
    catch { }
})

$script:form.Add_Shown({
    $split.SplitterDistance = [Math]::Max(420, [int]($split.ClientSize.Height * 0.72))
    $script:form.PerformLayout()
    $x = $script:form.ClientSize.Width - 20
    foreach ($b in @($script:btnClearLog, $script:btnCopyCmd, $script:btnRunExe, $script:btnOpenFolder, $script:btnCompile)) {
        $x -= $b.Width + 8
        $b.Location = New-Object System.Drawing.Point($x, 12)
    }
    Refresh-StudioRecent
    $restored = $false
    if ($ProfilePath -and (Test-Path -LiteralPath $ProfilePath)) {
        $script:Options = Import-PS2EXEProfile -Path $ProfilePath
        $restored = $true
    }
    else {
        $paths = Get-PS2EXEStudioAppData
        if (Test-Path -LiteralPath $paths.LastSession) {
            try {
                $script:Options = Import-PS2EXEProfile -Path $paths.LastSession
                $restored = $true
            }
            catch { }
        }
    }
    if ($restored) { Write-StudioOptionsToUi -Options $script:Options }
    if ($InputFile) { Use-StudioInputFile -Path $InputFile }
    Update-StudioScriptInfo
    Update-StudioIconPreview
    Update-StudioValidation
    Write-StudioLog "PS2EXE Studio $($script:PS2EXEStudioVersion) ready." 'INFO'
    if ($script:EngineLoaded) {
        Write-StudioLog 'Invoke-ps2exe engine loaded.' 'SUCCESS'
    }
    else {
        Write-StudioLog 'Engine not loaded. Compilation is disabled until ps2exe\Invoke-ps2exe.ps1 or the ps2exe module is available.' 'ERROR'
    }
    Write-StudioLog 'Set an input script, adjust options, and press F5 to compile.' 'INFO'
})

[System.Windows.Forms.Application]::Run($script:form)
