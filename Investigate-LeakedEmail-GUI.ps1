#Requires -Version 5.1
<#
.SYNOPSIS
  Windows GUI for the leaked-email investigation.

.DESCRIPTION
  Read-only Exchange Online investigation of an accidentally sent message:
  original recipients, forwards, redirects, auto-forward rules, tenant policy,
  and who opened the message. Run on Windows with ExchangeOnlineManagement 3.7+.

.EXAMPLE
  powershell.exe -STA -File .\Investigate-LeakedEmail-GUI.ps1
#>

if ($MyInvocation.InvocationName -ne '.' -and [System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    if ($env:LEAKINV_STA_RELAUNCH -eq '1') {
        Write-Error 'Start this tool with: powershell.exe -STA -File .\Investigate-LeakedEmail-GUI.ps1'
        exit 1
    }
    $env:LEAKINV_STA_RELAUNCH = '1'
    $hostPath = (Get-Process -Id $PID).Path
    Start-Process -FilePath $hostPath -ArgumentList @('-NoProfile', '-STA', '-File', $PSCommandPath) | Out-Null
    exit 0
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Data
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch { }
[System.Windows.Forms.Application]::EnableVisualStyles()

$script:CorePath = Join-Path $PSScriptRoot 'LeakedEmailInvestigation.Core.ps1'
if (-not (Test-Path -LiteralPath $script:CorePath)) {
    [System.Windows.Forms.MessageBox]::Show("Missing $($script:CorePath)", 'Leaked Email Investigation')
    exit 1
}
. $script:CorePath

$script:Ink = [System.Drawing.Color]::FromArgb(24, 42, 68)
$script:Page = [System.Drawing.Color]::FromArgb(245, 247, 250)
$script:Blue = [System.Drawing.Color]::FromArgb(0, 120, 212)
$script:Teal = [System.Drawing.Color]::FromArgb(0, 150, 136)
$script:Green = [System.Drawing.Color]::FromArgb(16, 137, 62)
$script:Red = [System.Drawing.Color]::FromArgb(196, 43, 28)
$script:Orange = [System.Drawing.Color]::FromArgb(202, 131, 0)
$script:Slate = [System.Drawing.Color]::FromArgb(55, 65, 81)
$script:Muted = [System.Drawing.Color]::FromArgb(100, 110, 125)
$script:CardBorder = [System.Drawing.Color]::FromArgb(214, 220, 228)
$script:LastResult = $null
$script:Pipeline = $null
$script:PipelineHandle = $null
$script:GridTabs = @()
$script:Cards = @()
$script:Sync = [hashtable]::Synchronized(@{
    State = 'Idle'
    Percent = 0
    Status = 'Ready'
    Cancel = $false
    Result = $null
    ErrorMessage = ''
    Connection = $null
    Log = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
})

function New-UiFont {
    param([float]$Size = 9, [System.Drawing.FontStyle]$Style = 'Regular')
    return (New-Object System.Drawing.Font('Segoe UI', $Size, $Style))
}

function New-FlatButton {
    param([string]$Text, [int]$Width, [System.Drawing.Color]$BackColor, [scriptblock]$OnClick)
    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Size = New-Object System.Drawing.Size($Width, 32)
    $button.FlatStyle = 'Flat'
    $button.FlatAppearance.BorderSize = 0
    $button.BackColor = $BackColor
    $button.ForeColor = [System.Drawing.Color]::White
    $button.Font = New-UiFont 9 Bold
    $button.Cursor = [System.Windows.Forms.Cursors]::Hand
    $button.Margin = New-Object System.Windows.Forms.Padding(0, 4, 8, 4)
    if ($OnClick) { $button.Add_Click($OnClick) }
    return $button
}

function New-FieldLabel {
    param([string]$Text, [int]$X, [int]$Y, [int]$Width = 100)
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Location = New-Object System.Drawing.Point($X, $Y)
    $label.Size = New-Object System.Drawing.Size($Width, 22)
    $label.Font = New-UiFont 9
    $label.ForeColor = $script:Ink
    $label.TextAlign = 'MiddleLeft'
    return $label
}

function Add-UiLog {
    param([string]$Line)
    if (-not $script:LogBox -or -not $Line) { return }
    $script:LogBox.AppendText($Line + [Environment]::NewLine)
    $script:LogBox.SelectionStart = $script:LogBox.TextLength
    $script:LogBox.ScrollToCaret()
}

function ConvertTo-FilterLiteral {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return $Text.Replace("'", "''").Replace('[', '[[]').Replace('%', '[%]').Replace('*', '[*]')
}

function Update-GridPresentation {
    param($TabState)
    if (-not $TabState -or -not $TabState.Table) { return }
    $parts = New-Object System.Collections.Generic.List[string]
    $externalColumn = $null
    if ($TabState.Table.Columns.Contains('External')) { $externalColumn = 'External' }
    elseif ($TabState.Table.Columns.Contains('Target external')) { $externalColumn = 'Target external' }
    if ($TabState.ExternalOnly.Checked -and $externalColumn) {
        $parts.Add(("[{0}] = 'Yes'" -f $externalColumn))
    }
    $text = $TabState.FilterBox.Text
    if (-not [string]::IsNullOrWhiteSpace($text)) {
        $safe = ConvertTo-FilterLiteral $text
        $likes = New-Object System.Collections.Generic.List[string]
        foreach ($column in $TabState.Table.Columns) {
            $likes.Add(("[{0}] LIKE '%{1}%'" -f $column.ColumnName.Replace(']', ']]'), $safe))
        }
        if ($likes.Count -gt 0) { $parts.Add('(' + ($likes -join ' OR ') + ')') }
    }
    try {
        $filter = ''
        if ($parts.Count -gt 0) { $filter = ($parts -join ' AND ') }
        $TabState.Binding.Filter = $filter
        $shown = 0
        if ($TabState.Binding.Count -ge 0) { $shown = $TabState.Binding.Count }
        $TabState.CountLabel.Text = ("{0} of {1}" -f $shown, $TabState.Table.Rows.Count)
    }
    catch {
        $TabState.CountLabel.Text = 'Filter is not valid for these columns'
    }

    $grid = $TabState.Grid
    foreach ($row in $grid.Rows) {
        if ($row.IsNewRow) { continue }
        $back = $script:Page
        $severity = $null
        $external = $false
        $delegate = $false
        if ($grid.Columns.Contains('Severity')) { $severity = [string]$row.Cells['Severity'].Value }
        if ($grid.Columns.Contains('External') -and [string]$row.Cells['External'].Value -eq 'Yes') { $external = $true }
        if ($grid.Columns.Contains('Target external') -and [string]$row.Cells['Target external'].Value -eq 'Yes') { $external = $true }
        if ($grid.Columns.Contains('Delegate') -and [string]$row.Cells['Delegate'].Value -eq 'Yes') { $delegate = $true }
        if ($severity -eq 'High' -or $external) { $back = [System.Drawing.Color]::FromArgb(255, 228, 228) }
        elseif ($severity -eq 'Medium' -or $delegate) { $back = [System.Drawing.Color]::FromArgb(255, 243, 220) }
        elseif ($severity -eq 'Info') { $back = [System.Drawing.Color]::FromArgb(232, 242, 252) }
        $row.DefaultCellStyle.BackColor = $back
    }
}

function Fill-ResultGrid {
    param($TabState, $Rows)
    $table = New-Object System.Data.DataTable
    foreach ($column in @($TabState.View.Columns)) {
        [void]$table.Columns.Add([string]$column.Header)
    }
    foreach ($row in (ConvertTo-ItemArray $Rows)) {
        $dataRow = $table.NewRow()
        foreach ($column in @($TabState.View.Columns)) {
            $dataRow[$column.Header] = ConvertTo-FieldText -Name $column.Property -Value (Get-ObjectProperty $row $column.Property)
        }
        [void]$table.Rows.Add($dataRow)
    }
    $TabState.Table = $table
    $TabState.Binding.DataSource = $table
    if ($TabState.Grid.DataSource -ne $TabState.Binding) {
        $TabState.Grid.DataSource = $TabState.Binding
    }
    $TabState.Grid.AutoResizeColumns([System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::DisplayedCells)
    foreach ($column in $TabState.Grid.Columns) {
        if ($column.Width -gt 380) { $column.Width = 380 }
    }
    Update-GridPresentation $TabState
}

function Show-RowDetails {
    param($Grid)
    if (-not $Grid -or -not $Grid.CurrentRow -or $Grid.CurrentRow.IsNewRow) { return }
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($cell in $Grid.CurrentRow.Cells) {
        $lines.Add(('{0}: {1}' -f $cell.OwningColumn.HeaderText, $cell.Value))
    }
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = 'Row details'
    $dialog.StartPosition = 'CenterParent'
    $dialog.Size = New-Object System.Drawing.Size(760, 520)
    $dialog.Font = New-UiFont 9
    $dialog.BackColor = $script:Page
    $box = New-Object System.Windows.Forms.TextBox
    $box.Multiline = $true
    $box.ReadOnly = $true
    $box.ScrollBars = 'Both'
    $box.Dock = 'Fill'
    $box.Font = New-Object System.Drawing.Font('Consolas', 10)
    $box.Text = ($lines -join [Environment]::NewLine)
    $box.WordWrap = $false
    $dialog.Controls.Add($box)
    [void]$dialog.ShowDialog()
    $dialog.Dispose()
}

function Export-GridView {
    param($TabState)
    if (-not $TabState -or -not $TabState.Table) {
        [System.Windows.Forms.MessageBox]::Show('Run an investigation before exporting this view.', 'Export')
        return
    }
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Filter = 'CSV files (*.csv)|*.csv'
    $dialog.FileName = $TabState.View.FileName
    if ($dialog.ShowDialog() -ne 'OK') { return }
    $view = $TabState.Table.DefaultView
    $columns = @($TabState.View.Columns)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($viewRow in $view) {
        $obj = New-Object PSObject
        $index = 0
        foreach ($column in $columns) {
            $obj | Add-Member -NotePropertyName $column.Header -NotePropertyValue ([string]$viewRow[$index])
            $index++
        }
        $rows.Add($obj)
    }
    if ($rows.Count -eq 0) {
        $header = ($columns | ForEach-Object { '"' + ($_.Header -replace '"', '""') + '"' }) -join ','
        $encoding = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllText($dialog.FileName, $header + "`r`n", $encoding)
    }
    else {
        $rows | Export-Csv -LiteralPath $dialog.FileName -NoTypeInformation -Encoding UTF8
    }
    Add-UiLog ("Exported {0} rows to {1}" -f $rows.Count, $dialog.FileName)
}

function New-ResultTab {
    param($View)
    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = '  ' + $View.Title + '  '
    $page.BackColor = $script:Page
    $page.Padding = New-Object System.Windows.Forms.Padding(6)

    $bar = New-Object System.Windows.Forms.FlowLayoutPanel
    $bar.Dock = 'Top'
    $bar.Height = 40
    $bar.WrapContents = $false
    $bar.FlowDirection = 'LeftToRight'
    $bar.BackColor = $script:Page
    $filterLabel = New-Object System.Windows.Forms.Label
    $filterLabel.Text = 'Filter'
    $filterLabel.AutoSize = $true
    $filterLabel.Margin = New-Object System.Windows.Forms.Padding(0, 10, 6, 0)
    $filterLabel.Font = New-UiFont 9
    $filterBox = New-Object System.Windows.Forms.TextBox
    $filterBox.Width = 240
    $filterBox.Font = New-UiFont 9
    $external = New-Object System.Windows.Forms.CheckBox
    $external.Text = 'External only'
    $external.AutoSize = $true
    $external.Margin = New-Object System.Windows.Forms.Padding(8, 8, 8, 0)
    $external.Font = New-UiFont 9
    $count = New-Object System.Windows.Forms.Label
    $count.Text = '0 rows'
    $count.AutoSize = $true
    $count.Margin = New-Object System.Windows.Forms.Padding(4, 10, 8, 0)
    $count.ForeColor = $script:Muted
    $hint = New-Object System.Windows.Forms.Label
    $hint.Text = $View.Description
    $hint.Dock = 'Top'
    $hint.Height = 32
    $hint.Font = New-UiFont 8
    $hint.ForeColor = $script:Muted

    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.AllowUserToOrderColumns = $true
    $grid.RowHeadersVisible = $false
    $grid.SelectionMode = 'FullRowSelect'
    $grid.MultiSelect = $true
    $grid.BackgroundColor = [System.Drawing.Color]::White
    $grid.BorderStyle = 'None'
    $grid.EnableHeadersVisualStyles = $false
    $grid.ColumnHeadersDefaultCellStyle.BackColor = $script:Ink
    $grid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $grid.ColumnHeadersDefaultCellStyle.Font = New-UiFont 9 Bold
    $grid.ColumnHeadersHeight = 32
    $grid.RowTemplate.Height = 26
    $grid.DefaultCellStyle.Font = New-UiFont 9
    $grid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(204, 228, 247)
    $grid.DefaultCellStyle.SelectionForeColor = $script:Ink
    $grid.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(248, 250, 252)
    $grid.GridColor = [System.Drawing.Color]::FromArgb(226, 230, 236)
    $grid.ClipboardCopyMode = 'EnableAlwaysIncludeHeaderText'
    $grid.AutoSizeColumnsMode = 'None'
    $grid.ScrollBars = 'Both'

    $binding = New-Object System.Windows.Forms.BindingSource
    $state = [pscustomobject]@{
        View = $View
        Page = $page
        Grid = $grid
        FilterBox = $filterBox
        ExternalOnly = $external
        CountLabel = $count
        Binding = $binding
        Table = $null
    }
    $filterBox.Tag = $state
    $external.Tag = $state
    $filterBox.Add_TextChanged({ Update-GridPresentation $this.Tag })
    $external.Add_CheckedChanged({ Update-GridPresentation $this.Tag })
    $grid.Add_CellDoubleClick({ Show-RowDetails $this })
    $exportButton = New-FlatButton 'Export view' 120 $script:Slate { Export-GridView $this.Tag }
    $exportButton.Tag = $state
    $bar.Controls.Add($filterLabel)
    $bar.Controls.Add($filterBox)
    $bar.Controls.Add($external)
    $bar.Controls.Add($exportButton)
    $bar.Controls.Add($count)
    $page.Controls.Add($grid)
    $page.Controls.Add($hint)
    $page.Controls.Add($bar)
    return $state
}

function Set-UiBusy {
    param([bool]$Busy)
    $script:RunButton.Enabled = -not $Busy
    $script:ConnectButton.Enabled = -not $Busy
    $script:DisconnectButton.Enabled = -not $Busy
    $script:CancelButton.Enabled = $Busy
    $script:FieldsPanel.Enabled = -not $Busy
    $script:OptionsPanel.Enabled = -not $Busy
    if ($Busy) {
        $script:Progress.Style = 'Marquee'
        $script:CancelButton.Text = 'Cancel'
    }
    else {
        $script:Progress.Style = 'Continuous'
    }
}

function Show-InvestigationResult {
    param($Result)
    $script:LastResult = $Result
    $summary = $Result.Summary
    foreach ($card in $script:Cards) {
        $value = [string](Get-ObjectProperty $summary $card.Property)
        if (-not $value) { $value = '0' }
        $card.ValueLabel.Text = $value
        $number = 0
        [void][int]::TryParse($value, [ref]$number)
        if ($card.Alert -and $number -gt 0) { $card.ValueLabel.ForeColor = $script:Red }
        else { $card.ValueLabel.ForeColor = $script:Ink }
    }
    $script:SummaryBox.Text = Format-InvestigationSummaryText -Report $Result
    foreach ($tab in $script:GridTabs) {
        Fill-ResultGrid $tab (Get-ObjectProperty $Result $tab.View.Collection)
    }
    if ($Result.OutputFolder) {
        $script:FolderBox.Text = $Result.OutputFolder
        $script:StatusLabel.Text = "Reports saved to $($Result.OutputFolder)"
    }
    $high = 0
    foreach ($finding in (ConvertTo-ItemArray $Result.Findings)) {
        if ($finding.Severity -eq 'High') { $high++ }
    }
    Add-UiLog ("Finished. {0} high-severity finding(s). External original recipients: {1}." -f $high, $summary.OriginalExternal)
    if ($Result.ExportError) {
        [System.Windows.Forms.MessageBox]::Show($Result.ExportError, 'Reports were not written', 'OK', 'Warning')
    }
}

function Start-WorkerScript {
    param([string]$Code, [object[]]$Arguments)
    if ($script:Pipeline) { return $false }
    $shell = [powershell]::Create()
    $shell.Runspace = $script:Runspace
    [void]$shell.AddScript($Code)
    foreach ($argument in $Arguments) { [void]$shell.AddArgument($argument) }
    $script:Pipeline = $shell
    $script:PipelineHandle = $shell.BeginInvoke()
    $script:UiTimer.Start()
    return $true
}

function Get-ConnectScript {
    return @'
param($CorePath, $Sync, $Upn)
$ErrorActionPreference = "Stop"
. $CorePath
try {
    $Sync.Status = "Opening the Exchange Online sign-in window"
    $info = Connect-InvestigationService -UserPrincipalName $Upn
    $Sync.Connection = $info
    if ($info.Connected) {
        $who = $info.User
        if (-not $who) { $who = "signed in" }
        $Sync.Log.Enqueue(("INFO  Connected as {0} (ExchangeOnlineManagement {1})" -f $who, $info.Version))
        $Sync.Status = "Connected"
        $Sync.State = "Connected"
    }
    else {
        $Sync.ErrorMessage = "Exchange Online did not report a connected session."
        $Sync.State = "Error"
    }
}
catch {
    $Sync.ErrorMessage = $_.Exception.Message
    $Sync.Log.Enqueue(("ERROR  {0}" -f $_.Exception.Message))
    $Sync.State = "Error"
}
'@
}

function Get-DisconnectScript {
    return @'
param($CorePath, $Sync)
$ErrorActionPreference = "Stop"
. $CorePath
try {
    Disconnect-InvestigationService
    $Sync.Connection = $null
    $Sync.Status = "Disconnected"
    $Sync.Log.Enqueue("INFO  Disconnected from Exchange Online")
    $Sync.State = "Disconnected"
}
catch {
    $Sync.ErrorMessage = $_.Exception.Message
    $Sync.State = "Error"
}
'@
}

function Get-InvestigationScript {
    return @'
param($CorePath, $Sync, $Params)
$ErrorActionPreference = "Stop"
. $CorePath
try {
    $Sync.Cancel = $false
    $Sync.Result = $null
    $Sync.ErrorMessage = ""
    $Sync.State = "Running"
    $result = Invoke-LeakedEmailInvestigation @Params `
        -ProgressHandler {
            param($Percent, $Phase, $Message)
            $Sync.Percent = $Percent
            if ($Message) { $Sync.Status = $Message }
        } `
        -LogHandler {
            param($Level, $Message)
            $Sync.Log.Enqueue(("{0}  {1}" -f $Level, $Message))
        } `
        -CancelHandler { [bool]$Sync.Cancel }
    $Sync.Result = $result
    if ($result.Cancelled) { $Sync.State = "Cancelled" }
    else { $Sync.State = "Completed" }
    $Sync.Percent = 100
    $Sync.Status = "Investigation finished"
}
catch {
    $stopped = $_.Exception.Message -match 'pipeline has been stopped|PipelineStopped'
    if ($stopped -or $Sync.Cancel) {
        $Sync.State = "Cancelled"
        $Sync.Status = "Investigation cancelled"
    }
    else {
        $Sync.ErrorMessage = $_.Exception.ToString()
        $Sync.Log.Enqueue(("ERROR  {0}" -f $_.Exception.Message))
        $Sync.State = "Error"
    }
}
'@
}

function Start-Connect {
    $script:Sync.State = 'Connecting'
    $script:Sync.ErrorMessage = ''
    Set-UiBusy $true
    $script:StatusLabel.Text = 'Waiting for Exchange Online sign-in...'
    Add-UiLog 'Connecting to Exchange Online'
    [void](Start-WorkerScript -Code (Get-ConnectScript) -Arguments @($script:CorePath, $script:Sync, $script:UpnBox.Text.Trim()))
}

function Start-Disconnect {
    $script:Sync.State = 'Disconnecting'
    Set-UiBusy $true
    [void](Start-WorkerScript -Code (Get-DisconnectScript) -Arguments @($script:CorePath, $script:Sync))
}

function Get-InvestigationParameters {
    $folder = $script:FolderBox.Text.Trim()
    return @{
        Subject = $script:SubjectBox.Text.Trim()
        OriginalSender = $script:SenderBox.Text.Trim()
        StartDate = $script:StartPicker.Value
        EndDate = $script:EndPicker.Value
        OutputFolder = $folder
        MessageId = $script:MessageIdBox.Text.Trim()
        AdditionalAuditUsers = @($script:ExtraUsersBox.Text)
        SignInUpn = $script:UpnBox.Text.Trim()
        CheckAutoForwarding = [bool]$script:ChkAuto.Checked
        IncludeDisabledRules = [bool]$script:ChkDisabled.Checked
        CheckTransportPolicy = [bool]$script:ChkPolicy.Checked
        AuditAllUsers = [bool]$script:ChkAuditAll.Checked
        SkipOpenAudit = -not [bool]$script:ChkOpens.Checked
        FastAudit = -not [bool]$script:ChkHigh.Checked
        IncludeTraceDetail = [bool]$script:ChkDetail.Checked
        ResolveSenderAliases = [bool]$script:ChkAliases.Checked
        AuditThroughNow = [bool]$script:ChkAuditNow.Checked
        LooseSubjectMatch = [bool]$script:ChkLoose.Checked
        SkipConnectionCheck = $false
    }
}

function Start-Investigation {
    $subject = $script:SubjectBox.Text.Trim()
    $sender = $script:SenderBox.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($subject) -or [string]::IsNullOrWhiteSpace($sender)) {
        [System.Windows.Forms.MessageBox]::Show('Enter the subject and the original sender.', 'Missing information')
        return
    }
    if (-not (Test-SmtpAddress $sender)) {
        [System.Windows.Forms.MessageBox]::Show('The original sender must be an email address.', 'Sender')
        return
    }
    if ($script:EndPicker.Value -le $script:StartPicker.Value) {
        [System.Windows.Forms.MessageBox]::Show('The end of the window must be later than the start.', 'Dates')
        return
    }
    $searched = (Get-NormalizedSubjectInfo -Subject $subject).Subject
    if ($searched.Length -lt 12) {
        $answer = [System.Windows.Forms.MessageBox]::Show(
            "The subject is very short after prefixes are removed (`"$searched`"). Message trace can return unrelated mail.`r`n`r`nRun anyway?",
            'Short subject', 'YesNo', 'Warning')
        if ($answer -ne 'Yes') { return }
    }
    $script:Sync.Cancel = $false
    $script:Sync.Result = $null
    $script:Sync.ErrorMessage = ''
    $script:Sync.Percent = 0
    $script:Sync.State = 'Running'
    Set-UiBusy $true
    $script:StatusLabel.Text = 'Starting investigation...'
    Add-UiLog ("Investigation started for '{0}' from {1}" -f $subject, $sender)
    [void](Start-WorkerScript -Code (Get-InvestigationScript) -Arguments @($script:CorePath, $script:Sync, (Get-InvestigationParameters)))
}

function Stop-Investigation {
    if (-not $script:Pipeline) { return }
    if (-not $script:Sync.Cancel) {
        $script:Sync.Cancel = $true
        $script:CancelButton.Text = 'Force stop'
        $script:StatusLabel.Text = 'Cancelling after the current Exchange query...'
        Add-UiLog 'Cancel requested. The current Exchange call will finish, then the run stops.'
        return
    }
    $script:Sync.State = 'Cancelled'
    try { $script:Pipeline.Stop() } catch { }
    Add-UiLog 'Force stop sent to the running query.'
}

function Save-InvestigationProfile {
    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Filter = 'Investigation profile (*.json)|*.json'
    $dialog.FileName = 'leaked-email-profile.json'
    if ($dialog.ShowDialog() -ne 'OK') { return }
    $profile = [ordered]@{
        Subject = $script:SubjectBox.Text
        OriginalSender = $script:SenderBox.Text
        MessageId = $script:MessageIdBox.Text
        AdditionalAuditUsers = $script:ExtraUsersBox.Text
        OutputFolder = $script:FolderBox.Text
        SignInUpn = $script:UpnBox.Text
        StartDate = $script:StartPicker.Value.ToString('o')
        EndDate = $script:EndPicker.Value.ToString('o')
        CheckAutoForwarding = [bool]$script:ChkAuto.Checked
        IncludeDisabledRules = [bool]$script:ChkDisabled.Checked
        CheckTransportPolicy = [bool]$script:ChkPolicy.Checked
        SearchOpens = [bool]$script:ChkOpens.Checked
        AuditAllUsers = [bool]$script:ChkAuditAll.Checked
        HighCompleteness = [bool]$script:ChkHigh.Checked
        IncludeTraceDetail = [bool]$script:ChkDetail.Checked
        ResolveSenderAliases = [bool]$script:ChkAliases.Checked
        AuditThroughNow = [bool]$script:ChkAuditNow.Checked
        LooseSubjectMatch = [bool]$script:ChkLoose.Checked
    }
    $profile | ConvertTo-Json | Set-Content -LiteralPath $dialog.FileName -Encoding UTF8
    Add-UiLog ("Saved profile {0}" -f $dialog.FileName)
}

function Restore-InvestigationProfile {
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = 'Investigation profile (*.json)|*.json'
    if ($dialog.ShowDialog() -ne 'OK') { return }
    $loaded = Get-Content -LiteralPath $dialog.FileName -Raw | ConvertFrom-Json
    $script:SubjectBox.Text = [string]$loaded.Subject
    $script:SenderBox.Text = [string]$loaded.OriginalSender
    $script:MessageIdBox.Text = [string]$loaded.MessageId
    $script:ExtraUsersBox.Text = [string]$loaded.AdditionalAuditUsers
    $script:FolderBox.Text = [string]$loaded.OutputFolder
    $script:UpnBox.Text = [string]$loaded.SignInUpn
    $start = [datetime]::MinValue
    $end = [datetime]::MinValue
    if ([datetime]::TryParse([string]$loaded.StartDate, [ref]$start)) { $script:StartPicker.Value = $start }
    if ([datetime]::TryParse([string]$loaded.EndDate, [ref]$end)) { $script:EndPicker.Value = $end }
    $script:ChkAuto.Checked = [bool]$loaded.CheckAutoForwarding
    $script:ChkDisabled.Checked = [bool]$loaded.IncludeDisabledRules
    $script:ChkPolicy.Checked = [bool]$loaded.CheckTransportPolicy
    $script:ChkOpens.Checked = [bool]$loaded.SearchOpens
    $script:ChkAuditAll.Checked = [bool]$loaded.AuditAllUsers
    $script:ChkHigh.Checked = [bool]$loaded.HighCompleteness
    $script:ChkDetail.Checked = [bool]$loaded.IncludeTraceDetail
    $script:ChkAliases.Checked = [bool]$loaded.ResolveSenderAliases
    $script:ChkAuditNow.Checked = [bool]$loaded.AuditThroughNow
    $script:ChkLoose.Checked = [bool]$loaded.LooseSubjectMatch
    Add-UiLog ("Loaded profile {0}" -f $dialog.FileName)
}

function Copy-InvestigationSummary {
    if (-not $script:LastResult) {
        [System.Windows.Forms.MessageBox]::Show('Run an investigation before copying the summary.', 'Summary')
        return
    }
    $text = Format-InvestigationSummaryText -Report $script:LastResult
    [System.Windows.Forms.Clipboard]::SetText($text)
    Add-UiLog 'Summary copied to the clipboard'
}

function Open-ReportFolder {
    $folder = $script:FolderBox.Text.Trim()
    if (-not $folder -or -not (Test-Path -LiteralPath $folder)) {
        [System.Windows.Forms.MessageBox]::Show('The report folder does not exist yet.', 'Open folder')
        return
    }
    Start-Process -FilePath explorer.exe -ArgumentList $folder
}

function Export-AllReports {
    if (-not $script:LastResult) {
        [System.Windows.Forms.MessageBox]::Show('Run an investigation before exporting.', 'Export')
        return
    }
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = 'Choose the folder for the CSV reports and Summary.txt'
    if ($script:LastResult.OutputFolder -and (Test-Path -LiteralPath $script:LastResult.OutputFolder)) {
        $dialog.SelectedPath = $script:LastResult.OutputFolder
    }
    if ($dialog.ShowDialog() -ne 'OK') { return }
    $script:LastResult.OutputFolder = $dialog.SelectedPath
    try {
        Export-InvestigationReport -Report $script:LastResult | Out-Null
        $script:FolderBox.Text = $dialog.SelectedPath
        Add-UiLog ("Exported all reports to {0}" -f $dialog.SelectedPath)
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Export failed', 'OK', 'Error')
    }
}

function Update-InvestigationUi {
    $line = ''
    while ($script:Sync.Log.TryDequeue([ref]$line)) { Add-UiLog $line }
    if ($script:Sync.Status) { $script:StatusLabel.Text = [string]$script:Sync.Status }
    $percent = 0
    if ([int]::TryParse([string]$script:Sync.Percent, [ref]$percent)) {
        if ($percent -lt 0) { $percent = 0 }
        if ($percent -gt 100) { $percent = 100 }
        if ($script:Progress.Style -eq 'Continuous') { $script:Progress.Value = $percent }
    }
    if (-not $script:PipelineHandle -or -not $script:PipelineHandle.IsCompleted) { return }
    try { $script:Pipeline.EndInvoke($script:PipelineHandle) | Out-Null }
    catch {
        if ($script:Sync.State -eq 'Running' -or $script:Sync.State -eq 'Connecting') {
            $script:Sync.State = 'Error'
            $script:Sync.ErrorMessage = $_.Exception.Message
        }
    }
    $script:Pipeline.Dispose()
    $script:Pipeline = $null
    $script:PipelineHandle = $null
    Set-UiBusy $false
    $state = [string]$script:Sync.State
    if ($state -eq 'Connected') {
        $info = $script:Sync.Connection
        $who = 'Connected'
        if ($info -and $info.User) { $who = "Connected: $($info.User)" }
        $script:ConnectionLabel.Text = $who
        $script:ConnectionLabel.ForeColor = $script:Green
    }
    elseif ($state -eq 'Disconnected') {
        $script:ConnectionLabel.Text = 'Not connected'
        $script:ConnectionLabel.ForeColor = [System.Drawing.Color]::White
    }
    elseif ($state -eq 'Completed' -or $state -eq 'Cancelled') {
        if ($script:Sync.Result) { Show-InvestigationResult $script:Sync.Result }
        if ($state -eq 'Cancelled') {
            [System.Windows.Forms.MessageBox]::Show('The investigation was cancelled. Partial results are shown and were written if export succeeded.', 'Cancelled')
        }
        $tabs = $script:Tabs.TabPages
        if ($tabs.Count -gt 1) { $script:Tabs.SelectedIndex = 1 }
    }
    elseif ($state -eq 'Error') {
        $message = [string]$script:Sync.ErrorMessage
        if (-not $message) { $message = 'The Exchange Online operation failed.' }
        [System.Windows.Forms.MessageBox]::Show($message, 'Investigation error', 'OK', 'Error')
        $script:ConnectionLabel.Text = 'Not connected'
    }
}

$script:Runspace = [runspacefactory]::CreateRunspace()
$script:Runspace.ApartmentState = 'STA'
$script:Runspace.ThreadOptions = 'ReuseThread'
$script:Runspace.Open()

$script:UiTimer = New-Object System.Windows.Forms.Timer
$script:UiTimer.Interval = 200
$script:UiTimer.Add_Tick({ Update-InvestigationUi })

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Leaked Email Investigation'
$form.StartPosition = 'CenterScreen'
$form.Size = New-Object System.Drawing.Size(1280, 860)
$form.MinimumSize = New-Object System.Drawing.Size(1100, 720)
$form.BackColor = $script:Page
$form.Font = New-UiFont 9
try {
    $flags = [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic
    $doubleBuffered = $form.GetType().GetProperty('DoubleBuffered', $flags)
    if ($doubleBuffered) { $doubleBuffered.SetValue($form, $true, $null) }
} catch { }

$header = New-Object System.Windows.Forms.Panel
$header.Dock = 'Top'
$header.Height = 64
$header.BackColor = $script:Ink
$title = New-Object System.Windows.Forms.Label
$title.Text = 'Leaked Email Investigation'
$title.Font = New-UiFont 16 Bold
$title.ForeColor = [System.Drawing.Color]::White
$title.Location = New-Object System.Drawing.Point(16, 8)
$title.AutoSize = $true
$subtitle = New-Object System.Windows.Forms.Label
$subtitle.Text = 'Read-only message trace and audit. Nothing is sent, deleted, or modified.'
$subtitle.Font = New-UiFont 8
$subtitle.ForeColor = [System.Drawing.Color]::FromArgb(190, 205, 220)
$subtitle.Location = New-Object System.Drawing.Point(18, 38)
$subtitle.AutoSize = $true
$script:ConnectionLabel = New-Object System.Windows.Forms.Label
$script:ConnectionLabel.Text = 'Not connected'
$script:ConnectionLabel.ForeColor = [System.Drawing.Color]::White
$script:ConnectionLabel.Font = New-UiFont 9 Bold
$script:ConnectionLabel.AutoSize = $true
$script:ConnectionLabel.Anchor = 'Top,Right'
$script:UpnBox = New-Object System.Windows.Forms.TextBox
$script:UpnBox.Width = 220
$script:UpnBox.Font = New-UiFont 9
$script:UpnBox.Anchor = 'Top,Right'
$upnLabel = New-FieldLabel 'Sign-in UPN' 0 0 80
$upnLabel.ForeColor = [System.Drawing.Color]::White
$upnLabel.Anchor = 'Top,Right'
$script:ConnectButton = New-FlatButton 'Connect' 100 $script:Blue { Start-Connect }
$script:DisconnectButton = New-FlatButton 'Disconnect' 110 $script:Slate { Start-Disconnect }
$script:ConnectButton.Anchor = 'Top,Right'
$script:DisconnectButton.Anchor = 'Top,Right'
$header.Controls.AddRange(@($title, $subtitle, $upnLabel, $script:UpnBox, $script:ConnectButton, $script:DisconnectButton, $script:ConnectionLabel))

$script:FieldsPanel = New-Object System.Windows.Forms.Panel
$script:FieldsPanel.Dock = 'Top'
$script:FieldsPanel.Height = 156
$script:FieldsPanel.BackColor = $script:Page
$script:FieldsPanel.Padding = New-Object System.Windows.Forms.Padding(12, 8, 12, 0)

$script:SubjectBox = New-Object System.Windows.Forms.TextBox
$script:SubjectBox.Font = New-UiFont 10
$script:SubjectBox.Anchor = 'Top,Left,Right'
$script:MessageIdBox = New-Object System.Windows.Forms.TextBox
$script:MessageIdBox.Font = New-UiFont 9
$script:MessageIdBox.Anchor = 'Top,Right'
$script:SenderBox = New-Object System.Windows.Forms.TextBox
$script:SenderBox.Font = New-UiFont 9
$script:StartPicker = New-Object System.Windows.Forms.DateTimePicker
$script:StartPicker.Format = 'Custom'
$script:StartPicker.CustomFormat = 'yyyy-MM-dd HH:mm'
$script:StartPicker.Width = 160
$script:StartPicker.Value = (Get-Date).AddDays(-7)
$script:EndPicker = New-Object System.Windows.Forms.DateTimePicker
$script:EndPicker.Format = 'Custom'
$script:EndPicker.CustomFormat = 'yyyy-MM-dd HH:mm'
$script:EndPicker.Width = 160
$script:EndPicker.Value = Get-Date
$script:FolderBox = New-Object System.Windows.Forms.TextBox
$script:FolderBox.Font = New-UiFont 9
$script:FolderBox.Anchor = 'Top,Left,Right'
$script:ExtraUsersBox = New-Object System.Windows.Forms.TextBox
$script:ExtraUsersBox.Font = New-UiFont 8
$script:ExtraUsersBox.Anchor = 'Top,Left,Right'
$browse = New-FlatButton 'Browse' 90 $script:Teal {
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = 'Report output folder. Leave the box empty to create a new timestamped folder.'
    if ($dialog.ShowDialog() -eq 'OK') { $script:FolderBox.Text = $dialog.SelectedPath }
}
$browse.Anchor = 'Top,Right'
$presetPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$presetPanel.Height = 32
$presetPanel.Width = 280
$presetPanel.FlowDirection = 'LeftToRight'
$presetPanel.WrapContents = $false
foreach ($preset in @(
    @{ Text = '24h'; Days = 1 }
    @{ Text = '7d'; Days = 7 }
    @{ Text = '30d'; Days = 30 }
    @{ Text = '90d'; Days = 90 }
)) {
    $days = [int]$preset.Days
    $presetButton = New-FlatButton $preset.Text 58 $script:Slate {}
    $presetButton.Height = 26
    $presetButton.Tag = $days
    $presetButton.Add_Click({
        $span = [int]$this.Tag
        $script:EndPicker.Value = Get-Date
        $script:StartPicker.Value = (Get-Date).AddDays(-1 * $span)
    })
    $presetPanel.Controls.Add($presetButton)
}

$subjectLabel = New-FieldLabel 'Subject' 12 12 90
$senderLabel = New-FieldLabel 'Sender' 12 46 90
$startLabel = New-FieldLabel 'Start' 430 46 40
$endLabel = New-FieldLabel 'End' 640 46 36
$idLabel = New-FieldLabel 'Message ID' 760 12 80
$idLabel.Anchor = 'Top,Right'
$folderLabel = New-FieldLabel 'Output folder' 12 80 90
$extraLabel = New-FieldLabel 'Also audit' 12 112 90
$script:SubjectBox.Location = New-Object System.Drawing.Point(108, 10)
$script:SubjectBox.Size = New-Object System.Drawing.Size(640, 26)
$script:MessageIdBox.Location = New-Object System.Drawing.Point(844, 10)
$script:MessageIdBox.Size = New-Object System.Drawing.Size(280, 24)
$script:SenderBox.Location = New-Object System.Drawing.Point(108, 44)
$script:SenderBox.Size = New-Object System.Drawing.Size(310, 24)
$script:StartPicker.Location = New-Object System.Drawing.Point(470, 44)
$script:EndPicker.Location = New-Object System.Drawing.Point(676, 44)
$presetPanel.Location = New-Object System.Drawing.Point(848, 40)
$script:FolderBox.Location = New-Object System.Drawing.Point(108, 78)
$script:FolderBox.Size = New-Object System.Drawing.Size(900, 24)
$browse.Location = New-Object System.Drawing.Point(1016, 74)
$script:ExtraUsersBox.Location = New-Object System.Drawing.Point(108, 110)
$script:ExtraUsersBox.Size = New-Object System.Drawing.Size(1000, 24)
$script:FieldsPanel.Controls.AddRange(@(
    $subjectLabel, $script:SubjectBox, $idLabel, $script:MessageIdBox,
    $senderLabel, $script:SenderBox, $startLabel, $script:StartPicker, $endLabel, $script:EndPicker, $presetPanel,
    $folderLabel, $script:FolderBox, $browse, $extraLabel, $script:ExtraUsersBox
))

$script:OptionsPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$script:OptionsPanel.Dock = 'Top'
$script:OptionsPanel.Height = 78
$script:OptionsPanel.Padding = New-Object System.Windows.Forms.Padding(12, 0, 12, 0)
$script:OptionsPanel.BackColor = $script:Page
$script:OptionsPanel.WrapContents = $true
$tip = New-Object System.Windows.Forms.ToolTip
function New-Option {
    param([string]$Name, [string]$Text, [bool]$Checked, [string]$TipText)
    $box = New-Object System.Windows.Forms.CheckBox
    $box.Name = $Name
    $box.Text = $Text
    $box.Checked = $Checked
    $box.AutoSize = $true
    $box.Font = New-UiFont 8
    $box.Margin = New-Object System.Windows.Forms.Padding(0, 4, 16, 0)
    $box.ForeColor = $script:Ink
    $tip.SetToolTip($box, $TipText)
    return $box
}
$script:ChkAuto = New-Option 'Auto' 'Auto-forward rules' $true 'Read mailbox forwarding and inbox forward/redirect rules for internal recipients.'
$script:ChkDisabled = New-Option 'Disabled' 'Include disabled rules' $false 'Also list inbox rules that are turned off.'
$script:ChkPolicy = New-Option 'Policy' 'Tenant policy' $true 'Transport rules, remote-domain auto-forward, and the outbound spam policy.'
$script:ChkOpens = New-Option 'Opens' 'Who opened it' $true 'Search MailItemsAccessed. This needs unified audit logging and, for most tenants, Audit Premium.'
$script:ChkAuditAll = New-Option 'AllUsers' 'Audit all users' $false 'Do not limit the audit search to recipients. This catches delegates and is much slower.'
$script:ChkHigh = New-Option 'High' 'High-completeness audit' $true 'Ask the audit service for a complete MailItemsAccessed result. Slower, fewer missed opens.'
$script:ChkDetail = New-Option 'Detail' 'Trace detail' $false 'Call Get-MessageTraceDetailV2 for related rows, external recipients first. Slower.'
$script:ChkAliases = New-Option 'Aliases' 'Resolve sender aliases' $true 'Treat the sender mailbox aliases as the original sender.'
$script:ChkAuditNow = New-Option 'Now' 'Search opens through now' $true 'Look for opens up to the current time, even if the trace window ended earlier.'
$script:ChkLoose = New-Option 'Loose' 'Loose subject match' $false 'Include subjects that contain the text after prefixes are removed. More false positives.'
$script:OptionsPanel.Controls.AddRange(@(
    $script:ChkAuto, $script:ChkDisabled, $script:ChkPolicy, $script:ChkOpens, $script:ChkAuditAll,
    $script:ChkHigh, $script:ChkDetail, $script:ChkAliases, $script:ChkAuditNow, $script:ChkLoose
))

$buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$buttonPanel.Dock = 'Top'
$buttonPanel.Height = 46
$buttonPanel.Padding = New-Object System.Windows.Forms.Padding(12, 0, 12, 0)
$buttonPanel.BackColor = $script:Page
$buttonPanel.WrapContents = $false
$script:RunButton = New-FlatButton 'Run investigation' 160 $script:Green { Start-Investigation }
$script:CancelButton = New-FlatButton 'Cancel' 100 $script:Red { Stop-Investigation }
$script:CancelButton.Enabled = $false
$exportAll = New-FlatButton 'Export all' 110 $script:Blue { Export-AllReports }
$openFolder = New-FlatButton 'Open folder' 110 $script:Teal { Open-ReportFolder }
$copySummary = New-FlatButton 'Copy summary' 120 $script:Slate { Copy-InvestigationSummary }
$saveProfile = New-FlatButton 'Save profile' 110 $script:Slate { Save-InvestigationProfile }
$loadProfile = New-FlatButton 'Load profile' 110 $script:Slate { Restore-InvestigationProfile }
$script:Progress = New-Object System.Windows.Forms.ProgressBar
$script:Progress.Width = 180
$script:Progress.Height = 18
$script:Progress.Margin = New-Object System.Windows.Forms.Padding(8, 12, 0, 0)
$script:Progress.Minimum = 0
$script:Progress.Maximum = 100
$buttonPanel.Controls.AddRange(@($script:RunButton, $script:CancelButton, $exportAll, $openFolder, $copySummary, $saveProfile, $loadProfile, $script:Progress))

$cardPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$cardPanel.Dock = 'Top'
$cardPanel.Height = 78
$cardPanel.Padding = New-Object System.Windows.Forms.Padding(12, 4, 12, 4)
$cardPanel.BackColor = $script:Page
$cardPanel.WrapContents = $false
foreach ($spec in @(
    @{ Property = 'OriginalRecipients'; Text = 'Original'; Alert = $false }
    @{ Property = 'OriginalExternal'; Text = 'External original'; Alert = $true }
    @{ Property = 'PropagationRecipients'; Text = 'Forwards'; Alert = $false }
    @{ Property = 'PropagationExternal'; Text = 'External forwards'; Alert = $true }
    @{ Property = 'Forwarders'; Text = 'Forwarders'; Alert = $false }
    @{ Property = 'AutoForwardExternal'; Text = 'External rules'; Alert = $true }
    @{ Property = 'OpenedMailboxes'; Text = 'Opened'; Alert = $false }
    @{ Property = 'NoOpenRecipients'; Text = 'No open event'; Alert = $false }
)) {
    $card = New-Object System.Windows.Forms.Panel
    $card.Size = New-Object System.Drawing.Size(140, 64)
    $card.Margin = New-Object System.Windows.Forms.Padding(0, 0, 8, 0)
    $card.BackColor = [System.Drawing.Color]::White
    $card.BorderStyle = 'FixedSingle'
    $valueLabel = New-Object System.Windows.Forms.Label
    $valueLabel.Text = '-'
    $valueLabel.Font = New-UiFont 16 Bold
    $valueLabel.ForeColor = $script:Ink
    $valueLabel.Location = New-Object System.Drawing.Point(8, 4)
    $valueLabel.Size = New-Object System.Drawing.Size(124, 30)
    $nameLabel = New-Object System.Windows.Forms.Label
    $nameLabel.Text = $spec.Text
    $nameLabel.Font = New-UiFont 8
    $nameLabel.ForeColor = $script:Muted
    $nameLabel.Location = New-Object System.Drawing.Point(8, 36)
    $nameLabel.Size = New-Object System.Drawing.Size(124, 22)
    $card.Controls.AddRange(@($valueLabel, $nameLabel))
    $cardPanel.Controls.Add($card)
    $script:Cards += [pscustomobject]@{ Property = $spec.Property; Text = $spec.Text; Alert = [bool]$spec.Alert; ValueLabel = $valueLabel }
}

$status = New-Object System.Windows.Forms.Panel
$status.Dock = 'Bottom'
$status.Height = 26
$status.BackColor = $script:Ink
$script:StatusLabel = New-Object System.Windows.Forms.Label
$script:StatusLabel.Dock = 'Fill'
$script:StatusLabel.ForeColor = [System.Drawing.Color]::White
$script:StatusLabel.Font = New-UiFont 8
$script:StatusLabel.TextAlign = 'MiddleLeft'
$script:StatusLabel.Padding = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)
$script:StatusLabel.Text = 'Ready. Connect, or run and sign in when prompted. Red rows are external addresses.'
$status.Controls.Add($script:StatusLabel)

$split = New-Object System.Windows.Forms.SplitContainer
$split.Dock = 'Fill'
$split.Orientation = 'Horizontal'
$split.SplitterWidth = 6
$split.BackColor = [System.Drawing.Color]::FromArgb(220, 225, 232)
$split.Panel1.BackColor = $script:Page
$split.Panel2.BackColor = $script:Page

$script:Tabs = New-Object System.Windows.Forms.TabControl
$script:Tabs.Dock = 'Fill'
$script:Tabs.Font = New-UiFont 9
$summaryPage = New-Object System.Windows.Forms.TabPage
$summaryPage.Text = '  Summary  '
$summaryPage.BackColor = $script:Page
$summaryPage.Padding = New-Object System.Windows.Forms.Padding(8)
$script:SummaryBox = New-Object System.Windows.Forms.TextBox
$script:SummaryBox.Multiline = $true
$script:SummaryBox.ReadOnly = $true
$script:SummaryBox.ScrollBars = 'Both'
$script:SummaryBox.Dock = 'Fill'
$script:SummaryBox.Font = New-Object System.Drawing.Font('Consolas', 10)
$script:SummaryBox.BackColor = [System.Drawing.Color]::White
$script:SummaryBox.Text = "Run an investigation to see original recipients, forwards, redirects, auto-forward rules, and opens.`r`n`r`nExternal addresses are highlighted in red. A missing open event is not proof the message was unread."
$summaryPage.Controls.Add($script:SummaryBox)
$script:Tabs.TabPages.Add($summaryPage)
foreach ($view in (Get-InvestigationViews)) {
    $tabState = New-ResultTab $view
    $script:GridTabs += $tabState
    $script:Tabs.TabPages.Add($tabState.Page)
}
$split.Panel1.Controls.Add($script:Tabs)

$logHeader = New-Object System.Windows.Forms.Panel
$logHeader.Dock = 'Top'
$logHeader.Height = 28
$logHeader.BackColor = $script:Page
$logLabel = New-Object System.Windows.Forms.Label
$logLabel.Text = 'Activity log'
$logLabel.Font = New-UiFont 9 Bold
$logLabel.ForeColor = $script:Ink
$logLabel.Location = New-Object System.Drawing.Point(8, 4)
$logLabel.AutoSize = $true
$clearLog = New-FlatButton 'Clear' 70 $script:Muted { $script:LogBox.Clear() }
$clearLog.Height = 24
$clearLog.Anchor = 'Top,Right'
$logHeader.Controls.AddRange(@($logLabel, $clearLog))
$script:LogBox = New-Object System.Windows.Forms.TextBox
$script:LogBox.Multiline = $true
$script:LogBox.ReadOnly = $true
$script:LogBox.ScrollBars = 'Both'
$script:LogBox.Dock = 'Fill'
$script:LogBox.Font = New-Object System.Drawing.Font('Consolas', 9)
$script:LogBox.BackColor = $script:Ink
$script:LogBox.ForeColor = [System.Drawing.Color]::FromArgb(230, 236, 242)
$script:LogBox.WordWrap = $false
$split.Panel2.Controls.Add($script:LogBox)
$split.Panel2.Controls.Add($logHeader)

$form.Controls.Add($split)
$form.Controls.Add($status)
$form.Controls.Add($cardPanel)
$form.Controls.Add($buttonPanel)
$form.Controls.Add($script:OptionsPanel)
$form.Controls.Add($script:FieldsPanel)
$form.Controls.Add($header)

function Update-HeaderLayout {
    $width = $header.ClientSize.Width
    $script:DisconnectButton.Left = $width - $script:DisconnectButton.Width - 16
    $script:DisconnectButton.Top = 16
    $script:ConnectButton.Left = $script:DisconnectButton.Left - $script:ConnectButton.Width - 8
    $script:ConnectButton.Top = 16
    $script:UpnBox.Left = $script:ConnectButton.Left - $script:UpnBox.Width - 8
    $script:UpnBox.Top = 18
    $upnLabel.Left = $script:UpnBox.Left - 84
    $upnLabel.Top = 18
    $script:ConnectionLabel.Left = [Math]::Max(360, $upnLabel.Left - $script:ConnectionLabel.Width - 16)
    $script:ConnectionLabel.Top = 20
}
function Update-FieldLayout {
    $width = $script:FieldsPanel.ClientSize.Width
    $right = 12
    $browse.Left = $width - $browse.Width - $right
    $browse.Top = 74
    $script:MessageIdBox.Width = 220
    $script:MessageIdBox.Left = $width - $script:MessageIdBox.Width - $right
    $idLabel.Left = $script:MessageIdBox.Left - 84
    $script:SubjectBox.Width = [Math]::Max(160, $idLabel.Left - $script:SubjectBox.Left - 12)
    $script:FolderBox.Width = [Math]::Max(160, $browse.Left - $script:FolderBox.Left - 8)
    $script:ExtraUsersBox.Width = [Math]::Max(160, $width - $script:ExtraUsersBox.Left - $right)
    $presetPanel.Left = $width - $presetPanel.Width - $right
    $script:EndPicker.Left = $presetPanel.Left - $script:EndPicker.Width - 36
    $endLabel.Left = $script:EndPicker.Left - 36
    $script:StartPicker.Left = $endLabel.Left - $script:StartPicker.Width - 56
    $startLabel.Left = $script:StartPicker.Left - 40
    $script:SenderBox.Width = [Math]::Max(120, $startLabel.Left - $script:SenderBox.Left - 12)
}
$header.Add_Resize({ Update-HeaderLayout })
$script:FieldsPanel.Add_Resize({ Update-FieldLayout })
$logHeader.Add_Resize({ $clearLog.Left = $logHeader.ClientSize.Width - $clearLog.Width - 8; $clearLog.Top = 2 })
$form.Add_Shown({
    Update-HeaderLayout
    Update-FieldLayout
    try { $split.SplitterDistance = [Math]::Max(240, $split.Height - 180) } catch { }
})
$form.Add_FormClosing({
    $script:Sync.Cancel = $true
    $script:UiTimer.Stop()
    if ($script:Pipeline) {
        try { $script:Pipeline.Stop() } catch { }
        try { $script:Pipeline.Dispose() } catch { }
    }
    try { $script:Runspace.Close() } catch { }
    try { $script:Runspace.Dispose() } catch { }
})

$tip.SetToolTip($script:ExtraUsersBox, 'Optional delegate or assistant UPNs, separated by commas, semicolons, or new lines. MailItemsAccessed records the person who opened the mailbox, not only the owner.')
$tip.SetToolTip($script:FolderBox, 'Leave empty to create EmailInvestigation_timestamp under Documents.')
$tip.SetToolTip($script:MessageIdBox, 'Optional Internet message ID of the original send. Forwards still use the subject search because they get a new message ID.')
$tip.SetToolTip($script:UpnBox, 'Optional sign-in hint. Leave blank to use the normal Exchange Online account picker.')

[void]$form.ShowDialog()
$form.Dispose()
