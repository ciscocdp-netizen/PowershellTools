<#
.SYNOPSIS
    Regression tests for the copy tool's live status, progress and ETA.

.DESCRIPTION
    Loads the progress engine out of M365-Mailbox-Copy-Tool.ps1 and drives it
    against a virtual clock, so the ETA maths can be asserted exactly instead of
    being timed against the wall clock. Get-CopyClockNow is redefined after the
    tool is imported, which is the seam the engine reads "now" through.

    Covered: duration formatting, the phase/detail/position status line, the
    percentage and marquee states of the progress bar, the estimate itself
    (including that it follows recent throughput rather than the average since
    the start), repaint throttling, mid-run total corrections, and that every
    entry point is inert when there is no UI (which is how the folder tests call
    the folder functions).

.EXAMPLE
    pwsh -File ./Invoke-ProgressTests.ps1

.NOTES
    Exits 1 if any case fails. Runs on Windows PowerShell 5.1 and PowerShell 7.
#>

[CmdletBinding()]
param(
    [string]$ToolPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'M365-Mailbox-Copy-Tool.ps1')
)

$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/WinFormsShim.ps1"
. "$PSScriptRoot/ToolLoader.ps1"
. ([scriptblock]::Create((Import-ToolDefinitions -Path $ToolPath)))

Assert-ToolFunctionsPresent -ToolPath $ToolPath -Names @(
    'Initialize-CopyUi', 'Start-CopyPhase', 'Set-CopyPhaseTotal', 'Set-CopyDetail',
    'Add-CopyWork', 'Update-CopyStatusDisplay', 'Get-CopyRate', 'Format-CopyDuration',
    'Format-CopyRateText', 'Get-CopyClockNow', 'Write-CopyLog'
)

# ------------------------------------------------------------------------------
# Virtual clock: replaces the tool's own Get-CopyClockNow
# ------------------------------------------------------------------------------
$script:FakeNow = [datetime]'2026-01-01T09:00:00'

function Get-CopyClockNow {
    return $script:FakeNow
}

function Step-Clock {
    param([double]$Seconds)
    $script:FakeNow = $script:FakeNow.AddSeconds($Seconds)
}

# ------------------------------------------------------------------------------
# Test plumbing
# ------------------------------------------------------------------------------
$script:Passed = 0
$script:Failed = 0

function Start-Case {
    param([string]$Name)
    Write-Host ''
    Write-Host "== $Name" -ForegroundColor White
}

function Assert-That {
    param([string]$Description, [bool]$Condition, [string]$Detail = '')
    if ($Condition) {
        $script:Passed++
        Write-Host "   PASS  $Description" -ForegroundColor Green
    }
    else {
        $script:Failed++
        Write-Host "   FAIL  $Description" -ForegroundColor Red
        if ($Detail) { Write-Host "         $Detail" -ForegroundColor Red }
    }
}

function New-TestUi {
    param([datetime]$StartTime = [datetime]'2026-01-01T09:00:00')

    $script:FakeNow = $StartTime
    $ui = @{
        StatusBox   = New-Object System.Windows.Forms.TextBox
        ProgressBar = New-Object System.Windows.Forms.ProgressBar
        PhaseLabel  = New-Object System.Windows.Forms.Label
        EtaLabel    = New-Object System.Windows.Forms.Label
    }
    Initialize-CopyUi -StatusBox $ui.StatusBox -ProgressBar $ui.ProgressBar `
        -PhaseLabel $ui.PhaseLabel -EtaLabel $ui.EtaLabel
    return $ui
}

# ==============================================================================
Start-Case 'Durations are formatted at a useful scale'
Assert-That "45 seconds reads '45s'"            ((Format-CopyDuration 45) -eq '45s')            "got '$(Format-CopyDuration 45)'"
Assert-That "90 seconds reads '1m 30s'"         ((Format-CopyDuration 90) -eq '1m 30s')         "got '$(Format-CopyDuration 90)'"
Assert-That "3725 seconds reads '1h 02m 05s'"   ((Format-CopyDuration 3725) -eq '1h 02m 05s')   "got '$(Format-CopyDuration 3725)'"
Assert-That "90000 seconds reads '1d 01h 00m'"  ((Format-CopyDuration 90000) -eq '1d 01h 00m')  "got '$(Format-CopyDuration 90000)'"
Assert-That "a negative duration reads '--'"    ((Format-CopyDuration -5) -eq '--')             "got '$(Format-CopyDuration -5)'"
Assert-That 'a sub-item-per-second rate is shown per minute' `
    ((Format-CopyRateText 0.25) -eq '15.0 items/min') "got '$(Format-CopyRateText 0.25)'"
Assert-That 'a fast rate is shown per second' `
    ((Format-CopyRateText 4.26) -eq '4.3 items/s') "got '$(Format-CopyRateText 4.26)'"

# ==============================================================================
Start-Case 'A phase of unknown size counts up and runs the bar as a marquee'
$ui = New-TestUi
Start-CopyPhase -Name 'Scanning source folders' -Indeterminate
foreach ($path in @('Inbox', 'Inbox\Clients', 'Inbox\Clients\2024')) {
    Step-Clock 1
    Add-CopyWork -Done 1 -Detail $path
}
Assert-That 'the phase name is shown' ($ui.PhaseLabel.Text -like 'Scanning source folders*') "got '$($ui.PhaseLabel.Text)'"
Assert-That 'the current folder is shown' ($ui.PhaseLabel.Text -like "*Inbox\Clients\2024*") "got '$($ui.PhaseLabel.Text)'"
Assert-That 'the running count is shown' ($ui.PhaseLabel.Text -like '*3 so far*') "got '$($ui.PhaseLabel.Text)'"
Assert-That 'no percentage is invented' ($ui.PhaseLabel.Text -notlike '*%*') "got '$($ui.PhaseLabel.Text)'"
Assert-That 'the ETA line says it is still working' ($ui.EtaLabel.Text -like '*working...*') "got '$($ui.EtaLabel.Text)'"
Assert-That 'the progress bar is a marquee' `
    ($ui.ProgressBar.Style -eq [System.Windows.Forms.ProgressBarStyle]::Marquee) "got '$($ui.ProgressBar.Style)'"

# ==============================================================================
Start-Case 'A sized phase reports position, percentage and a remaining estimate'
$ui = New-TestUi
Start-CopyPhase -Name 'Copying email' -Total 100
Step-Clock 50
Add-CopyWork -Done 25 -Copied 20 -Skipped 4 -Failed 1 -Detail "folder 1/3 'Inbox'"
Assert-That 'the position is shown' ($ui.PhaseLabel.Text -like '*25 / 100*') "got '$($ui.PhaseLabel.Text)'"
Assert-That 'the percentage is shown' ($ui.PhaseLabel.Text -like '*(25%)*') "got '$($ui.PhaseLabel.Text)'"
Assert-That 'the progress bar switched to a percentage' `
    ($ui.ProgressBar.Style -eq [System.Windows.Forms.ProgressBarStyle]::Continuous -and $ui.ProgressBar.Value -eq 25) `
    "style '$($ui.ProgressBar.Style)', value $($ui.ProgressBar.Value)"
# 25 items in 50s is 0.5/s, so the remaining 75 need 150 seconds.
Assert-That 'the remaining time is estimated from throughput' ($ui.EtaLabel.Text -like '*remaining ~2m 30s*') "got '$($ui.EtaLabel.Text)'"
Assert-That 'the finish time is shown as a wall-clock time' ($ui.EtaLabel.Text -like '*done by 09:03*') "got '$($ui.EtaLabel.Text)'"
Assert-That 'the throughput is shown' ($ui.EtaLabel.Text -like '*0.5 items/s*' -or $ui.EtaLabel.Text -like '*30.0 items/min*') "got '$($ui.EtaLabel.Text)'"
Assert-That 'the running totals are shown' ($ui.EtaLabel.Text -like '*copied 20, skipped 4, failed 1*') "got '$($ui.EtaLabel.Text)'"

# ==============================================================================
Start-Case 'The estimate follows recent throughput, not the average since the start'
$ui = New-TestUi
Start-CopyPhase -Name 'Copying email' -Total 1000
Step-Clock 20
Add-CopyWork -Done 200          # 10 items/s to begin with
$fastRate = Get-CopyRate
Assert-That 'the fast opening rate is measured' ([math]::Round($fastRate, 2) -eq 10) "got $fastRate"
# Graph starts throttling: 30 items over the next 150 seconds, which is longer
# than the trailing window, so the fast opening drops out of the estimate.
for ($i = 0; $i -lt 30; $i++) {
    Step-Clock 5
    Add-CopyWork -Done 1
}
$slowRate    = Get-CopyRate
$averageRate = 230 / 170
Assert-That 'the rate drops once throughput drops' ($slowRate -lt $fastRate) "fast $fastRate, now $slowRate"
Assert-That 'the drop is sharper than the average since the phase started' ($slowRate -lt $averageRate) `
    "windowed $slowRate, average since start $averageRate"
Assert-That 'the remaining estimate grew accordingly' ($ui.EtaLabel.Text -notlike '*remaining ~1m*') "got '$($ui.EtaLabel.Text)'"

# ==============================================================================
Start-Case 'Repaints are throttled but never lose the underlying counters'
$ui = New-TestUi
Start-CopyPhase -Name 'Copying email' -Total 100
Step-Clock 10
Add-CopyWork -Done 10
$afterFirst = $ui.PhaseLabel.Text
Step-Clock 0.1                      # inside the 250 ms repaint window
Add-CopyWork -Done 5
Assert-That 'a repaint inside the window is skipped' ($ui.PhaseLabel.Text -eq $afterFirst) "got '$($ui.PhaseLabel.Text)'"
Set-CopyDetail -Detail 'forced' -Force
Assert-That 'a forced repaint shows the work done in between' ($ui.PhaseLabel.Text -like '*15 / 100*') "got '$($ui.PhaseLabel.Text)'"
Assert-That 'the forced detail is shown' ($ui.PhaseLabel.Text -like '*forced*') "got '$($ui.PhaseLabel.Text)'"

# ==============================================================================
Start-Case 'A corrected total is reflected in the percentage and the estimate'
$ui = New-TestUi
Start-CopyPhase -Name 'Copying email' -Total 100
Step-Clock 20
Add-CopyWork -Done 50
Assert-That 'the original total gives 50%' ($ui.PhaseLabel.Text -like '*(50%)*') "got '$($ui.PhaseLabel.Text)'"
Set-CopyPhaseTotal -Total 200       # the folder actually held twice as much
Assert-That 'the corrected total gives 25%' ($ui.PhaseLabel.Text -like '*50 / 200*' -and $ui.PhaseLabel.Text -like '*(25%)*') `
    "got '$($ui.PhaseLabel.Text)'"
Assert-That 'the progress bar follows the correction' ($ui.ProgressBar.Value -eq 25) "value $($ui.ProgressBar.Value)"

# ==============================================================================
Start-Case 'A finished phase does not report a remaining time'
$ui = New-TestUi
Start-CopyPhase -Name 'Copying email' -Total 40
Step-Clock 60
Add-CopyWork -Done 40 -Copied 40
Assert-That 'the position reads 100%' ($ui.PhaseLabel.Text -like '*(100%)*') "got '$($ui.PhaseLabel.Text)'"
Assert-That 'no remaining time is shown' ($ui.EtaLabel.Text -notlike '*remaining*') "got '$($ui.EtaLabel.Text)'"
Assert-That 'the phase duration is reported' ($ui.EtaLabel.Text -like '*phase complete in 1m 00s*') "got '$($ui.EtaLabel.Text)'"
Add-CopyWork -Done 10               # more items than the folder claimed to hold
Update-CopyStatusDisplay -Force
Assert-That 'overshooting the total cannot push the bar past 100%' ($ui.ProgressBar.Value -eq 100) `
    "value $($ui.ProgressBar.Value)"
Assert-That 'the position is clamped to the total' ($ui.PhaseLabel.Text -like '*40 / 40*') "got '$($ui.PhaseLabel.Text)'"

# ==============================================================================
Start-Case 'A new phase restarts the counters and the estimate'
$ui = New-TestUi
Start-CopyPhase -Name 'Copying email' -Total 100
Step-Clock 30
Add-CopyWork -Done 60 -Copied 55 -Failed 5
Start-CopyPhase -Name 'Copying calendar' -Total 20
Assert-That 'the new phase name is shown' ($ui.PhaseLabel.Text -like 'Copying calendar*') "got '$($ui.PhaseLabel.Text)'"
Assert-That 'the item counter restarts' ($ui.PhaseLabel.Text -like '*0 / 20*') "got '$($ui.PhaseLabel.Text)'"
Assert-That 'the copied/failed totals restart' ($ui.EtaLabel.Text -notlike '*copied*') "got '$($ui.EtaLabel.Text)'"
Assert-That 'the elapsed time still covers the whole run' ($ui.EtaLabel.Text -like '*Elapsed 30s*') "got '$($ui.EtaLabel.Text)'"

# ==============================================================================
Start-Case 'Without a UI the engine is inert, so the folder code stays callable'
$script:Ui   = $null
$script:Prog = $null
$noUiFailure = $null
try {
    Start-CopyPhase -Name 'Scanning' -Indeterminate
    Set-CopyPhaseTotal -Total 10
    Set-CopyDetail -Detail 'anything' -Force
    Add-CopyWork -Done 1 -Copied 1
    Update-CopyStatusDisplay -Force
    Assert-That 'the rate of a missing run is zero' ((Get-CopyRate) -eq 0)
}
catch {
    $noUiFailure = $_.Exception.Message
}
Assert-That 'no progress call throws without a UI' ($null -eq $noUiFailure) "threw: $noUiFailure"

# ==============================================================================
Start-Case 'Log lines reach the status box'
$ui = New-TestUi
Write-CopyLog 'first line'
Write-CopyLog 'second line'
Assert-That 'both lines are in the status box' `
    ($ui.StatusBox.Text -like "*first line*" -and $ui.StatusBox.Text -like "*second line*") `
    "got '$($ui.StatusBox.Text)'"
Assert-That 'lines are separated by a CRLF' ($ui.StatusBox.Text -eq "first line`r`nsecond line`r`n") `
    "got '$($ui.StatusBox.Text -replace "`r`n", '<crlf>')'"

# ==============================================================================
Write-Host ''
Write-Host ('-' * 60)
Write-Host ("Passed: {0}   Failed: {1}" -f $script:Passed, $script:Failed) `
    -ForegroundColor $(if ($script:Failed -gt 0) { 'Red' } else { 'Green' })

if ($script:Failed -gt 0) { exit 1 }
exit 0
