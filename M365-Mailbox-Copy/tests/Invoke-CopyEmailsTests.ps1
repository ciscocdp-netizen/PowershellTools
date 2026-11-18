<#
.SYNOPSIS
    End-to-end tests for Copy-Emails against a fake Graph.

.DESCRIPTION
    Runs the real Copy-Emails over the folder mocks in GraphMocks.ps1 and the
    message mocks in MessageMocks.ps1, so the whole pass is exercised: scan both
    mailboxes, diff the structures, create only what is missing, then copy mail
    folder by folder with duplicate detection, progress and the ETA.

    These cases are about the wiring between the pieces rather than the folder
    algebra (Invoke-FolderStructureTests.ps1) or the estimate (Invoke-ProgressTests.ps1).

.EXAMPLE
    pwsh -File ./Invoke-CopyEmailsTests.ps1

.NOTES
    Exits 1 if any case fails. Runs on Windows PowerShell 5.1 and PowerShell 7.
#>

[CmdletBinding()]
param(
    [string]$ToolPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'M365-Mailbox-Copy-Tool.ps1')
)

$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/WinFormsShim.ps1"
. "$PSScriptRoot/GraphMocks.ps1"
. "$PSScriptRoot/MessageMocks.ps1"
. "$PSScriptRoot/ToolLoader.ps1"
. ([scriptblock]::Create((Import-ToolDefinitions -Path $ToolPath)))

Assert-ToolFunctionsPresent -ToolPath $ToolPath -Names @('Copy-Emails', 'Initialize-CopyUi')

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

function Reset-World {
    Reset-FakeGraph
    Reset-FakeMail
    $script:CancelRequested = $false
    $script:FolderScanIncomplete = $false
}

function Get-TargetFolderIdByPath {
    param([string]$UserId, [string]$Path)
    $parentId = $null
    foreach ($segment in ($Path -split '\\')) {
        $match = @(Get-FakeChildren -UserId $UserId -ParentId $parentId | Where-Object { $_.DisplayName -eq $segment })
        if ($match.Count -ne 1) { return $null }
        $parentId = $match[0].Id
    }
    return $parentId
}

function Assert-TargetFolderHolds {
    param([string]$UserId, [string]$Path, [string[]]$Subjects)

    $folderId = Get-TargetFolderIdByPath -UserId $UserId -Path $Path
    if (-not $folderId) {
        Assert-That "target folder '$Path' exists" $false "not found in the target mailbox"
        return
    }
    $actual = @(Get-FakeMessageSubjects -UserId $UserId -FolderId $folderId | Sort-Object)
    $wanted = @($Subjects | Sort-Object)
    Assert-That "'$Path' holds exactly [$($wanted -join ', ')]" `
        (($actual -join '|') -eq ($wanted -join '|')) "found [$($actual -join ', ')]"
}

# ==============================================================================
Start-Case 'A full copy mirrors the structure and files every message in its folder'
Reset-World
$ui = New-TestUi
$src = 'src@contoso.com'; $tgt = 'tgt@contoso.com'

New-FakeMailbox -UserId $src
$srcInbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -WellKnownName 'inbox'
$srcSent  = Add-FakeFolder -UserId $src -DisplayName 'Sent Items' -WellKnownName 'sentitems'
Add-FakeFolder -UserId $src -DisplayName 'Drafts' -WellKnownName 'drafts' | Out-Null
$srcClients  = Add-FakeFolder -UserId $src -DisplayName 'Clients' -ParentId $srcInbox
$srcInvoices = Add-FakeFolder -UserId $src -DisplayName 'Invoices' -ParentId $srcClients
Add-FakeFolder -UserId $src -DisplayName 'Empty Folder' -ParentId $srcInbox | Out-Null

Add-FakeMessage -UserId $src -FolderId $srcInbox    -Subject 'inbox one'   | Out-Null
Add-FakeMessage -UserId $src -FolderId $srcInbox    -Subject 'inbox two'   | Out-Null
Add-FakeMessage -UserId $src -FolderId $srcInbox    -Subject 'inbox three' | Out-Null
Add-FakeMessage -UserId $src -FolderId $srcSent     -Subject 'sent one'    | Out-Null
Add-FakeMessage -UserId $src -FolderId $srcClients  -Subject 'client one'  | Out-Null
Add-FakeMessage -UserId $src -FolderId $srcInvoices -Subject 'invoice one' | Out-Null
Add-FakeMessage -UserId $src -FolderId $srcInvoices -Subject 'invoice two' | Out-Null
Sync-FakeItemCounts -UserId $src

New-FakeMailbox -UserId $tgt
Add-FakeFolder -UserId $tgt -DisplayName 'Inbox' -WellKnownName 'inbox' | Out-Null
Add-FakeFolder -UserId $tgt -DisplayName 'Sent Items' -WellKnownName 'sentitems' | Out-Null
Add-FakeFolder -UserId $tgt -DisplayName 'Drafts' -WellKnownName 'drafts' | Out-Null

$result = Copy-Emails -SourceEmail $src -TargetEmail $tgt -StatusBox $ui.StatusBox -ProgressBar $ui.ProgressBar

Assert-That 'the copy reports success' ([bool]$result.Success)
Assert-That 'all seven messages were copied' ($result.Copied -eq 7) "copied $($result.Copied)"
Assert-That 'nothing was skipped' ($result.Skipped -eq 0) "skipped $($result.Skipped)"
Assert-That 'nothing failed' ($result.Failed -eq 0) "failed $($result.Failed)"
Assert-That 'three folders were reported as already present' ($result.FoldersExisted -eq 3) `
    "existed $($result.FoldersExisted)"
Assert-That 'the three absent folders were created' ($result.FoldersCreated -eq 3) `
    "created $($result.FoldersCreated)"
Assert-TargetFolderHolds -UserId $tgt -Path 'Inbox' -Subjects @('inbox one', 'inbox two', 'inbox three')
Assert-TargetFolderHolds -UserId $tgt -Path 'Sent Items' -Subjects @('sent one')
Assert-TargetFolderHolds -UserId $tgt -Path 'Inbox\Clients' -Subjects @('client one')
Assert-TargetFolderHolds -UserId $tgt -Path 'Inbox\Clients\Invoices' -Subjects @('invoice one', 'invoice two')
Assert-That 'the empty source folder was created empty' `
    ((Get-TargetFolderIdByPath -UserId $tgt -Path 'Inbox\Empty Folder') -and
     (Get-FakeMessageSubjects -UserId $tgt -FolderId (Get-TargetFolderIdByPath -UserId $tgt -Path 'Inbox\Empty Folder')).Count -eq 0)
Assert-That 'no message was posted to the mailbox root' ($script:RootPostedMessages.Count -eq 0) `
    ("root posts: " + ($script:RootPostedMessages -join ', '))
Assert-That 'the log shows the structure comparison' ($ui.StatusBox.Text -match 'FOLDER STRUCTURE COMPARISON') 
Assert-That 'the progress bar finished at 100%' ($ui.ProgressBar.Value -eq 100) "value $($ui.ProgressBar.Value)"
Assert-That 'the progress engine accounted for every message' ($script:Prog.Done -eq 7) "done $($script:Prog.Done)"

# ==============================================================================
Start-Case 'A second run copies nothing and creates nothing'
$ui = New-TestUi
$postsBefore = $script:MessagePostCount
$result = Copy-Emails -SourceEmail $src -TargetEmail $tgt -StatusBox $ui.StatusBox -ProgressBar $ui.ProgressBar

Assert-That 'every message is recognised as a duplicate' ($result.Skipped -eq 7) "skipped $($result.Skipped)"
Assert-That 'nothing was copied again' ($result.Copied -eq 0) "copied $($result.Copied)"
Assert-That 'no message create was attempted' ($script:MessagePostCount -eq $postsBefore) `
    "$($script:MessagePostCount - $postsBefore) creates"
Assert-That 'the structures now match' ($result.FoldersMissing -eq 0) "missing $($result.FoldersMissing)"
Assert-That 'no folder was created' ($result.FoldersCreated -eq 0) "created $($result.FoldersCreated)"
Assert-TargetFolderHolds -UserId $tgt -Path 'Inbox' -Subjects @('inbox one', 'inbox two', 'inbox three')

# ==============================================================================
Start-Case 'Only messages the target is missing are copied'
Reset-World
$ui = New-TestUi
$src = 'src2@contoso.com'; $tgt = 'tgt2@contoso.com'

New-FakeMailbox -UserId $src
$srcInbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -WellKnownName 'inbox'
Add-FakeMessage -UserId $src -FolderId $srcInbox -Subject 'already there' -Received '2025-02-01T09:30:00Z' | Out-Null
Add-FakeMessage -UserId $src -FolderId $srcInbox -Subject 'brand new'     -Received '2025-02-02T09:30:00Z' | Out-Null
Sync-FakeItemCounts -UserId $src

New-FakeMailbox -UserId $tgt
$tgtInbox = Add-FakeFolder -UserId $tgt -DisplayName 'Inbox' -WellKnownName 'inbox'
Add-FakeMessage -UserId $tgt -FolderId $tgtInbox -Subject 'already there' -Received '2025-02-01T09:30:00Z' | Out-Null
Sync-FakeItemCounts -UserId $tgt

$result = Copy-Emails -SourceEmail $src -TargetEmail $tgt -StatusBox $ui.StatusBox -ProgressBar $ui.ProgressBar

Assert-That 'the duplicate was skipped' ($result.Skipped -eq 1) "skipped $($result.Skipped)"
Assert-That 'the new message was copied' ($result.Copied -eq 1) "copied $($result.Copied)"
Assert-TargetFolderHolds -UserId $tgt -Path 'Inbox' -Subjects @('already there', 'brand new')

# ==============================================================================
Start-Case 'Mail from a folder that cannot be created is skipped, never drafted'
Reset-World
$ui = New-TestUi
$src = 'src3@contoso.com'; $tgt = 'tgt3@contoso.com'

New-FakeMailbox -UserId $src
$srcInbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -WellKnownName 'inbox'
$srcLegal = Add-FakeFolder -UserId $src -DisplayName 'Legal' -ParentId $srcInbox
$srcCases = Add-FakeFolder -UserId $src -DisplayName 'Cases' -ParentId $srcLegal
Add-FakeMessage -UserId $src -FolderId $srcInbox -Subject 'ordinary mail' | Out-Null
Add-FakeMessage -UserId $src -FolderId $srcLegal -Subject 'legal mail'    | Out-Null
Add-FakeMessage -UserId $src -FolderId $srcCases -Subject 'case mail'     | Out-Null
Sync-FakeItemCounts -UserId $src

New-FakeMailbox -UserId $tgt
Add-FakeFolder -UserId $tgt -DisplayName 'Inbox' -WellKnownName 'inbox' | Out-Null
$script:FailFolderCreate['Legal'] = 'Status: 403 (Forbidden) Code: ErrorAccessDenied Message: Access is denied.'

$result = Copy-Emails -SourceEmail $src -TargetEmail $tgt -StatusBox $ui.StatusBox -ProgressBar $ui.ProgressBar

Assert-That 'the folder that could be created still received its mail' ($result.Copied -eq 1) "copied $($result.Copied)"
Assert-That 'the two unreachable messages are counted as failures' ($result.Failed -eq 2) "failed $($result.Failed)"
Assert-That 'the failed folder is reported' ($result.FoldersFailed -ge 1) "foldersFailed $($result.FoldersFailed)"
Assert-That 'nothing was posted to the mailbox root' ($script:RootPostedMessages.Count -eq 0) `
    ("root posts: " + ($script:RootPostedMessages -join ', '))
Assert-That 'the log explains the skip' ($ui.StatusBox.Text -match 'SKIPPED: no target folder') 
Assert-TargetFolderHolds -UserId $tgt -Path 'Inbox' -Subjects @('ordinary mail')
Assert-That 'the subtree under the failed folder was not created' `
    ($null -eq (Get-TargetFolderIdByPath -UserId $tgt -Path 'Inbox\Legal'))

# ==============================================================================
Start-Case 'A folder whose item count was wrong corrects the overall total'
Reset-World
$ui = New-TestUi
$src = 'src4@contoso.com'; $tgt = 'tgt4@contoso.com'

New-FakeMailbox -UserId $src
$srcInbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -WellKnownName 'inbox'
Add-FakeMessage -UserId $src -FolderId $srcInbox -Subject 'real one' | Out-Null
Add-FakeMessage -UserId $src -FolderId $srcInbox -Subject 'real two' | Out-Null
Sync-FakeItemCounts -UserId $src
# Exchange reports associated/hidden items in TotalItemCount, so the folder can
# claim more than /messages ever returns.
$script:Store[$src].Folders[$srcInbox].TotalItemCount = 9

New-FakeMailbox -UserId $tgt
Add-FakeFolder -UserId $tgt -DisplayName 'Inbox' -WellKnownName 'inbox' | Out-Null

$result = Copy-Emails -SourceEmail $src -TargetEmail $tgt -StatusBox $ui.StatusBox -ProgressBar $ui.ProgressBar

Assert-That 'both real messages were copied' ($result.Copied -eq 2) "copied $($result.Copied)"
Assert-That 'the total was corrected to what the folder actually returned' ($script:Prog.Total -eq 2) `
    "total $($script:Prog.Total)"
Assert-That 'the progress bar still reached 100%' ($ui.ProgressBar.Value -eq 100) "value $($ui.ProgressBar.Value)"
Assert-That 'the log records the listed count' ($ui.StatusBox.Text -match 'source folder listed 2 messages')

# ==============================================================================
Start-Case 'A message that Graph rejects is counted and the folder carries on'
Reset-World
$ui = New-TestUi
$src = 'src5@contoso.com'; $tgt = 'tgt5@contoso.com'

New-FakeMailbox -UserId $src
$srcInbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -WellKnownName 'inbox'
Add-FakeMessage -UserId $src -FolderId $srcInbox -Subject 'good one' | Out-Null
Add-FakeMessage -UserId $src -FolderId $srcInbox -Subject 'poison'   | Out-Null
Add-FakeMessage -UserId $src -FolderId $srcInbox -Subject 'good two' | Out-Null
Sync-FakeItemCounts -UserId $src

New-FakeMailbox -UserId $tgt
Add-FakeFolder -UserId $tgt -DisplayName 'Inbox' -WellKnownName 'inbox' | Out-Null
$script:FailMessageCreate['poison'] = 'Status: 400 (BadRequest) Code: ErrorInvalidPropertySet Message: nope.'

$result = Copy-Emails -SourceEmail $src -TargetEmail $tgt -StatusBox $ui.StatusBox -ProgressBar $ui.ProgressBar

Assert-That 'the other messages still copied' ($result.Copied -eq 2) "copied $($result.Copied)"
Assert-That 'the rejected message is counted as failed' ($result.Failed -eq 1) "failed $($result.Failed)"
Assert-That 'the failure names the message' ($ui.StatusBox.Text -match "Failed 'poison'")
Assert-TargetFolderHolds -UserId $tgt -Path 'Inbox' -Subjects @('good one', 'good two')

# ==============================================================================
Start-Case 'Cancelling mid-copy stops and reports the work done so far'
Reset-World
$ui = New-TestUi
$src = 'src6@contoso.com'; $tgt = 'tgt6@contoso.com'

New-FakeMailbox -UserId $src
$srcInbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -WellKnownName 'inbox'
foreach ($n in 1..6) { Add-FakeMessage -UserId $src -FolderId $srcInbox -Subject "message $n" | Out-Null }
Sync-FakeItemCounts -UserId $src

New-FakeMailbox -UserId $tgt
Add-FakeFolder -UserId $tgt -DisplayName 'Inbox' -WellKnownName 'inbox' | Out-Null

$script:CancelAfterPosts = 3     # user hits Cancel after the third message

$result = Copy-Emails -SourceEmail $src -TargetEmail $tgt -StatusBox $ui.StatusBox -ProgressBar $ui.ProgressBar

Assert-That 'the run reports it was cancelled' ([bool]$result.Cancelled)
Assert-That 'it stopped before copying everything' ($result.Copied -lt 6 -and $result.Copied -ge 1) `
    "copied $($result.Copied)"
Assert-That 'the log says it was cancelled' ($ui.StatusBox.Text -match 'COPY CANCELLED BY USER')
Assert-That 'what was copied is really in the target folder' `
    ((Get-FakeMessageSubjects -UserId $tgt -FolderId (Get-TargetFolderIdByPath -UserId $tgt -Path 'Inbox')).Count -eq $result.Copied) `
    "target holds $((Get-FakeMessageSubjects -UserId $tgt -FolderId (Get-TargetFolderIdByPath -UserId $tgt -Path 'Inbox')).Count), reported $($result.Copied)"

# ==============================================================================
Write-Host ''
Write-Host ('-' * 60)
Write-Host ("Passed: {0}   Failed: {1}" -f $script:Passed, $script:Failed) `
    -ForegroundColor $(if ($script:Failed -gt 0) { 'Red' } else { 'Green' })

if ($script:Failed -gt 0) { exit 1 }
exit 0
