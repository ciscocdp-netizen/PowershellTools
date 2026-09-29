<#
.SYNOPSIS
    Regression tests for mailbox reachability and for Graph errors that used to
    pass unnoticed.

.DESCRIPTION
    Covers the failure this exists to prevent: Graph answers "there is no
    mailbox behind this address" with a non-terminating 404 raised deep inside a
    listing call, so the tool printed

        Get-MgUserMailFolder : The specified object was not found in the store.,
        Default folder Root not found. Status: 404 (NotFound)
        ErrorCode: ErrorItemNotFound

    to the console, read the listing as an empty mailbox, and went on to report a
    completed copy of nothing.

    The cases here check that such a mailbox is identified BEFORE anything is
    created, that the explanation names the checks to run, and that a listing
    error can never again be mistaken for an empty mailbox.

.EXAMPLE
    pwsh -File ./Invoke-MailboxAccessTests.ps1

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

Assert-ToolFunctionsPresent -ToolPath $ToolPath -Names @(
    'Test-MailboxAccess', 'Get-GraphFailureKind', 'Get-MailboxProblemAdvice',
    'Write-UnreadableMailboxResult', 'Get-AllMailFolders', 'Copy-Emails'
)

# The verbatim Graph error from the field report, wrapped the way the SDK
# surfaces it.
$script:RootNotFoundError = 'The specified object was not found in the store., Default folder Root not found. Status: 404 (NotFound) ErrorCode: ErrorItemNotFound'

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
    $script:CancelRequested      = $false
    $script:FolderScanIncomplete = $false
    $script:LastFolderScanError  = $null
}

function New-PopulatedMailbox {
    param([string]$UserId)
    New-FakeMailbox -UserId $UserId
    $inbox = Add-FakeFolder -UserId $UserId -DisplayName 'Inbox' -WellKnownName 'inbox'
    Add-FakeFolder -UserId $UserId -DisplayName 'Sent Items' -WellKnownName 'sentitems' | Out-Null
    return $inbox
}

function Get-AdviceText {
    param($Check)
    return (@($Check.Advice) -join "`n")
}

# ==============================================================================
Start-Case 'A mailbox that opens passes the check'
Reset-World
New-PopulatedMailbox -UserId 'src@contoso.com' | Out-Null

$check = Test-MailboxAccess -Address 'src@contoso.com' -Role 'Source'

Assert-That 'the check passes' ([bool]$check.Ok) $check.Problem
Assert-That 'the mailbox root is identified' ([bool]$check.RootId)
Assert-That 'nothing is reported as a problem' ([string]::IsNullOrEmpty($check.Problem)) $check.Problem

# ==============================================================================
Start-Case 'A display name or bare alias is rejected without asking Graph'
Reset-World

foreach ($bad in @('Kirk Smith', 'ksmith', 'kirk@contoso', '')) {
    $script:MailFolderCallCount = 0
    $check = Test-MailboxAccess -Address $bad -Role 'Target'

    Assert-That "'$bad' is refused" (-not $check.Ok)
    Assert-That "'$bad' is reported as not an address" ($check.Kind -eq 'NotAnAddress') "kind was $($check.Kind)"
    Assert-That "'$bad' never reached Graph" ($script:MailFolderCallCount -eq 0) `
        "$($script:MailFolderCallCount) mailFolder calls were made"
}

$check = Test-MailboxAccess -Address 'Kirk Smith' -Role 'Target'
Assert-That 'the advice asks for the primary SMTP address' ((Get-AdviceText -Check $check) -match 'primary SMTP address')

# ==============================================================================
Start-Case 'An address with no mailbox behind it is explained, not dumped'
Reset-World
$script:FailMailbox['kirk@contoso.com'] = $script:RootNotFoundError

$check = Test-MailboxAccess -Address 'kirk@contoso.com' -Role 'Target'
$advice = Get-AdviceText -Check $check

Assert-That 'the check fails' (-not $check.Ok)
Assert-That 'it is classified as a missing mailbox' ($check.Kind -eq 'NoMailbox') "kind was $($check.Kind)"
Assert-That 'the problem names the mailbox and its role' `
    (($check.Problem -match 'kirk@contoso\.com') -and ($check.Problem -match 'Target'))  $check.Problem
Assert-That 'the raw Graph text is kept for the log' ($check.Detail -match 'Default folder Root not found')
Assert-That 'the advice covers the licence' ($advice -match 'licence')
Assert-That 'the advice covers a mailbox that is still on-premises' ($advice -match 'on-premises')
Assert-That 'the advice covers mail users and groups that have no mailbox' ($advice -match 'Mail-enabled users')
Assert-That 'the advice gives a command that settles it' ($advice -match 'Get-Mailbox -Identity')

# ==============================================================================
Start-Case 'An address that is not in the tenant is told apart from one without a mailbox'
Reset-World
$script:FailMailbox['nobody@contoso.com'] = 'Status: 404 (NotFound) Code: Request_ResourceNotFound Message: Resource ''nobody@contoso.com'' does not exist.'

$check = Test-MailboxAccess -Address 'nobody@contoso.com' -Role 'Source'
$advice = Get-AdviceText -Check $check

Assert-That 'the check fails' (-not $check.Ok)
Assert-That 'it is classified as an unknown account' ($check.Kind -eq 'UnknownUser') "kind was $($check.Kind)"
Assert-That 'the advice mentions the tenant' ($advice -match 'tenant')
Assert-That 'the advice does not send the operator to check licensing' (-not ($advice -match 'licence'))

# ==============================================================================
Start-Case 'A mailbox the signed-in account may not open names the permission to grant'
Reset-World
$script:FailMailbox['locked@contoso.com'] = 'Status: 403 (Forbidden) Code: ErrorAccessDenied Message: Access is denied. Check credentials and try again.'

$check = Test-MailboxAccess -Address 'locked@contoso.com' -Role 'Target'
$advice = Get-AdviceText -Check $check

Assert-That 'the check fails' (-not $check.Ok)
Assert-That 'it is classified as an access problem' ($check.Kind -eq 'AccessDenied') "kind was $($check.Kind)"
Assert-That 'the advice gives the Add-MailboxPermission command' ($advice -match 'Add-MailboxPermission')
Assert-That 'the advice warns that the grant takes time to reach Graph' ($advice -match 'minutes')

# ==============================================================================
Start-Case 'Graph error text maps to the cause an operator can act on'
$cases = @(
    @{ Kind = 'NoMailbox';    Text = $script:RootNotFoundError },
    @{ Kind = 'NoMailbox';    Text = 'Status: 404 Code: MailboxNotEnabledForRESTAPI Message: REST API is not yet supported for this mailbox.' },
    @{ Kind = 'NoMailbox';    Text = 'The mailbox is either inactive, soft-deleted, or is hosted on-premise.' },
    @{ Kind = 'NoMailbox';    Text = 'Status: 404 (NotFound) Code: ErrorItemNotFound Message: The specified object was not found in the store.' },
    @{ Kind = 'UnknownUser';  Text = 'Status: 404 Code: Request_ResourceNotFound' },
    @{ Kind = 'UnknownUser';  Text = 'Status: 404 Code: ErrorInvalidUser Message: The requested user is invalid.' },
    @{ Kind = 'AccessDenied'; Text = 'Status: 403 (Forbidden) Code: ErrorAccessDenied' },
    @{ Kind = 'AccessDenied'; Text = 'Code: Authorization_RequestDenied Message: Insufficient privileges to complete the operation.' },
    @{ Kind = 'SignedOut';    Text = 'Code: InvalidAuthenticationToken Message: Lifetime validation failed, the token is expired.' },
    @{ Kind = 'Throttled';    Text = 'Status: 429 Message: Too many requests. Please retry.' },
    @{ Kind = 'Unknown';      Text = 'Status: 500 Code: InternalServerError' },
    @{ Kind = 'Unknown';      Text = '' }
)
foreach ($case in $cases) {
    $kind = Get-GraphFailureKind -Message $case.Text
    $shown = if ($case.Text) { $case.Text.Substring(0, [math]::Min(48, $case.Text.Length)) } else { '(empty)' }
    Assert-That "'$shown' -> $($case.Kind)" ($kind -eq $case.Kind) "got $kind"
}

# ==============================================================================
Start-Case 'A non-terminating Graph error is no longer read as an empty mailbox'
Reset-World
New-PopulatedMailbox -UserId 'src@contoso.com' | Out-Null
$script:FailMailbox['src@contoso.com'] = $script:RootNotFoundError

# The hazard itself: with the console's own preferences, the SDK cmdlet writes an
# error and returns nothing rather than throwing, which no try/catch can see.
$savedPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $raw = Get-MgUserMailFolder -UserId 'src@contoso.com' -All 2>$null
    Assert-That 'the failing listing returns nothing instead of throwing' ($null -eq $raw)

    $box = New-Object System.Windows.Forms.TextBox
    $folders = @(Get-AllMailFolders -UserId 'src@contoso.com' -StatusBox $box 2>$null)

    Assert-That 'the scan reports no folders' ($folders.Count -eq 0)
    Assert-That 'the scan is recorded as incomplete' ([bool]$script:FolderScanIncomplete)
    Assert-That 'the failure is kept for the explanation' ($script:LastFolderScanError -match 'Default folder Root not found')
    Assert-That 'the GUI log carries the warning' ($box.Text -match 'WARNING')
    Assert-That 'the log says the subtree is not copied' ($box.Text -match 'will NOT be copied')
}
finally {
    $ErrorActionPreference = $savedPreference
}

# ==============================================================================
Start-Case 'A source mailbox that cannot be read stops the copy instead of reporting success'
Reset-World
$ui = New-TestUi
$src = 'kirk@contoso.com'
$tgt = 'tgt@contoso.com'

New-PopulatedMailbox -UserId $src | Out-Null
New-PopulatedMailbox -UserId $tgt | Out-Null
$script:FailMailbox[$src] = $script:RootNotFoundError

$result = Copy-Emails -SourceEmail $src -TargetEmail $tgt -StatusBox $ui.StatusBox -ProgressBar $ui.ProgressBar

Assert-That 'the copy reports failure' (-not $result.Success)
Assert-That 'the result says which mailbox blocked it' ($result.BlockedRole -eq 'Source') "role was $($result.BlockedRole)"
Assert-That 'nothing is counted as copied' ([int]$result.Copied -eq 0)
Assert-That 'the log explains the abort' ($ui.StatusBox.Text -match 'EMAIL COPY ABORTED')
Assert-That 'the log does not claim the copy completed' (-not ($ui.StatusBox.Text -match 'EMAIL COPY COMPLETED'))
Assert-That 'the log repeats what Graph said' ($ui.StatusBox.Text -match 'Default folder Root not found')
Assert-That 'the log lists the checks to run' ($ui.StatusBox.Text -match 'Get-Mailbox -Identity')
Assert-That 'no folder was created in the target' ($script:CreatedFolderNames.Count -eq 0) `
    "created: $($script:CreatedFolderNames -join ', ')"

# ==============================================================================
Start-Case 'An unreadable target mailbox stops the copy before anything is written'
Reset-World
$ui = New-TestUi
$src = 'src@contoso.com'
$tgt = 'kirk@contoso.com'

$srcInbox = New-PopulatedMailbox -UserId $src
Add-FakeFolder -UserId $src -DisplayName 'Clients' -ParentId $srcInbox | Out-Null
Add-FakeMessage -UserId $src -FolderId $srcInbox -Subject 'inbox one' | Out-Null
Sync-FakeItemCounts -UserId $src

New-PopulatedMailbox -UserId $tgt | Out-Null
$script:FailMailbox[$tgt] = $script:RootNotFoundError

$result = Copy-Emails -SourceEmail $src -TargetEmail $tgt -StatusBox $ui.StatusBox -ProgressBar $ui.ProgressBar

Assert-That 'the copy reports failure' (-not $result.Success)
Assert-That 'the result says the target blocked it' ($result.BlockedRole -eq 'Target') "role was $($result.BlockedRole)"
Assert-That 'the source was still read' ($ui.StatusBox.Text -match 'SOURCE FOLDER STRUCTURE')
Assert-That 'no folder was created in the target' ($script:CreatedFolderNames.Count -eq 0) `
    "created: $($script:CreatedFolderNames -join ', ')"
Assert-That 'no message was written to the target' ((Get-FakeMessageCount -UserId $tgt) -eq 0)

# ==============================================================================
Write-Host ''
Write-Host ('-' * 60)
Write-Host ("Passed: {0}   Failed: {1}" -f $script:Passed, $script:Failed) `
    -ForegroundColor $(if ($script:Failed -gt 0) { 'Red' } else { 'Green' })
if ($script:Failed -gt 0) { exit 1 }
exit 0
