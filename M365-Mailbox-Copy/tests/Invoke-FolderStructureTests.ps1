<#
.SYNOPSIS
    Regression tests for the mailbox copy tool's folder replication.

.DESCRIPTION
    Loads the folder functions out of M365-Mailbox-Copy-Tool.ps1 (the real file,
    so the tests cannot drift from it) and runs them against the fake Graph in
    GraphMocks.ps1. Only function definitions and $script: variables are taken
    from the tool, so the module bootstrap and the GUI never execute.

    Each case covers a folder shape that used to be replicated incorrectly:
    empty folders, names containing an apostrophe or a backslash, a localized
    target mailbox, repeated names under different parents, and a folder listing
    that fails partway through.

.EXAMPLE
    pwsh -File ./Invoke-FolderStructureTests.ps1

.NOTES
    Exits 1 if any case fails, so it can be used as a build check. Runs on
    Windows PowerShell 5.1 and on PowerShell 7 (any OS).
#>

[CmdletBinding()]
param(
    [string]$ToolPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'M365-Mailbox-Copy-Tool.ps1')
)

$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/WinFormsShim.ps1"
. "$PSScriptRoot/GraphMocks.ps1"
. "$PSScriptRoot/ToolLoader.ps1"
. ([scriptblock]::Create((Import-ToolDefinitions -Path $ToolPath)))

Assert-ToolFunctionsPresent -ToolPath $ToolPath -Names @(
    'Get-AllMailFolders', 'Compare-MailFolderStructure', 'Sync-MailFolderStructure',
    'Find-ChildFolderByName', 'New-TargetMailFolder', 'Get-WellKnownFolderMap',
    'Get-CanonicalFolderParts', 'Get-IndexedFolderId', 'Get-FolderPathKey'
)

# ------------------------------------------------------------------------------
# Test plumbing
# ------------------------------------------------------------------------------
$script:Passed = 0
$script:Failed = 0
$script:CurrentCase = ''

function Start-Case {
    param([string]$Name)
    $script:CurrentCase = $Name
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

function Assert-PathsPresent {
    param([string]$UserId, [string[]]$ExpectedPaths)
    $actual = @(Get-FakeFolderPaths -UserId $UserId)
    foreach ($path in $ExpectedPaths) {
        Assert-That "target contains '$path'" ($actual -contains $path) ("target tree: " + ($actual -join ' | '))
    }
}

function Assert-PathsAbsent {
    param([string]$UserId, [string[]]$UnexpectedPaths)
    $actual = @(Get-FakeFolderPaths -UserId $UserId)
    foreach ($path in $UnexpectedPaths) {
        Assert-That "target does NOT contain '$path'" (-not ($actual -contains $path)) ("target tree: " + ($actual -join ' | '))
    }
}

function New-TestStatusBox {
    return (New-Object System.Windows.Forms.TextBox)
}

function Add-DefaultTargetMailbox {
    param([string]$UserId)
    New-FakeMailbox -UserId $UserId
    Add-FakeFolder -UserId $UserId -DisplayName 'Inbox'         -WellKnownName 'inbox'        | Out-Null
    Add-FakeFolder -UserId $UserId -DisplayName 'Drafts'        -WellKnownName 'drafts'       | Out-Null
    Add-FakeFolder -UserId $UserId -DisplayName 'Sent Items'    -WellKnownName 'sentitems'    | Out-Null
    Add-FakeFolder -UserId $UserId -DisplayName 'Deleted Items' -WellKnownName 'deleteditems' | Out-Null
    Add-FakeFolder -UserId $UserId -DisplayName 'Junk Email'    -WellKnownName 'junkemail'    | Out-Null
}

<#
.SYNOPSIS
    Runs the same folder pass Copy-Emails performs: enumerate both mailboxes,
    diff them, and create only the folders the target is missing.
#>
function Invoke-FolderMirror {
    param([string]$SourceEmail, [string]$TargetEmail, $StatusBox)

    $script:FolderScanIncomplete = $false

    $sourceWellKnown = Get-WellKnownFolderMap -UserId $SourceEmail
    $sourceFolders   = @(Get-AllMailFolders -UserId $SourceEmail -WellKnownMap $sourceWellKnown -StatusBox $StatusBox)
    $targetWellKnown = Get-WellKnownFolderMap -UserId $TargetEmail
    $targetFolders   = @(Get-AllMailFolders -UserId $TargetEmail -WellKnownMap $targetWellKnown -StatusBox $StatusBox)

    $sync = Sync-MailFolderStructure -TargetUserId $TargetEmail -SourceFolders $sourceFolders `
        -TargetFolders $targetFolders -StatusBox $StatusBox

    # What Copy-Emails would actually use per source folder.
    $resolved = @{}
    foreach ($folder in $sourceFolders) {
        $id = Get-IndexedFolderId -Index $sync.Index -Folder $folder
        if ($id) { $resolved[$folder.FullPath] = $id }
    }

    return @{
        SourceFolders  = $sourceFolders
        TargetFolders  = $targetFolders
        Sync           = $sync
        Comparison     = $sync.Comparison
        Resolved       = $resolved
        ScanIncomplete = $script:FolderScanIncomplete
        Log            = $StatusBox.Text
    }
}

function Get-MirroredId {
    param($Result, [string]$FullPath)
    if ($Result.Resolved.ContainsKey($FullPath)) { return $Result.Resolved[$FullPath] }
    return $null
}

function Assert-EveryFolderMirrored {
    param($Result)
    $total  = $Result.SourceFolders.Count
    $mapped = $Result.Resolved.Count
    Assert-That "all $total source folders resolved to a target folder" ($mapped -eq $total) `
        "resolved $mapped of $total; folder errors: $($Result.Sync.Unavailable.Values -join ' | ')"
}

# ==============================================================================
Start-Case 'Empty folders are mirrored, not skipped'
Reset-FakeGraph
$src = 'source@contoso.com'; $tgt = 'target@contoso.com'
New-FakeMailbox -UserId $src
$inbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -ItemCount 12 -WellKnownName 'inbox'
Add-FakeFolder -UserId $src -DisplayName 'Drafts' -ItemCount 2 -WellKnownName 'drafts' | Out-Null
Add-FakeFolder -UserId $src -DisplayName 'Sent Items' -ItemCount 7 -WellKnownName 'sentitems' | Out-Null
Add-FakeFolder -UserId $src -DisplayName 'Archive 2019' -ParentId $inbox -ItemCount 0 | Out-Null
$projects = Add-FakeFolder -UserId $src -DisplayName 'Projects' -ParentId $inbox -ItemCount 0
Add-FakeFolder -UserId $src -DisplayName '2024' -ParentId $projects -ItemCount 5 | Out-Null
$vendors = Add-FakeFolder -UserId $src -DisplayName 'Vendors' -ParentId $inbox -ItemCount 3
Add-FakeFolder -UserId $src -DisplayName 'Contracts' -ParentId $vendors -ItemCount 0 | Out-Null
Add-DefaultTargetMailbox -UserId $tgt
$result = Invoke-FolderMirror -SourceEmail $src -TargetEmail $tgt -StatusBox (New-TestStatusBox)
Assert-EveryFolderMirrored -Result $result
Assert-PathsPresent -UserId $tgt -ExpectedPaths @(
    'Inbox', 'Inbox\Archive 2019', 'Inbox\Projects', 'Inbox\Projects\2024',
    'Inbox\Vendors', 'Inbox\Vendors\Contracts', 'Drafts', 'Sent Items'
)

# ==============================================================================
Start-Case "Nested folder name with an apostrophe keeps its place in the tree"
Reset-FakeGraph
$src = 'src2@contoso.com'; $tgt = 'tgt2@contoso.com'
New-FakeMailbox -UserId $src
$inbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -ItemCount 4 -WellKnownName 'inbox'
$obrien = Add-FakeFolder -UserId $src -DisplayName "O'Brien Ltd" -ParentId $inbox -ItemCount 9
Add-FakeFolder -UserId $src -DisplayName 'Invoices' -ParentId $obrien -ItemCount 6 | Out-Null
Add-DefaultTargetMailbox -UserId $tgt
$result = Invoke-FolderMirror -SourceEmail $src -TargetEmail $tgt -StatusBox (New-TestStatusBox)
Assert-EveryFolderMirrored -Result $result
Assert-PathsPresent -UserId $tgt -ExpectedPaths @("Inbox\O'Brien Ltd", "Inbox\O'Brien Ltd\Invoices")
Assert-PathsAbsent  -UserId $tgt -UnexpectedPaths @('Inbox\Invoices')
Assert-That 'no malformed $filter was sent to Graph' ($script:FilterSyntaxErrors -eq 0) `
    "Graph rejected $script:FilterSyntaxErrors filter clause(s); the name was not OData-escaped"

# ==============================================================================
Start-Case "Top-level folder name with an apostrophe resolves (mail is not drafted)"
Reset-FakeGraph
$src = 'src3@contoso.com'; $tgt = 'tgt3@contoso.com'
New-FakeMailbox -UserId $src
Add-FakeFolder -UserId $src -DisplayName 'Inbox' -ItemCount 3 -WellKnownName 'inbox' | Out-Null
$archive = Add-FakeFolder -UserId $src -DisplayName "Dave's Archive" -ItemCount 40
Add-FakeFolder -UserId $src -DisplayName '2023' -ParentId $archive -ItemCount 15 | Out-Null
Add-DefaultTargetMailbox -UserId $tgt
$result = Invoke-FolderMirror -SourceEmail $src -TargetEmail $tgt -StatusBox (New-TestStatusBox)
Assert-EveryFolderMirrored -Result $result
Assert-PathsPresent -UserId $tgt -ExpectedPaths @("Dave's Archive", "Dave's Archive\2023")
Assert-PathsAbsent  -UserId $tgt -UnexpectedPaths @('2023')
Assert-That 'no malformed $filter was sent to Graph' ($script:FilterSyntaxErrors -eq 0) `
    "Graph rejected $script:FilterSyntaxErrors filter clause(s); the name was not OData-escaped"

# ==============================================================================
Start-Case 'A backslash in a display name does not become a nested path'
Reset-FakeGraph
$src = 'src4@contoso.com'; $tgt = 'tgt4@contoso.com'
New-FakeMailbox -UserId $src
$inbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -ItemCount 1 -WellKnownName 'inbox'
Add-FakeFolder -UserId $src -DisplayName 'HR\Payroll' -ParentId $inbox -ItemCount 8 | Out-Null
Add-DefaultTargetMailbox -UserId $tgt
$result = Invoke-FolderMirror -SourceEmail $src -TargetEmail $tgt -StatusBox (New-TestStatusBox)
Assert-EveryFolderMirrored -Result $result
$targetInboxId = $script:Store[$tgt].WellKnown['inbox']
$inboxChildren = @(Get-FakeChildren -UserId $tgt -ParentId $targetInboxId)
Assert-That 'target Inbox has exactly one child' ($inboxChildren.Count -eq 1) "found $($inboxChildren.Count)"
Assert-That "that child is named 'HR\Payroll'" ($inboxChildren.Count -eq 1 -and $inboxChildren[0].DisplayName -eq 'HR\Payroll') `
    ("names: " + (($inboxChildren | ForEach-Object { $_.DisplayName }) -join ', '))
if ($inboxChildren.Count -eq 1) {
    Assert-That "'HR\Payroll' has no child folders" ((Get-FakeChildren -UserId $tgt -ParentId $inboxChildren[0].Id).Count -eq 0)
}

# ==============================================================================
Start-Case 'Localized target mailbox is not given duplicate well-known folders'
Reset-FakeGraph
$src = 'src5@contoso.com'; $tgt = 'tgt5@contoso.com'
New-FakeMailbox -UserId $src
$inbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -ItemCount 11 -WellKnownName 'inbox'
Add-FakeFolder -UserId $src -DisplayName 'Clients' -ParentId $inbox -ItemCount 4 | Out-Null
Add-FakeFolder -UserId $src -DisplayName 'Sent Items' -ItemCount 5 -WellKnownName 'sentitems' | Out-Null
New-FakeMailbox -UserId $tgt
Add-FakeFolder -UserId $tgt -DisplayName 'Postvak IN'      -WellKnownName 'inbox'     | Out-Null
Add-FakeFolder -UserId $tgt -DisplayName 'Concepten'       -WellKnownName 'drafts'    | Out-Null
Add-FakeFolder -UserId $tgt -DisplayName 'Verzonden items' -WellKnownName 'sentitems' | Out-Null
$result = Invoke-FolderMirror -SourceEmail $src -TargetEmail $tgt -StatusBox (New-TestStatusBox)
Assert-EveryFolderMirrored -Result $result
Assert-PathsPresent -UserId $tgt -ExpectedPaths @('Postvak IN', 'Postvak IN\Clients', 'Verzonden items')
Assert-PathsAbsent  -UserId $tgt -UnexpectedPaths @('Inbox', 'Sent Items', 'Inbox\Clients')
$rootCount = @(Get-FakeChildren -UserId $tgt -ParentId $null).Count
Assert-That 'no extra top-level folder was created' ($rootCount -eq 3) "top-level folders: $rootCount"

# ==============================================================================
Start-Case 'The same folder name under two parents stays separate'
Reset-FakeGraph
$src = 'src6@contoso.com'; $tgt = 'tgt6@contoso.com'
New-FakeMailbox -UserId $src
$inbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -ItemCount 2 -WellKnownName 'inbox'
$clientA = Add-FakeFolder -UserId $src -DisplayName 'ClientA' -ParentId $inbox -ItemCount 1
$clientB = Add-FakeFolder -UserId $src -DisplayName 'ClientB' -ParentId $inbox -ItemCount 1
Add-FakeFolder -UserId $src -DisplayName 'Invoices' -ParentId $clientA -ItemCount 3 | Out-Null
Add-FakeFolder -UserId $src -DisplayName 'Invoices' -ParentId $clientB -ItemCount 4 | Out-Null
Add-DefaultTargetMailbox -UserId $tgt
$result = Invoke-FolderMirror -SourceEmail $src -TargetEmail $tgt -StatusBox (New-TestStatusBox)
Assert-EveryFolderMirrored -Result $result
Assert-PathsPresent -UserId $tgt -ExpectedPaths @('Inbox\ClientA\Invoices', 'Inbox\ClientB\Invoices')

# ==============================================================================
Start-Case 'A failed folder listing is reported and marks the scan incomplete'
Reset-FakeGraph
$src = 'src7@contoso.com'; $tgt = 'tgt7@contoso.com'
New-FakeMailbox -UserId $src
$inbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -ItemCount 6 -WellKnownName 'inbox'
$legal = Add-FakeFolder -UserId $src -DisplayName 'Legal' -ParentId $inbox -ItemCount 20
Add-FakeFolder -UserId $src -DisplayName 'Contracts 2022' -ParentId $legal -ItemCount 120 | Out-Null
Add-FakeFolder -UserId $src -DisplayName 'Contracts 2023' -ParentId $legal -ItemCount 140 | Out-Null
Add-FakeFolder -UserId $src -DisplayName 'Finance' -ParentId $inbox -ItemCount 30 | Out-Null
$script:FailChildListing[$legal] = 'Status: 403 (Forbidden) Code: ErrorAccessDenied Message: Access is denied.'
Add-DefaultTargetMailbox -UserId $tgt
$result = Invoke-FolderMirror -SourceEmail $src -TargetEmail $tgt -StatusBox (New-TestStatusBox)
Assert-That 'the scan is flagged incomplete' ([bool]$result.ScanIncomplete)
Assert-That 'the status log warns about the unreadable subtree' ($result.Log -match 'WARNING' -and $result.Log -match 'Legal') `
    "log: $($result.Log)"
Assert-That 'the readable folders were still mirrored' ($result.Resolved.Count -eq 3) `
    "mirrored $($result.Resolved.Count)"

# ==============================================================================
Start-Case 'A target that already matches the source is left completely alone'
Reset-FakeGraph
$src = 'src10@contoso.com'; $tgt = 'tgt10@contoso.com'
New-FakeMailbox -UserId $src
$inbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -ItemCount 9 -WellKnownName 'inbox'
$clients = Add-FakeFolder -UserId $src -DisplayName 'Clients' -ParentId $inbox -ItemCount 3
Add-FakeFolder -UserId $src -DisplayName 'Invoices' -ParentId $clients -ItemCount 2 | Out-Null
Add-FakeFolder -UserId $src -DisplayName 'Sent Items' -ItemCount 4 -WellKnownName 'sentitems' | Out-Null
Add-DefaultTargetMailbox -UserId $tgt
$tgtInbox = $script:Store[$tgt].WellKnown['inbox']
$tgtClients = Add-FakeFolder -UserId $tgt -DisplayName 'Clients' -ParentId $tgtInbox
Add-FakeFolder -UserId $tgt -DisplayName 'Invoices' -ParentId $tgtClients | Out-Null
$before = @(Get-FakeFolderPaths -UserId $tgt)
$result = Invoke-FolderMirror -SourceEmail $src -TargetEmail $tgt -StatusBox (New-TestStatusBox)
Assert-EveryFolderMirrored -Result $result
Assert-That 'the comparison finds nothing missing' ($result.Comparison.Missing.Count -eq 0) `
    ("missing: " + (($result.Comparison.Missing | ForEach-Object { $_.FullPath }) -join ', '))
Assert-That 'no folder was created' ($script:CreatedFolderNames.Count -eq 0) `
    ("created: " + ($script:CreatedFolderNames -join ', '))
Assert-That 'no per-segment name lookup was needed' ($script:FilterQueryCount -eq 0) `
    "$script:FilterQueryCount filter queries were sent"
Assert-That 'the target tree is byte-for-byte unchanged' `
    ((@(Get-FakeFolderPaths -UserId $tgt) -join '|') -eq ($before -join '|')) `
    ("before: " + ($before -join ', ') + "  after: " + (@(Get-FakeFolderPaths -UserId $tgt) -join ', '))

# ==============================================================================
Start-Case 'Only the folders missing from the target are added'
Reset-FakeGraph
$src = 'src11@contoso.com'; $tgt = 'tgt11@contoso.com'
New-FakeMailbox -UserId $src
$inbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -ItemCount 5 -WellKnownName 'inbox'
$clients = Add-FakeFolder -UserId $src -DisplayName 'Clients' -ParentId $inbox -ItemCount 2
Add-FakeFolder -UserId $src -DisplayName 'Invoices' -ParentId $clients -ItemCount 4 | Out-Null
Add-FakeFolder -UserId $src -DisplayName 'Quotes'   -ParentId $clients -ItemCount 1 | Out-Null
Add-FakeFolder -UserId $src -DisplayName 'Archive'  -ItemCount 7 | Out-Null
Add-DefaultTargetMailbox -UserId $tgt
$tgtInbox   = $script:Store[$tgt].WellKnown['inbox']
$tgtClients = Add-FakeFolder -UserId $tgt -DisplayName 'Clients' -ParentId $tgtInbox
$tgtInvoices = Add-FakeFolder -UserId $tgt -DisplayName 'Invoices' -ParentId $tgtClients
$result = Invoke-FolderMirror -SourceEmail $src -TargetEmail $tgt -StatusBox (New-TestStatusBox)
Assert-EveryFolderMirrored -Result $result
Assert-That 'exactly the two absent folders are reported missing' ($result.Comparison.Missing.Count -eq 2) `
    ("missing: " + (($result.Comparison.Missing | ForEach-Object { $_.FullPath }) -join ', '))
Assert-That 'exactly two folders were created' ($script:CreatedFolderNames.Count -eq 2) `
    ("created: " + ($script:CreatedFolderNames -join ', '))
Assert-That "the created folders are 'Quotes' and 'Archive'" `
    ((($script:CreatedFolderNames | Sort-Object) -join ',') -eq 'Archive,Quotes') `
    ("created: " + ($script:CreatedFolderNames -join ', '))
Assert-That 'the pre-existing Invoices folder was reused, not replaced' `
    ((Get-MirroredId -Result $result -FullPath 'Inbox\Clients\Invoices') -eq $tgtInvoices)
Assert-PathsPresent -UserId $tgt -ExpectedPaths @(
    'Inbox\Clients', 'Inbox\Clients\Invoices', 'Inbox\Clients\Quotes', 'Archive'
)

# ==============================================================================
Start-Case 'Folders that exist only in the target are reported and kept'
Reset-FakeGraph
$src = 'src12@contoso.com'; $tgt = 'tgt12@contoso.com'
New-FakeMailbox -UserId $src
$inbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -ItemCount 3 -WellKnownName 'inbox'
Add-FakeFolder -UserId $src -DisplayName 'Clients' -ParentId $inbox -ItemCount 1 | Out-Null
Add-DefaultTargetMailbox -UserId $tgt
$tgtInbox = $script:Store[$tgt].WellKnown['inbox']
Add-FakeFolder -UserId $tgt -DisplayName 'Personal'      -ParentId $tgtInbox | Out-Null
Add-FakeFolder -UserId $tgt -DisplayName 'Old Mailbox'   -ParentId $null     | Out-Null
$result = Invoke-FolderMirror -SourceEmail $src -TargetEmail $tgt -StatusBox (New-TestStatusBox)
Assert-EveryFolderMirrored -Result $result
$extraPaths = @($result.Comparison.TargetOnly | ForEach-Object { $_.FullPath })
Assert-That "'Inbox\Personal' is reported as target-only" ($extraPaths -contains 'Inbox\Personal') `
    ("target-only: " + ($extraPaths -join ', '))
Assert-That "'Old Mailbox' is reported as target-only" ($extraPaths -contains 'Old Mailbox') `
    ("target-only: " + ($extraPaths -join ', '))
Assert-PathsPresent -UserId $tgt -ExpectedPaths @('Inbox\Personal', 'Old Mailbox', 'Inbox\Clients')

# ==============================================================================
Start-Case 'A display name colliding with a target well-known folder is adopted, not duplicated'
Reset-FakeGraph
$src = 'src13@contoso.com'; $tgt = 'tgt13@contoso.com'
New-FakeMailbox -UserId $src
Add-FakeFolder -UserId $src -DisplayName 'Inbox' -ItemCount 2 -WellKnownName 'inbox' | Out-Null
# 'Archive' is an ordinary folder in the source but the well-known archive in the
# target, so the two canonical paths do not match and a create is attempted.
$srcArchive = Add-FakeFolder -UserId $src -DisplayName 'Archive' -ItemCount 30
Add-FakeFolder -UserId $src -DisplayName '2022' -ParentId $srcArchive -ItemCount 12 | Out-Null
Add-DefaultTargetMailbox -UserId $tgt
$tgtArchiveId = Add-FakeFolder -UserId $tgt -DisplayName 'Archive' -WellKnownName 'archive'
$script:FailFilterQueries = $true    # force the client-side fallback as well
$result = Invoke-FolderMirror -SourceEmail $src -TargetEmail $tgt -StatusBox (New-TestStatusBox)
Assert-EveryFolderMirrored -Result $result
$archiveFolders = @(Get-FakeChildren -UserId $tgt -ParentId $null | Where-Object { $_.DisplayName -eq 'Archive' })
Assert-That 'the target keeps a single Archive folder' ($archiveFolders.Count -eq 1) "found $($archiveFolders.Count)"
Assert-That 'the existing well-known Archive folder was adopted' `
    ((Get-MirroredId -Result $result -FullPath 'Archive') -eq $tgtArchiveId)
Assert-That 'the adoption is reported as a reuse, not a creation' ($result.Sync.Adopted -eq 1) `
    "created $($result.Sync.Created), adopted $($result.Sync.Adopted)"
Assert-PathsPresent -UserId $tgt -ExpectedPaths @('Archive\2022')

# ==============================================================================
Start-Case "A folder that appears only when Graph reports the conflict is matched by name"
Reset-FakeGraph
$src = 'src14@contoso.com'; $tgt = 'tgt14@contoso.com'
New-FakeMailbox -UserId $src
Add-FakeFolder -UserId $src -DisplayName 'Inbox' -ItemCount 1 -WellKnownName 'inbox' | Out-Null
$srcObrien = Add-FakeFolder -UserId $src -DisplayName "O'Brien Ltd" -ItemCount 14
Add-FakeFolder -UserId $src -DisplayName 'Invoices' -ParentId $srcObrien -ItemCount 6 | Out-Null
Add-DefaultTargetMailbox -UserId $tgt
# The folder is in the target but absent from the listing the diff was built
# from, so the create returns 409 and the name lookup has to find it. That
# lookup is the only place a folder name reaches an OData $filter.
$hiddenId = Add-FakeFolder -UserId $tgt -DisplayName "O'Brien Ltd"
$script:HideFromListing[$hiddenId] = $true
$result = Invoke-FolderMirror -SourceEmail $src -TargetEmail $tgt -StatusBox (New-TestStatusBox)
Assert-EveryFolderMirrored -Result $result
Assert-That 'no malformed $filter was sent to Graph' ($script:FilterSyntaxErrors -eq 0) `
    "Graph rejected $script:FilterSyntaxErrors filter clause(s); the name was not OData-escaped"
Assert-That 'the folder already in the target was matched by name' `
    ((Get-MirroredId -Result $result -FullPath "O'Brien Ltd") -eq $hiddenId) `
    "resolved to '$(Get-MirroredId -Result $result -FullPath "O'Brien Ltd")', expected '$hiddenId'"
Assert-That 'it is reported as a reuse' ($result.Sync.Adopted -eq 1) `
    "created $($result.Sync.Created), adopted $($result.Sync.Adopted)"
$obrienCount = @(Get-FakeChildren -UserId $tgt -ParentId $null | Where-Object { $_.DisplayName -eq "O'Brien Ltd" }).Count
Assert-That 'the target did not gain a duplicate' ($obrienCount -eq 1) "found $obrienCount"
Assert-PathsPresent -UserId $tgt -ExpectedPaths @("O'Brien Ltd\Invoices")
Assert-PathsAbsent  -UserId $tgt -UnexpectedPaths @('Invoices')

# ==============================================================================
Start-Case 'A name lookup that returns nothing still finds the existing folder'
Reset-FakeGraph
$src = 'src8@contoso.com'; $tgt = 'tgt8@contoso.com'
New-FakeMailbox -UserId $src
$inbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -ItemCount 1 -WellKnownName 'inbox'
Add-FakeFolder -UserId $src -DisplayName 'Vendors' -ParentId $inbox -ItemCount 2 | Out-Null
Add-DefaultTargetMailbox -UserId $tgt
$targetInboxId = $script:Store[$tgt].WellKnown['inbox']
$existingId = Add-FakeFolder -UserId $tgt -DisplayName 'Vendors' -ParentId $targetInboxId
$script:HideFromFilter['Vendors'] = $true    # the $filter query finds nothing
$result = Invoke-FolderMirror -SourceEmail $src -TargetEmail $tgt -StatusBox (New-TestStatusBox)
Assert-EveryFolderMirrored -Result $result
$vendorFolders = @(Get-FakeChildren -UserId $tgt -ParentId $targetInboxId | Where-Object { $_.DisplayName -eq 'Vendors' })
Assert-That 'the existing folder was reused, not duplicated' ($vendorFolders.Count -eq 1) "found $($vendorFolders.Count)"
Assert-That 'the reused folder is the pre-existing one' `
    ((Get-MirroredId -Result $result -FullPath 'Inbox\Vendors') -eq $existingId)

# ==============================================================================
Start-Case 'A name lookup that errors falls back to matching client-side'
Reset-FakeGraph
$src = 'src9@contoso.com'; $tgt = 'tgt9@contoso.com'
New-FakeMailbox -UserId $src
$inbox = Add-FakeFolder -UserId $src -DisplayName 'Inbox' -ItemCount 1 -WellKnownName 'inbox'
Add-FakeFolder -UserId $src -DisplayName 'Vendors' -ParentId $inbox -ItemCount 2 | Out-Null
Add-DefaultTargetMailbox -UserId $tgt
$targetInboxId = $script:Store[$tgt].WellKnown['inbox']
$existingId = Add-FakeFolder -UserId $tgt -DisplayName 'Vendors' -ParentId $targetInboxId
$script:FailFilterQueries = $true    # every $filter query errors out
$result = Invoke-FolderMirror -SourceEmail $src -TargetEmail $tgt -StatusBox (New-TestStatusBox)
Assert-EveryFolderMirrored -Result $result
$vendorFolders = @(Get-FakeChildren -UserId $tgt -ParentId $targetInboxId | Where-Object { $_.DisplayName -eq 'Vendors' })
Assert-That 'the existing folder was reused despite the failing lookup' ($vendorFolders.Count -eq 1) "found $($vendorFolders.Count)"
Assert-That 'the reused folder is the pre-existing one' `
    ((Get-MirroredId -Result $result -FullPath 'Inbox\Vendors') -eq $existingId)

# ==============================================================================
Write-Host ''
Write-Host ('-' * 60)
Write-Host ("Passed: {0}   Failed: {1}" -f $script:Passed, $script:Failed) `
    -ForegroundColor $(if ($script:Failed -gt 0) { 'Red' } else { 'Green' })

if ($script:Failed -gt 0) { exit 1 }
exit 0
