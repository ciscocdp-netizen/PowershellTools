<#
.SYNOPSIS
    In-memory stand-in for the Graph message endpoints used by Copy-Emails.

.DESCRIPTION
    Extends GraphMocks.ps1 (which covers mail folders) with the raw REST calls
    the copy makes for messages, so the whole Copy-Emails pass can run without a
    tenant:

      GET  /users/{id}/mailFolders/{folderId}/messages   paged list, 2 per page
      GET  /users/{id}/messages/{messageId}              full message
      POST /users/{id}/mailFolders/{folderId}/messages   create
      POST /users/{id}/messages                          create (must never
                                                         happen: Graph files
                                                         these as drafts)

    Get-GraphAccessTokenString is stubbed to return nothing, which sends the
    creates down the Invoke-MgGraphRequest branch of Invoke-GraphJsonPost, and
    Start-Sleep is stubbed so paging and retry back-off do not slow the suite.

    Fault injection:
      $script:FailMessageCreate['<subject>'] = '<error message>'
      $script:FailMessageList[<folderId>]    = '<error message>'
      $script:CancelAfterPosts               = <n>   # request cancel after n
                                                     # successful creates
#>

$script:Mail                = @{}   # userId -> folderId -> ArrayList of messages
$script:RootPostedMessages  = New-Object System.Collections.ArrayList
$script:FailMessageCreate   = @{}
$script:FailMessageList     = @{}
$script:MessageGetCount     = 0
$script:MessagePostCount    = 0
$script:MessageCreatedCount = 0
$script:CancelAfterPosts    = 0

function Reset-FakeMail {
    $script:Mail = @{}
    $script:RootPostedMessages.Clear()
    $script:FailMessageCreate.Clear()
    $script:FailMessageList.Clear()
    $script:MessageGetCount     = 0
    $script:MessagePostCount    = 0
    $script:MessageCreatedCount = 0
    $script:CancelAfterPosts    = 0
}

function Get-FakeMailBucket {
    param([string]$UserId, [string]$FolderId)
    if (-not $script:Mail.ContainsKey($UserId)) { $script:Mail[$UserId] = @{} }
    if (-not $script:Mail[$UserId].ContainsKey($FolderId)) {
        $script:Mail[$UserId][$FolderId] = New-Object System.Collections.ArrayList
    }
    # Comma: an empty ArrayList would otherwise unroll to nothing on return.
    return , $script:Mail[$UserId][$FolderId]
}

function Add-FakeMessage {
    param(
        [Parameter(Mandatory = $true)][string]$UserId,
        [Parameter(Mandatory = $true)][string]$FolderId,
        [Parameter(Mandatory = $true)][string]$Subject,
        [string]$From = 'sender@contoso.com',
        [string]$Received = '2025-01-01T08:00:00Z',
        [bool]$IsRead = $true,
        [bool]$HasAttachments = $false
    )
    $bucket = Get-FakeMailBucket -UserId $UserId -FolderId $FolderId
    $id = "MSG$([guid]::NewGuid().ToString('N').Substring(0, 12))"
    [void]$bucket.Add(@{
        id               = $id
        subject          = $Subject
        from             = @{ emailAddress = @{ address = $From; name = $From } }
        sender           = @{ emailAddress = @{ address = $From; name = $From } }
        receivedDateTime = $Received
        sentDateTime     = $Received
        isRead           = $IsRead
        isDraft          = $false
        hasAttachments   = $HasAttachments
        importance       = 'normal'
        body             = @{ contentType = 'text'; content = "body of $Subject" }
        toRecipients     = @(@{ emailAddress = @{ address = 'recipient@contoso.com' } })
        categories       = @()
    })
    return $id
}

function Get-FakeMessageSubjects {
    param([string]$UserId, [string]$FolderId)
    $bucket = Get-FakeMailBucket -UserId $UserId -FolderId $FolderId
    return @($bucket | ForEach-Object { $_.subject })
}

function Get-FakeMessageCount {
    param([string]$UserId)
    $total = 0
    if (-not $script:Mail.ContainsKey($UserId)) { return 0 }
    foreach ($bucket in $script:Mail[$UserId].Values) { $total += $bucket.Count }
    return $total
}

<#
.SYNOPSIS
    Sets every folder's TotalItemCount from the fake message store, so the
    folder listing and the message listing agree the way a real mailbox does.
#>
function Sync-FakeItemCounts {
    param([string]$UserId)
    foreach ($folder in $script:Store[$UserId].Folders.Values) {
        $bucket = Get-FakeMailBucket -UserId $UserId -FolderId $folder.Id
        $folder.TotalItemCount = $bucket.Count
    }
}

function Split-FakeUri {
    param([string]$Uri)

    $path  = ($Uri -split '\?')[0]
    $query = ''
    if ($Uri -match '\?(.*)$') { $query = $Matches[1] }

    $result = @{ UserId = $null; FolderId = $null; MessageId = $null; Skip = 0; Query = $query }

    if ($path -match '/users/([^/]+)') { $result.UserId = [uri]::UnescapeDataString($Matches[1]) }
    if ($path -match '/mailFolders/([^/]+)') { $result.FolderId = [uri]::UnescapeDataString($Matches[1]) }
    if ($path -match '/messages/([^/?]+)$') { $result.MessageId = [uri]::UnescapeDataString($Matches[1]) }
    if ($query -match '\$skip=(\d+)') { $result.Skip = [int]$Matches[1] }

    return $result
}

function Invoke-MgGraphRequest {
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory = $true)][string]$Uri,
        $Body,
        [string]$ContentType
    )

    $parts = Split-FakeUri -Uri $Uri

    if ($Method -eq 'GET') {
        if ($parts.MessageId) {
            $script:MessageGetCount++
            foreach ($bucket in $script:Mail[$parts.UserId].Values) {
                foreach ($msg in $bucket) {
                    if ($msg.id -eq $parts.MessageId) { return $msg }
                }
            }
            throw "Status: 404 (NotFound) Code: ErrorItemNotFound Message: message $($parts.MessageId)"
        }

        if (-not $parts.FolderId) {
            throw "Status: 400 (BadRequest) Message: the copy must not enumerate the whole mailbox ($Uri)"
        }
        if ($script:FailMessageList.ContainsKey($parts.FolderId)) {
            throw $script:FailMessageList[$parts.FolderId]
        }

        # Two per page, so the paging loop and its progress reporting run.
        $bucket = Get-FakeMailBucket -UserId $parts.UserId -FolderId $parts.FolderId
        $all    = @($bucket.ToArray())
        $page   = @($all | Select-Object -Skip $parts.Skip -First 2)
        $response = @{ value = $page }
        if (($parts.Skip + 2) -lt $all.Count) {
            $response['@odata.nextLink'] = "$($Uri -replace '&\$skip=\d+', '')&`$skip=$($parts.Skip + 2)"
        }
        return $response
    }

    if ($Method -eq 'POST') {
        $script:MessagePostCount++

        # Invoke-GraphJsonPost retries the same create with a JSON string body,
        # so both shapes have to be understood or a rejected message would look
        # like it was accepted on the retry.
        $item = $null
        if ($Body -is [System.Collections.IDictionary]) {
            $item = @{}
            foreach ($k in $Body.Keys) { $item[$k] = $Body[$k] }
        }
        elseif ($Body -is [string] -and $Body.Trim().StartsWith('{')) {
            $parsed = $Body | ConvertFrom-Json
            $item = @{}
            foreach ($p in $parsed.PSObject.Properties) { $item[$p.Name] = $p.Value }
        }
        else {
            throw "Status: 400 (BadRequest) Message: unsupported POST body type $($Body.GetType().Name)"
        }

        $subject = $item['subject']
        if ($subject -and $script:FailMessageCreate.ContainsKey($subject)) {
            throw $script:FailMessageCreate[$subject]
        }
        if (-not $parts.FolderId) {
            # Graph silently files these in Drafts; the tool must never do it.
            [void]$script:RootPostedMessages.Add($subject)
            return @{ id = "ROOT$([guid]::NewGuid().ToString('N').Substring(0, 8))" }
        }

        $bucket = Get-FakeMailBucket -UserId $parts.UserId -FolderId $parts.FolderId
        $id = "MSG$([guid]::NewGuid().ToString('N').Substring(0, 12))"
        $item['id'] = $id
        if (-not $item.ContainsKey('receivedDateTime')) { $item['receivedDateTime'] = '2025-01-01T08:00:00Z' }
        [void]$bucket.Add($item)
        $script:MessageCreatedCount++
        if ($script:CancelAfterPosts -gt 0 -and $script:MessageCreatedCount -ge $script:CancelAfterPosts) {
            $script:CancelRequested = $true
        }
        return @{ id = $id }
    }

    throw "unsupported method $Method"
}

# No access token in the test, so Invoke-GraphJsonPost uses Invoke-MgGraphRequest.
function Get-GraphAccessTokenString { return $null }

# Attachment copying has its own Graph surface; it is out of scope here.
function Copy-MessageAttachments {
    param($SourceUserId, $SourceMessageId, $TargetUserId, $TargetMessageId, $HasAttachments)
}

# Keep paging delays and retry back-off out of the test run time.
function Start-Sleep {
    param([int]$Seconds, [int]$Milliseconds)
}
