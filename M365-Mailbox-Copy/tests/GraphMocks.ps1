<#
.SYNOPSIS
    In-memory stand-in for the Microsoft Graph mail-folder endpoints.

.DESCRIPTION
    Provides a fake two-mailbox store plus replacements for the Get-Mg* /
    New-Mg* folder cmdlets, so the copy tool's folder code can be exercised
    without a tenant. The mocks reproduce the behaviour that actually matters
    for folder replication:

      * GET /users/{id}/mailFolders returns only the ROOT folder's children
      * a well-known name ('inbox', 'sentitems', ...) resolves to that mailbox's
        own folder, whatever its display name is
      * $filter=displayName eq '...' is case-insensitive, and an unescaped
        apostrophe is a 400 Bad Request from the OData parser
      * creating a duplicate name in one parent is 409 ErrorFolderExists

    Failure injection:
      $script:FailChildListing[<folderId>] = '<error message>'   # listing fails
      $script:HideFromFilter['<name>']     = $true               # $filter finds nothing
      $script:FailFilterQueries            = $true               # $filter itself errors
#>

$script:Store             = @{}
$script:FailChildListing  = @{}
$script:HideFromFilter    = @{}
$script:FailFilterQueries = $false
# Counts $filter clauses Graph's OData parser would reject, so a test can prove
# the tool escapes folder names rather than relying on its own error fallback.
$script:FilterSyntaxErrors = 0

function Reset-FakeGraph {
    $script:Store.Clear()
    $script:FailChildListing.Clear()
    $script:HideFromFilter.Clear()
    $script:FailFilterQueries  = $false
    $script:FilterSyntaxErrors = 0
}

function New-FakeMailbox {
    param([Parameter(Mandatory = $true)][string]$UserId)
    $script:Store[$UserId] = @{ Folders = @{}; WellKnown = @{} }
}

function Add-FakeFolder {
    param(
        [Parameter(Mandatory = $true)][string]$UserId,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [string]$ParentId = $null,
        [int]$ItemCount = 0,
        [string]$WellKnownName = $null
    )
    $mbx = $script:Store[$UserId]
    $id  = "AAMk$([guid]::NewGuid().ToString('N').Substring(0, 16))=="
    $mbx.Folders[$id] = [pscustomobject]@{
        Id              = $id
        DisplayName     = $DisplayName
        ParentId        = $ParentId
        TotalItemCount  = $ItemCount
        UnreadItemCount = 0
    }
    if ($WellKnownName) { $mbx.WellKnown[$WellKnownName] = $id }
    return $id
}

function Get-FakeChildren {
    param([string]$UserId, [string]$ParentId = $null)
    $mbx = $script:Store[$UserId]
    return @($mbx.Folders.Values | Where-Object { $_.ParentId -eq $ParentId } | Sort-Object DisplayName)
}

function Get-FakeFolderPaths {
    param([string]$UserId, [string]$ParentId = $null, [string[]]$Prefix = @())
    $paths = New-Object System.Collections.Generic.List[string]
    foreach ($f in (Get-FakeChildren -UserId $UserId -ParentId $ParentId)) {
        $segments = @($Prefix) + @($f.DisplayName)
        $paths.Add($segments -join '\')
        foreach ($p in (Get-FakeFolderPaths -UserId $UserId -ParentId $f.Id -Prefix $segments)) { $paths.Add($p) }
    }
    return $paths
}

function Format-FakeTree {
    param([string]$UserId, [string]$ParentId = $null, [int]$Depth = 0)
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($f in (Get-FakeChildren -UserId $UserId -ParentId $ParentId)) {
        $lines.Add(("{0}{1}  [{2} items]" -f ('  ' * $Depth), $f.DisplayName, $f.TotalItemCount))
        foreach ($l in (Format-FakeTree -UserId $UserId -ParentId $f.Id -Depth ($Depth + 1))) { $lines.Add($l) }
    }
    return $lines
}

function ConvertTo-FakeSdkFolder {
    param($Folder, [string]$UserId)
    return [pscustomobject]@{
        Id               = $Folder.Id
        DisplayName      = $Folder.DisplayName
        TotalItemCount   = $Folder.TotalItemCount
        UnreadItemCount  = $Folder.UnreadItemCount
        ChildFolderCount = (Get-FakeChildren -UserId $UserId -ParentId $Folder.Id).Count
    }
}

function Resolve-FakeFilterValue {
    param([string]$Filter)
    if ($Filter -notmatch "^displayName eq '(.*)'$") {
        $script:FilterSyntaxErrors++
        throw "Status: 400 (BadRequest) Code: RequestBroker--ParseUri Message: Invalid filter clause: $Filter"
    }

    # Inside the literal every quote must be doubled. Anything left over after
    # removing the doubled pairs ends the string early, which is what Graph's
    # parser rejects.
    $literal = $Matches[1]
    if ($literal.Replace("''", '') -match "'") {
        $script:FilterSyntaxErrors++
        throw "Status: 400 (BadRequest) Code: RequestBroker--ParseUri Message: Syntax error at position $($Filter.IndexOf("'")) in '$Filter'."
    }

    return $literal.Replace("''", "'")
}

function Select-FakeFolders {
    param($Folders, [string]$Filter, [string]$UserId)
    $set = @($Folders)
    if ($Filter) {
        $name = Resolve-FakeFilterValue -Filter $Filter
        if ($script:FailFilterQueries) {
            throw "Status: 400 (BadRequest) Code: ErrorInvalidProperty Message: The property cannot be used in a restriction."
        }
        if ($script:HideFromFilter.ContainsKey($name)) { return @() }
        $set = @($set | Where-Object { $_.DisplayName -ieq $name })   # OData eq ignores case
    }
    return @($set | ForEach-Object { ConvertTo-FakeSdkFolder -Folder $_ -UserId $UserId })
}

function Get-MgUserMailFolder {
    param(
        [string]$UserId,
        [string]$MailFolderId,
        [string]$Filter,
        [switch]$All,
        [int]$Top,
        $ErrorAction
    )
    $mbx = $script:Store[$UserId]
    if (-not $mbx) { throw "Status: 404 (NotFound) Code: ErrorInvalidUser Message: Unknown mailbox $UserId" }

    if ($MailFolderId) {
        $wellKnown = "$MailFolderId".ToLowerInvariant()
        if ($mbx.WellKnown.ContainsKey($wellKnown)) {
            return (ConvertTo-FakeSdkFolder -Folder $mbx.Folders[$mbx.WellKnown[$wellKnown]] -UserId $UserId)
        }
        if ($mbx.Folders.ContainsKey($MailFolderId)) {
            return (ConvertTo-FakeSdkFolder -Folder $mbx.Folders[$MailFolderId] -UserId $UserId)
        }
        throw "Status: 404 (NotFound) Code: ErrorItemNotFound Message: The specified object was not found in the store."
    }

    return (Select-FakeFolders -Folders (Get-FakeChildren -UserId $UserId -ParentId $null) -Filter $Filter -UserId $UserId)
}

function Get-MgUserMailFolderChildFolder {
    param(
        [string]$UserId,
        [string]$MailFolderId,
        [string]$Filter,
        [switch]$All,
        $ErrorAction
    )
    $mbx      = $script:Store[$UserId]
    $parentId = $MailFolderId
    $wellKnown = "$MailFolderId".ToLowerInvariant()
    if ($mbx.WellKnown.ContainsKey($wellKnown)) { $parentId = $mbx.WellKnown[$wellKnown] }

    if ($script:FailChildListing.ContainsKey($parentId)) {
        throw $script:FailChildListing[$parentId]
    }

    return (Select-FakeFolders -Folders (Get-FakeChildren -UserId $UserId -ParentId $parentId) -Filter $Filter -UserId $UserId)
}

function New-MgUserMailFolder {
    param([string]$UserId, $BodyParameter, $ErrorAction)
    $name = $BodyParameter.DisplayName
    if (Get-FakeChildren -UserId $UserId -ParentId $null | Where-Object { $_.DisplayName -ieq $name }) {
        throw "Status: 409 (Conflict) Code: ErrorFolderExists Message: A folder with the specified name already exists."
    }
    $id = Add-FakeFolder -UserId $UserId -DisplayName $name
    return (ConvertTo-FakeSdkFolder -Folder $script:Store[$UserId].Folders[$id] -UserId $UserId)
}

function New-MgUserMailFolderChildFolder {
    param([string]$UserId, [string]$MailFolderId, $BodyParameter, $ErrorAction)
    $name = $BodyParameter.DisplayName
    if (Get-FakeChildren -UserId $UserId -ParentId $MailFolderId | Where-Object { $_.DisplayName -ieq $name }) {
        throw "Status: 409 (Conflict) Code: ErrorFolderExists Message: A folder with the specified name already exists."
    }
    $id = Add-FakeFolder -UserId $UserId -DisplayName $name -ParentId $MailFolderId
    return (ConvertTo-FakeSdkFolder -Folder $script:Store[$UserId].Folders[$id] -UserId $UserId)
}
