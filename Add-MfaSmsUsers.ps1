#Requires -Version 5.1
<#
.SYNOPSIS
    Interactively adds users from a TXT file to the Entra ID group "MFA-SMS_Users".

.DESCRIPTION
    Standalone single-file script. Save or rename it (SMSAdd.ps1 is fine) and run
    that one .ps1. Nothing else is dotted-sourced or written out to extra scripts.

    - Opens a file picker to choose a .txt file (one UPN/email per line)
    - Shows the users found and asks for confirmation
    - Skips users who are already members
    - Shows a results window and saves a CSV log next to the input file

    Fixes versus the original paste:
      - Membership is added with Invoke-WebRequest (bearer token from the Graph
        session), not New-MgGroupMember -DirectoryObjectId and not
        Invoke-MgGraphRequest JSON $batch, both of which fail on Windows PowerShell 5.1.
      - Users are processed in parallel runspaces, in batches of 10-20 (default 20)
        with a configurable worker throttle (default 6).
      - Each batch looks users up, then PATCH members@odata.bind for that chunk.
        A failed PATCH falls back to per-user POST /members/$ref so one bad row
        does not fail the other 19.
      - Lines may be a UPN or a mail address; lookup falls back from /users/{id} to
        userPrincipalName and mail filters.
      - On-premises-synced and dynamic groups are rejected with a clear error instead
        of a generic Graph 400.
      - "Already a member" Graph errors are counted as Skipped, not Failed.
      - Connect-MgGraph -NoWelcome is used only when the installed module has it.
      - WAM / ISE "window handle" sign-in failures fall back to device code.
      - Existing Graph sessions missing GroupMember.ReadWrite.All are re-authenticated.
      - 429/503/504 responses are retried. Member lists are paged.
      - TXT parsing strips BOM, comments, mailto:, quotes, and CSV/TSV first-column noise.
      - NuGet / PSGallery trust is ensured on Windows PowerShell 5.1 before Install-Module.

.PARAMETER UserListPath
    Skip the file picker and use this .txt file.

.PARAMETER GroupId
    Entra group object ID. Defaults to the MFA-SMS_Users group.

.PARAMETER GroupName
    Display name used in prompts and the log file prefix.

.PARAMETER Force
    Do not prompt for confirmation after the file is read.

.PARAMETER Preview
    Parse and list users, then exit without connecting to Graph.

.PARAMETER SkipGridView
    Do not open Out-GridView at the end (CSV log is still written).

.PARAMETER NonInteractive
    No MessageBox, Out-GridView, or "Press Enter to exit". Requires -UserListPath.
    Use -Force to skip the confirmation prompt.

.PARAMETER BatchSize
    Users processed together in each parallel worker (1-20). Default 20.

.PARAMETER ThrottleLimit
    How many batches run at the same time (1-10). Default 6. Lower this if the
    tenant throttles aggressively.

.PARAMETER SelfTest
    Run helper checks (no Graph, no WinForms dialogs) and exit.

.EXAMPLE
    .\Add-MfaSmsUsers.ps1

.EXAMPLE
    .\Add-MfaSmsUsers.ps1 -UserListPath .\users.txt -SkipGridView

.EXAMPLE
    .\Add-MfaSmsUsers.ps1 -SelfTest
#>

[CmdletBinding()]
param(
    [string]$UserListPath,
    [string]$GroupId = 'cf5c24b8-2289-4311-8b80-e43e6df8455d',
    [string]$GroupName = 'MFA-SMS_Users',
    [switch]$Force,
    [switch]$Preview,
    [switch]$SkipGridView,
    [switch]$NonInteractive,
    [ValidateRange(1, 20)]
    [int]$BatchSize = 20,
    [ValidateRange(1, 10)]
    [int]$ThrottleLimit = 6,
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ToolVersion = '1.7'
$script:GraphBase = 'https://graph.microsoft.com/v1.0'
$script:GraphBatchMax = 20
$script:UserSelect = 'id,userPrincipalName,displayName,mail'
$script:WinFormsReady = $false
$script:ConnectedToGraph = $false
$script:RequiredScopes = @('GroupMember.ReadWrite.All', 'User.Read.All', 'Group.Read.All')

# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

function ConvertTo-TrimmedString {
    param($Value)
    if ($null -eq $Value) { return '' }
    return ([string]$Value).Trim()
}

function Get-PropertyValue {
    param(
        $Object,
        [string]$Name,
        $Default = $null
    )
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Name)) { return $Default }

    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) {
            if ([string]$key -eq $Name) { return $Object[$key] }
        }
        return $Default
    }

    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $Default
}

function ConvertTo-ODataLiteral {
    param([string]$Value)
    return ((ConvertTo-TrimmedString $Value) -replace "'", "''")
}

function Get-ErrorText {
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return '' }
    $parts = New-StringList
    try {
        $msg = ConvertTo-TrimmedString $ErrorRecord.Exception.Message
        if ($msg) { [void]$parts.Add($msg) }
    } catch { }
    try {
        $details = ConvertTo-TrimmedString $ErrorRecord.ErrorDetails.Message
        if ($details -and $parts -notcontains $details) { [void]$parts.Add($details) }
    } catch { }
    $inner = $null
    try { $inner = $ErrorRecord.Exception.InnerException } catch { }
    while ($inner) {
        $innerMsg = ConvertTo-TrimmedString $inner.Message
        if ($innerMsg -and $parts -notcontains $innerMsg) { [void]$parts.Add($innerMsg) }
        try { $inner = $inner.InnerException } catch { break }
    }
    return ($parts -join ' | ')
}

function Get-HttpStatusFromError {
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return 0 }

    $response = $null
    try { $response = $ErrorRecord.Exception.Response } catch { }
    if ($response) {
        try {
            $code = Get-PropertyValue $response 'StatusCode' $null
            if ($code -is [enum] -or $code -is [int] -or $code -is [byte]) { return [int]$code }
        } catch { }
    }

    $ex = $null
    try { $ex = $ErrorRecord.Exception } catch { }
    while ($ex) {
        foreach ($name in @('StatusCode', 'ResponseStatusCode')) {
            try {
                $code = Get-PropertyValue $ex $name $null
                if ($code -is [enum] -or $code -is [int]) {
                    $intCode = [int]$code
                    if ($intCode -ge 100 -and $intCode -le 599) { return $intCode }
                }
            } catch { }
        }
        $msg = ConvertTo-TrimmedString $ex.Message
        if ($msg -match 'status code[^\d]*(\d{3})' -or $msg -match '\((429|503|504|404|400|403)\)') {
            return [int]$Matches[1]
        }
        try { $ex = $ex.InnerException } catch { break }
    }

    $text = Get-ErrorText $ErrorRecord
    if ($text -match '"status"\s*:\s*(\d{3})' -or $text -match '\b(429|503|504)\b') {
        return [int]$Matches[1]
    }
    return 0
}

function Test-IsTransientGraphError {
    param($ErrorRecord)
    $status = Get-HttpStatusFromError $ErrorRecord
    if ($status -in 429, 503, 504) { return $true }
    $text = Get-ErrorText $ErrorRecord
    return ($text -match 'Too Many Requests|temporarily unavailable|throttl')
}

function Test-IsNotFoundError {
    param($ErrorRecord)
    $status = Get-HttpStatusFromError $ErrorRecord
    if ($status -eq 404) { return $true }
    $text = Get-ErrorText $ErrorRecord
    return ($text -match 'Request_ResourceNotFound|ResourceNotFound|does not exist|not found')
}

function Test-IsAlreadyMemberError {
    param($ErrorRecord)
    $text = Get-ErrorText $ErrorRecord
    return ($text -match 'already exist|already a member|added object references already exist')
}

function Get-RetryAfterSeconds {
    param($ErrorRecord, [int]$Attempt = 1)
    $headerValue = $null
    try {
        $headers = $ErrorRecord.Exception.Response.Headers
        if ($headers) {
            foreach ($key in @('Retry-After', 'RetryAfter')) {
                try {
                    $headerValue = $headers[$key]
                    if ($headerValue) { break }
                } catch { }
            }
        }
    } catch { }

    $seconds = 0
    if ($headerValue) {
        $text = ConvertTo-TrimmedString ($headerValue | Select-Object -First 1)
        [void][int]::TryParse($text, [ref]$seconds)
    }
    if ($seconds -lt 1) {
        $seconds = [Math]::Min(60, [int][Math]::Pow(2, [Math]::Min($Attempt, 5)))
    }
    return $seconds
}

function Get-PercentComplete {
    param([int]$Current, [int]$Total)
    if ($Total -le 0) { return 0 }
    $pct = [int](($Current / [double]$Total) * 100)
    if ($pct -lt 0) { return 0 }
    if ($pct -gt 100) { return 100 }
    return $pct
}

function Test-IsGuid {
    param([string]$Value)
    $parsed = [guid]::Empty
    return [guid]::TryParse((ConvertTo-TrimmedString $Value), [ref]$parsed)
}

function Get-RuntimeGraphBase {
    foreach ($scope in @('Script', 'Global')) {
        try {
            $variable = Get-Variable -Name GraphBase -Scope $scope -ErrorAction SilentlyContinue
            $value = ConvertTo-TrimmedString $(if ($variable) { $variable.Value } else { '' })
            if ($value) { return $value }
        } catch { }
    }
    return 'https://graph.microsoft.com/v1.0'
}

function Get-RuntimeUserSelect {
    foreach ($scope in @('Script', 'Global')) {
        try {
            $variable = Get-Variable -Name UserSelect -Scope $scope -ErrorAction SilentlyContinue
            $value = ConvertTo-TrimmedString $(if ($variable) { $variable.Value } else { '' })
            if ($value) { return $value }
        } catch { }
    }
    return 'id,userPrincipalName,displayName,mail'
}

function Get-GroupMemberODataId {
    param([string]$DirectoryObjectId)
    return ('{0}/directoryObjects/{1}' -f (Get-RuntimeGraphBase), (ConvertTo-TrimmedString $DirectoryObjectId))
}

function Get-AddMemberUri {
    param([string]$TargetGroupId)
    return ('{0}/groups/{1}/members/$ref' -f (Get-RuntimeGraphBase), (ConvertTo-TrimmedString $TargetGroupId))
}

function Get-AddMemberJsonBody {
    param([string]$DirectoryObjectId)
    $odataId = Get-GroupMemberODataId $DirectoryObjectId
    return ('{{"@odata.id":"{0}"}}' -f $odataId)
}

function ConvertTo-JsonString {
    param([string]$Value)
    $text = ''
    if ($null -ne $Value) { $text = [string]$Value }
    return ($text.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t'))
}

function New-IgnoreCaseMap {
    # PowerShell @{} is a case-insensitive Hashtable. A two-parameter generic
    # dictionary throws "Argument types do not match" on Windows PowerShell 5.1.
    return @{}
}

function New-ObjectList {
    # Unary comma: an empty List is IEnumerable and would otherwise return $null.
    return ,[System.Collections.Generic.List[object]]::new()
}

function New-StringList {
    return ,[System.Collections.Generic.List[string]]::new()
}

function Disconnect-MfaSmsGraph {
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
    } catch { }
}

function Get-ListChunks {
    param(
        $Items,
        [int]$Size
    )
    if ($Size -lt 1) { $Size = 1 }
    $chunks = New-Object System.Collections.ArrayList
    $current = New-Object System.Collections.ArrayList
    foreach ($item in @($Items)) {
        [void]$current.Add($item)
        if ($current.Count -ge $Size) {
            [void]$chunks.Add(@($current.ToArray()))
            $current = New-Object System.Collections.ArrayList
        }
    }
    if ($current.Count -gt 0) { [void]$chunks.Add(@($current.ToArray())) }
    return ,$chunks
}

function ConvertTo-StringArray {
    param($Items)
    $list = New-Object System.Collections.ArrayList
    foreach ($item in @($Items)) {
        $text = ConvertTo-TrimmedString $item
        if ($text) { [void]$list.Add($text) }
    }
    if ($list.Count -eq 0) { return [string[]]@() }
    return [string[]]$list.ToArray()
}

function Get-BindMembersJson {
    param([string[]]$DirectoryObjectIds)
    $parts = New-StringList
    foreach ($id in @($DirectoryObjectIds)) {
        $oid = ConvertTo-TrimmedString $id
        if (-not $oid) { continue }
        [void]$parts.Add(('"{0}"' -f (ConvertTo-JsonString (Get-GroupMemberODataId $oid))))
    }
    return ('{{"members@odata.bind":[{0}]}}' -f ($parts -join ','))
}

function New-GraphBatchItem {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Url,
        $Headers = $null,
        [string]$BodyJson = ''
    )
    return [pscustomobject]@{
        Id       = $Id
        Method   = $Method
        Url      = $Url
        Headers  = $Headers
        BodyJson = $BodyJson
    }
}

function Get-GraphBatchJson {
    param($Requests)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('{"requests":[')
    $first = $true
    foreach ($req in @($Requests)) {
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        [void]$sb.Append('{"id":"')
        [void]$sb.Append((ConvertTo-JsonString ([string](Get-PropertyValue $req 'Id' ''))))
        [void]$sb.Append('","method":"')
        [void]$sb.Append((ConvertTo-JsonString ([string](Get-PropertyValue $req 'Method' ''))))
        [void]$sb.Append('","url":"')
        [void]$sb.Append((ConvertTo-JsonString ([string](Get-PropertyValue $req 'Url' ''))))
        [void]$sb.Append('"')

        $headers = Get-PropertyValue $req 'Headers' $null
        if ($headers) {
            [void]$sb.Append(',"headers":{')
            $headerFirst = $true
            if ($headers -is [System.Collections.IDictionary]) {
                foreach ($key in $headers.Keys) {
                    if (-not $headerFirst) { [void]$sb.Append(',') }
                    $headerFirst = $false
                    [void]$sb.Append('"')
                    [void]$sb.Append((ConvertTo-JsonString ([string]$key)))
                    [void]$sb.Append('":"')
                    [void]$sb.Append((ConvertTo-JsonString ([string]$headers[$key])))
                    [void]$sb.Append('"')
                }
            }
            [void]$sb.Append('}')
        }

        $bodyJson = ConvertTo-TrimmedString (Get-PropertyValue $req 'BodyJson' '')
        if ($bodyJson) {
            [void]$sb.Append(',"body":')
            [void]$sb.Append($bodyJson)
        }
        [void]$sb.Append('}')
    }
    [void]$sb.Append(']}')
    return $sb.ToString()
}

function Get-UserLookupRelativeUrl {
    param([string]$Identity)
    $encoded = [uri]::EscapeDataString((ConvertTo-TrimmedString $Identity))
    return ('/users/{0}?$select={1}' -f $encoded, (Get-RuntimeUserSelect))
}

function Get-UserFilterRelativeUrl {
    param([string]$Identity)
    $literal = ConvertTo-ODataLiteral $Identity
    $filter = "userPrincipalName eq '$literal' or mail eq '$literal'"
    return ('/users?$filter={0}&$select={1}' -f [uri]::EscapeDataString($filter), (Get-RuntimeUserSelect))
}

function Get-GraphErrorMessageFromBody {
    param($Body)
    if ($null -eq $Body) { return '' }
    $err = Get-PropertyValue $Body 'error' $null
    if ($err) {
        $code = ConvertTo-TrimmedString (Get-PropertyValue $err 'code' '')
        $msg = ConvertTo-TrimmedString (Get-PropertyValue $err 'message' '')
        if ($code -and $msg) { return "$code : $msg" }
        if ($msg) { return $msg }
        if ($code) { return $code }
    }
    return (ConvertTo-TrimmedString $Body)
}

function Test-IsAlreadyMemberText {
    param([string]$Text)
    return ((ConvertTo-TrimmedString $Text) -match 'already exist|already a member|added object references already exist')
}

function Get-BatchItemStatus {
    param($Item)
    $status = Get-PropertyValue $Item 'status' 0
    try { return [int]$status } catch { return 0 }
}

function Get-UserPreviewLines {
    param($Users, [int]$MaxNamed = 15)
    $lines = New-StringList
    $count = $Users.Count
    $shown = [Math]::Min($MaxNamed, $count)
    $i = 0
    foreach ($upn in $Users) {
        if ($i -ge $shown) { break }
        [void]$lines.Add("  $upn")
        $i++
    }
    if ($count -gt $shown) {
        [void]$lines.Add(('  ... and {0} more' -f ($count - $shown)))
    }
    return ,$lines
}

function Get-RateStatus {
    param([int]$Done, [int]$Total, [datetime]$Started, [string]$Verb)
    if ($Done -le 0) { return ('{0} {1} of {2}' -f $Verb, $Done, $Total) }
    $elapsed = (Get-Date) - $Started
    $seconds = [Math]::Max($elapsed.TotalSeconds, 0.001)
    $rate = $Done / $seconds
    $remain = [int][Math]::Ceiling(($Total - $Done) / [Math]::Max($rate, 0.001))
    if ($remain -lt 0) { $remain = 0 }
    return ('{0} {1} of {2} ({3:N0}/s, ~{4}s left)' -f $Verb, $Done, $Total, $rate, $remain)
}

function Get-GroupMembershipBlockers {
    param($Group)
    $blockers = New-StringList

    $sync = Get-PropertyValue $Group 'onPremisesSyncEnabled' $false
    if ($sync -eq $true -or "$sync" -eq 'True') {
        [void]$blockers.Add("This group is synced from on-premises Active Directory. Add members in AD (or use a cloud-only group). Graph cannot update on-premises-mastered membership.")
    }

    $types = @()
    $rawTypes = Get-PropertyValue $Group 'groupTypes' @()
    if ($rawTypes) { $types = @($rawTypes) }

    $rule = ConvertTo-TrimmedString (Get-PropertyValue $Group 'membershipRule' '')
    $ruleState = ConvertTo-TrimmedString (Get-PropertyValue $Group 'membershipRuleProcessingState' '')
    if ($types -contains 'DynamicMembership' -or ($ruleState -eq 'On' -and $rule)) {
        [void]$blockers.Add("This is a dynamic group. Membership is controlled by a rule, not by adding users.")
    }

    # Unary comma stops PowerShell enumerating the List on return (0/1 items).
    return ,$blockers
}

function ConvertTo-UserIdentityList {
    param([string[]]$Lines)

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $list = New-StringList

    foreach ($raw in @($Lines)) {
        $text = ConvertTo-TrimmedString $raw
        if (-not $text) { continue }

        $text = $text.Trim([char]0xFEFF, [char]0x200B, [char]0x00A0)
        if (-not $text) { continue }
        if ($text.StartsWith('#')) { continue }
        if ($text -match '^(?i)(upn|userprincipalname|email|mail|user|user name)$') { continue }

        if ($text.Length -ge 7 -and $text.StartsWith('mailto:', [StringComparison]::OrdinalIgnoreCase)) {
            $text = $text.Substring(7).Trim()
        }

        if ($text.Length -ge 2) {
            $first = $text[0]
            $last = $text[$text.Length - 1]
            if (($first -eq [char]'"' -and $last -eq [char]'"') -or ($first -eq [char]"'" -and $last -eq [char]"'")) {
                $text = $text.Substring(1, $text.Length - 2).Trim()
            }
        }

        if ($text.Contains("`t")) {
            $text = (ConvertTo-TrimmedString ($text -split "`t", 2)[0])
        }
        elseif ($text.Contains(',')) {
            $text = (ConvertTo-TrimmedString ($text -split ',', 2)[0]).Trim('"')
        }

        $text = ConvertTo-TrimmedString $text
        if (-not $text -or $text.StartsWith('#')) { continue }
        if ($seen.Add($text)) { [void]$list.Add($text) }
    }

    return ,$list
}

function Read-UserListFile {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "File not found: $Path"
    }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $text = ''
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $text = [Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
    }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $text = [Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        $text = [Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2)
    }
    else {
        $text = [Text.Encoding]::UTF8.GetString($bytes)
    }

    $lines = $text -split '\r\n|\n|\r'
    return ,(ConvertTo-UserIdentityList -Lines $lines)
}

function Get-ResultLogPath {
    param([string]$SourcePath, [string]$Prefix)

    $name = ('{0}_Results_{1}.csv' -f $Prefix, (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $candidates = New-StringList

    $parent = ''
    try { $parent = Split-Path -Path $SourcePath -Parent } catch { }
    if ($parent) { [void]$candidates.Add($parent) }

    try {
        $desktop = [Environment]::GetFolderPath('Desktop')
        if ($desktop) { [void]$candidates.Add($desktop) }
    } catch { }

    [void]$candidates.Add([IO.Path]::GetTempPath())

    foreach ($folder in $candidates) {
        if (-not $folder) { continue }
        $probe = Join-Path $folder ('.write-test-' + [guid]::NewGuid().ToString('N'))
        try {
            [IO.File]::WriteAllText($probe, 'ok')
            Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
            return (Join-Path $folder $name)
        } catch { }
    }

    return (Join-Path ([IO.Path]::GetTempPath()) $name)
}

function New-UserResult {
    param(
        [string]$UserPrincipalName,
        [string]$Status,
        [string]$Detail = '',
        [string]$ObjectId = '',
        [string]$ResolvedUpn = ''
    )
    return [pscustomobject]@{
        UserPrincipalName = $UserPrincipalName
        ResolvedUpn       = $ResolvedUpn
        ObjectId          = $ObjectId
        Status            = $Status
        Detail            = $Detail
    }
}

function Test-IsEmbeddedHost {
    $name = ''
    try { $name = [string]$Host.Name } catch { }
    if ($name -match 'ISE|Visual Studio') { return $true }
    try {
        if ($null -ne $psISE) { return $true }
    } catch { }
    return $false
}

function Test-HasGraphScopes {
    param($Context, [string[]]$Required)
    if (-not $Context) { return $false }

    $have = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($scope in @((Get-PropertyValue $Context 'Scopes' @()))) {
        $name = ConvertTo-TrimmedString $scope
        if (-not $name) { continue }
        if ($name -match '/([^/]+)$') { $name = $Matches[1] }
        [void]$have.Add($name)
    }

    foreach ($need in @($Required)) {
        if (-not $have.Contains($need)) { return $false }
    }
    return $true
}

# ---------------------------------------------------------------------------
# WinForms (loaded only for interactive GUI runs)
# ---------------------------------------------------------------------------

function Initialize-WinForms {
    if ($script:WinFormsReady) { return }
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch { }
    $script:WinFormsReady = $true
}

function Select-UserListFile {
    Initialize-WinForms
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = "Select the user list for $GroupName"
    $dialog.Filter = 'Text files (*.txt)|*.txt|All files (*.*)|*.*'
    $dialog.Multiselect = $false
    try {
        $desktop = [Environment]::GetFolderPath('Desktop')
        if ($desktop -and (Test-Path -LiteralPath $desktop)) {
            $dialog.InitialDirectory = $desktop
        }
    } catch { }

    $owner = $null
    try {
        $owner = New-Object System.Windows.Forms.Form -Property @{ TopMost = $true; ShowInTaskbar = $false }
        $result = $dialog.ShowDialog($owner)
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) { return $dialog.FileName }
        return $null
    }
    finally {
        if ($owner) { $owner.Dispose() }
        if ($dialog) { $dialog.Dispose() }
    }
}

function Show-Message {
    param(
        [string]$Text,
        [string]$Title = $GroupName,
        [System.Windows.Forms.MessageBoxButtons]$Buttons = [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::Information
    )
    Initialize-WinForms
    return [System.Windows.Forms.MessageBox]::Show($Text, $Title, $Buttons, $Icon)
}

function Confirm-UserList {
    param(
        [int]$Count,
        [string]$Path
    )

    if ($Force) { return $true }

    $prompt = "Add $Count user(s) to '$GroupName'?`r`n`r`nFile: $Path"
    if ($Count -ge 50) {
        $prompt = $prompt + ("`r`n`r`nUses {0} parallel workers with {1} users per batch. Typically a few minutes for thousands of users." -f $ThrottleLimit, $BatchSize)
    }
    if (-not $NonInteractive) {
        try {
            $answer = Show-Message -Text $prompt -Buttons ([System.Windows.Forms.MessageBoxButtons]::YesNo) -Icon ([System.Windows.Forms.MessageBoxIcon]::Question)
            return ($answer -eq [System.Windows.Forms.DialogResult]::Yes)
        } catch {
            # Fall through to console confirm when WinForms is unavailable.
        }
    }

    Write-Host $prompt
    $typed = Read-Host 'Continue? [Y/N]'
    return ((ConvertTo-TrimmedString $typed) -match '^(y|yes)$')
}

# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------

function Install-GraphAuthModule {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Host 'Installing Microsoft.Graph.Authentication...' -ForegroundColor Yellow
        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
        }
        $gallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($gallery -and $gallery.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop | Out-Null
}

function Invoke-GraphWithRetry {
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 5
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return & $ScriptBlock
        }
        catch {
            if ($attempt -ge $MaxAttempts -or -not (Test-IsTransientGraphError $_)) { throw }
            $wait = Get-RetryAfterSeconds -ErrorRecord $_ -Attempt $attempt
            Write-Host "Graph throttled or unavailable; retrying in $wait s (attempt $attempt of $MaxAttempts)..." -ForegroundColor Yellow
            Start-Sleep -Seconds $wait
        }
    }
}

function Connect-MfaSmsGraph {
    Install-GraphAuthModule
    $connect = Get-Command Connect-MgGraph -ErrorAction Stop

    $ctx = $null
    try { $ctx = Get-MgContext } catch { }
    if (Test-HasGraphScopes -Context $ctx -Required $script:RequiredScopes) {
        Write-Host 'Already connected to Microsoft Graph with the required scopes.' -ForegroundColor DarkGray
        $script:ConnectedToGraph = $true
        return
    }
    if ($ctx) {
        Disconnect-MfaSmsGraph
    }

    try {
        if (Get-Command Set-MgGraphOption -ErrorAction SilentlyContinue) {
            $opt = Get-Command Set-MgGraphOption
            if ($opt.Parameters.ContainsKey('DisableLoginByWAM')) {
                Set-MgGraphOption -DisableLoginByWAM $true
            }
        }
    } catch { }

    $params = @{
        Scopes      = $script:RequiredScopes
        ErrorAction = 'Stop'
    }
    if ($connect.Parameters.ContainsKey('NoWelcome')) {
        $params['NoWelcome'] = $true
    }

    $useDevice = $connect.Parameters.ContainsKey('UseDeviceCode')
    $embedded = Test-IsEmbeddedHost

    Write-Host 'Connecting to Microsoft Graph (a sign-in window will appear)...' -ForegroundColor Cyan

    if ($embedded -and $useDevice) {
        Write-Host 'Embedded host (ISE / VS) detected. WAM sign-in needs a window handle, so device code will be used.' -ForegroundColor Yellow
        $params['UseDeviceCode'] = $true
        Connect-MgGraph @params | Out-Null
        $script:ConnectedToGraph = $true
        return
    }

    try {
        Connect-MgGraph @params | Out-Null
        $script:ConnectedToGraph = $true
        return
    }
    catch {
        $text = Get-ErrorText $_
        if (-not $useDevice) { throw }
        Write-Host "Browser / WAM sign-in failed: $text" -ForegroundColor Yellow
        Write-Host 'Falling back to device code sign-in. Follow the instructions below.' -ForegroundColor Yellow
        $params['UseDeviceCode'] = $true
        Connect-MgGraph @params | Out-Null
        $script:ConnectedToGraph = $true
    }
}

function Get-TargetGroup {
    param([string]$TargetGroupId)
    $select = 'id,displayName,groupTypes,securityEnabled,mailEnabled,onPremisesSyncEnabled,membershipRule,membershipRuleProcessingState,isAssignableToRole'
    $uri = '{0}/groups/{1}?$select={2}' -f $script:GraphBase, $TargetGroupId, $select
    return Invoke-GraphWithRetry -ScriptBlock { Invoke-MgGraphRequest -Method GET -Uri $uri }
}

function Get-ExistingMemberIdSet {
    param([string]$TargetGroupId)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $uri = '{0}/groups/{1}/members?$select=id&$top=999' -f $script:GraphBase, $TargetGroupId
    while ($uri) {
        $pageUri = $uri
        $resp = Invoke-GraphWithRetry -ScriptBlock { Invoke-MgGraphRequest -Method GET -Uri $pageUri }
        foreach ($item in @((Get-PropertyValue $resp 'value' @()))) {
            $mid = ConvertTo-TrimmedString (Get-PropertyValue $item 'id' '')
            if ($mid) { [void]$set.Add($mid) }
        }
        $uri = Get-PropertyValue $resp '@odata.nextLink' $null
    }
    return ,$set
}

function ConvertTo-PlainToken {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [securestring]) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        try {
            return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
    try {
        $prop = $Value.PSObject.Properties['Token']
        if ($prop -and $null -ne $prop.Value -and -not [object]::ReferenceEquals($prop.Value, $Value)) {
            $inner = ConvertTo-PlainToken $prop.Value
            if ($inner) { return $inner }
        }
    } catch { }
    $text = ConvertTo-TrimmedString $Value
    if ($text.Length -lt 20) { return '' }
    if ($text -match '\s') { return '' }
    if ($text -notmatch '^eyJ') { return '' }
    return $text
}

function Get-JwtFromCacheText {
    param([string]$Text)
    $raw = ConvertTo-TrimmedString $Text
    if (-not $raw) { return '' }
    $direct = ConvertTo-PlainToken $raw
    if ($direct) { return $direct }
    $found = ''
    foreach ($match in [regex]::Matches($raw, 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')) {
        if ($match.Value.Length -gt $found.Length) { $found = $match.Value }
    }
    return $found
}

function Get-TokenFromObject {
    param($Object, [int]$Depth = 0)
    if ($null -eq $Object -or $Depth -gt 5) { return '' }

    foreach ($name in @('AccessToken', 'Token', 'GraphToken', 'RawToken')) {
        try {
            $prop = $Object.PSObject.Properties[$name]
            if ($prop) {
                $text = ConvertTo-PlainToken $prop.Value
                if ($text) { return $text }
            }
        } catch { }
        try {
            $p = $Object.GetType().GetProperty($name)
            if ($p) {
                $text = ConvertTo-PlainToken ($p.GetValue($Object, $null))
                if ($text) { return $text }
            }
        } catch { }
    }

    foreach ($name in @('LastAuthResult', 'AuthResult', 'AuthContext', 'Result', 'AuthenticationResult', 'TokenCredential', 'Credential')) {
        $child = $null
        try {
            $prop = $Object.PSObject.Properties[$name]
            if ($prop) { $child = $prop.Value }
        } catch { }
        if ($null -eq $child) {
            try {
                $p = $Object.GetType().GetProperty($name)
                if ($p) { $child = $p.GetValue($Object, $null) }
            } catch { }
        }
        if ($null -ne $child -and -not [object]::ReferenceEquals($child, $Object)) {
            $text = Get-TokenFromObject -Object $child -Depth ($Depth + 1)
            if ($text) { return $text }
            if ($name -in @('TokenCredential', 'Credential')) {
                $text = Get-TokenFromTokenCredential -Credential $child -Scopes (Get-GraphTokenScopes)
                if ($text) { return $text }
            }
        }
    }

    try {
        $flags = [System.Reflection.BindingFlags]'Instance,Public,NonPublic'
        foreach ($field in $Object.GetType().GetFields($flags)) {
            if ($field.Name -notmatch 'token|auth|credential|cache|result') { continue }
            $val = $null
            try { $val = $field.GetValue($Object) } catch { continue }
            if ($null -eq $val -or [object]::ReferenceEquals($val, $Object)) { continue }
            $text = ConvertTo-PlainToken $val
            if ($text) { return $text }
            if ($Depth -lt 4) {
                $text = Get-TokenFromObject -Object $val -Depth ($Depth + 1)
                if ($text) { return $text }
            }
        }
    } catch { }

    return ''
}

function Get-GraphSessionInstance {
    try {
        $type = [type]'Microsoft.Graph.PowerShell.Authentication.GraphSession'
        if ($type) { return $type::Instance }
    } catch { }
    return $null
}

function Get-GraphTokenScopes {
    $scopes = New-Object System.Collections.ArrayList
    try {
        $auth = $null
        $session = Get-GraphSessionInstance
        if ($session) {
            try { $auth = $session.AuthContext } catch { }
        }
        if (-not $auth) {
            try { $auth = Get-MgContext } catch { }
        }
        foreach ($scope in @((Get-PropertyValue $auth 'Scopes' @()))) {
            $name = ConvertTo-TrimmedString $scope
            if ($name) { [void]$scopes.Add($name) }
        }
    } catch { }
    if ($scopes.Count -eq 0) {
        [void]$scopes.Add('https://graph.microsoft.com/.default')
    }
    return [string[]]$scopes.ToArray()
}

function Get-TokenFromTokenCredential {
    param($Credential, $Scopes)
    if ($null -eq $Credential) { return '' }
    $scopeArray = [string[]]@($Scopes)
    if ($scopeArray.Count -eq 0) {
        $scopeArray = [string[]]@('https://graph.microsoft.com/.default')
    }

    $requestContext = $null
    $ctxType = $null
    try { $ctxType = [type]'Azure.Core.TokenRequestContext' } catch { }
    if (-not $ctxType) { return '' }
    try {
        $requestContext = [Azure.Core.TokenRequestContext]::new($scopeArray, $null, $null, $null, $true)
    } catch {
        try { $requestContext = [Azure.Core.TokenRequestContext]::new($scopeArray) } catch { return '' }
    }

    $none = [System.Threading.CancellationToken]::None
    foreach ($name in @('GetToken', 'GetTokenAsync')) {
        try {
            $result = $Credential.$name($requestContext, $none)
            if ($result -is [System.Threading.Tasks.Task]) {
                $result = $result.GetAwaiter().GetResult()
            }
            $text = ConvertTo-PlainToken $result
            if (-not $text) { $text = ConvertTo-PlainToken (Get-PropertyValue $result 'Token' $null) }
            if ($text) { return $text }
        } catch { }
    }
    return ''
}

function Get-TokenFromInMemoryCache {
    param($Session)
    if ($null -eq $Session) { return '' }
    $cache = $null
    try { $cache = $Session.InMemoryTokenCache } catch { }
    if ($null -eq $cache) { return '' }

    $bytes = $null
    try {
        $flags = [System.Reflection.BindingFlags]'Instance,Public,NonPublic'
        $method = $cache.GetType().GetMethod('ReadTokenData', $flags)
        if ($method) { $bytes = $method.Invoke($cache, @()) }
    } catch { }
    if ($null -eq $bytes) {
        try { $bytes = $cache.ReadTokenData() } catch { }
    }
    if ($null -eq $bytes) { return '' }

    $text = ''
    try {
        if ($bytes -is [byte[]]) {
            $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        }
        else {
            $text = [string]$bytes
        }
    } catch { }
    return (Get-JwtFromCacheText $text)
}

function Get-TokenFromGraphHttpClient {
    try {
        $helpers = [type]'Microsoft.Graph.PowerShell.Authentication.Helpers.HttpHelpers'
        if (-not $helpers) { return '' }
        $client = $helpers::GetGraphHttpClient()
        if (-not $client) { return '' }
        $header = $null
        try { $header = $client.DefaultRequestHeaders.Authorization } catch { }
        if ($header) {
            $text = ConvertTo-PlainToken (Get-PropertyValue $header 'Parameter' $null)
            if ($text) { return $text }
        }
    } catch { }
    return ''
}

function Get-GraphAccessToken {
    $session = Get-GraphSessionInstance
    if ($session) {
        $text = Get-TokenFromObject $session
        if ($text) { return $text }
        try {
            foreach ($p in $session.GetType().GetProperties()) {
                $val = $null
                try { $val = $p.GetValue($session, $null) } catch { continue }
                $text = Get-TokenFromObject $val
                if ($text) { return $text }
            }
        } catch { }
        try {
            $auth = $session.AuthContext
            $cred = Get-PropertyValue $auth 'TokenCredential' $null
            $text = Get-TokenFromTokenCredential -Credential $cred -Scopes (Get-GraphTokenScopes)
            if ($text) { return $text }
        } catch { }
        $text = Get-TokenFromInMemoryCache $session
        if ($text) { return $text }
    }

    $text = Get-TokenFromGraphHttpClient
    if ($text) { return $text }

    try {
        $ctx = Get-MgContext
        $text = Get-TokenFromObject $ctx
        if ($text) { return $text }
        $cred = Get-PropertyValue $ctx 'TokenCredential' $null
        $text = Get-TokenFromTokenCredential -Credential $cred -Scopes (Get-GraphTokenScopes)
        if ($text) { return $text }
    } catch { }

    return ''
}

function Invoke-GraphWebRequest {
    param(
        [string]$Method,
        [string]$Uri,
        [string]$Token,
        [string]$Body = '',
        [int]$MaxAttempts = 5
    )

    $headers = @{
        Authorization = ('Bearer {0}' -f $Token)
        Accept        = 'application/json'
    }

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $params = @{
                Method          = $Method
                Uri             = $Uri
                Headers         = $headers
                UseBasicParsing = $true
                ErrorAction     = 'Stop'
            }
            if (-not [string]::IsNullOrEmpty($Body)) {
                $params['ContentType'] = 'application/json; charset=utf-8'
                $params['Body'] = [System.Text.Encoding]::UTF8.GetBytes($Body)
            }
            $resp = Invoke-WebRequest @params
            $obj = $null
            $content = ''
            try { $content = [string]$resp.Content } catch { }
            if ($content) {
                try { $obj = $content | ConvertFrom-Json } catch { }
            }
            $code = 0
            try { $code = [int]$resp.StatusCode } catch { $code = 200 }
            return [pscustomobject]@{
                Status = $code
                Body   = $obj
                Error  = ''
            }
        }
        catch {
            $status = Get-HttpStatusFromError $_
            $errBody = $null
            $msg = Get-ErrorText $_
            try {
                $response = $_.Exception.Response
                if ($response) {
                    try { $status = [int]$response.StatusCode } catch { }
                    try {
                        $stream = $response.GetResponseStream()
                        if ($stream) {
                            $reader = New-Object System.IO.StreamReader($stream)
                            $text = $reader.ReadToEnd()
                            try { $reader.Dispose() } catch { try { $reader.Close() } catch { } }
                            if ($text) {
                                try { $errBody = $text | ConvertFrom-Json } catch { }
                                $fromBody = Get-GraphErrorMessageFromBody $errBody
                                if ($fromBody) { $msg = $fromBody }
                                elseif (-not $msg) { $msg = $text }
                            }
                        }
                    } catch { }
                }
            } catch { }

            if ((-not $errBody) -and $_.ErrorDetails -and $_.ErrorDetails.Message) {
                $detailText = [string]$_.ErrorDetails.Message
                try { $errBody = $detailText | ConvertFrom-Json } catch { }
                $fromBody = Get-GraphErrorMessageFromBody $errBody
                if ($fromBody) { $msg = $fromBody }
                elseif (-not $msg) { $msg = $detailText }
            }

            if (($status -in 429, 503, 504) -and $attempt -lt $MaxAttempts) {
                $wait = [Math]::Min(60, [int][Math]::Pow(2, $attempt))
                Start-Sleep -Seconds $wait
                continue
            }

            return [pscustomobject]@{
                Status = $status
                Body   = $errBody
                Error  = $msg
            }
        }
    }
}

function New-ResolvedUser {
    param(
        [string]$Identity,
        [string]$ObjectId = '',
        [string]$ResolvedUpn = '',
        [string]$ErrorText = ''
    )
    return [pscustomobject]@{
        Identity    = $Identity
        ObjectId    = $ObjectId
        ResolvedUpn = $ResolvedUpn
        ErrorText   = $ErrorText
        Found       = -not [string]::IsNullOrWhiteSpace($ObjectId)
    }
}

function Read-UserFromGraphBody {
    param($Body)
    if ($null -eq $Body) { return $null }
    $directId = ConvertTo-TrimmedString (Get-PropertyValue $Body 'id' '')
    if ($directId) { return $Body }
    $values = @((Get-PropertyValue $Body 'value' @()))
    if ($values.Count -eq 1) { return $values[0] }
    if ($values.Count -gt 1) { return 'AMBIGUOUS' }
    return $null
}

function Invoke-UserChunkWork {
    param(
        $Identities,
        [string]$Token,
        [string]$GroupId,
        $ExistingIds
    )

    $existing = @{}
    foreach ($id in @($ExistingIds)) {
        $mid = ConvertTo-TrimmedString $id
        if ($mid) { $existing[$mid] = $true }
    }

    $results = New-Object System.Collections.ArrayList
    $idList = @($Identities)
    if ($idList.Count -eq 0) { return @() }

    $lookupMap = @{}
    $needFilter = New-Object System.Collections.ArrayList
    $batchOk = $false

    $batchItems = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $idList.Count; $i++) {
        $identity = [string]$idList[$i]
        [void]$batchItems.Add((New-GraphBatchItem -Id ([string]($i + 1)) -Method 'GET' -Url (Get-UserLookupRelativeUrl $identity)))
    }

    $batchUri = '{0}/$batch' -f (Get-RuntimeGraphBase)
    $batchJson = Get-GraphBatchJson -Requests $batchItems
    $batchResp = Invoke-GraphWebRequest -Method POST -Uri $batchUri -Token $Token -Body $batchJson
    if ($batchResp.Status -eq 200 -and $batchResp.Body) {
        $batchOk = $true
        $batchById = @{}
        foreach ($item in @((Get-PropertyValue $batchResp.Body 'responses' @()))) {
            $rid = [string](Get-PropertyValue $item 'id' '')
            if ($rid) { $batchById[$rid] = $item }
        }
        for ($i = 0; $i -lt $idList.Count; $i++) {
            $identity = [string]$idList[$i]
            $rid = [string]($i + 1)
            if (-not $batchById.ContainsKey($rid)) {
                [void]$needFilter.Add($identity)
                continue
            }
            $row = $batchById[$rid]
            $status = Get-BatchItemStatus $row
            $body = Get-PropertyValue $row 'body' $null
            if ($status -eq 200) {
                $user = Read-UserFromGraphBody $body
                $objectId = ConvertTo-TrimmedString (Get-PropertyValue $user 'id' '')
                $upn = ConvertTo-TrimmedString (Get-PropertyValue $user 'userPrincipalName' '')
                if ($objectId) {
                    $lookupMap[$identity] = New-ResolvedUser -Identity $identity -ObjectId $objectId -ResolvedUpn $upn
                }
                else {
                    $lookupMap[$identity] = New-ResolvedUser -Identity $identity -ErrorText 'Graph returned a user without an id'
                }
            }
            elseif ($status -eq 404) {
                [void]$needFilter.Add($identity)
            }
            else {
                $detail = Get-GraphErrorMessageFromBody $body
                if (-not $detail) { $detail = "Graph user lookup failed with HTTP $status" }
                $lookupMap[$identity] = New-ResolvedUser -Identity $identity -ErrorText $detail
            }
        }
    }
    else {
        foreach ($identity in $idList) { [void]$needFilter.Add([string]$identity) }
    }

    foreach ($identity in @($needFilter)) {
        if ($lookupMap.ContainsKey([string]$identity)) { continue }

        if (-not $batchOk) {
            $directUri = '{0}{1}' -f (Get-RuntimeGraphBase), (Get-UserLookupRelativeUrl $identity)
            $direct = Invoke-GraphWebRequest -Method GET -Uri $directUri -Token $Token
            if ($direct.Status -eq 200) {
                $user = Read-UserFromGraphBody $direct.Body
                $objectId = ConvertTo-TrimmedString (Get-PropertyValue $user 'id' '')
                $upn = ConvertTo-TrimmedString (Get-PropertyValue $user 'userPrincipalName' '')
                if ($objectId) {
                    $lookupMap[$identity] = New-ResolvedUser -Identity $identity -ObjectId $objectId -ResolvedUpn $upn
                    continue
                }
            }
            elseif ($direct.Status -notin 0, 404) {
                $detail = Get-GraphErrorMessageFromBody $direct.Body
                if (-not $detail) { $detail = ConvertTo-TrimmedString $direct.Error }
                if (-not $detail) { $detail = "Graph user lookup failed with HTTP $($direct.Status)" }
                $lookupMap[$identity] = New-ResolvedUser -Identity $identity -ErrorText $detail
                continue
            }
        }

        $filterUri = '{0}{1}' -f (Get-RuntimeGraphBase), (Get-UserFilterRelativeUrl $identity)
        $resp = Invoke-GraphWebRequest -Method GET -Uri $filterUri -Token $Token
        if ($resp.Status -eq 200) {
            $user = Read-UserFromGraphBody $resp.Body
            if ($user -eq 'AMBIGUOUS') {
                $lookupMap[$identity] = New-ResolvedUser -Identity $identity -ErrorText "Multiple Entra users matched '$identity'"
                continue
            }
            $objectId = ConvertTo-TrimmedString (Get-PropertyValue $user 'id' '')
            $upn = ConvertTo-TrimmedString (Get-PropertyValue $user 'userPrincipalName' '')
            if ($objectId) {
                $lookupMap[$identity] = New-ResolvedUser -Identity $identity -ObjectId $objectId -ResolvedUpn $upn
                continue
            }
        }
        $detail = Get-GraphErrorMessageFromBody $resp.Body
        if (-not $detail) { $detail = ConvertTo-TrimmedString $resp.Error }
        if (-not $detail) { $detail = "User not found: $identity" }
        $lookupMap[$identity] = New-ResolvedUser -Identity $identity -ErrorText $detail
    }

    $toAdd = New-Object System.Collections.ArrayList
    $seenIds = @{}
    foreach ($identity in $idList) {
        $key = [string]$identity
        $item = $null
        if ($lookupMap.ContainsKey($key)) { $item = $lookupMap[$key] }
        if (-not $item -or -not $item.Found) {
            $detail = ''
            if ($item) { $detail = ConvertTo-TrimmedString $item.ErrorText }
            if (-not $detail) { $detail = "User not found: $key" }
            [void]$results.Add((New-UserResult -UserPrincipalName $key -Status 'Failed' -Detail $detail))
            continue
        }
        $objectId = ConvertTo-TrimmedString $item.ObjectId
        $upn = ConvertTo-TrimmedString $item.ResolvedUpn
        if ($existing.ContainsKey($objectId) -or $seenIds.ContainsKey($objectId)) {
            [void]$results.Add((New-UserResult -UserPrincipalName $key -Status 'Skipped' -Detail 'Already a member' -ObjectId $objectId -ResolvedUpn $upn))
            continue
        }
        $seenIds[$objectId] = $true
        [void]$toAdd.Add($item)
    }

    if ($toAdd.Count -eq 0) {
        return ,$results.ToArray()
    }

    $ids = New-Object System.Collections.ArrayList
    foreach ($member in $toAdd) {
        [void]$ids.Add([string]$member.ObjectId)
    }

    $patchUri = '{0}/groups/{1}' -f (Get-RuntimeGraphBase), $GroupId
    $patchBody = Get-BindMembersJson -DirectoryObjectIds ([string[]]@($ids.ToArray()))
    $patchResp = Invoke-GraphWebRequest -Method PATCH -Uri $patchUri -Token $Token -Body $patchBody
    if ($patchResp.Status -in 200, 204) {
        foreach ($member in $toAdd) {
            [void]$results.Add((New-UserResult -UserPrincipalName $member.Identity -Status 'Added' -ObjectId $member.ObjectId -ResolvedUpn $member.ResolvedUpn))
        }
        return ,$results.ToArray()
    }

    $patchDetail = Get-GraphErrorMessageFromBody $patchResp.Body
    if (-not $patchDetail) { $patchDetail = ConvertTo-TrimmedString $patchResp.Error }
    if ($toAdd.Count -eq 1 -and (Test-IsAlreadyMemberText $patchDetail)) {
        $member = $toAdd[0]
        [void]$results.Add((New-UserResult -UserPrincipalName $member.Identity -Status 'Skipped' -Detail 'Already a member' -ObjectId $member.ObjectId -ResolvedUpn $member.ResolvedUpn))
        return ,$results.ToArray()
    }

    foreach ($member in $toAdd) {
        $refUri = Get-AddMemberUri -TargetGroupId $GroupId
        $refBody = Get-AddMemberJsonBody -DirectoryObjectId $member.ObjectId
        $refResp = Invoke-GraphWebRequest -Method POST -Uri $refUri -Token $Token -Body $refBody
        $refDetail = Get-GraphErrorMessageFromBody $refResp.Body
        if (-not $refDetail) { $refDetail = ConvertTo-TrimmedString $refResp.Error }
        if ($refResp.Status -in 200, 204) {
            [void]$results.Add((New-UserResult -UserPrincipalName $member.Identity -Status 'Added' -ObjectId $member.ObjectId -ResolvedUpn $member.ResolvedUpn))
        }
        elseif (Test-IsAlreadyMemberText $refDetail) {
            [void]$results.Add((New-UserResult -UserPrincipalName $member.Identity -Status 'Skipped' -Detail 'Already a member' -ObjectId $member.ObjectId -ResolvedUpn $member.ResolvedUpn))
        }
        else {
            if (-not $refDetail) { $refDetail = "Graph add-member failed with HTTP $($refResp.Status)" }
            [void]$results.Add((New-UserResult -UserPrincipalName $member.Identity -Status 'Failed' -Detail $refDetail -ObjectId $member.ObjectId -ResolvedUpn $member.ResolvedUpn))
        }
    }

    return ,$results.ToArray()
}

function Get-UserChunkWorkerFunctionNames {
    return @(
        'ConvertTo-TrimmedString',
        'Get-PropertyValue',
        'ConvertTo-ODataLiteral',
        'ConvertTo-JsonString',
        'Get-ErrorText',
        'New-StringList',
        'Get-HttpStatusFromError',
        'Get-GraphErrorMessageFromBody',
        'Test-IsAlreadyMemberText',
        'Get-BatchItemStatus',
        'Read-UserFromGraphBody',
        'New-ResolvedUser',
        'New-UserResult',
        'Get-RuntimeGraphBase',
        'Get-RuntimeUserSelect',
        'Get-GroupMemberODataId',
        'Get-AddMemberUri',
        'Get-AddMemberJsonBody',
        'Get-BindMembersJson',
        'Get-UserLookupRelativeUrl',
        'Get-UserFilterRelativeUrl',
        'New-GraphBatchItem',
        'Get-GraphBatchJson',
        'Invoke-GraphWebRequest',
        'Invoke-UserChunkWork'
    )
}

function Get-UserChunkWorkerScriptBlock {
    # Embed this file's functions inside one scriptblock so parallel workers
    # do not depend on extra .ps1 files, modules, or InitialSessionState copies.
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('param($ChunkIdentities, $Token, $GraphBase, $UserSelect, $GroupId, $ExistingIds)')
    [void]$sb.AppendLine('Set-StrictMode -Version 2.0')
    [void]$sb.AppendLine('$ErrorActionPreference = ''Stop''')
    [void]$sb.AppendLine('$script:GraphBase = $GraphBase')
    [void]$sb.AppendLine('$script:UserSelect = $UserSelect')
    [void]$sb.AppendLine('$global:GraphBase = $GraphBase')
    [void]$sb.AppendLine('$global:UserSelect = $UserSelect')
    [void]$sb.AppendLine('try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }')
    foreach ($name in (Get-UserChunkWorkerFunctionNames)) {
        $cmd = Get-Command -Name $name -CommandType Function -ErrorAction Stop
        [void]$sb.Append('function ')
        [void]$sb.Append($name)
        [void]$sb.AppendLine(' {')
        [void]$sb.AppendLine($cmd.Definition)
        [void]$sb.AppendLine('}')
    }
    [void]$sb.AppendLine('try {')
    [void]$sb.AppendLine('    Invoke-UserChunkWork -Identities $ChunkIdentities -Token $Token -GroupId $GroupId -ExistingIds $ExistingIds')
    [void]$sb.AppendLine('} catch {')
    [void]$sb.AppendLine('    $msg = $_.Exception.Message')
    [void]$sb.AppendLine('    $out = New-Object System.Collections.ArrayList')
    [void]$sb.AppendLine('    foreach ($id in @($ChunkIdentities)) {')
    [void]$sb.AppendLine('        [void]$out.Add((New-UserResult -UserPrincipalName ([string]$id) -Status ''Failed'' -Detail $msg))')
    [void]$sb.AppendLine('    }')
    [void]$sb.AppendLine('    return ,$out.ToArray()')
    [void]$sb.AppendLine('}')
    return [scriptblock]::Create($sb.ToString())
}

function Invoke-UserChunkWorkLocal {
    param(
        $Identities,
        [string]$Token,
        [string]$GroupId,
        $ExistingIds
    )
    Invoke-UserChunkWork -Identities $Identities -Token $Token -GroupId $GroupId -ExistingIds $ExistingIds
}

function Invoke-GraphSdkGet {
    param([string]$Uri)
    try {
        $resp = Invoke-GraphWithRetry -ScriptBlock { Invoke-MgGraphRequest -Method GET -Uri $Uri }
        return [pscustomobject]@{ Status = 200; Body = $resp; Error = '' }
    }
    catch {
        $status = Get-HttpStatusFromError $_
        if ($status -eq 0 -and (Test-IsNotFoundError $_)) { $status = 404 }
        return [pscustomobject]@{ Status = $status; Body = $null; Error = (Get-ErrorText $_) }
    }
}

function Invoke-GraphSdkSend {
    param([string]$Method, [string]$Uri, $Body)
    try {
        Invoke-GraphWithRetry -ScriptBlock { Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $Body } | Out-Null
        return [pscustomobject]@{ Status = 204; Body = $null; Error = '' }
    }
    catch {
        return [pscustomobject]@{
            Status = (Get-HttpStatusFromError $_)
            Body   = $null
            Error  = (Get-ErrorText $_)
        }
    }
}

function Get-BindMembersHashtable {
    param($DirectoryObjectIds)
    $ids = New-Object System.Collections.ArrayList
    foreach ($id in @($DirectoryObjectIds)) {
        $oid = ConvertTo-TrimmedString $id
        if ($oid) { [void]$ids.Add((Get-GroupMemberODataId $oid)) }
    }
    $map = @{}
    $map['members@odata.bind'] = $ids.ToArray()
    return $map
}

function Invoke-SequentialSdkAdds {
    param(
        $Identities,
        [string]$GroupId,
        $ExistingIds,
        [int]$Size = 20
    )
    if ($Size -lt 1) { $Size = 1 }
    if ($Size -gt 20) { $Size = 20 }

    $existing = @{}
    foreach ($id in @($ExistingIds)) {
        $mid = ConvertTo-TrimmedString $id
        if ($mid) { $existing[$mid] = $true }
    }

    $rows = New-Object System.Collections.ArrayList
    $chunks = Get-ListChunks -Items $Identities -Size $Size
    $total = @($Identities).Count
    $started = Get-Date
    $done = 0
    $select = Get-RuntimeUserSelect
    $base = Get-RuntimeGraphBase

    foreach ($chunk in $chunks) {
        $toAdd = New-Object System.Collections.ArrayList
        $seenIds = @{}
        foreach ($raw in @($chunk)) {
            $identity = [string]$raw
            $encoded = [uri]::EscapeDataString($identity)
            $directUri = '{0}/users/{1}?$select={2}' -f $base, $encoded, $select
            $resp = Invoke-GraphSdkGet -Uri $directUri
            $user = $null
            if ($resp.Status -eq 200) {
                $user = Read-UserFromGraphBody $resp.Body
            }
            elseif ($resp.Status -in 0, 404) {
                $filterUri = '{0}{1}' -f $base, (Get-UserFilterRelativeUrl $identity)
                $filterResp = Invoke-GraphSdkGet -Uri $filterUri
                if ($filterResp.Status -eq 200) {
                    $user = Read-UserFromGraphBody $filterResp.Body
                    if ($user -eq 'AMBIGUOUS') {
                        [void]$rows.Add((New-UserResult -UserPrincipalName $identity -Status 'Failed' -Detail "Multiple Entra users matched '$identity'"))
                        continue
                    }
                }
                else {
                    $detail = ConvertTo-TrimmedString $filterResp.Error
                    if (-not $detail) { $detail = "User not found: $identity" }
                    [void]$rows.Add((New-UserResult -UserPrincipalName $identity -Status 'Failed' -Detail $detail))
                    continue
                }
            }
            else {
                $detail = ConvertTo-TrimmedString $resp.Error
                if (-not $detail) { $detail = "Graph user lookup failed with HTTP $($resp.Status)" }
                [void]$rows.Add((New-UserResult -UserPrincipalName $identity -Status 'Failed' -Detail $detail))
                continue
            }

            $objectId = ConvertTo-TrimmedString (Get-PropertyValue $user 'id' '')
            $upn = ConvertTo-TrimmedString (Get-PropertyValue $user 'userPrincipalName' '')
            if (-not $objectId) {
                [void]$rows.Add((New-UserResult -UserPrincipalName $identity -Status 'Failed' -Detail "User not found: $identity"))
                continue
            }
            if ($existing.ContainsKey($objectId) -or $seenIds.ContainsKey($objectId)) {
                [void]$rows.Add((New-UserResult -UserPrincipalName $identity -Status 'Skipped' -Detail 'Already a member' -ObjectId $objectId -ResolvedUpn $upn))
                continue
            }
            $seenIds[$objectId] = $true
            [void]$toAdd.Add((New-ResolvedUser -Identity $identity -ObjectId $objectId -ResolvedUpn $upn))
        }

        if ($toAdd.Count -gt 0) {
            $ids = New-Object System.Collections.ArrayList
            foreach ($member in $toAdd) { [void]$ids.Add([string]$member.ObjectId) }
            $patchUri = '{0}/groups/{1}' -f $base, $GroupId
            $patchResp = Invoke-GraphSdkSend -Method PATCH -Uri $patchUri -Body (Get-BindMembersHashtable -DirectoryObjectIds $ids)
            if (($patchResp.Status -in 200, 204, 0) -and -not $patchResp.Error) {
                foreach ($member in $toAdd) {
                    $existing[$member.ObjectId] = $true
                    [void]$rows.Add((New-UserResult -UserPrincipalName $member.Identity -Status 'Added' -ObjectId $member.ObjectId -ResolvedUpn $member.ResolvedUpn))
                }
            }
            elseif ($toAdd.Count -eq 1 -and (Test-IsAlreadyMemberText $patchResp.Error)) {
                $member = $toAdd[0]
                $existing[$member.ObjectId] = $true
                [void]$rows.Add((New-UserResult -UserPrincipalName $member.Identity -Status 'Skipped' -Detail 'Already a member' -ObjectId $member.ObjectId -ResolvedUpn $member.ResolvedUpn))
            }
            else {
                foreach ($member in $toAdd) {
                    $refUri = Get-AddMemberUri -TargetGroupId $GroupId
                    $refBody = @{}
                    $refBody['@odata.id'] = Get-GroupMemberODataId $member.ObjectId
                    $refResp = Invoke-GraphSdkSend -Method POST -Uri $refUri -Body $refBody
                    if (($refResp.Status -in 200, 204, 0) -and -not $refResp.Error) {
                        $existing[$member.ObjectId] = $true
                        [void]$rows.Add((New-UserResult -UserPrincipalName $member.Identity -Status 'Added' -ObjectId $member.ObjectId -ResolvedUpn $member.ResolvedUpn))
                    }
                    elseif (Test-IsAlreadyMemberText $refResp.Error) {
                        $existing[$member.ObjectId] = $true
                        [void]$rows.Add((New-UserResult -UserPrincipalName $member.Identity -Status 'Skipped' -Detail 'Already a member' -ObjectId $member.ObjectId -ResolvedUpn $member.ResolvedUpn))
                    }
                    else {
                        $detail = ConvertTo-TrimmedString $refResp.Error
                        if (-not $detail) { $detail = ConvertTo-TrimmedString $patchResp.Error }
                        if (-not $detail) { $detail = "Graph add-member failed with HTTP $($refResp.Status)" }
                        [void]$rows.Add((New-UserResult -UserPrincipalName $member.Identity -Status 'Failed' -Detail $detail -ObjectId $member.ObjectId -ResolvedUpn $member.ResolvedUpn))
                    }
                }
            }
        }

        $done += @($chunk).Count
        Write-Progress -Activity "Adding users to $GroupName" -Status (Get-RateStatus -Done $done -Total $total -Started $started -Verb 'Processed') -PercentComplete (Get-PercentComplete -Current $done -Total $total)
        Write-Host (Get-RateStatus -Done $done -Total $total -Started $started -Verb 'Processed') -ForegroundColor DarkGray
    }

    Write-Progress -Activity "Adding users to $GroupName" -Completed
    return ,$rows
}

function Invoke-ParallelUserAdds {
    param(
        $Identities,
        [string]$Token,
        [string]$GroupId,
        $ExistingIds,
        [int]$Size = 20,
        [int]$Throttle = 6
    )
    if ($Size -lt 1) { $Size = 1 }
    if ($Size -gt 20) { $Size = 20 }
    if ($Throttle -lt 1) { $Throttle = 1 }

    $chunks = Get-ListChunks -Items $Identities -Size $Size
    $total = @($Identities).Count
    $started = Get-Date
    $existingIdArray = ConvertTo-StringArray $ExistingIds
    $graphBase = Get-RuntimeGraphBase
    $userSelect = Get-RuntimeUserSelect

    function Add-ChunkOutput {
        param($Target, $Output)
        foreach ($row in @($Output)) {
            if ($row) { [void]$Target.Add($row) }
        }
    }

    $rows = New-Object System.Collections.ArrayList
    $doneUsers = 0
    $doneChunks = 0
    $chunkCount = @($chunks).Count

    $worker = $null
    $pool = $null
    $useRunspaces = $Throttle -gt 1
    if ($useRunspaces) {
        try {
            $worker = Get-UserChunkWorkerScriptBlock
            $pool = [runspacefactory]::CreateRunspacePool(1, $Throttle)
            try { $pool.ApartmentState = [System.Threading.ApartmentState]::MTA } catch { }
            $pool.Open()
        }
        catch {
            Write-Host ("Parallel runspaces unavailable ({0}); staying in this script and processing batches one at a time." -f $_.Exception.Message) -ForegroundColor Yellow
            $useRunspaces = $false
            if ($pool) {
                try { $pool.Dispose() } catch { }
                $pool = $null
            }
        }
    }

    if (-not $useRunspaces) {
        foreach ($chunk in $chunks) {
            $chunkIds = ConvertTo-StringArray $chunk
            $output = Invoke-UserChunkWorkLocal -Identities $chunkIds -Token $Token -GroupId $GroupId -ExistingIds $existingIdArray
            Add-ChunkOutput -Target $rows -Output $output
            $doneChunks++
            $doneUsers += $chunkIds.Count
            Write-Progress -Activity "Adding users to $GroupName" -Status (Get-RateStatus -Done $doneUsers -Total $total -Started $started -Verb 'Processed') -PercentComplete (Get-PercentComplete -Current $doneUsers -Total $total)
            if ($doneChunks -eq 1 -or ($doneChunks % 5) -eq 0 -or $doneChunks -eq $chunkCount) {
                Write-Host (Get-RateStatus -Done $doneUsers -Total $total -Started $started -Verb 'Processed') -ForegroundColor DarkGray
            }
        }
        Write-Progress -Activity "Adding users to $GroupName" -Completed
        return ,$rows
    }

    $jobs = New-Object System.Collections.ArrayList
    try {
        foreach ($chunk in $chunks) {
            $chunkIds = ConvertTo-StringArray $chunk
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($worker)
            [void]$ps.AddArgument($chunkIds)
            [void]$ps.AddArgument($Token)
            [void]$ps.AddArgument($graphBase)
            [void]$ps.AddArgument($userSelect)
            [void]$ps.AddArgument($GroupId)
            [void]$ps.AddArgument($existingIdArray)
            $handle = $ps.BeginInvoke()
            [void]$jobs.Add([pscustomobject]@{
                    PowerShell = $ps
                    Handle     = $handle
                    Size       = $chunkIds.Count
                })
        }

        $pending = New-Object System.Collections.ArrayList
        foreach ($job in $jobs) { [void]$pending.Add($job) }

        while ($pending.Count -gt 0) {
            Start-Sleep -Milliseconds 200
            $still = New-Object System.Collections.ArrayList
            foreach ($job in $pending) {
                if (-not $job.Handle.IsCompleted) {
                    [void]$still.Add($job)
                    continue
                }

                $output = $null
                try {
                    $output = $job.PowerShell.EndInvoke($job.Handle)
                }
                catch {
                    Write-Host ("A parallel batch failed: {0}" -f (Get-ErrorText $_)) -ForegroundColor Yellow
                }

                try {
                    if ($job.PowerShell.HadErrors) {
                        $msgs = New-Object System.Collections.ArrayList
                        foreach ($err in @($job.PowerShell.Streams.Error)) {
                            [void]$msgs.Add((Get-ErrorText $err))
                        }
                        if ($msgs.Count -gt 0) {
                            Write-Host ("A parallel batch reported errors: {0}" -f ($msgs -join ' | ')) -ForegroundColor Yellow
                        }
                    }
                } catch { }

                Add-ChunkOutput -Target $rows -Output $output
                try { $job.PowerShell.Dispose() } catch { }
                $doneChunks++
                $doneUsers += [int]$job.Size
                Write-Progress -Activity "Adding users to $GroupName" -Status (Get-RateStatus -Done $doneUsers -Total $total -Started $started -Verb 'Processed') -PercentComplete (Get-PercentComplete -Current $doneUsers -Total $total)
                if ($doneChunks -eq 1 -or ($doneChunks % 5) -eq 0 -or $doneChunks -eq $jobs.Count) {
                    Write-Host (Get-RateStatus -Done $doneUsers -Total $total -Started $started -Verb 'Processed') -ForegroundColor DarkGray
                }
            }
            $pending = $still
        }

        Write-Progress -Activity "Adding users to $GroupName" -Completed
        return ,$rows
    }
    finally {
        foreach ($job in $jobs) {
            try { $job.PowerShell.Dispose() } catch { }
        }
        if ($pool) {
            try { $pool.Close() } catch { }
            try { $pool.Dispose() } catch { }
        }
    }
}

# ---------------------------------------------------------------------------
# Self-test (no Graph / no WinForms dialogs)
# ---------------------------------------------------------------------------

function Invoke-SelfTest {
    function Assert-True {
        param([bool]$Condition, [string]$Name)
        if ($Condition) {
            $script:SelfTestPassed++
            Write-Host "  PASS  $Name" -ForegroundColor Green
        }
        else {
            $script:SelfTestFailed++
            Write-Host "  FAIL  $Name" -ForegroundColor Red
        }
    }

    $script:SelfTestPassed = 0
    $script:SelfTestFailed = 0

    Write-Host ''
    Write-Host 'Add-MfaSmsUsers self-test' -ForegroundColor Cyan
    Write-Host ''

    $parseErrors = $null
    $tokens = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$tokens, [ref]$parseErrors)
    Assert-True -Condition ($parseErrors.Count -eq 0) -Name 'Script AST parses with no errors'

    $requiresGraph = $false
    foreach ($token in @($tokens)) {
        if ($token.Kind.ToString() -eq 'Comment' -and $token.Text -match '(?im)^#Requires\s+-Modules\s+Microsoft\.Graph') {
            $requiresGraph = $true
            break
        }
    }
    Assert-True -Condition (-not $requiresGraph) -Name '#Requires -Modules Microsoft.Graph is omitted so -SelfTest runs without the SDK'

    Assert-True -Condition ((ConvertTo-ODataLiteral -Value "O'Brien@contoso.com") -eq "O''Brien@contoso.com") -Name 'OData literals double single quotes'
    Assert-True -Condition ((Get-PercentComplete -Current 1 -Total 0) -eq 0) -Name 'PercentComplete is 0 when the total is 0'
    Assert-True -Condition ((Get-PercentComplete -Current 3 -Total 3) -eq 100) -Name 'PercentComplete reaches 100 on the last item'
    Assert-True -Condition (Test-IsGuid 'cf5c24b8-2289-4311-8b80-e43e6df8455d') -Name 'Default MFA-SMS_Users group ID is a GUID'
    Assert-True -Condition (-not (Test-IsGuid 'not-a-guid')) -Name 'Non-GUID strings are rejected'

    $odata = Get-GroupMemberODataId '11111111-2222-3333-4444-555555555555'
    Assert-True -Condition ($odata -eq 'https://graph.microsoft.com/v1.0/directoryObjects/11111111-2222-3333-4444-555555555555') -Name 'Member $ref body uses directoryObjects/{id}'
    $addUri = Get-AddMemberUri 'cf5c24b8-2289-4311-8b80-e43e6df8455d'
    Assert-True -Condition ($addUri -eq 'https://graph.microsoft.com/v1.0/groups/cf5c24b8-2289-4311-8b80-e43e6df8455d/members/$ref') -Name 'Add-member URI is POST /groups/{id}/members/$ref'
    $json = Get-AddMemberJsonBody '11111111-2222-3333-4444-555555555555'
    Assert-True -Condition ($json -eq '{"@odata.id":"https://graph.microsoft.com/v1.0/directoryObjects/11111111-2222-3333-4444-555555555555"}') -Name 'Add-member JSON body is an @odata.id reference'

    $users = ConvertTo-UserIdentityList @(
        '# comment',
        '',
        '  alice@contoso.com  ',
        'ALICE@contoso.com',
        'mailto:bob@contoso.com',
        '"carol@contoso.com"',
        'dave@contoso.com,Dave D',
        "eve@contoso.com`tEve",
        'UPN',
        'frank@contoso.com'
    )
    Assert-True -Condition ($users.Count -eq 6 -and $users[0] -eq 'alice@contoso.com' -and $users.Contains('bob@contoso.com') -and $users.Contains('carol@contoso.com') -and $users.Contains('dave@contoso.com') -and $users.Contains('eve@contoso.com') -and $users.Contains('frank@contoso.com')) -Name 'User list strips comments, duplicates, mailto:, quotes, and extra columns'

    $emptyUsers = ConvertTo-UserIdentityList @('# only comments', '', '   ')
    Assert-True -Condition ($emptyUsers.Count -eq 0) -Name 'Empty user lists stay empty collections (not $null)'

    $one = ConvertTo-UserIdentityList @('only@contoso.com')
    $oneCount = 0
    foreach ($identity in $one) { $oneCount++ }
    Assert-True -Condition ($one.Count -eq 1 -and $oneCount -eq 1 -and $one[0] -eq 'only@contoso.com') -Name 'A one-user list is not enumerated as individual characters'

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('mfa-sms-users-' + [guid]::NewGuid().ToString('N') + '.txt')
    $utf8Bom = New-Object System.Text.UTF8Encoding $true
    [IO.File]::WriteAllText($tmp, "# header`r`njohn.doe@contoso.com`r`n`r`njane.doe@contoso.com`r`n", $utf8Bom)
    try {
        $fromFile = Read-UserListFile -Path $tmp
        Assert-True -Condition ($fromFile.Count -eq 2 -and $fromFile[0] -eq 'john.doe@contoso.com') -Name 'UTF-8 BOM text files parse without a junk first character'
    }
    finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }

    $onPrem = @{
        onPremisesSyncEnabled = $true
        groupTypes            = @()
        membershipRule        = $null
    }
    $dynamic = @{
        onPremisesSyncEnabled         = $false
        groupTypes                    = @('DynamicMembership')
        membershipRule                = 'user.accountEnabled -eq true'
        membershipRuleProcessingState = 'On'
    }
    $cloud = @{
        onPremisesSyncEnabled = $false
        groupTypes            = @()
        displayName           = 'MFA-SMS_Users'
    }
    $onPremBlockers = Get-GroupMembershipBlockers $onPrem
    $dynamicBlockers = Get-GroupMembershipBlockers $dynamic
    $cloudBlockers = Get-GroupMembershipBlockers $cloud
    Assert-True -Condition ($onPremBlockers.Count -eq 1) -Name 'On-premises-synced groups are blocked'
    Assert-True -Condition ($dynamicBlockers.Count -eq 1 -and $dynamicBlockers[0] -like '*dynamic*') -Name 'Dynamic groups are blocked'
    Assert-True -Condition ($cloudBlockers.Count -eq 0) -Name 'Cloud assigned groups are allowed'

    $already = New-Object System.Management.Automation.ErrorRecord (
        (New-Object System.InvalidOperationException "One or more added object references already exist for the following modified properties: 'members'."),
        'AlreadyExists',
        [System.Management.Automation.ErrorCategory]::ResourceExists,
        $null
    )
    Assert-True -Condition (Test-IsAlreadyMemberError $already) -Name 'Graph already-exists is treated as Skipped'

    $missing = New-Object System.Management.Automation.ErrorRecord (
        (New-Object System.Exception 'Response status code does not indicate success: 404 (Not Found).'),
        'NotFound',
        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
        $null
    )
    Assert-True -Condition (Test-IsNotFoundError $missing) -Name '404 is treated as user not found'
    Assert-True -Condition ((Get-HttpStatusFromError $missing) -eq 404) -Name 'HTTP 404 is parsed from the exception message'

    $throttled = New-Object System.Management.Automation.ErrorRecord (
        (New-Object System.Exception 'Response status code does not indicate success: 429 (Too Many Requests).'),
        'Throttled',
        [System.Management.Automation.ErrorCategory]::ResourceBusy,
        $null
    )
    Assert-True -Condition ((Get-HttpStatusFromError $throttled) -eq 429) -Name 'HTTP 429 is parsed from the exception message'
    Assert-True -Condition (Test-IsTransientGraphError $throttled) -Name '429 is retried as a transient Graph error'

    $ctx = [pscustomobject]@{ Scopes = @('https://graph.microsoft.com/User.Read.All', 'GroupMember.ReadWrite.All') }
    Assert-True -Condition (-not (Test-HasGraphScopes -Context $ctx -Required $script:RequiredScopes)) -Name 'Existing Graph session missing Group.Read.All is not reused'
    $full = [pscustomobject]@{ Scopes = @('GroupMember.ReadWrite.All', 'User.Read.All', 'Group.Read.All') }
    Assert-True -Condition (Test-HasGraphScopes -Context $full -Required $script:RequiredScopes) -Name 'Existing Graph session with all three scopes is reused'

    $row = New-UserResult -UserPrincipalName 'a@x.com' -Status 'Added' -ResolvedUpn 'a@x.com' -ObjectId 'abc'
    Assert-True -Condition ($row.Status -eq 'Added' -and $row.UserPrincipalName -eq 'a@x.com') -Name 'Result rows include Status and the original identity'

    $log = Get-ResultLogPath -SourcePath $tmp -Prefix 'MFA-SMS_Users'
    Assert-True -Condition ($log -like '*MFA-SMS_Users_Results_*.csv') -Name 'Result log name matches MFA-SMS_Users_Results_<timestamp>.csv'

    $fortyFive = 1..45
    $chunks = Get-ListChunks -Items $fortyFive -Size 20
    Assert-True -Condition ($chunks.Count -eq 3 -and $chunks[0].Count -eq 20 -and $chunks[1].Count -eq 20 -and $chunks[2].Count -eq 5) -Name 'Lists split into Graph-sized chunks of 20'
    $oneChunk = Get-ListChunks -Items @(1) -Size 20
    Assert-True -Condition ($oneChunk.Count -eq 1 -and $oneChunk[0].Count -eq 1) -Name 'A single item still returns one chunk collection'

    $bindOne = Get-BindMembersJson -DirectoryObjectIds @('11111111-2222-3333-4444-555555555555')
    Assert-True -Condition ($bindOne -eq '{"members@odata.bind":["https://graph.microsoft.com/v1.0/directoryObjects/11111111-2222-3333-4444-555555555555"]}') -Name 'Single-member PATCH body stays a JSON array (PowerShell 5.1 ConvertTo-Json would unwrap it)'
    $bindTwo = Get-BindMembersJson -DirectoryObjectIds @('11111111-2222-3333-4444-555555555555', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
    Assert-True -Condition ($bindTwo -like '*directoryObjects/11111111-2222-3333-4444-555555555555*directoryObjects/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee*') -Name 'PATCH body can bind 20 members via members@odata.bind'

    $lookupUrl = Get-UserLookupRelativeUrl 'jane.doe@contoso.com'
    Assert-True -Condition ($lookupUrl -eq '/users/jane.doe%40contoso.com?$select=id,userPrincipalName,displayName,mail') -Name 'Batch lookup URLs encode @ and keep $select literal'

    $batchJson = Get-GraphBatchJson @(
        (New-GraphBatchItem -Id '1' -Method 'GET' -Url $lookupUrl),
        (New-GraphBatchItem -Id '2' -Method 'PATCH' -Url '/groups/cf5c24b8-2289-4311-8b80-e43e6df8455d' -Headers @{ 'Content-Type' = 'application/json' } -BodyJson $bindOne)
    )
    Assert-True -Condition ($batchJson -like '*"url":"/users/jane.doe%40contoso.com?$select=id,userPrincipalName,displayName,mail"*') -Name 'JSON $batch keeps relative URLs and $select'
    Assert-True -Condition ($batchJson -match '"body":\{"members@odata.bind":\[') -Name 'JSON $batch embeds PATCH bind body as an object, not a string'
    Assert-True -Condition ((Get-ListChunks -Items (1..400) -Size 20).Count -eq 20) -Name '400 members become 20 parallel batches of 20'

    $previewLines = Get-UserPreviewLines -Users (1..20 | ForEach-Object { "user$_@contoso.com" })
    Assert-True -Condition ($previewLines.Count -eq 16 -and $previewLines[15] -like '*and 5 more*') -Name 'Large lists preview the first names instead of printing thousands of lines'
    Assert-True -Condition (-not $Preview) -Name '-Preview is not clobbered by preview line output (PowerShell variables are case-insensitive)'

    $emptyStrings = New-StringList
    [void]$emptyStrings.Add('one')
    Assert-True -Condition ($emptyStrings.Count -eq 1 -and $emptyStrings[0] -eq 'one') -Name 'Empty generic lists are returned as collections, not $null'

    $map = New-IgnoreCaseMap
    $map['Alice@Contoso.com'] = 'ok'
    Assert-True -Condition ($map.ContainsKey('alice@contoso.com') -and $map['ALICE@CONTOSO.COM'] -eq 'ok') -Name 'Ignore-case map is a PowerShell hashtable (Windows PowerShell 5.1 safe)'
    $src = [IO.File]::ReadAllText($PSCommandPath)
    Assert-True -Condition ($src -notmatch '\[System\.Collections\.Generic\.Dictionary') -Name 'Script does not construct a two-parameter generic dictionary'
    Assert-True -Condition ($src -notmatch 'param\(\[System\.Collections\.Generic\.IList') -Name 'JSON batch helper Items parameter is untyped for Windows PowerShell 5.1'
    Assert-True -Condition ($src -notmatch 'New-Object System\.Collections\.Generic\.List\[') -Name 'Generic lists are created with ::new(), not unquoted New-Object'
    Assert-True -Condition (Test-IsAlreadyMemberText "One or more added object references already exist for the following modified properties: 'members'.") -Name 'Batch 400 already-exists text is classified as Skipped'
    Assert-True -Condition ($src -notmatch '(?m)^function Invoke-GraphJsonBatch') -Name 'Live path no longer uses Invoke-MgGraphRequest JSON $batch'
    Assert-True -Condition ($src -notmatch 'Runspaces\.SessionStateFunctionEntry') -Name 'Single-file script does not copy helpers into a separate InitialSessionState'
    Assert-True -Condition ($src -match 'Get-UserChunkWorkerScriptBlock' -and $src -match 'Invoke-WebRequest') -Name 'Parallel workers are built from this same .ps1'

    $sampleJwt = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.abcdefghijklmnopqrstuv'
    $tokenObj = [pscustomobject]@{ AuthContext = [pscustomobject]@{ LastAuthResult = [pscustomobject]@{ AccessToken = $sampleJwt } } }
    Assert-True -Condition ((Get-TokenFromObject $tokenObj) -eq $sampleJwt) -Name 'Graph access token is read from nested AuthContext.LastAuthResult'
    $tokenStruct = [pscustomobject]@{ Token = $sampleJwt; ExpiresOn = [datetime]::UtcNow }
    Assert-True -Condition ((ConvertTo-PlainToken $tokenStruct) -eq $sampleJwt) -Name 'Azure.Core AccessToken-shaped objects unwrap .Token'
    Assert-True -Condition ((Get-JwtFromCacheText ('prefix ' + $sampleJwt + ' suffix')) -eq $sampleJwt) -Name 'MSAL cache blobs yield the JWT'
    Assert-True -Condition ((Get-GraphAccessToken) -eq '') -Name 'Get-GraphAccessToken returns empty without a Graph session instead of throwing'
    $bindHash = Get-BindMembersHashtable -DirectoryObjectIds @('11111111-2222-3333-4444-555555555555')
    Assert-True -Condition (@($bindHash['members@odata.bind']).Count -eq 1) -Name 'SDK fallback PATCH body keeps members@odata.bind as an array'
    $ids = ConvertTo-StringArray @('aaa', '', 'bbb', $null)
    Assert-True -Condition ($ids.Count -eq 2 -and $ids[0] -eq 'aaa' -and $ids[1] -eq 'bbb') -Name 'Existing member ids convert to a string array without empty entries'
    $tenChunks = Get-ListChunks -Items (1..25) -Size 10
    Assert-True -Condition ($tenChunks.Count -eq 3 -and $tenChunks[0].Count -eq 10 -and $tenChunks[2].Count -eq 5) -Name 'Lists split into parallel batches of 10'

    $worker = Get-UserChunkWorkerScriptBlock
    $emptyLocal = @(& $worker ([string[]]@()) 'token' $script:GraphBase $script:UserSelect '11111111-2222-3333-4444-555555555555' ([string[]]@()))
    Assert-True -Condition ($emptyLocal.Count -eq 0) -Name 'Chunk worker runs inside this same .ps1 with no extra files'

    $pool = $null
    $ps = $null
    try {
        $pool = [runspacefactory]::CreateRunspacePool(1, 1)
        $pool.Open()
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($worker)
        [void]$ps.AddArgument([string[]]@())
        [void]$ps.AddArgument('token')
        [void]$ps.AddArgument($script:GraphBase)
        [void]$ps.AddArgument($script:UserSelect)
        [void]$ps.AddArgument('11111111-2222-3333-4444-555555555555')
        [void]$ps.AddArgument([string[]]@())
        $emptyRemote = @($ps.Invoke())
        Assert-True -Condition ($emptyRemote.Count -eq 0) -Name 'Self-contained worker scriptblock runs in a default runspace pool'
    }
    catch {
        Assert-True -Condition $false -Name ('Self-contained worker scriptblock runs in a default runspace pool: ' + $_.Exception.Message)
    }
    finally {
        if ($ps) { try { $ps.Dispose() } catch { } }
        if ($pool) {
            try { $pool.Close() } catch { }
            try { $pool.Dispose() } catch { }
        }
    }

    Write-Host ''
    Write-Host ('  {0} passed, {1} failed' -f $script:SelfTestPassed, $script:SelfTestFailed) -ForegroundColor $(if ($script:SelfTestFailed) { 'Red' } else { 'Green' })
    return ($script:SelfTestFailed -eq 0)
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

function Invoke-AddMfaSmsUsers {
    Write-Host ("Add-MfaSmsUsers v{0}" -f $script:ToolVersion) -ForegroundColor DarkGray

    if (-not (Test-IsGuid $GroupId)) {
        throw "GroupId '$GroupId' is not a valid GUID."
    }

    if ($NonInteractive -and -not $UserListPath) {
        throw '-NonInteractive requires -UserListPath.'
    }

    $path = ConvertTo-TrimmedString $UserListPath
    if (-not $path) {
        if ($NonInteractive) { throw '-NonInteractive requires -UserListPath.' }
        Initialize-WinForms
        while (-not $path) {
            $path = Select-UserListFile
            if (-not $path) {
                $retry = Show-Message -Text 'No file selected. Do you want to choose a file again?' -Buttons ([System.Windows.Forms.MessageBoxButtons]::YesNo) -Icon ([System.Windows.Forms.MessageBoxIcon]::Question)
                if ($retry -ne [System.Windows.Forms.DialogResult]::Yes) {
                    Write-Host 'Cancelled by user.' -ForegroundColor Yellow
                    return
                }
            }
        }
    }

    Write-Host "Selected file: $path" -ForegroundColor Cyan

    $users = Read-UserListFile -Path $path
    if ($users.Count -eq 0) {
        $msg = "The selected file doesn't contain any users."
        Write-Host $msg -ForegroundColor Yellow
        if (-not $NonInteractive) {
            try { Show-Message -Text $msg -Icon ([System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null } catch { }
        }
        return
    }

    Write-Host ''
    Write-Host ("Found {0} user(s):" -f $users.Count) -ForegroundColor Cyan
    # Do not assign $preview — PowerShell is case-insensitive, so that would
    # overwrite the -Preview switch and skip Graph entirely.
    $previewLines = Get-UserPreviewLines -Users $users
    foreach ($line in $previewLines) { Write-Host $line }
    Write-Host ''

    if ($Preview) {
        Write-Host 'Preview only; not connecting to Microsoft Graph.' -ForegroundColor Yellow
        return
    }

    if (-not (Confirm-UserList -Count $users.Count -Path $path)) {
        Write-Host 'Cancelled by user.' -ForegroundColor Yellow
        return
    }

    Connect-MfaSmsGraph

    $group = Get-TargetGroup -TargetGroupId $GroupId
    $display = ConvertTo-TrimmedString (Get-PropertyValue $group 'displayName' $GroupName)
    Write-Host "Target group: $display ($GroupId)" -ForegroundColor Cyan
    if ($display -and $GroupName -and ($display -ne $GroupName)) {
        Write-Host "Warning: group display name is '$display', expected '$GroupName'." -ForegroundColor Yellow
    }

    $blockers = Get-GroupMembershipBlockers $group
    if ($blockers.Count -gt 0) {
        throw ($blockers -join ' ')
    }

    $roleAssignable = Get-PropertyValue $group 'isAssignableToRole' $false
    if ($roleAssignable -eq $true -or "$roleAssignable" -eq 'True') {
        Write-Host 'Warning: this group is role-assignable. Privileged Role Administrator may be required.' -ForegroundColor Yellow
    }

    $existingMembers = $null
    try {
        $existingMembers = Get-ExistingMemberIdSet -TargetGroupId $GroupId
        Write-Host ("Loaded {0} existing member(s)." -f $existingMembers.Count) -ForegroundColor DarkGray
    }
    catch {
        Write-Host ("Could not preload members (will treat Graph already-exists as Skipped): {0}" -f (Get-ErrorText $_)) -ForegroundColor Yellow
        $existingMembers = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    }

    $started = Get-Date
    $token = Get-GraphAccessToken
    $existingIds = ConvertTo-StringArray $existingMembers
    if ($token) {
        Write-Host ("Processing {0} user(s) with {1} parallel workers, {2} users per batch..." -f $users.Count, $ThrottleLimit, $BatchSize) -ForegroundColor Cyan
        $outcomeRows = Invoke-ParallelUserAdds -Identities $users -Token $token -GroupId $GroupId -ExistingIds $existingIds -Size $BatchSize -Throttle $ThrottleLimit
    }
    else {
        Write-Host ("Could not copy a bearer token from Microsoft.Graph.Authentication (normal on current SDK versions). Processing {0} user(s) in this script with Graph batches of {1}..." -f $users.Count, $BatchSize) -ForegroundColor Yellow
        $outcomeRows = Invoke-SequentialSdkAdds -Identities $users -GroupId $GroupId -ExistingIds $existingIds -Size $BatchSize
    }

    $outcomeMap = New-IgnoreCaseMap
    foreach ($row in @($outcomeRows)) {
        $identity = ConvertTo-TrimmedString (Get-PropertyValue $row 'UserPrincipalName' '')
        if (-not $identity) { continue }
        $outcomeMap[$identity] = $row
        if ((Get-PropertyValue $row 'Status' '') -eq 'Failed') {
            $detail = ConvertTo-TrimmedString (Get-PropertyValue $row 'Detail' '')
            Write-Host ("[FAIL]  {0} - {1}" -f $identity, $detail) -ForegroundColor Red
        }
    }

    $results = New-ObjectList
    foreach ($upn in $users) {
        $identity = [string]$upn
        if ($outcomeMap.ContainsKey($identity)) {
            [void]$results.Add($outcomeMap[$identity])
        }
        else {
            [void]$results.Add((New-UserResult -UserPrincipalName $identity -Status 'Failed' -Detail 'No result recorded'))
        }
    }

    $logPath = Get-ResultLogPath -SourcePath $path -Prefix 'MFA-SMS_Users'
    $results | Export-Csv -Path $logPath -NoTypeInformation -Encoding UTF8

    $added = @($results | Where-Object { $_.Status -eq 'Added' }).Count
    $skipped = @($results | Where-Object { $_.Status -eq 'Skipped' }).Count
    $failed = @($results | Where-Object { $_.Status -eq 'Failed' }).Count

    $elapsed = (Get-Date) - $started
    $summary = "Added:   $added`nSkipped: $skipped`nFailed:  $failed`nElapsed: {0:N1}s`n`nLog saved to:`n$logPath" -f $elapsed.TotalSeconds
    Write-Host ''
    Write-Host $summary

    if (-not $NonInteractive) {
        try {
            $icon = [System.Windows.Forms.MessageBoxIcon]::Information
            if ($failed -gt 0) { $icon = [System.Windows.Forms.MessageBoxIcon]::Warning }
            Show-Message -Text $summary -Title "$GroupName - Complete" -Icon $icon | Out-Null
        } catch { }
    }

    $showGrid = -not $SkipGridView -and -not $NonInteractive
    if ($showGrid -and $results.Count -gt 250) {
        Write-Host 'Skipping Out-GridView for a large result set; open the CSV log instead.' -ForegroundColor DarkGray
        $showGrid = $false
    }
    if ($showGrid) {
        try {
            $results | Out-GridView -Title "$GroupName - Results (close this window to finish)" -Wait
        }
        catch {
            Write-Host 'Out-GridView is not available in this host; results are in the CSV log.' -ForegroundColor DarkGray
        }
    }
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if ($SelfTest) {
    $ok = Invoke-SelfTest
    if ($ok) { exit 0 } else { exit 1 }
}

try {
    Invoke-AddMfaSmsUsers
}
catch {
    $text = Get-ErrorText $_
    $where = ''
    try {
        $line = Get-PropertyValue $_.InvocationInfo 'ScriptLineNumber' $null
        if ($line) { $where = " (line $line)" }
    } catch { }
    Write-Host "ERROR: $text$where" -ForegroundColor Red
    try {
        $stack = ConvertTo-TrimmedString $_.ScriptStackTrace
        if ($stack) { Write-Host $stack -ForegroundColor DarkGray }
    } catch { }
    if (-not $NonInteractive) {
        try {
            Initialize-WinForms
            Show-Message -Text "An error occurred:`r`n`r`n$text$where" -Icon ([System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        } catch { }
    }
    exit 1
}
finally {
    if ($script:ConnectedToGraph) {
        Disconnect-MfaSmsGraph
    }
    if (-not $SelfTest -and -not $NonInteractive) {
        try { Read-Host 'Press Enter to exit' | Out-Null } catch { }
    }
}
