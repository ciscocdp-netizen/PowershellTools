#Requires -Version 5.1
<#
.SYNOPSIS
    Interactively adds users from a TXT file to the Entra ID group "MFA-SMS_Users".

.DESCRIPTION
    - Opens a file picker to choose a .txt file (one UPN/email per line)
    - Shows the users found and asks for confirmation
    - Skips users who are already members
    - Shows a results window and saves a CSV log next to the input file

    Fixes versus the original paste:
      - Membership is added with Graph JSON $batch and PATCH members@odata.bind
        (Invoke-MgGraphRequest), not New-MgGroupMember -DirectoryObjectId, which is
        broken or missing in several Graph SDK versions.
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
      - Large lists (~5000) use Graph JSON $batch (20 lookups per HTTP call) and
        PATCH members@odata.bind (20 members per PATCH, up to 20 PATCHes per $batch
        = 400 adds per HTTP call). Failed PATCHes fall back to per-user POST $ref
        in a batch so one bad row does not fail the other 19.

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
    Graph JSON $batch / members@odata.bind size (1-20). Default 20. Lower this
    only if the tenant throttles aggressively.

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
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ToolVersion = '1.4'
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

function Get-GroupMemberODataId {
    param([string]$DirectoryObjectId)
    return ('{0}/directoryObjects/{1}' -f $script:GraphBase, (ConvertTo-TrimmedString $DirectoryObjectId))
}

function Get-AddMemberUri {
    param([string]$TargetGroupId)
    return ('{0}/groups/{1}/members/$ref' -f $script:GraphBase, (ConvertTo-TrimmedString $TargetGroupId))
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
    $chunks = New-ObjectList
    $current = New-ObjectList
    foreach ($item in @($Items)) {
        [void]$current.Add($item)
        if ($current.Count -ge $Size) {
            [void]$chunks.Add($current)
            $current = New-ObjectList
        }
    }
    if ($current.Count -gt 0) { [void]$chunks.Add($current) }
    return ,$chunks
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
    return ('/users/{0}?$select={1}' -f $encoded, $script:UserSelect)
}

function Get-UserFilterRelativeUrl {
    param([string]$Identity)
    $literal = ConvertTo-ODataLiteral $Identity
    $filter = "userPrincipalName eq '$literal' or mail eq '$literal'"
    return ('/users?$filter={0}&$select={1}' -f [uri]::EscapeDataString($filter), $script:UserSelect)
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
        $prompt = $prompt + "`r`n`r`nUses Graph batches (20 lookups / up to 400 adds per request), typically a few minutes for thousands of users."
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

function Resolve-EntraUser {
    param([Parameter(Mandatory)][string]$Identity)

    $id = ConvertTo-TrimmedString $Identity
    if (-not $id) { throw 'User identity is empty.' }

    $select = 'id,userPrincipalName,displayName,mail'
    $encoded = [uri]::EscapeDataString($id)
    try {
        $directUri = '{0}/users/{1}?$select={2}' -f $script:GraphBase, $encoded, $select
        return Invoke-GraphWithRetry -ScriptBlock { Invoke-MgGraphRequest -Method GET -Uri $directUri }
    }
    catch {
        if (-not (Test-IsNotFoundError $_)) { throw }
    }

    $literal = ConvertTo-ODataLiteral $id
    foreach ($filter in @(
            "userPrincipalName eq '$literal'",
            "mail eq '$literal'"
        )) {
        $filterUri = '{0}/users?$filter={1}&$select={2}' -f $script:GraphBase, [uri]::EscapeDataString($filter), $select
        $resp = Invoke-GraphWithRetry -ScriptBlock { Invoke-MgGraphRequest -Method GET -Uri $filterUri }
        $values = @((Get-PropertyValue $resp 'value' @()))
        if ($values.Count -eq 1) { return $values[0] }
        if ($values.Count -gt 1) { throw "Multiple Entra users matched '$id'." }
    }

    throw "User not found: $id"
}

function Add-EntraGroupMember {
    param(
        [Parameter(Mandatory)][string]$TargetGroupId,
        [Parameter(Mandatory)][string]$DirectoryObjectId
    )
    $uri = Get-AddMemberUri -TargetGroupId $TargetGroupId
    $body = Get-AddMemberJsonBody -DirectoryObjectId $DirectoryObjectId
    Invoke-GraphWithRetry -ScriptBlock {
        Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType 'application/json'
    } | Out-Null
}

function Invoke-GraphJsonBatch {
    # Keep -Items untyped. A generic list parameter type throws
    # "Argument types do not match" on Windows PowerShell 5.1.
    param($Items)

    $byId = @{}
    if ($null -eq $Items -or $Items.Count -eq 0) { return $byId }
    if ($Items.Count -gt $script:GraphBatchMax) {
        throw ("JSON batch cannot exceed {0} requests (got {1})." -f $script:GraphBatchMax, $Items.Count)
    }

    $pending = New-ObjectList
    foreach ($item in $Items) { [void]$pending.Add($item) }

    $attempt = 0
    while ($pending.Count -gt 0) {
        $attempt++
        $json = Get-GraphBatchJson -Requests $pending
        $uri = '{0}/$batch' -f $script:GraphBase
        $resp = Invoke-GraphWithRetry -ScriptBlock {
            Invoke-MgGraphRequest -Method POST -Uri $uri -Body $json -ContentType 'application/json'
        }

        $returned = @{}
        foreach ($item in @((Get-PropertyValue $resp 'responses' @()))) {
            $id = [string](Get-PropertyValue $item 'id' '')
            if ($id) { $returned[$id] = $item }
        }

        $retry = New-ObjectList
        $wait = 0
        foreach ($item in $pending) {
            $id = [string](Get-PropertyValue $item 'Id' '')
            if (-not $returned.ContainsKey($id)) {
                [void]$retry.Add($item)
                continue
            }
            $row = $returned[$id]
            $status = Get-BatchItemStatus $row
            if ($status -in 429, 503, 504) {
                [void]$retry.Add($item)
                $headers = Get-PropertyValue $row 'headers' $null
                if ($headers) {
                    foreach ($key in @('Retry-After', 'retry-after', 'RetryAfter')) {
                        $headerVal = Get-PropertyValue $headers $key $null
                        if ($headerVal) {
                            $n = 0
                            if ([int]::TryParse((ConvertTo-TrimmedString $headerVal), [ref]$n) -and $n -gt $wait) { $wait = $n }
                        }
                    }
                }
                continue
            }
            $byId[$id] = $row
        }

        if ($retry.Count -eq 0) { break }
        if ($attempt -ge 5) {
            foreach ($item in $retry) {
                $id = [string](Get-PropertyValue $item 'Id' '')
                if ($id -and -not $byId.ContainsKey($id) -and $returned.ContainsKey($id)) {
                    $byId[$id] = $returned[$id]
                }
            }
            break
        }
        if ($wait -lt 1) { $wait = [Math]::Min(60, [int][Math]::Pow(2, $attempt)) }
        Write-Host ("Graph batch throttled ({0} request(s)); retrying in {1} s..." -f $retry.Count, $wait) -ForegroundColor Yellow
        Start-Sleep -Seconds $wait
        $pending = $retry
    }

    return $byId
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

function Resolve-EntraUsersBatched {
    param(
        $Identities,
        [int]$Size = 20
    )
    if ($Size -lt 1) { $Size = 1 }
    if ($Size -gt $script:GraphBatchMax) { $Size = $script:GraphBatchMax }

    $map = New-IgnoreCaseMap
    $needFilter = New-StringList
    $chunks = Get-ListChunks -Items $Identities -Size $Size
    $done = 0
    $total = $Identities.Count
    $started = Get-Date

    foreach ($chunk in $chunks) {
        $batch = New-ObjectList
        for ($i = 0; $i -lt $chunk.Count; $i++) {
            $identity = [string]$chunk[$i]
            [void]$batch.Add((New-GraphBatchItem -Id ([string]($i + 1)) -Method 'GET' -Url (Get-UserLookupRelativeUrl $identity)))
        }

        $responses = Invoke-GraphJsonBatch -Items $batch
        for ($i = 0; $i -lt $chunk.Count; $i++) {
            $identity = [string]$chunk[$i]
            $id = [string]($i + 1)
            if (-not $responses.ContainsKey($id)) {
                $map[$identity] = New-ResolvedUser -Identity $identity -ErrorText 'No Graph batch response for user lookup'
                continue
            }
            $row = $responses[$id]
            $status = Get-BatchItemStatus $row
            $body = Get-PropertyValue $row 'body' $null
            if ($status -eq 200) {
                $user = Read-UserFromGraphBody $body
                $objectId = ConvertTo-TrimmedString (Get-PropertyValue $user 'id' '')
                $upn = ConvertTo-TrimmedString (Get-PropertyValue $user 'userPrincipalName' '')
                if ($objectId) {
                    $map[$identity] = New-ResolvedUser -Identity $identity -ObjectId $objectId -ResolvedUpn $upn
                }
                else {
                    $map[$identity] = New-ResolvedUser -Identity $identity -ErrorText 'Graph returned a user without an id'
                }
            }
            elseif ($status -eq 404) {
                [void]$needFilter.Add($identity)
            }
            else {
                $map[$identity] = New-ResolvedUser -Identity $identity -ErrorText (Get-GraphErrorMessageFromBody $body)
            }
        }

        $done += $chunk.Count
        Write-Progress -Activity "Resolving users in Microsoft Graph" -Status (Get-RateStatus -Done $done -Total $total -Started $started -Verb 'Looked up') -PercentComplete (Get-PercentComplete -Current $done -Total $total)
    }

    $filterChunks = Get-ListChunks -Items $needFilter -Size $Size
    foreach ($chunk in $filterChunks) {
        $batch = New-ObjectList
        for ($i = 0; $i -lt $chunk.Count; $i++) {
            $identity = [string]$chunk[$i]
            [void]$batch.Add((New-GraphBatchItem -Id ([string]($i + 1)) -Method 'GET' -Url (Get-UserFilterRelativeUrl $identity)))
        }
        $responses = Invoke-GraphJsonBatch -Items $batch
        for ($i = 0; $i -lt $chunk.Count; $i++) {
            $identity = [string]$chunk[$i]
            $id = [string]($i + 1)
            if (-not $responses.ContainsKey($id)) {
                $map[$identity] = New-ResolvedUser -Identity $identity -ErrorText 'User not found'
                continue
            }
            $row = $responses[$id]
            $status = Get-BatchItemStatus $row
            $body = Get-PropertyValue $row 'body' $null
            if ($status -ne 200) {
                $detail = Get-GraphErrorMessageFromBody $body
                if (-not $detail) { $detail = "User not found: $identity" }
                $map[$identity] = New-ResolvedUser -Identity $identity -ErrorText $detail
                continue
            }
            $user = Read-UserFromGraphBody $body
            if ($user -eq 'AMBIGUOUS') {
                $map[$identity] = New-ResolvedUser -Identity $identity -ErrorText "Multiple Entra users matched '$identity'"
                continue
            }
            $objectId = ConvertTo-TrimmedString (Get-PropertyValue $user 'id' '')
            $upn = ConvertTo-TrimmedString (Get-PropertyValue $user 'userPrincipalName' '')
            if ($objectId) {
                $map[$identity] = New-ResolvedUser -Identity $identity -ObjectId $objectId -ResolvedUpn $upn
            }
            else {
                $map[$identity] = New-ResolvedUser -Identity $identity -ErrorText "User not found: $identity"
            }
        }
    }

    Write-Progress -Activity "Resolving users in Microsoft Graph" -Completed
    return $map
}

function Set-IdentityOutcome {
    param(
        $OutcomeMap,
        $Members,
        [string]$Status,
        [string]$Detail = ''
    )
    foreach ($member in @($Members)) {
        $identity = [string](Get-PropertyValue $member 'Identity' '')
        if (-not $identity) { continue }
        $objectId = ConvertTo-TrimmedString (Get-PropertyValue $member 'ObjectId' '')
        $upn = ConvertTo-TrimmedString (Get-PropertyValue $member 'ResolvedUpn' '')
        $OutcomeMap[$identity] = New-UserResult -UserPrincipalName $identity -Status $Status -Detail $Detail -ObjectId $objectId -ResolvedUpn $upn
    }
}

function Add-EntraGroupMembersBatched {
    param(
        [string]$TargetGroupId,
        $Members,
        $ExistingMembers,
        $OutcomeMap,
        [int]$Size = 20
    )
    if ($Size -lt 1) { $Size = 1 }
    if ($Size -gt $script:GraphBatchMax) { $Size = $script:GraphBatchMax }

    $pending = New-ObjectList
    $seenIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($member in @($Members)) {
        $identity = [string](Get-PropertyValue $member 'Identity' '')
        $objectId = ConvertTo-TrimmedString (Get-PropertyValue $member 'ObjectId' '')
        if (-not $identity -or -not $objectId) { continue }
        if ($ExistingMembers.Contains($objectId) -or -not $seenIds.Add($objectId)) {
            Set-IdentityOutcome -OutcomeMap $OutcomeMap -Members @($member) -Status 'Skipped' -Detail 'Already a member'
            continue
        }
        [void]$pending.Add($member)
    }

    $bindChunks = Get-ListChunks -Items $pending -Size $Size
    $httpChunks = Get-ListChunks -Items $bindChunks -Size $script:GraphBatchMax
    $done = 0
    $total = $pending.Count
    $started = Get-Date

    foreach ($httpChunk in $httpChunks) {
        $batch = New-ObjectList
        $chunkById = @{}
        for ($i = 0; $i -lt $httpChunk.Count; $i++) {
            $bindChunk = $httpChunk[$i]
            $id = [string]($i + 1)
            $chunkById[$id] = $bindChunk
            $ids = New-StringList
            foreach ($member in $bindChunk) { [void]$ids.Add([string](Get-PropertyValue $member 'ObjectId' '')) }
            [void]$batch.Add((New-GraphBatchItem -Id $id -Method 'PATCH' -Url ('/groups/{0}' -f $TargetGroupId) -Headers @{ 'Content-Type' = 'application/json' } -BodyJson (Get-BindMembersJson -DirectoryObjectIds $ids)))
        }

        $responses = Invoke-GraphJsonBatch -Items $batch
        $fallback = New-ObjectList
        foreach ($id in ($chunkById.Keys | Sort-Object)) {
            $bindChunk = $chunkById[$id]
            if (-not $responses.ContainsKey($id)) {
                foreach ($member in $bindChunk) { [void]$fallback.Add($member) }
                continue
            }
            $row = $responses[$id]
            $status = Get-BatchItemStatus $row
            if ($status -in 200, 204) {
                foreach ($member in $bindChunk) {
                    $objectId = ConvertTo-TrimmedString (Get-PropertyValue $member 'ObjectId' '')
                    if ($objectId) { [void]$ExistingMembers.Add($objectId) }
                }
                Set-IdentityOutcome -OutcomeMap $OutcomeMap -Members $bindChunk -Status 'Added'
                $done += $bindChunk.Count
            }
            elseif ($bindChunk.Count -eq 1 -and (Test-IsAlreadyMemberText (Get-GraphErrorMessageFromBody (Get-PropertyValue $row 'body' $null)))) {
                $objectId = ConvertTo-TrimmedString (Get-PropertyValue $bindChunk[0] 'ObjectId' '')
                if ($objectId) { [void]$ExistingMembers.Add($objectId) }
                Set-IdentityOutcome -OutcomeMap $OutcomeMap -Members $bindChunk -Status 'Skipped' -Detail 'Already a member'
                $done += 1
            }
            else {
                foreach ($member in $bindChunk) { [void]$fallback.Add($member) }
            }
        }

        if ($fallback.Count -gt 0) {
            $refChunks = Get-ListChunks -Items $fallback -Size $script:GraphBatchMax
            foreach ($refChunk in $refChunks) {
                $refBatch = New-ObjectList
                for ($i = 0; $i -lt $refChunk.Count; $i++) {
                    $member = $refChunk[$i]
                    $objectId = ConvertTo-TrimmedString (Get-PropertyValue $member 'ObjectId' '')
                    [void]$refBatch.Add((New-GraphBatchItem -Id ([string]($i + 1)) -Method 'POST' -Url ('/groups/{0}/members/$ref' -f $TargetGroupId) -Headers @{ 'Content-Type' = 'application/json' } -BodyJson (Get-AddMemberJsonBody -DirectoryObjectId $objectId)))
                }
                $refResponses = Invoke-GraphJsonBatch -Items $refBatch
                for ($i = 0; $i -lt $refChunk.Count; $i++) {
                    $member = $refChunk[$i]
                    $rid = [string]($i + 1)
                    $objectId = ConvertTo-TrimmedString (Get-PropertyValue $member 'ObjectId' '')
                    if (-not $refResponses.ContainsKey($rid)) {
                        Set-IdentityOutcome -OutcomeMap $OutcomeMap -Members @($member) -Status 'Failed' -Detail 'No Graph batch response for add-member'
                        $done += 1
                        continue
                    }
                    $row = $refResponses[$rid]
                    $status = Get-BatchItemStatus $row
                    $detail = Get-GraphErrorMessageFromBody (Get-PropertyValue $row 'body' $null)
                    if ($status -in 200, 204) {
                        if ($objectId) { [void]$ExistingMembers.Add($objectId) }
                        Set-IdentityOutcome -OutcomeMap $OutcomeMap -Members @($member) -Status 'Added'
                    }
                    elseif (Test-IsAlreadyMemberText $detail) {
                        if ($objectId) { [void]$ExistingMembers.Add($objectId) }
                        Set-IdentityOutcome -OutcomeMap $OutcomeMap -Members @($member) -Status 'Skipped' -Detail 'Already a member'
                    }
                    else {
                        if (-not $detail) { $detail = "Graph add-member failed with HTTP $status" }
                        Set-IdentityOutcome -OutcomeMap $OutcomeMap -Members @($member) -Status 'Failed' -Detail $detail
                        Write-Host ("[FAIL]  {0} - {1}" -f (Get-PropertyValue $member 'Identity' ''), $detail) -ForegroundColor Red
                    }
                    $done += 1
                }
            }
        }

        Write-Progress -Activity "Adding users to $GroupName" -Status (Get-RateStatus -Done $done -Total $total -Started $started -Verb 'Added') -PercentComplete (Get-PercentComplete -Current $done -Total $total)
        if ($total -gt 0) {
            Write-Host (Get-RateStatus -Done $done -Total $total -Started $started -Verb 'Added') -ForegroundColor DarkGray
        }
    }

    Write-Progress -Activity "Adding users to $GroupName" -Completed
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
    Assert-True -Condition ((Get-ListChunks -Items (1..400) -Size 20).Count -eq 20) -Name '400 members become 20 PATCH operations (one Graph $batch HTTP call)'

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
    Write-Host ("Resolving {0} user(s) with Graph JSON batches of {1}..." -f $users.Count, $BatchSize) -ForegroundColor Cyan
    $resolved = Resolve-EntraUsersBatched -Identities $users -Size $BatchSize

    $toAdd = New-ObjectList
    $outcomeMap = New-IgnoreCaseMap
    foreach ($upn in $users) {
        $identity = [string]$upn
        if (-not $resolved.ContainsKey($identity)) {
            $outcomeMap[$identity] = New-UserResult -UserPrincipalName $identity -Status 'Failed' -Detail 'User lookup returned no result'
            Write-Host "[FAIL]  $identity - User lookup returned no result" -ForegroundColor Red
            continue
        }
        $item = $resolved[$identity]
        if (-not $item.Found) {
            $detail = ConvertTo-TrimmedString $item.ErrorText
            if (-not $detail) { $detail = "User not found: $identity" }
            $outcomeMap[$identity] = New-UserResult -UserPrincipalName $identity -Status 'Failed' -Detail $detail
            Write-Host "[FAIL]  $identity - $detail" -ForegroundColor Red
            continue
        }
        [void]$toAdd.Add($item)
    }

    $lookupFailed = $users.Count - $toAdd.Count
    Write-Host ("Lookup complete: {0} resolved, {1} not found (~{2} Graph HTTP calls)." -f $toAdd.Count, $lookupFailed, [int][Math]::Ceiling($users.Count / [double]$BatchSize)) -ForegroundColor DarkGray
    Write-Host ("Adding {0} resolved user(s); up to {1} members per PATCH, {2} PATCHes per HTTP call..." -f $toAdd.Count, $BatchSize, $script:GraphBatchMax) -ForegroundColor Cyan
    Add-EntraGroupMembersBatched -TargetGroupId $GroupId -Members $toAdd -ExistingMembers $existingMembers -OutcomeMap $outcomeMap -Size $BatchSize

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
