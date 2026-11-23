<#
.SYNOPSIS
    Mailbox Recovery Console - a Windows Forms GUI for finding, previewing and restoring
    items held in a user's Recoverable Items (Deletions, Purges, DiscoveryHolds) or Deleted Items.

.DESCRIPTION
    Windows PowerShell 5.1 GUI (no external DLLs). Exchange Online lists and restores items.
    Sign in opens the normal Microsoft window for Exchange Online and the Microsoft Graph
    PowerShell module. Remote work runs on one reused background runspace.

.PARAMETER SelfTest
    Run the built-in logic checks and exit. No mailbox is contacted and no window is opened.

.NOTES
    Run:  powershell.exe -STA -ExecutionPolicy Bypass -File .\MailboxRecoveryConsole.ps1
    Test: powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\MailboxRecoveryConsole.ps1 -SelfTest
#>
#Requires -Version 5.1
[CmdletBinding()]
param([switch]$SelfTest)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

$script:AppName    = 'Mailbox Recovery Console'
$script:AppVersion = '1.2.3'

#region ---------- Shared helpers (also loaded into the worker runspace) ----------
$script:SharedFunctions = {
    function global:ConvertTo-Base64Url {
        param([byte[]]$Bytes)
        return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }

    function global:Convert-EntryIdFormats {
        param([string]$EntryID)
        $raw = if ($EntryID) { $EntryID.Trim() } else { '' }
        $info = New-Object psobject -Property @{
            Input  = $raw
            Kind   = 'Unknown'
            Hex    = ''
            RestId = ''
            EwsId  = ''
        }
        if (-not $raw) { return $info }
        $compact = $raw -replace '\s', ''
        if ($compact -match '^[0-9A-Fa-f]+$' -and ($compact.Length % 2) -eq 0 -and $compact.Length -ge 2) {
            $bytes = New-Object byte[] ($compact.Length / 2)
            for ($i = 0; $i -lt $bytes.Length; $i++) {
                $bytes[$i] = [Convert]::ToByte($compact.Substring($i * 2, 2), 16)
            }
            $b64 = [Convert]::ToBase64String($bytes)
            $trimmed = $b64.TrimEnd('=')
            $info.Kind = 'Hex'
            $info.Hex = $compact.ToUpperInvariant()
            $info.EwsId = $b64
            $info.RestId = $trimmed.Replace('+', '-').Replace('/', '_') + [string]($b64.Length - $trimmed.Length)
            return $info
        }
        if ($compact -match '^[A-Za-z0-9+/]+=*$' -and $compact.Length -ge 8) {
            $info.Kind = 'Ews'
            $info.EwsId = $compact
            try {
                $pad = $compact
                switch ($pad.Length % 4) { 2 { $pad += '==' } 3 { $pad += '=' } }
                $bytes = [Convert]::FromBase64String($pad)
                $b64 = [Convert]::ToBase64String($bytes)
                $trimmed = $b64.TrimEnd('=')
                $info.RestId = $trimmed.Replace('+', '-').Replace('/', '_') + [string]($b64.Length - $trimmed.Length)
                $hex = New-Object System.Text.StringBuilder
                foreach ($b in $bytes) { [void]$hex.AppendFormat('{0:X2}', $b) }
                $info.Hex = $hex.ToString()
            } catch { }
            return $info
        }
        if ($compact -match '^[A-Za-z0-9_-]{8,}\d$') {
            $info.Kind = 'Rest'
            $info.RestId = $compact
        }
        return $info
    }

    function global:Get-ODataLiteral {
        param([string]$Value)
        if ($null -eq $Value) { $Value = '' }
        return "'" + $Value.Replace("'", "''") + "'"
    }

    function global:Escape-JsonString {
        param([string]$Text)
        $sb = New-Object System.Text.StringBuilder
        foreach ($ch in @($Text.ToCharArray())) {
            $code = [int]$ch
            if ($code -eq 34) { [void]$sb.Append('\"'); continue }
            if ($code -eq 92) { [void]$sb.Append('\\'); continue }
            if ($code -eq 8)  { [void]$sb.Append('\b'); continue }
            if ($code -eq 9)  { [void]$sb.Append('\t'); continue }
            if ($code -eq 10) { [void]$sb.Append('\n'); continue }
            if ($code -eq 12) { [void]$sb.Append('\f'); continue }
            if ($code -eq 13) { [void]$sb.Append('\r'); continue }
            if ($code -lt 32) { [void]$sb.AppendFormat('\u{0:x4}', $code); continue }
            [void]$sb.Append($ch)
        }
        return $sb.ToString()
    }

    function global:ConvertTo-JsonBody {
        param($Value, [int]$Depth = 0, $Box)
        # Arrays are passed inside a one-property object so Windows PowerShell does not unwrap them.
        if ($PSBoundParameters.ContainsKey('Box')) { $Value = $Box.Value }
        if ($Depth -gt 20) { throw 'The Graph request was too deep to encode.' }
        if ($null -eq $Value) { return 'null' }
        if ($Value -is [string]) { return '"' + (Escape-JsonString -Text $Value) + '"' }
        if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
        if ($Value -is [byte] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [single]) {
            return $Value.ToString([Globalization.CultureInfo]::InvariantCulture)
        }
        if ($Value -is [datetime]) { throw 'Date values are not sent in Graph JSON bodies.' }
        $dict = $Value -as [System.Collections.IDictionary]
        if ($dict) {
            $parts = New-Object System.Collections.Generic.List[string]
            foreach ($key in @($dict.Keys)) {
                $keyJson = ConvertTo-JsonBody -Box ([pscustomobject]@{ Value = [string]$key }) -Depth ($Depth + 1)
                $valJson = ConvertTo-JsonBody -Box ([pscustomobject]@{ Value = $dict[$key] }) -Depth ($Depth + 1)
                $parts.Add($keyJson + ':' + $valJson)
            }
            return '{' + ($parts -join ',') + '}'
        }
        $list = $Value -as [System.Collections.IEnumerable]
        if ($list) {
            $parts = New-Object System.Collections.Generic.List[string]
            foreach ($item in $list) { $parts.Add((ConvertTo-JsonBody -Box ([pscustomobject]@{ Value = $item }) -Depth ($Depth + 1))) }
            return '[' + ($parts -join ',') + ']'
        }
        throw "Cannot encode a $($Value.GetType().FullName) as JSON."
    }

    function global:ConvertTo-ExchangeFolderPath {
        param([string]$Path)
        if (-not $Path) { return '' }
        $parts = @($Path -split '[/\\]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        return ($parts -join '\')
    }

    function global:ConvertTo-GraphFolderPath {
        param([string]$Path)
        if (-not $Path) { return '' }
        $parts = @($Path -split '[/\\]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        return ($parts -join '/')
    }

    function global:ConvertTo-DisplayFolder {
        param([string]$Path)
        return (ConvertTo-GraphFolderPath $Path)
    }

    function global:Get-WellKnownFolderId {
        param([string]$Name)
        if (-not $Name) { return $null }
        switch ($Name.Trim().ToLowerInvariant()) {
            'inbox' { return 'inbox' }
            'sent items' { return 'sentitems' }
            'sent' { return 'sentitems' }
            'drafts' { return 'drafts' }
            'deleted items' { return 'deleteditems' }
            'junk email' { return 'junkemail' }
            'junk e-mail' { return 'junkemail' }
            'archive' { return 'archive' }
            'outbox' { return 'outbox' }
            'conversation history' { return 'conversationhistory' }
            'sync issues' { return 'syncissues' }
            default { return $null }
        }
    }

    function global:Test-FolderPathSafe {
        param([string]$Path)
        if (-not $Path) { return $false }
        if ($Path -match '[:*?"<>|]') { return $false }
        $parts = @($Path -split '[/\\]')
        foreach ($p in $parts) { if ($p.Trim()) { return $true } }
        return $false
    }

    function global:Get-AadErrorHint {
        param([string]$Message)
        if (-not $Message) { return '' }
        $rules = @(
            @{ Match = 'AADSTS65001'; Hint = 'Admin consent is required for the requested Microsoft Graph permissions.' }
            @{ Match = 'AADSTS65002|AADSTS70011|invalid_scope'; Hint = 'This application is not allowed the requested Graph scopes. Register your own public client with Mail.ReadWrite.Shared and device-code flow enabled.' }
            @{ Match = 'AADSTS700016'; Hint = 'The application ID was not found in this tenant.' }
            @{ Match = 'AADSTS7000215|invalid_client'; Hint = 'The client secret was rejected. Check that it is current and belongs to this application.' }
            @{ Match = 'AADSTS700027'; Hint = 'The certificate assertion was rejected. Check the thumbprint, private key, and the certificate registered on the app.' }
            @{ Match = 'AADSTS53003'; Hint = 'Conditional Access blocked this sign-in.' }
            @{ Match = 'AADSTS50076|AADSTS50079'; Hint = 'This account needs extra verification. Complete the interactive sign-in prompt.' }
            @{ Match = 'AADSTS50126'; Hint = 'The username or password was not accepted.' }
            @{ Match = 'AADSTS900144|AADSTS90014'; Hint = 'The token request was missing a required field. Check the tenant and application ID.' }
        )
        foreach ($rule in $rules) {
            if ($Message -match $rule.Match) { return $rule.Hint }
        }
        return ''
    }

    function global:Add-ErrorHint {
        param([string]$Message)
        $hint = Get-AadErrorHint $Message
        if ($hint -and $Message -notlike "*$hint*") { return "$Message $hint" }
        return $Message
    }

    function global:Get-GraphModuleEnvironment {
        param([string]$CloudKey)
        switch ($CloudKey) {
            'GCCHigh' { return 'USGov' }
            'DoD' { return 'USGovDoD' }
            'China' { return 'China' }
            default { return 'Global' }
        }
    }

    function global:Get-RetryAfterSeconds {
        param($Value, [int]$Default = 5, [int]$Max = 60)
        $text = [string]$Value
        if (-not $text) { return $Default }
        $n = 0
        if ([int]::TryParse($text, [ref]$n)) {
            if ($n -lt 1) { return 1 }
            if ($n -gt $Max) { return $Max }
            return $n
        }
        return $Default
    }

    function global:Protect-LogText {
        param([string]$Message)
        if ($null -eq $Message) { return '' }
        return (($Message -replace '[\r\n]+', ' | ') -replace '\s+', ' ').Trim()
    }

    function global:ConvertTo-CsvSafe {
        param([string]$Value)
        if ($null -eq $Value) { return '' }
        $text = [string]$Value
        if ($text -match '^[\s]*[=+\-@]') { return "'" + $text }
        return $text
    }

    function global:ConvertTo-PlainText {
        param([string]$Html)
        if (-not $Html) { return '' }
        $t = [regex]::Replace($Html, '(?is)<!--.*?-->', '')
        $t = [regex]::Replace($t, '(?is)<script\b[^>]*>.*?</script\s*>', '')
        $t = [regex]::Replace($t, '(?is)<style\b[^>]*>.*?</style\s*>', '')
        $t = [regex]::Replace($t, '(?i)<br\s*/?>', "`n")
        $t = [regex]::Replace($t, '(?i)</p\s*>', "`n`n")
        $t = [regex]::Replace($t, '(?i)</div\s*>', "`n")
        $t = [regex]::Replace($t, '(?is)<[^>]+>', '')
        try { $t = [System.Net.WebUtility]::HtmlDecode($t) } catch { }
        return $t.Trim()
    }

    function global:ConvertTo-SafeHtml {
        param([string]$Html, [bool]$AllowRemote)
        if (-not $Html) { return '' }
        $b = [regex]::Replace($Html, '(?is)<!--.*?-->', '')
        $b = [regex]::Replace($b, '(?is)<script\b[^>]*>.*?</script\s*>', '')
        $b = [regex]::Replace($b, '(?is)<script\b[^>]*>', '')
        $b = [regex]::Replace($b, '(?is)<style\b[^>]*>.*?</style\s*>', {
            param($m)
            if ($m.Value -match '(?i)expression\s*\(|javascript\s*:|behavior\s*:|@import') { return '' }
            return $m.Value
        })
        $b = [regex]::Replace($b, '(?is)<(iframe|object|embed|applet|form|base|link|meta|svg|math|frame|frameset)\b[^>]*>.*?</\1\s*>', '')
        $b = [regex]::Replace($b, '(?is)<(iframe|object|embed|applet|form|base|link|meta|svg|math|frame|frameset)\b[^>]*\/?>', '')
        $b = [regex]::Replace($b, '(?i)\s+on[a-z0-9]+\s*=\s*("[^"]*"|''[^'']*''|[^\s>]+)', '')
        $b = [regex]::Replace($b, '(?i)(href|src|action|formaction|poster)\s*=\s*(["'']?)\s*(javascript|vbscript|data)\s*:', '$1=$2#blocked:')
        $b = [regex]::Replace($b, '(?i)\s+srcset\s*=\s*("[^"]*"|''[^'']*''|[^\s>]+)', '')
        if (-not $AllowRemote) {
            $b = [regex]::Replace($b, '(?i)(<img\b[^>]*?)\ssrc\s*=\s*(["'']?)\s*https?:', '$1 data-blocked-src=$2http:')
            $b = [regex]::Replace($b, '(?i)url\(\s*([''"]?)\s*https?:', 'url($1#blocked:')
        }
        return $b
    }

    function global:New-PreviewDocument {
        param([string]$InnerHtml, [string]$BannerHtml = '')
        return "<!-- saved from url=(0014)about:internet -->`r`n" +
            '<!DOCTYPE html><html><head><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta charset="utf-8">' +
            '<style>body{font-family:Segoe UI,Arial,sans-serif;font-size:13px;margin:12px;color:#0f172a;word-wrap:break-word}img{max-width:100%}pre{white-space:pre-wrap;font-family:Segoe UI,Arial,sans-serif}</style>' +
            '</head><body>' + $BannerHtml + $InnerHtml + '</body></html>'
    }

    function global:Escape-GraphSegment {
        param([string]$Value)
        return [uri]::EscapeDataString([string]$Value)
    }

    function global:Get-JobParameterTable {
        param($Parameters)
        $clean = @{}
        if (-not $Parameters) { return $clean }
        foreach ($key in @($Parameters.Keys)) {
            if ($null -ne $Parameters[$key]) { $clean[$key] = $Parameters[$key] }
        }
        return $clean
    }
}

& $script:SharedFunctions

function Invoke-MrcSelfTest {
    $fails = New-Object System.Collections.Generic.List[string]
    $pass = 0
    function Add-Pass { $script:pass++; }
    # The nested function above cannot increment the local. Use the list and a counter object.
    $counter = New-Object psobject -Property @{ Pass = 0 }
    function Assert-True {
        param([string]$Name, $Condition)
        if ($Condition) { $script:TestCounter.Pass++ } else { $script:TestFails.Add($Name) }
    }
    function Assert-Equal {
        param([string]$Name, $Actual, $Expected)
        if ("$Actual" -eq "$Expected") { $script:TestCounter.Pass++ }
        else { $script:TestFails.Add("$Name expected [$Expected] actual [$Actual]") }
    }
    $script:TestFails = $fails
    $script:TestCounter = $counter

    $fmt = Convert-EntryIdFormats '00FF'
    Assert-Equal 'entry hex kind' $fmt.Kind 'Hex'
    Assert-Equal 'entry rest id' $fmt.RestId 'AP81'
    Assert-Equal 'entry ews id' $fmt.EwsId 'AP8='
    $spaced = Convert-EntryIdFormats '00 ff'
    Assert-Equal 'entry hex ignores spaces' $spaced.RestId 'AP81'

    Assert-Equal 'odata quote' (Get-ODataLiteral "O'Brien") "'O''Brien'"
    Assert-Equal 'exchange path' (ConvertTo-ExchangeFolderPath 'Inbox/Sub Folder/') 'Inbox\Sub Folder'
    Assert-Equal 'graph path' (ConvertTo-GraphFolderPath '\Inbox\Sub Folder\') 'Inbox/Sub Folder'
    Assert-Equal 'graph env commercial' (Get-GraphModuleEnvironment 'Commercial') 'Global'
    Assert-Equal 'graph env gcch' (Get-GraphModuleEnvironment 'GCCHigh') 'USGov'
    Assert-Equal 'graph env dod' (Get-GraphModuleEnvironment 'DoD') 'USGovDoD'
    Assert-Equal 'graph env china' (Get-GraphModuleEnvironment 'China') 'China'
    Assert-Equal 'well known inbox' (Get-WellKnownFolderId 'Inbox') 'inbox'
    Assert-True 'localized inbox is not aliased' (-not (Get-WellKnownFolderId 'Posteingang'))
    Assert-True 'folder path accepts inbox' (Test-FolderPathSafe 'Inbox/Recovered')
    Assert-True 'folder path rejects colon' (-not (Test-FolderPathSafe 'Inbox/Bad:Name'))

    $json = ConvertTo-JsonBody -Value @{ inputIds = @('abc'); sourceIdType = 'entryId' }
    Assert-True 'json keeps one-element array' ($json -match '"inputIds":\["abc"\]')
    $json2 = ConvertTo-JsonBody -Value @{ inputIds = @('a b', 'c"d') }
    Assert-True 'json keeps two-element array' ($json2 -match '"inputIds":\["a b","c\\"d"\]')
    $json3 = ConvertTo-JsonBody -Value ([ordered]@{ on = $false; n = 0 })
    Assert-Equal 'json false and zero' $json3 '{"on":false,"n":0}'

    $html = ConvertTo-SafeHtml '<div onclick="alert(1)"><!-- <script>hidden</script> --><script>bad()</script><a href="javascript:alert(1)">x</a><img src="https://evil/a.png"></div>' $false
    Assert-True 'html removes script' ($html -notmatch '<script')
    Assert-True 'html removes onclick' ($html -notmatch 'onclick')
    Assert-True 'html blocks javascript url' ($html -notmatch 'javascript:')
    Assert-True 'html blocks remote image' ($html -notmatch 'src\s*=\s*"https:')
    $open = ConvertTo-SafeHtml '<img src="https://cdn.example/a.png">' $true
    Assert-True 'html allows remote image when asked' ($open -match 'https://cdn\.example/a\.png')
    $plain = ConvertTo-PlainText "<p>Hello<br>there</p>"
    Assert-True 'plain text keeps words' ($plain -match 'Hello' -and $plain -match 'there' -and $plain -match "`n")

    $doc = New-PreviewDocument '<p>Body</p>'
    Assert-True 'preview document forces internet zone' ($doc.StartsWith('<!-- saved from url=(0014)about:internet -->'))
    Assert-True 'preview document keeps body' ($doc -match '<p>Body</p>')

    Assert-True 'aad consent hint' ((Get-AadErrorHint 'AADSTS65001 consent') -match 'Admin consent')
    Assert-Equal 'retry-after cap' (Get-RetryAfterSeconds 120) '60'
    Assert-Equal 'retry-after default' (Get-RetryAfterSeconds '') '5'
    Assert-Equal 'log flattens newlines' (Protect-LogText "one`r`ntwo") 'one | two'
    Assert-Equal 'csv formula guarded' (ConvertTo-CsvSafe '=cmd|/2') "'=cmd|/2"
    Assert-Equal 'csv plain kept' (ConvertTo-CsvSafe 'Invoice') 'Invoice'

    $bound = Get-JobParameterTable @{ A = 'x'; B = $null; C = $false; D = 0; E = '' }
    Assert-True 'null parameter removed' (-not $bound.ContainsKey('B'))
    Assert-True 'false parameter kept' ($bound.ContainsKey('C') -and $bound['C'] -eq $false)
    Assert-True 'zero parameter kept' ($bound.ContainsKey('D') -and $bound['D'] -eq 0)
    Assert-True 'empty string kept' ($bound.ContainsKey('E'))
    if ($script:WS_Search) {
        $searchText = $script:WS_Search.ToString()
        Assert-True 'search worker keeps param first' ($searchText -match '(?s)^\s*param\(')
        Assert-True 'search worker boots after param' ($searchText -match '(?s)param\(.*?\)\s*\$ErrorActionPreference\s*=\s*''Stop''')
        Assert-True 'blank subject uses a wide date range' ($searchText -match 'Get-Date -Year 1990')
        Assert-True 'asterisk subject is not a literal filter' ($searchText -match [regex]::Escape("-eq '*'"))
    }
    if ($script:WS_Init) {
        Assert-True 'init worker boots first' ($script:WS_Init.ToString() -match '(?s)^\s*\$ErrorActionPreference\s*=\s*''Stop''')
    }
    if ($script:WS_SignIn) {
        $signText = $script:WS_SignIn.ToString()
        Assert-True 'sign-in worker keeps param first' ($signText -match '(?s)^\s*param\(')
        Assert-True 'sign-in worker boots after param' ($signText -match '(?s)param\(.*?\)\s*\$ErrorActionPreference\s*=\s*''Stop''')
        Assert-True 'sign-in uses exchange online' ($signText -match 'Connect-ExchangeOnline')
        Assert-True 'exchange sign-in opens the browser' ($signText -match 'DisableWAM')
    }
    if ($script:WS_AdoptGraph) {
        Assert-True 'graph background session reads the module' ($script:WS_AdoptGraph.ToString() -match 'Get-MgContext')
    }

    $shareError = ''
    $rs = $null
    try {
        $rs = [runspacefactory]::CreateRunspace()
        $rs.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
        $rs.Open()
        $ps = [powershell]::Create()
        $ps.Runspace = $rs
        [void]$ps.AddScript($script:SharedFunctions.ToString())
        $null = $ps.Invoke()
        if ($ps.Streams.Error.Count -gt 0) { throw $ps.Streams.Error[0].ToString() }
        $ps.Dispose()
        $ps2 = [powershell]::Create()
        $ps2.Runspace = $rs
        [void]$ps2.AddScript("param([string]`$A, `$B)`n" + 'ConvertTo-JsonBody -Value @{ inputIds = @($A); other = $B }')
        [void]$ps2.AddParameter('A', 'abc')
        $encoded = @($ps2.Invoke())
        if ($ps2.Streams.Error.Count -gt 0) { throw $ps2.Streams.Error[0].ToString() }
        $ps2.Dispose()
        if (($encoded -join '') -notmatch '"inputIds":\["abc"\]') { throw "worker json was $($encoded -join '')" }
        $ps3 = [powershell]::Create()
        $ps3.Runspace = $rs
        [void]$ps3.AddScript('param($A) $A')
        $nullRejected = $false
        try { [void]$ps3.AddParameter('A', $null) }
        catch {
            $nullRejected = $true
            if ("$_" -notmatch 'null') { throw }
        }
        # Windows PowerShell 5.1 throws when the value is null. PowerShell 7 accepts it.
        # Callers still omit nulls so the same job table works on both.
        if (-not $nullRejected -and $PSVersionTable.PSVersion.Major -lt 6) { throw 'AddParameter accepted null' }
        $ps3.Dispose()
    } catch {
        $shareError = "$_"
    } finally {
        if ($rs) { try { $rs.Close() } catch { }; try { $rs.Dispose() } catch { } }
    }
    Assert-True "worker runspace shares helpers$(if ($shareError) { " ($shareError)" })" (-not $shareError)

    if ($fails.Count) {
        Write-Host ("FAILED {0} check(s): {1}" -f $fails.Count, ($fails -join ' || '))
        return 1
    }
    Write-Host ("OK {0} checks" -f $counter.Pass)
    return 0
}

if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA -and -not $SelfTest) {
    $self = $MyInvocation.MyCommand.Path
    if ($self) {
        $arg = "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$self`""
        Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $arg -WindowStyle Hidden
        return
    }
}

$script:WorkerCompileError = $null
try {
#region ---------- Background worker scripts ----------
$script:WorkerBoot = @'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ConfirmPreference = 'None'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
'@
function New-MrcWorker {
    param([string]$Source)
    $text = $Source.Trim()
    $boot = $script:WorkerBoot.Trim()
    if ($text -match '(?s)^param\(.*?\)') {
        $text = $Matches[0] + "`r`n" + $boot + "`r`n" + $text.Substring($Matches[0].Length).TrimStart()
    } else {
        $text = $boot + "`r`n" + $text
    }
    return [scriptblock]::Create($text)
}

$script:WS_Init = New-MrcWorker @'

$global:GraphAuth = $null
$global:GraphBase = 'https://graph.microsoft.com/v1.0'
$global:LoginBase = 'https://login.microsoftonline.com'
$global:PendingDevice = $null
$global:GraphRootIds = @{}

function global:Get-WebErrorText {
    param($ErrorRecord)
    $msg = $null
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { $msg = [string]$ErrorRecord.ErrorDetails.Message }
    if (-not $msg -and $ErrorRecord.Exception -and $ErrorRecord.Exception.Response) {
        try {
            $stream = $ErrorRecord.Exception.Response.GetResponseStream()
            if ($stream) {
                if ($stream.CanSeek) { $stream.Position = 0 }
                $reader = New-Object System.IO.StreamReader($stream)
                $msg = $reader.ReadToEnd()
            }
        } catch { }
    }
    if (-not $msg -and $ErrorRecord.Exception) { $msg = [string]$ErrorRecord.Exception.Message }
    if (-not $msg) { return 'Unknown error' }
    try {
        $j = $msg | ConvertFrom-Json
        if ($j.error -and $j.error.message) { $msg = ('{0}: {1}' -f $j.error.code, $j.error.message) }
        elseif ($j.error_description) { $msg = ([string]$j.error_description -split "`r?`n")[0] }
    } catch { }
    return (Add-ErrorHint $msg)
}

function global:Get-OAuthErrorCode {
    param($ErrorRecord)
    try {
        $raw = $null
        if ($ErrorRecord.ErrorDetails) { $raw = $ErrorRecord.ErrorDetails.Message }
        if (-not $raw -and $ErrorRecord.Exception.Response) {
            $stream = $ErrorRecord.Exception.Response.GetResponseStream()
            if ($stream) {
                if ($stream.CanSeek) { $stream.Position = 0 }
                $raw = (New-Object System.IO.StreamReader($stream)).ReadToEnd()
            }
        }
        if (-not $raw) { return '' }
        return [string](($raw | ConvertFrom-Json).error)
    } catch { return '' }
}

function global:Get-AuthCertificate {
    param([string]$Thumbprint)
    $t = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    foreach ($store in 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My') {
        $certs = @(Get-ChildItem -Path $store -ErrorAction SilentlyContinue)
        foreach ($c in $certs) {
            if ($c.Thumbprint -and $c.Thumbprint.ToUpperInvariant() -eq $t) {
                $hasKey = $false
                try { $hasKey = [bool]$c.HasPrivateKey } catch { throw "Certificate $t was found but its private key could not be read. $_" }
                if (-not $hasKey) { throw "Certificate $t was found but has no private key." }
                return $c
            }
        }
    }
    throw "Certificate with thumbprint $t was not found in CurrentUser\My or LocalMachine\My."
}

function global:New-ClientAssertion {
    param([string]$TenantId, [string]$ClientId, $Certificate)
    $epoch = New-Object DateTime(1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc))
    $now = [int]([DateTime]::UtcNow - $epoch).TotalSeconds
    $header = ConvertTo-JsonBody -Value @{ alg = 'RS256'; typ = 'JWT'; x5t = (ConvertTo-Base64Url $Certificate.GetCertHash()) }
    $payload = ConvertTo-JsonBody -Value @{
        aud = "$(Get-LoginBase)/$TenantId/oauth2/v2.0/token"
        iss = $ClientId
        sub = $ClientId
        jti = [guid]::NewGuid().ToString()
        nbf = ($now - 120)
        exp = ($now + 600)
    }
    $unsigned = (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($header))) + '.' + (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($payload)))
    $rsa = $null
    try { $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate) } catch { }
    if (-not $rsa) { throw 'Unable to access the certificate RSA private key.' }
    $sig = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($unsigned), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    return $unsigned + '.' + (ConvertTo-Base64Url $sig)
}

function global:Get-LoginBase {
    if ($global:LoginBase) { return $global:LoginBase.TrimEnd('/') }
    return 'https://login.microsoftonline.com'
}

function global:Get-GraphDefaultScope {
    $base = [string]$global:GraphBase
    if ($base -match '^(https://[^/]+)') { return $Matches[1] + '/.default' }
    return 'https://graph.microsoft.com/.default'
}

function global:Request-GraphToken {
    param([string]$TenantId, [hashtable]$Body)
    try {
        return Invoke-RestMethod -Method Post -Uri "$(Get-LoginBase)/$TenantId/oauth2/v2.0/token" -Body $Body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
    } catch { throw "Token request failed: $(Get-WebErrorText $_)" }
}

function global:Set-GraphTokenResult {
    param($Response)
    $seconds = 3600
    try { if ($Response.expires_in) { $seconds = [int]$Response.expires_in } } catch { }
    $skew = 120
    if ($seconds -le $skew) { $skew = [Math]::Max([int]($seconds / 2), 0) }
    $global:GraphAuth.AccessToken = [string]$Response.access_token
    $global:GraphAuth.ExpiresOn = (Get-Date).AddSeconds($seconds - $skew)
    if ($Response.refresh_token) { $global:GraphAuth.RefreshToken = [string]$Response.refresh_token }
}

function global:Get-GraphAccessToken {
    $a = $global:GraphAuth
    if (-not $a) { throw 'Microsoft Graph is not connected.' }
    if ($a.AccessToken -and (Get-Date) -lt $a.ExpiresOn) { return [string]$a.AccessToken }
    switch ($a.Mode) {
        'Secret' {
            $r = Request-GraphToken -TenantId $a.TenantId -Body @{ client_id = $a.ClientId; client_secret = $a.Secret; scope = (Get-GraphDefaultScope); grant_type = 'client_credentials' }
        }
        'Certificate' {
            $cert = Get-AuthCertificate -Thumbprint $a.Thumbprint
            $r = Request-GraphToken -TenantId $a.TenantId -Body @{
                client_id = $a.ClientId
                scope = (Get-GraphDefaultScope)
                grant_type = 'client_credentials'
                client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                client_assertion = (New-ClientAssertion -TenantId $a.TenantId -ClientId $a.ClientId -Certificate $cert)
            }
        }
        'DeviceCode' {
            if (-not $a.RefreshToken) { throw 'The Graph session has expired. Reconnect Microsoft Graph.' }
            $r = Request-GraphToken -TenantId $a.TenantId -Body @{ client_id = $a.ClientId; grant_type = 'refresh_token'; refresh_token = $a.RefreshToken; scope = $a.Scope }
        }
        'Module' { throw 'This Graph session is held by the Microsoft Graph module. Sign in again if the call failed.' }
        default { throw "Unknown Graph auth mode '$($a.Mode)'." }
    }
    Set-GraphTokenResult $r
    return [string]$global:GraphAuth.AccessToken
}

function global:Invoke-GraphModule {
    param([string]$Method = 'GET', [string]$Path, $Body, [hashtable]$Headers)
    $cmd = Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue
    if (-not $cmd) { throw 'The Microsoft Graph module is not loaded. Sign in again.' }
    $uri = if ($Path -match '^https://') { $Path } else { $global:GraphBase.TrimEnd('/') + '/' + $Path.TrimStart('/') }
    $attempt = 0
    while ($true) {
        $attempt++
        $p = @{ Method = $Method; Uri = $uri; ErrorAction = 'Stop' }
        if ($cmd.Parameters.ContainsKey('OutputType')) { $p.OutputType = 'PSObject' }
        if ($Headers) { $p.Headers = $Headers }
        if ($null -ne $Body) {
            $p.Body = ConvertTo-JsonBody -Value $Body
            if ($cmd.Parameters.ContainsKey('ContentType')) { $p.ContentType = 'application/json' }
        }
        try { return Invoke-MgGraphRequest @p }
        catch {
            $status = 0
            $text = Get-WebErrorText $_
            if ($text -match '\b(429|503|504)\b') { try { $status = [int]$Matches[1] } catch { } }
            try { if (-not $status -and $_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode } } catch { }
            if (($status -eq 429 -or $status -eq 503 -or $status -eq 504) -and $attempt -lt 5) {
                $wait = 5
                try { $wait = Get-RetryAfterSeconds $_.Exception.Response.Headers['Retry-After'] } catch { }
                Start-Sleep -Seconds $wait
                continue
            }
            $extra = ''
            if ($status -eq 403) { $extra = ' Access was denied. The signed-in account needs Full Access to the mailbox, and the Graph sign-in needs Mail.ReadWrite.Shared.' }
            elseif ($status -eq 404) { $extra = ' The object was not found in Microsoft Graph.' }
            throw "Graph $Method failed ($status): $text$extra"
        }
    }
}

function global:Invoke-Graph {
    param([string]$Method = 'GET', [string]$Path, $Body, [hashtable]$Headers)
    if ($global:GraphAuth -and [string]$global:GraphAuth.Mode -eq 'Module') {
        return (Invoke-GraphModule -Method $Method -Path $Path -Body $Body -Headers $Headers)
    }
    $uri = if ($Path -match '^https://') { $Path } else { $global:GraphBase.TrimEnd('/') + '/' + $Path.TrimStart('/') }
    $attempt = 0
    $refreshed = $false
    while ($true) {
        $attempt++
        $h = @{ Authorization = 'Bearer ' + (Get-GraphAccessToken) }
        if ($Headers) { foreach ($k in @($Headers.Keys)) { $h[$k] = $Headers[$k] } }
        $p = @{ Method = $Method; Uri = $uri; Headers = $h; ErrorAction = 'Stop' }
        if ($null -ne $Body) {
            $p.Body = [Text.Encoding]::UTF8.GetBytes((ConvertTo-JsonBody -Value $Body))
            $p.ContentType = 'application/json'
        }
        try { return Invoke-RestMethod @p }
        catch {
            $status = 0
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }
            if ($status -eq 401 -and -not $refreshed) {
                $refreshed = $true
                $global:GraphAuth.AccessToken = $null
                $global:GraphAuth.ExpiresOn = [datetime]::MinValue
                continue
            }
            if (($status -eq 429 -or $status -eq 503 -or $status -eq 504) -and $attempt -lt 5) {
                $wait = 5
                try { $wait = Get-RetryAfterSeconds $_.Exception.Response.Headers['Retry-After'] } catch { }
                Start-Sleep -Seconds $wait
                continue
            }
            $extra = ''
            if ($status -eq 403) { $extra = ' Access was denied. Delegated sign-in needs Full Access plus Mail.ReadWrite.Shared. App-only needs Mail.ReadWrite and an application access policy that includes this mailbox.' }
            elseif ($status -eq 404) { $extra = ' The object was not found in Microsoft Graph.' }
            throw "Graph $Method failed ($status): $(Get-WebErrorText $_)$extra"
        }
    }
}

function global:Get-GraphValues {
    param([string]$Path, [int]$Max = 200)
    $items = New-Object System.Collections.Generic.List[object]
    $next = $Path
    for ($i = 0; $i -lt 20 -and $next -and $items.Count -lt $Max; $i++) {
        $page = Invoke-Graph -Path $next
        $values = @()
        if ($page -and $page.PSObject.Properties['value']) { $values = @($page.value) }
        foreach ($v in $values) { if ($null -ne $v) { $items.Add($v) } }
        $next = $null
        if ($page -and $page.PSObject.Properties['@odata.nextLink'] -and $page.'@odata.nextLink') {
            $next = [string]$page.'@odata.nextLink'
        }
    }
    return @($items.ToArray())
}

function global:Get-GraphObjectProperty {
    param($Object, [string[]]$Names)
    if (-not $Object) { return $null }
    foreach ($name in $Names) {
        $p = $Object.PSObject.Properties[$name]
        if ($p -and $null -ne $p.Value -and "$($p.Value)" -ne '') { return $p.Value }
    }
    return $null
}

function global:Test-GraphMessage {
    param([string]$User, [string]$Id)
    if (-not $Id) { return $null }
    try {
        $m = Invoke-Graph -Path ("/users/{0}/messages/{1}?`$select=id" -f (Escape-GraphSegment $User), (Escape-GraphSegment $Id))
        if ($m.id) { return [string]$m.id }
    } catch { }
    return $null
}

function global:Convert-GraphExchangeId {
    param([string]$User, [string]$SourceId, [string]$SourceType)
    $r = Invoke-Graph -Method POST -Path ("/users/{0}/translateExchangeIds" -f (Escape-GraphSegment $User)) -Body @{
        inputIds = @($SourceId)
        sourceIdType = $SourceType
        targetIdType = 'restId'
    }
    $row = @($r.value) | Where-Object { $_ } | Select-Object -First 1
    if (-not $row) { return $null }
    if ($row.PSObject.Properties['errorDetails'] -and $row.errorDetails) { return $null }
    return [string]$row.targetId
}

function global:Get-GraphRecoverableFolderId {
    param([string]$User, [string]$SourceFolder)
    $u = Escape-GraphSegment $User
    switch ($SourceFolder) {
        'DeletedItems' { return 'deleteditems' }
        'RecoverableItems' { return 'recoverableitemsdeletions' }
    }
    $wellKnown = @{ PurgedItems = 'recoverableitemspurges'; DiscoveryHoldsItems = 'recoverableitemsdiscoveryholds' }[$SourceFolder]
    $display = @{ PurgedItems = 'Purges'; DiscoveryHoldsItems = 'DiscoveryHolds' }[$SourceFolder]
    if ($wellKnown) {
        try {
            $f = Invoke-Graph -Path "/users/$u/mailFolders/${wellKnown}?`$select=id"
            if ($f.id) { return [string]$f.id }
        } catch { }
    }
    $del = Invoke-Graph -Path "/users/$u/mailFolders/recoverableitemsdeletions?`$select=id,parentFolderId"
    $kids = @(Get-GraphValues "/users/$u/mailFolders/$(Escape-GraphSegment $del.parentFolderId)/childFolders?`$select=id,displayName&`$top=100&includeHiddenFolders=true" -Max 200)
    $m = $kids | Where-Object { $_.displayName -and $_.displayName.Equals([string]$display, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
    if ($m) { return [string]$m.id }
    throw "Could not locate Recoverable Items\$display through Microsoft Graph."
}

function global:Resolve-GraphMessageId {
    param([string]$User, [string]$EntryID, [string]$SourceFolder, [string]$Subject, $LastModified)
    $formats = Convert-EntryIdFormats $EntryID
    $notes = New-Object System.Collections.Generic.List[string]
    $candidates = @()
    if ($formats.RestId) { $candidates += @{ Kind = 'direct'; Id = $formats.RestId } }
    if ($formats.Hex) { $candidates += @{ Kind = 'entryId'; Id = $formats.Hex } }
    if ($formats.EwsId) { $candidates += @{ Kind = 'ewsId'; Id = $formats.EwsId } }
    $seen = @{}
    foreach ($c in $candidates) {
        $key = $c.Kind + '|' + $c.Id
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        try {
            if ($c.Kind -eq 'direct') {
                $got = Test-GraphMessage -User $User -Id $c.Id
                if ($got) { return $got }
                $notes.Add('direct rest id was not a message')
            } else {
                $translated = Convert-GraphExchangeId -User $User -SourceId $c.Id -SourceType $c.Kind
                if ($translated) {
                    $got = Test-GraphMessage -User $User -Id $translated
                    if ($got) { return $got }
                    $notes.Add("$($c.Kind) translated but the message was not readable")
                } else { $notes.Add("$($c.Kind) translation returned no id") }
            }
        } catch { $notes.Add("$($c.Kind): $(Get-WebErrorText $_)") }
    }

    if (-not $Subject) { throw "The Exchange entry id could not be translated and the item has no subject to search on. $($notes -join ' | ')" }
    $folderId = Get-GraphRecoverableFolderId -User $User -SourceFolder $SourceFolder
    $filter = [uri]::EscapeDataString('subject eq ' + (Get-ODataLiteral $Subject))
    $uri = "/users/{0}/mailFolders/{1}/messages?`$filter={2}&`$select=id,subject,lastModifiedDateTime&`$top=50" -f (Escape-GraphSegment $User), (Escape-GraphSegment $folderId), $filter
    $found = @()
    try { $found = @(Get-GraphValues $uri -Max 50 | Where-Object { $_ -and [string]$_.subject -eq [string]$Subject }) }
    catch { $notes.Add("subject search failed: $(Get-WebErrorText $_)") }
    if ($found.Count -eq 1) { return [string]$found[0].id }
    if ($found.Count -gt 1 -and $LastModified) {
        $target = ([datetime]$LastModified).ToUniversalTime()
        $ranked = @($found | Sort-Object { [Math]::Abs(([datetime]$_.lastModifiedDateTime).ToUniversalTime().Subtract($target).TotalSeconds) })
        $bestDelta = [Math]::Abs(([datetime]$ranked[0].lastModifiedDateTime).ToUniversalTime().Subtract($target).TotalSeconds)
        $secondDelta = [double]::MaxValue
        if ($ranked.Count -gt 1) { $secondDelta = [Math]::Abs(([datetime]$ranked[1].lastModifiedDateTime).ToUniversalTime().Subtract($target).TotalSeconds) }
        if ($bestDelta -le 180 -and ($secondDelta - $bestDelta) -ge 5) { return [string]$ranked[0].id }
    }
    if ($found.Count -gt 1) {
        throw "Several messages in this folder share that subject, and the entry id could not be translated, so the exact item was not guessed. $($notes -join ' | ')"
    }
    throw "Message not found through Microsoft Graph. $($notes -join ' | ')"
}

function global:Format-GraphRecipients {
    param($List)
    $out = foreach ($r in @($List)) {
        if (-not $r -or -not $r.emailAddress) { continue }
        $name = [string]$r.emailAddress.name
        $addr = [string]$r.emailAddress.address
        if ($name -and $name -ne $addr) { '{0} <{1}>' -f $name, $addr } else { $addr }
    }
    return (@($out | Where-Object { $_ }) -join '; ')
}

function global:Get-GraphFolderDisplayPath {
    param([string]$User, [string]$FolderId)
    if (-not $global:GraphRootIds) { $global:GraphRootIds = @{} }
    $u = Escape-GraphSegment $User
    if (-not $global:GraphRootIds.ContainsKey($User)) {
        $global:GraphRootIds[$User] = (Invoke-Graph -Path "/users/$u/mailFolders/msgfolderroot?`$select=id").id
    }
    $root = [string]$global:GraphRootIds[$User]
    $names = New-Object System.Collections.Generic.List[string]
    $current = $FolderId
    for ($i = 0; $i -lt 12 -and $current -and $current -ne $root; $i++) {
        try { $f = Invoke-Graph -Path ("/users/{0}/mailFolders/{1}?`$select=id,displayName,parentFolderId" -f $u, (Escape-GraphSegment $current)) }
        catch { break }
        $names.Insert(0, [string]$f.displayName)
        $current = [string]$f.parentFolderId
    }
    if ($names.Count -eq 0) { return '(unknown folder)' }
    return ($names -join '/')
}

function global:Resolve-GraphChildFolder {
    param([string]$User, [string]$ParentId, [string]$Name, [bool]$Create)
    $u = Escape-GraphSegment $User
    $p = Escape-GraphSegment $ParentId
    $kids = @()
    try {
        $flt = [uri]::EscapeDataString('displayName eq ' + (Get-ODataLiteral $Name))
        $kids = @(Get-GraphValues "/users/$u/mailFolders/$p/childFolders?`$filter=$flt&`$select=id,displayName&includeHiddenFolders=true" -Max 20)
    } catch { $kids = @() }
    $m = $kids | Where-Object { $_.displayName -and $_.displayName.Equals($Name, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
    if (-not $m) {
        $all = @(Get-GraphValues "/users/$u/mailFolders/$p/childFolders?`$select=id,displayName&`$top=100&includeHiddenFolders=true" -Max 300)
        $m = $all | Where-Object { $_.displayName -and $_.displayName.Equals($Name, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
    }
    if (-not $m) {
        if (-not $Create) { throw "Folder '$Name' was not found." }
        $m = Invoke-Graph -Method POST -Path "/users/$u/mailFolders/$p/childFolders" -Body @{ displayName = $Name }
    }
    return [string]$m.id
}

function global:Resolve-GraphFolderPath {
    param([string]$User, [string]$Path, [bool]$Create)
    $segments = @($Path -split '[/\\]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($segments.Count -eq 0) { throw 'A destination folder is required.' }
    $well = Get-WellKnownFolderId $segments[0]
    if ($well) {
        $current = $well
        $start = 1
    } else {
        $current = (Invoke-Graph -Path ("/users/{0}/mailFolders/msgfolderroot?`$select=id" -f (Escape-GraphSegment $User))).id
        $start = 0
    }
    for ($i = $start; $i -lt $segments.Count; $i++) {
        $current = Resolve-GraphChildFolder -User $User -ParentId $current -Name $segments[$i] -Create $Create
    }
    return [string]$current
}

function global:Find-GraphMessagesBySubject {
    param([string]$User, [string]$Subject)
    $flt = [uri]::EscapeDataString('subject eq ' + (Get-ODataLiteral $Subject))
    return @(Get-GraphValues ("/users/{0}/messages?`$filter={1}&`$select=id,subject,parentFolderId,lastModifiedDateTime,internetMessageId&`$top=25" -f (Escape-GraphSegment $User), $flt) -Max 50)
}

function global:Find-GraphMessagesByInternetId {
    param([string]$User, [string]$InternetMessageId)
    $flt = [uri]::EscapeDataString('internetMessageId eq ' + (Get-ODataLiteral $InternetMessageId))
    return @(Get-GraphValues ("/users/{0}/messages?`$filter={1}&`$select=id,subject,parentFolderId,lastModifiedDateTime,internetMessageId&`$top=25" -f (Escape-GraphSegment $User), $flt) -Max 25)
}

[pscustomobject]@{
    PSVersion = $PSVersionTable.PSVersion.ToString()
}
'@

$script:WS_InstallExo = New-MrcWorker @'
if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
    try { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -Confirm:$false | Out-Null }
    catch { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false | Out-Null }
}
try { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop } catch { }
Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber -Repository PSGallery -Confirm:$false
$env:PSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('PSModulePath', 'User')
$m = Get-Module -ListAvailable -Name ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1
if (-not $m) { throw 'ExchangeOnlineManagement was not found after installation.' }
if ($m.PowerShellVersion -and $m.PowerShellVersion -gt $PSVersionTable.PSVersion) {
    throw "Installed ExchangeOnlineManagement $($m.Version) requires PowerShell $($m.PowerShellVersion). This console runs on Windows PowerShell $($PSVersionTable.PSVersion)."
}
$m.Version.ToString()
'@

$script:WS_ConnectExo = New-MrcWorker @'
param([string]$Method, [string]$Upn, [string]$Organization, [string]$AppId, [string]$Thumbprint, [string]$ExchangeEnvironment)
if (-not (Get-Module ExchangeOnlineManagement)) { Import-Module ExchangeOnlineManagement -ErrorAction Stop }
$cmd = Get-Command Connect-ExchangeOnline -ErrorAction Stop
$p = @{ ShowBanner = $false }
if ($Method -eq 'Certificate') {
    $p.AppId = $AppId
    $p.CertificateThumbprint = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    $p.Organization = $Organization
} else {
    if ($Upn) { $p.UserPrincipalName = $Upn }
    if ($cmd.Parameters.ContainsKey('DisableWAM')) { $p.DisableWAM = $true }
}
if ($ExchangeEnvironment -and $cmd.Parameters.ContainsKey('ExchangeEnvironmentName')) { $p.ExchangeEnvironmentName = $ExchangeEnvironment }
Connect-ExchangeOnline @p | Out-Null
$info = $null
if (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue) {
    $info = Get-ConnectionInformation | Where-Object { $_.State -eq 'Connected' } | Select-Object -Last 1
}
[pscustomobject]@{
    Identity              = if ($info -and $info.UserPrincipalName) { [string]$info.UserPrincipalName } elseif ($Method -eq 'Certificate') { "App $AppId" } else { $Upn }
    Organization          = if ($info -and $info.Organization) { [string]$info.Organization } else { $Organization }
    HasGetRecoverable     = [bool](Get-Command Get-RecoverableItems -ErrorAction SilentlyContinue)
    HasRestoreRecoverable = [bool](Get-Command Restore-RecoverableItems -ErrorAction SilentlyContinue)
    ModuleVersion         = (Get-Module ExchangeOnlineManagement).Version.ToString()
}
'@

$script:WS_InstallModules = New-MrcWorker @'
param([bool]$Exchange, [bool]$Graph)
if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
    try { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -Confirm:$false | Out-Null }
    catch { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false | Out-Null }
}
try { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop } catch { }
$names = @()
if ($Exchange) { $names += 'ExchangeOnlineManagement' }
if ($Graph) { $names += 'Microsoft.Graph.Authentication' }
foreach ($name in $names) {
    Install-Module -Name $name -Scope CurrentUser -Force -AllowClobber -Repository PSGallery -Confirm:$false | Out-Null
}
$env:PSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('PSModulePath', 'User')
$installed = @{}
foreach ($name in $names) {
    $m = Get-Module -ListAvailable -Name $name | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $m) { throw "$name was not found after installation." }
    if ($m.PowerShellVersion -and $m.PowerShellVersion -gt $PSVersionTable.PSVersion) {
        throw "Installed $name $($m.Version) requires PowerShell $($m.PowerShellVersion). This console runs on Windows PowerShell $($PSVersionTable.PSVersion)."
    }
    $installed[$name] = $m.Version.ToString()
}
[pscustomobject]$installed
'@

$script:WS_SignIn = New-MrcWorker @'
param([string]$Upn)
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
if (-not (Get-Module ExchangeOnlineManagement)) { Import-Module ExchangeOnlineManagement -ErrorAction Stop }
$cmd = Get-Command Connect-ExchangeOnline -ErrorAction Stop
$p = @{ ShowBanner = $false; ErrorAction = 'Stop' }
if ($Upn) { $p.UserPrincipalName = $Upn }
if ($cmd.Parameters.ContainsKey('DisableWAM')) { $p.DisableWAM = $true }
Connect-ExchangeOnline @p | Out-Null
$info = $null
if (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue) {
    $info = Get-ConnectionInformation | Where-Object { $_.State -eq 'Connected' } | Select-Object -Last 1
}
[pscustomobject]@{
    Identity              = if ($info -and $info.UserPrincipalName) { [string]$info.UserPrincipalName } elseif ($Upn) { $Upn } else { 'Signed in' }
    Organization          = if ($info -and $info.Organization) { [string]$info.Organization } else { '' }
    HasGetRecoverable     = [bool](Get-Command Get-RecoverableItems -ErrorAction SilentlyContinue)
    HasRestoreRecoverable = [bool](Get-Command Restore-RecoverableItems -ErrorAction SilentlyContinue)
    ModuleVersion         = (Get-Module ExchangeOnlineManagement).Version.ToString()
}
'@

$script:WS_AdoptGraph = New-MrcWorker @'
if (-not (Get-Module Microsoft.Graph.Authentication)) { Import-Module Microsoft.Graph.Authentication -ErrorAction Stop }
$ctx = Get-MgContext
if (-not $ctx) { throw 'Microsoft Graph is signed in on the main window, but the background session cannot see it. Close this console and start it again.' }
$global:GraphBase = 'https://graph.microsoft.com/v1.0'
$global:LoginBase = 'https://login.microsoftonline.com'
$scopes = @()
if ($ctx.Scopes) { $scopes = @($ctx.Scopes | ForEach-Object { [string]$_ } | Where-Object { $_ }) }
$global:GraphAuth = @{
    Mode = 'Module'; AccessToken = $null; ExpiresOn = [datetime]::MaxValue; RefreshToken = $null
    Scope = ($scopes -join ' '); TenantId = [string]$ctx.TenantId; ClientId = [string]$ctx.ClientId
}
$global:GraphRootIds = @{}
[pscustomobject]@{
    Account = if ($ctx.Account) { [string]$ctx.Account } else { '' }
    HasMail = [bool]($scopes | Where-Object { $_ -match '(^|/)Mail\.Read' })
    HasMailWrite = [bool]($scopes | Where-Object { $_ -match '(^|/)Mail\.ReadWrite' })
}
'@

$script:WS_DisconnectAll = New-MrcWorker @'
try { if (Get-Command Disconnect-ExchangeOnline -ErrorAction SilentlyContinue) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } } catch { }
try { if (Get-Module Microsoft.Graph.Authentication) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } } catch { }
$global:GraphAuth = $null
$global:GraphRootIds = @{}
$global:PendingDevice = $null
'Disconnected'
'@

$script:WS_GraphAppConnect = New-MrcWorker @'
param([string]$Mode, [string]$TenantId, [string]$ClientId, [string]$Secret, [string]$Thumbprint, [string]$LoginBase, [string]$GraphBase)
if ($LoginBase) { $global:LoginBase = $LoginBase }
if ($GraphBase) { $global:GraphBase = $GraphBase }
$global:GraphAuth = @{ Mode = $Mode; TenantId = $TenantId; ClientId = $ClientId; Secret = $Secret; Thumbprint = $Thumbprint; AccessToken = $null; ExpiresOn = [datetime]::MinValue; RefreshToken = $null; Scope = '' }
$global:GraphRootIds = @{}
try { $token = Get-GraphAccessToken } catch { $global:GraphAuth = $null; throw }
$claims = $null
try {
    $part = $token.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($part.Length % 4) { 2 { $part += '==' } 3 { $part += '=' } }
    $claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($part)) | ConvertFrom-Json
} catch { }
$roles = @()
if ($claims -and $claims.roles) { $roles = @($claims.roles) }
[pscustomobject]@{
    Identity     = "App $ClientId"
    Permissions  = ($roles -join ', ')
    HasMail      = [bool]($roles | Where-Object { $_ -like 'Mail.Read*' })
    HasMailWrite = [bool]($roles | Where-Object { $_ -in @('Mail.ReadWrite', 'Mail.ReadWrite.All') })
}
'@

$script:WS_GraphDeviceStart = New-MrcWorker @'
param([string]$TenantId, [string]$ClientId, [string]$Scope, [string]$LoginBase, [string]$GraphBase)
if ($LoginBase) { $global:LoginBase = $LoginBase }
if ($GraphBase) { $global:GraphBase = $GraphBase }
try {
    $r = Invoke-RestMethod -Method Post -Uri "$(Get-LoginBase)/$TenantId/oauth2/v2.0/devicecode" -Body @{ client_id = $ClientId; scope = $Scope } -ContentType 'application/x-www-form-urlencoded'
} catch { throw "Device code request failed: $(Get-WebErrorText $_)" }
$global:PendingDevice = @{
    TenantId = $TenantId; ClientId = $ClientId; Scope = $Scope; DeviceCode = $r.device_code
    Interval = [Math]::Max([int]$r.interval, 5); ExpiresOn = (Get-Date).AddSeconds([int]$r.expires_in)
}
[pscustomobject]@{ UserCode = [string]$r.user_code; Uri = [string]$r.verification_uri; Message = [string]$r.message }
'@

$script:WS_GraphDevicePoll = New-MrcWorker @'
$d = $global:PendingDevice
if (-not $d) { throw 'No device code sign-in is pending.' }
$resp = $null
while ((Get-Date) -lt $d.ExpiresOn) {
    Start-Sleep -Seconds $d.Interval
    try {
        $resp = Invoke-RestMethod -Method Post -Uri "$(Get-LoginBase)/$($d.TenantId)/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
            grant_type = 'urn:ietf:params:oauth:grant-type:device_code'; client_id = $d.ClientId; device_code = $d.DeviceCode
        }
        break
    } catch {
        $code = Get-OAuthErrorCode $_
        if ($code -eq 'authorization_pending') { continue }
        if ($code -eq 'slow_down') { $d.Interval += 5; continue }
        throw "Device sign-in failed: $(Get-WebErrorText $_)"
    }
}
if (-not $resp) { throw 'The device code expired before sign-in was completed.' }
$global:PendingDevice = $null
$global:GraphAuth = @{ Mode = 'DeviceCode'; TenantId = $d.TenantId; ClientId = $d.ClientId; Scope = $d.Scope; AccessToken = $null; ExpiresOn = [datetime]::MinValue; RefreshToken = $null }
$global:GraphRootIds = @{}
Set-GraphTokenResult $resp
$claims = $null
try {
    $part = $resp.access_token.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($part.Length % 4) { 2 { $part += '==' } 3 { $part += '=' } }
    $claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($part)) | ConvertFrom-Json
} catch { }
$me = $null
try { $me = Invoke-Graph -Path '/me?$select=userPrincipalName,displayName' } catch { }
$scp = if ($claims) { [string]$claims.scp } else { '' }
$scopeNames = @($scp -split '\s+' | Where-Object { $_ })
[pscustomobject]@{
    Identity     = if ($me -and $me.userPrincipalName) { [string]$me.userPrincipalName } elseif ($claims -and $claims.upn) { [string]$claims.upn } else { '' }
    Permissions  = $scp
    HasMail      = [bool]($scopeNames | Where-Object { $_ -like 'Mail.Read*' })
    HasMailWrite = [bool]($scopeNames | Where-Object { $_ -in @('Mail.ReadWrite', 'Mail.ReadWrite.Shared', 'Mail.ReadWrite.All') })
}
'@

$script:WS_ResolveMailbox = New-MrcWorker @'
param([string]$Identity)
$mbx = Get-Mailbox -Identity $Identity -ErrorAction Stop | Select-Object -First 1
$smtp = [string]$mbx.PrimarySmtpAddress
$stats = @()
try {
    $stats = @(Get-MailboxFolderStatistics -Identity $smtp -FolderScope RecoverableItems -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name       = [string](Get-GraphObjectProperty $_ @('Name'))
            FolderType = [string](Get-GraphObjectProperty $_ @('FolderType'))
            Items      = [int64](Get-GraphObjectProperty $_ @('ItemsInFolder'))
            Size       = ([string](Get-GraphObjectProperty $_ @('FolderSize')) -replace '\s*\(.*\)$', '')
            TotalItems = [int64](Get-GraphObjectProperty $_ @('ItemsInFolderAndSubfolders'))
            TotalSize  = ([string](Get-GraphObjectProperty $_ @('FolderAndSubfolderSize')) -replace '\s*\(.*\)$', '')
        }
    })
} catch { }
$holds = @()
if ($mbx.InPlaceHolds) { $holds = @($mbx.InPlaceHolds | ForEach-Object { [string]$_ } | Where-Object { $_ }) }
[pscustomobject]@{
    DisplayName           = [string]$mbx.DisplayName
    PrimarySmtpAddress    = $smtp
    UserPrincipalName     = [string]$mbx.UserPrincipalName
    GraphId               = if ($mbx.ExternalDirectoryObjectId) { [string]$mbx.ExternalDirectoryObjectId } else { [string]$mbx.UserPrincipalName }
    RecipientTypeDetails  = [string]$mbx.RecipientTypeDetails
    LitigationHoldEnabled = [bool]$mbx.LitigationHoldEnabled
    InPlaceHolds          = $holds
    ComplianceTagHold     = [bool]$mbx.ComplianceTagHoldApplied
    DelayHold             = [bool]$mbx.DelayHoldApplied
    RetentionHoldEnabled  = [bool]$mbx.RetentionHoldEnabled
    SingleItemRecovery    = [bool]$mbx.SingleItemRecoveryEnabled
    RetainDeletedItemsFor = [string]$mbx.RetainDeletedItemsFor
    ArchiveStatus         = [string]$mbx.ArchiveStatus
    RecoverableStats      = $stats
}
'@

$script:WS_Search = New-MrcWorker @'
param([string]$Mailbox, [string[]]$Folders, [string]$ItemType, [string]$Subject, $Start, $End, [int]$Max, [string]$EntryID)
$all = New-Object System.Collections.Generic.List[object]
$warnings = New-Object System.Collections.Generic.List[string]
$counts = @{}
$truncated = New-Object System.Collections.Generic.List[string]

function New-SearchItem($Item, [string]$Folder) {
    $lm = $null
    $rawTime = Get-GraphObjectProperty $Item @('LastModifiedTime', 'LastModificationTime')
    try { if ($rawTime) { $lm = [datetime]$rawTime } } catch { }
    $source = $Folder
    $reported = [string](Get-GraphObjectProperty $Item @('SourceFolder'))
    if ($reported) { $source = $reported }
    return [pscustomobject]@{
        Subject              = [string](Get-GraphObjectProperty $Item @('Subject'))
        SourceFolder         = $source
        LastParentPath       = [string](Get-GraphObjectProperty $Item @('LastParentPath', 'LastParentFolderPath'))
        OriginalFolderExists = [string](Get-GraphObjectProperty $Item @('OriginalFolderExists'))
        ItemClass            = [string](Get-GraphObjectProperty $Item @('ItemClass'))
        LastModifiedTime     = $lm
        EntryID              = [string](Get-GraphObjectProperty $Item @('EntryID', 'EntryId'))
    }
}

$subjectText = if ($Subject) { $Subject.Trim() } else { '' }
if ($subjectText -eq '*') { $subjectText = '' }
$openSubject = -not $subjectText
$usedDefaultDates = $false
if ($EntryID) {
    try {
        $items = @(Get-RecoverableItems -Identity $Mailbox -EntryID $EntryID -ErrorAction Stop)
        foreach ($i in $items) { if ($i) { $all.Add((New-SearchItem $i '')) } }
        $counts['EntryID'] = $all.Count
    } catch { throw "EntryID search failed: $($_.Exception.Message)" }
} else {
    foreach ($f in @($Folders)) {
        $p = @{ Identity = $Mailbox; SourceFolder = $f; ResultSize = $Max; ErrorAction = 'Stop' }
        if ($ItemType) { $p.FilterItemType = $ItemType }
        if ($subjectText) { $p.SubjectContains = $subjectText }
        if ($Start -or $End) {
            $p.FilterStartTime = if ($Start) { [datetime]$Start } else { Get-Date -Year 1990 -Month 1 -Day 1 }
            $p.FilterEndTime = if ($End) { [datetime]$End } else { (Get-Date).AddDays(1) }
        } elseif ($openSubject) {
            $p.FilterStartTime = Get-Date -Year 1990 -Month 1 -Day 1
            $p.FilterEndTime = (Get-Date).AddDays(1)
            $usedDefaultDates = $true
        }
        try { $items = @(Get-RecoverableItems @p) }
        catch { $warnings.Add("$f : $($_.Exception.Message)"); $counts[$f] = -1; continue }
        $counts[$f] = $items.Count
        if ($items.Count -ge $Max) { $truncated.Add($f) }
        foreach ($i in $items) { if ($i) { $all.Add((New-SearchItem $i $f)) } }
    }
    if (@($Folders).Count -gt 0 -and $warnings.Count -eq @($Folders).Count) { throw ($warnings -join ' | ') }
}
[pscustomobject]@{ Items = $all.ToArray(); Warnings = $warnings.ToArray(); Counts = $counts; Truncated = $truncated.ToArray(); OpenSubject = [bool]$openSubject; UsedDefaultDates = [bool]$usedDefaultDates }
'@

$script:WS_LoadFolders = New-MrcWorker @'
param([string]$Mailbox)
$skip = @('Root', 'RecoverableItemsRoot', 'RecoverableItemsDeletions', 'RecoverableItemsPurges', 'RecoverableItemsVersions', 'RecoverableItemsDiscoveryHolds', 'Audits', 'CalendarLogging')
@(Get-MailboxFolderStatistics -Identity $Mailbox -ErrorAction Stop | Where-Object {
    $_.FolderPath -and [string]$_.FolderPath -ne '/' -and
    [string]$_.FolderPath -notlike '/Recoverable Items*' -and
    [string]$_.FolderPath -notlike '\Recoverable Items*' -and
    ($skip -notcontains [string]$_.FolderType) -and
    (-not $_.ContainerClass -or [string]$_.ContainerClass -like 'IPF.Note*')
} | ForEach-Object { (ConvertTo-DisplayFolder ([string]$_.FolderPath)) } | Where-Object { $_ } | Sort-Object -Unique)
'@

$script:WS_Preview = New-MrcWorker @'
param([string]$GraphUser, [string]$EntryID, [string]$SourceFolder, [string]$Subject, $LastModified)
$id = Resolve-GraphMessageId -User $GraphUser -EntryID $EntryID -SourceFolder $SourceFolder -Subject $Subject -LastModified $LastModified
$sel = 'id,subject,from,toRecipients,ccRecipients,sentDateTime,receivedDateTime,hasAttachments,importance,body,internetMessageId'
$m = Invoke-Graph -Path ("/users/{0}/messages/{1}?`$select={2}" -f (Escape-GraphSegment $GraphUser), (Escape-GraphSegment $id), $sel) -Headers @{ Prefer = 'outlook.body-content-type="html"' }
$atts = @()
if ($m.hasAttachments) {
    try {
        $a = Invoke-Graph -Path ("/users/{0}/messages/{1}/attachments?`$select=name,size,contentType,isInline" -f (Escape-GraphSegment $GraphUser), (Escape-GraphSegment $id))
        $atts = @(@($a.value) | Where-Object { $_ -and -not $_.isInline } | ForEach-Object { '{0} ({1:N0} KB)' -f $_.name, ([double]$_.size / 1KB) })
    } catch { $atts = @('(could not list attachments)') }
}
[pscustomobject]@{
    GraphId            = $id
    Subject            = [string]$m.subject
    From               = Format-GraphRecipients @($m.from)
    To                 = Format-GraphRecipients $m.toRecipients
    Cc                 = Format-GraphRecipients $m.ccRecipients
    Sent               = if ($m.sentDateTime) { ([datetime]$m.sentDateTime).ToLocalTime() } else { $null }
    Received           = if ($m.receivedDateTime) { ([datetime]$m.receivedDateTime).ToLocalTime() } else { $null }
    Importance         = [string]$m.importance
    BodyType           = [string]$m.body.contentType
    Body               = [string]$m.body.content
    InternetMessageId  = [string]$m.internetMessageId
    Attachments        = $atts
}
'@

$script:WS_Restore = New-MrcWorker @'
param([string]$Mailbox, [string]$GraphUser, [string]$EntryID, [string]$SourceFolder, [string]$Mode,
      [string]$TargetFolder, [bool]$Verify, [string]$Subject, [string]$OriginalPath, $LastModified, [string]$InternetMessageId)
$t0 = Get-Date
$graphReady = [bool]$global:GraphAuth
$notes = New-Object System.Collections.Generic.List[string]
$result = [ordered]@{ Status = 'Success'; Message = ''; Destination = ''; Verified = $false }

if ($Mode -eq 'GraphMove') {
    if (-not $graphReady) { throw 'Moving to an exact folder requires a Microsoft Graph connection.' }
    $msgId = Resolve-GraphMessageId -User $GraphUser -EntryID $EntryID -SourceFolder $SourceFolder -Subject $Subject -LastModified $LastModified
    $destId = Resolve-GraphFolderPath -User $GraphUser -Path $TargetFolder -Create $true
    $moved = Invoke-Graph -Method POST -Path ("/users/{0}/messages/{1}/move" -f (Escape-GraphSegment $GraphUser), (Escape-GraphSegment $msgId)) -Body @{ destinationId = $destId }
    $result.Destination = ConvertTo-GraphFolderPath $TargetFolder
    $check = $null
    if ($moved.id) {
        try { $check = Invoke-Graph -Path ("/users/{0}/messages/{1}?`$select=id,parentFolderId" -f (Escape-GraphSegment $GraphUser), (Escape-GraphSegment $moved.id)) } catch { }
    }
    if ($check -and [string]$check.parentFolderId -eq [string]$destId) {
        $result.Verified = $true
        $result.Destination = Get-GraphFolderDisplayPath -User $GraphUser -FolderId $check.parentFolderId
        $result.Message = "Moved to '$($result.Destination)' and verified in the destination folder."
    } elseif ($moved.id) {
        $result.Status = 'Warning'
        $result.Message = "Move returned success but the destination could not be confirmed. Check '$($result.Destination)'."
    } else { throw 'The Graph move request did not return a message.' }
    return [pscustomobject]$result
}

if (-not (Get-Command Restore-RecoverableItems -ErrorAction SilentlyContinue)) {
    throw "Restore-RecoverableItems is not available. Assign the Mailbox Import Export role to the signing-in account and reconnect."
}
$base = @{ Identity = $Mailbox; EntryID = $EntryID; ErrorAction = 'Stop' }
$out = $null
if ($Mode -eq 'Original') {
    $out = Restore-RecoverableItems @base -SourceFolder $SourceFolder
    $result.Destination = if ($OriginalPath) { ConvertTo-DisplayFolder $OriginalPath } else { 'default folder (Inbox)' }
} else {
    $exchangePath = ConvertTo-ExchangeFolderPath $TargetFolder
    try { $out = Restore-RecoverableItems @base -SourceFolder $SourceFolder -RestoreTargetFolder $exchangePath }
    catch {
        if ("$_" -match 'parameter set|cannot be resolved|cannot be used together|ambiguous') {
            $notes.Add('retried without -SourceFolder')
            $out = Restore-RecoverableItems @base -RestoreTargetFolder $exchangePath
        } else { throw }
    }
    $result.Destination = ConvertTo-DisplayFolder $exchangePath
}
foreach ($o in @($out | Where-Object { $null -ne $_ })) {
    $flag = $o.PSObject.Properties['WasRestoredSuccessfully']
    if ($flag -and "$($flag.Value)" -eq 'False') { throw 'Exchange reported WasRestoredSuccessfully = False for this item.' }
}
if ($SourceFolder -in @('DiscoveryHoldsItems', 'PurgedItems')) { $notes.Add('the held copy remains while the hold is active') }

if (-not $Verify) {
    $result.Message = "Restore command completed to '$($result.Destination)' (verification skipped)."
} else {
    $verified = $false
    if ($graphReady -and ($InternetMessageId -or $Subject)) {
        $expected = ConvertTo-GraphFolderPath $result.Destination
        for ($i = 0; $i -lt 4 -and -not $verified; $i++) {
            if ($i -gt 0) { Start-Sleep -Seconds 2 }
            try {
                $found = @()
                if ($InternetMessageId) { $found = @(Find-GraphMessagesByInternetId -User $GraphUser -InternetMessageId $InternetMessageId) }
                if ($found.Count -eq 0 -and $Subject) { $found = @(Find-GraphMessagesBySubject -User $GraphUser -Subject $Subject) }
                $recent = @($found | Where-Object { $_.lastModifiedDateTime -and ([datetime]$_.lastModifiedDateTime).ToLocalTime() -ge $t0.AddMinutes(-2) })
                $pool = if ($recent.Count) { $recent } else { @() }
                if ($pool.Count -eq 1) {
                    $verified = $true
                    $result.Destination = Get-GraphFolderDisplayPath -User $GraphUser -FolderId $pool[0].parentFolderId
                    if ($InternetMessageId -and [string]$pool[0].internetMessageId -eq $InternetMessageId) { $notes.Add('matched internet message id') }
                } elseif ($pool.Count -gt 1) {
                    $picked = $null
                    foreach ($item in $pool) {
                        $folder = Get-GraphFolderDisplayPath -User $GraphUser -FolderId $item.parentFolderId
                        if ($expected -and (ConvertTo-GraphFolderPath $folder) -eq $expected) { $picked = $item; $result.Destination = $folder; break }
                    }
                    if ($picked) { $verified = $true; $notes.Add('matched one of several recent copies by folder') }
                    elseif ($i -eq 3) { $notes.Add('several recent messages share this subject') }
                }
            } catch { $notes.Add("Graph verification error: $_"); break }
        }
        if ($verified) { $result.Verified = $true; $result.Message = "Restored and verified in '$($result.Destination)'." }
    }
    if (-not $verified -and $SourceFolder -ne 'DiscoveryHoldsItems' -and $SourceFolder -ne 'PurgedItems') {
        Start-Sleep -Seconds 2
        $still = @()
        try { $still = @(Get-RecoverableItems -Identity $Mailbox -EntryID $EntryID -SourceFolder $SourceFolder -ErrorAction Stop) } catch { }
        if ($still.Count -eq 0) {
            $verified = $true
            $result.Verified = $true
            $result.Message = "Restored to '$($result.Destination)'. Verified: the item is no longer in the source folder."
        }
    }
    if (-not $verified) {
        $result.Status = 'Warning'
        $hint = if (-not $graphReady) { ' Connect Microsoft Graph to verify where the item landed.' } else { '' }
        $result.Message = "Restore command succeeded but the item could not be verified at '$($result.Destination)'.$hint"
    }
}
if ($notes.Count) { $result.Message += ' [' + ($notes -join '; ') + ']' }
[pscustomobject]$result
'@
#endregion
} catch {
    $script:WorkerCompileError = $_
}
if ($SelfTest) {
    if ($script:WorkerCompileError) {
        Write-Host ("FAILED worker compile: {0}" -f $script:WorkerCompileError.Exception.Message)
        exit 1
    }
    $code = Invoke-MrcSelfTest
    exit $code
}


Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
try { Add-Type -AssemblyName System.Web } catch { }
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

function Enable-MrcDpi {
    try {
        if (-not ('MrcDpiNative' -as [type])) {
            Add-Type -Namespace MrcDpiNative -Name Win32 -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
'@
        }
        [void][MrcDpiNative.Win32]::SetProcessDPIAware()
    } catch { }
}
Enable-MrcDpi
[System.Windows.Forms.Application]::EnableVisualStyles()
try { [System.Windows.Forms.Application]::SetUnhandledExceptionMode('CatchException') } catch { }
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch { }

function Set-BrowserEmulation {
    try {
        $reg = 'HKCU:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION'
        if (-not (Test-Path $reg)) { New-Item -Path $reg -Force | Out-Null }
        foreach ($name in 'powershell.exe', 'powershell_ise.exe') {
            New-ItemProperty -Path $reg -Name $name -Value 11001 -PropertyType DWord -Force | Out-Null
        }
    } catch { }
}
Set-BrowserEmulation

try {
    if ($script:WorkerCompileError) { throw $script:WorkerCompileError }
    $script:AppStartupError = $null
#region ---------- App paths, settings and logging ----------
$script:DataDir = Join-Path $env:APPDATA 'MailboxRecoveryConsole'
if (-not (Test-Path $script:DataDir)) { [void](New-Item -ItemType Directory -Path $script:DataDir -Force) }
$script:LogPath = Join-Path $script:DataDir ('RecoveryLog_{0:yyyyMMdd}.log' -f (Get-Date))
$script:SettingsPath = Join-Path $script:DataDir 'settings.json'
$script:DefaultGraphClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
$script:Closing = $false
$script:LoadingSettings = $true

$script:Clouds = [ordered]@{
    Commercial = @{ Label = 'Commercial and GCC'; Login = 'https://login.microsoftonline.com'; Graph = 'https://graph.microsoft.com/v1.0'; ExoEnvironment = 'O365Default' }
    GCCHigh    = @{ Label = 'GCC High'; Login = 'https://login.microsoftonline.us'; Graph = 'https://graph.microsoft.us/v1.0'; ExoEnvironment = 'O365USGovGCCHigh' }
    DoD        = @{ Label = 'DoD'; Login = 'https://login.microsoftonline.us'; Graph = 'https://dod-graph.microsoft.us/v1.0'; ExoEnvironment = 'O365USGovDoD' }
    China      = @{ Label = 'China (21Vianet)'; Login = 'https://login.chinacloudapi.cn'; Graph = 'https://microsoftgraph.chinacloudapi.cn/v1.0'; ExoEnvironment = 'O365China' }
}

function Get-AppSettings {
    $defaults = [ordered]@{
        ExoMethod       = 'Interactive'
        AdminUpn        = ''
        Organization    = ''
        ExoAppId        = ''
        ExoThumbprint   = ''
        GraphMethod     = 'Interactive'
        SignInExo       = 'True'
        SignInGraph     = 'True'
        TenantId        = ''
        GraphClientId   = $script:DefaultGraphClientId
        GraphThumbprint = ''
        LastMailbox     = ''
        LastFolder      = 'Recovered Items'
        Cloud           = 'Commercial'
        MailboxHistory  = ''
        LastSource      = '0'
        LastItemType    = 'Email'
        VerifyRestore   = 'True'
        AutoPreview     = 'True'
        PlainPreview    = 'False'
        RemoteImages    = 'False'
        WindowX         = ''
        WindowY         = ''
        WindowW         = ''
        WindowH         = ''
        Splitter        = ''
    }
    if (Test-Path $script:SettingsPath) {
        try {
            $raw = [System.IO.File]::ReadAllText($script:SettingsPath)
            $saved = $raw | ConvertFrom-Json
            foreach ($p in $saved.PSObject.Properties) {
                if ($defaults.Contains($p.Name) -and $null -ne $p.Value) { $defaults[$p.Name] = [string]$p.Value }
            }
        } catch { }
    }
    return $defaults
}

function Save-AppSettings {
    try {
        $json = ConvertTo-JsonBody -Value $script:Settings
        $utf8 = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($script:SettingsPath, $json, $utf8)
    } catch { }
}

function Write-Log {
    param([string]$Level = 'INFO', [string]$Message)
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1,-7}] {2}' -f (Get-Date), $Level.ToUpper(), (Protect-LogText $Message)
    try {
        $utf8 = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::AppendAllText($script:LogPath, $line + [Environment]::NewLine, $utf8)
    } catch { }
}

$script:Settings = Get-AppSettings
function Get-SettingFlag([string]$Name, [bool]$Default) {
    $v = [string]$script:Settings[$Name]
    if ($v -eq 'True') { return $true }
    if ($v -eq 'False') { return $false }
    return $Default
}
#endregion

#region ---------- Status icons ----------
function New-StatusBitmap {
    param([string]$Kind, [int]$Size = 16)
    $bmp = New-Object System.Drawing.Bitmap($Size, $Size)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $trash = New-Object System.Collections.Generic.List[System.IDisposable]
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)
    $s = $Size / 16.0
    $pf = { param($x, $y) New-Object System.Drawing.PointF(($x * $s), ($y * $s)) }
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, (2.0 * $s))
    $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
    $brush = {
        param($r, $gr, $b)
        $br = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb($r, $gr, $b))
        $trash.Add($br)
        return $br
    }
    try {
        switch ($Kind) {
            'Success' {
                $g.FillEllipse((& $brush 22 163 74), (0.5 * $s), (0.5 * $s), (15 * $s), (15 * $s))
                $g.DrawLines($pen, [System.Drawing.PointF[]]@((& $pf 4 8.3), (& $pf 7 11.3), (& $pf 12 5.2)))
            }
            'Failed' {
                $g.FillEllipse((& $brush 220 38 38), (0.5 * $s), (0.5 * $s), (15 * $s), (15 * $s))
                $g.DrawLine($pen, (& $pf 5 5), (& $pf 11 11))
                $g.DrawLine($pen, (& $pf 11 5), (& $pf 5 11))
            }
            'Warning' {
                $tri = [System.Drawing.PointF[]]@((& $pf 8 0.8), (& $pf 15.4 14.6), (& $pf 0.6 14.6))
                $g.FillPolygon((& $brush 217 119 6), $tri)
                $g.DrawLine($pen, (& $pf 8 5.5), (& $pf 8 9.5))
                $g.FillEllipse([System.Drawing.Brushes]::White, (7 * $s), (11.2 * $s), (2 * $s), (2 * $s))
            }
            'Running' {
                $g.FillEllipse((& $brush 37 99 235), (0.5 * $s), (0.5 * $s), (15 * $s), (15 * $s))
                $g.FillPolygon([System.Drawing.Brushes]::White, [System.Drawing.PointF[]]@((& $pf 6 4.5), (& $pf 11.5 8), (& $pf 6 11.5)))
            }
            'Queued' {
                $g.FillEllipse((& $brush 148 163 184), (0.5 * $s), (0.5 * $s), (15 * $s), (15 * $s))
                $g.DrawLine($pen, (& $pf 8 4.5), (& $pf 8 8.5))
                $g.DrawLine($pen, (& $pf 8 8.5), (& $pf 10.8 10))
            }
            'Info' {
                $g.FillEllipse((& $brush 59 130 246), (0.5 * $s), (0.5 * $s), (15 * $s), (15 * $s))
                $g.FillEllipse([System.Drawing.Brushes]::White, (7 * $s), (3.4 * $s), (2 * $s), (2 * $s))
                $g.DrawLine($pen, (& $pf 8 7.3), (& $pf 8 12))
            }
            'Mail' {
                $edge = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(71, 85, 105), (1.2 * $s))
                $trash.Add($edge)
                $g.FillRectangle((& $brush 241 245 249), (1.5 * $s), (3.5 * $s), (13 * $s), (9 * $s))
                $g.DrawRectangle($edge, (1.5 * $s), (3.5 * $s), (13 * $s), (9 * $s))
                $g.DrawLines($edge, [System.Drawing.PointF[]]@((& $pf 1.8 3.8), (& $pf 8 9), (& $pf 14.2 3.8)))
            }
            'Disconnected' {
                $g.FillEllipse((& $brush 203 213 225), (0.5 * $s), (0.5 * $s), (15 * $s), (15 * $s))
            }
        }
    } finally {
        $pen.Dispose()
        foreach ($d in $trash) { try { $d.Dispose() } catch { } }
        $g.Dispose()
    }
    return $bmp
}

$script:Icons = @{}
foreach ($k in 'Success', 'Failed', 'Warning', 'Running', 'Queued', 'Info', 'Mail', 'Disconnected') {
    $script:Icons[$k] = New-StatusBitmap -Kind $k
}
$script:ImageList = New-Object System.Windows.Forms.ImageList
$script:ImageList.ColorDepth = [System.Windows.Forms.ColorDepth]::Depth32Bit
$script:ImageList.ImageSize = New-Object System.Drawing.Size(16, 16)
foreach ($k in $script:Icons.Keys) { $script:ImageList.Images.Add($k, $script:Icons[$k]) }
#endregion

#region ---------- ListView column sorter ----------
if (-not ('MrcListViewSorter' -as [type])) {
    Add-Type -ReferencedAssemblies System.Windows.Forms -TypeDefinition @'
using System;
using System.Collections;
using System.Windows.Forms;
public class MrcListViewSorter : IComparer
{
    public int Column = 0;
    public bool Descending = false;
    public int Compare(object x, object y)
    {
        ListViewItem a = (ListViewItem)x;
        ListViewItem b = (ListViewItem)y;
        string sa = Column < a.SubItems.Count ? a.SubItems[Column].Text : "";
        string sb = Column < b.SubItems.Count ? b.SubItems[Column].Text : "";
        DateTime da, db;
        int r;
        if (DateTime.TryParse(sa, out da) && DateTime.TryParse(sb, out db)) { r = DateTime.Compare(da, db); }
        else { r = String.Compare(sa, sb, StringComparison.CurrentCultureIgnoreCase); }
        return Descending ? -r : r;
    }
}
'@
}
#endregion

#region ---------- Friendly names ----------
$script:SourceFolderNames = [ordered]@{
    'DiscoveryHoldsItems' = 'Recoverable Items \ DiscoveryHolds'
    'RecoverableItems'    = 'Recoverable Items \ Deletions'
    'PurgedItems'         = 'Recoverable Items \ Purges'
    'DeletedItems'        = 'Deleted Items'
}
function Get-LocationName([string]$SourceFolder) {
    if ($SourceFolder -and $script:SourceFolderNames.Contains($SourceFolder)) { return $script:SourceFolderNames[$SourceFolder] }
    if ($SourceFolder) { return $SourceFolder }
    return ''
}
function Test-GuidText([string]$Value) {
    return $Value -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
}
function Get-SelectedCloudKey { return 'Commercial' }
function Get-SelectedCloud { return $script:Clouds['Commercial'] }
#endregion

#region ---------- Background job engine ----------
$script:Worker = $null
$script:WorkerClosed = $false
$script:JobQueue = New-Object System.Collections.Queue
$script:CurrentJob = $null
$script:InJobTick = $false
$script:State = @{
    ExoConnected = $false; ExoIdentity = ''; ExoVersion = ''; CanRestore = $false; ExoInstalled = $false
    GraphConnected = $false; GraphIdentity = ''; GraphCanWrite = $false; GraphInstalled = $false; GraphVersion = ''
    Mailbox = $null; AllItems = @(); SelectedData = $null; Batch = $null; HasSearched = $false
}

function Enable-ControlBuffer($Control) {
    try {
        $flags = [System.Reflection.BindingFlags]'Instance, NonPublic'
        $prop = $Control.GetType().GetProperty('DoubleBuffered', $flags)
        if ($prop) { $prop.SetValue($Control, $true, $null) }
    } catch { }
}

function Show-Message {
    param([string]$Text, [string]$Title = '', [string]$Buttons = 'OK', [string]$Icon = 'Information')
    if (-not $Title) { $Title = $script:AppName }
    $owner = $null
    try { if ($script:Form -and $script:Form.IsHandleCreated) { $owner = $script:Form } } catch { }
    if ($owner) { return [System.Windows.Forms.MessageBox]::Show($owner, $Text, $Title, $Buttons, $Icon) }
    return [System.Windows.Forms.MessageBox]::Show($Text, $Title, $Buttons, $Icon)
}

function Show-TextDialog {
    param([string]$Title, [string]$Text, [int]$Width = 720, [int]$Height = 480)
    $dlg = New-DialogForm $Title $Width $Height
    $box = New-Object System.Windows.Forms.TextBox
    $box.Multiline = $true; $box.ReadOnly = $true; $box.ScrollBars = 'Both'; $box.Dock = 'Fill'
    $box.BackColor = [System.Drawing.Color]::White
    $box.Font = New-Object System.Drawing.Font('Consolas', 9.5)
    $box.Text = $Text
    $dlg.Controls.Add($box)
    [void]$dlg.ShowDialog($script:Form)
    $dlg.Dispose()
}

function Add-Activity {
    param([string]$Status, [string]$Action, [string]$Details)
    $lvi = New-Object System.Windows.Forms.ListViewItem($Status)
    $lvi.ImageKey = $Status
    [void]$lvi.SubItems.Add((Get-Date).ToString('HH:mm:ss'))
    [void]$lvi.SubItems.Add('')
    [void]$lvi.SubItems.Add($Action)
    [void]$lvi.SubItems.Add($Details)
    $lvi.Tag = @{ Start = Get-Date }
    Set-ActivityColor $lvi $Status
    $script:lvActivity.Items.Insert(0, $lvi)
    while ($script:lvActivity.Items.Count -gt 500) { $script:lvActivity.Items.RemoveAt($script:lvActivity.Items.Count - 1) }
    if ($Status -ne 'Queued') {
        $lvLevel = switch ($Status) { 'Failed' { 'ERROR' } 'Warning' { 'WARN' } 'Success' { 'SUCCESS' } default { 'INFO' } }
        Write-Log -Level $lvLevel -Message "$Action - $Details"
    }
    # ListViewItem enumerates its subitems, so a bare return hands back those pieces instead of the row.
    return ,$lvi
}

function Write-Activity {
    param([string]$Status, [string]$Action, [string]$Details)
    [void](Add-Activity -Status $Status -Action $Action -Details $Details)
}

function Set-ActivityColor {
    param($Item, [string]$Status)
    $Item.ForeColor = switch ($Status) {
        'Success' { [System.Drawing.Color]::FromArgb(21, 128, 61) }
        'Failed'  { [System.Drawing.Color]::FromArgb(185, 28, 28) }
        'Warning' { [System.Drawing.Color]::FromArgb(180, 83, 9) }
        'Running' { [System.Drawing.Color]::FromArgb(29, 78, 216) }
        'Queued'  { [System.Drawing.Color]::FromArgb(100, 116, 139) }
        default   { [System.Drawing.Color]::FromArgb(30, 41, 59) }
    }
}

function Set-Activity {
    param($Item, [string]$Status, [string]$Details)
    if ($Item -isnot [System.Windows.Forms.ListViewItem]) { return }
    $Item.Text = $Status
    $Item.ImageKey = $Status
    if ($Status -eq 'Running' -and $Item.Tag) { $Item.Tag.Start = Get-Date }
    if ($Item.Tag -and $Item.Tag.Start) { $Item.SubItems[2].Text = ('{0:N1}s' -f ((Get-Date) - $Item.Tag.Start).TotalSeconds) }
    if ($null -ne $Details) { $Item.SubItems[4].Text = $Details }
    Set-ActivityColor $Item $Status
    if ($Status -in 'Success', 'Failed', 'Warning', 'Info') {
        $lvl = switch ($Status) { 'Failed' { 'ERROR' } 'Warning' { 'WARN' } 'Success' { 'SUCCESS' } default { 'INFO' } }
        Write-Log -Level $lvl -Message ('{0} - {1}' -f $Item.SubItems[3].Text, $Item.SubItems[4].Text)
    }
}

function Add-Job {
    param(
        [string]$Name, [scriptblock]$Script, $Parameters = $null,
        [scriptblock]$OnSuccess, [scriptblock]$OnFailure, [scriptblock]$OnStart, $Context, [switch]$Quiet
    )
    if (-not $Parameters) { $Parameters = @{} }
    $act = $null
    $waiting = 'Starting...'
    if ($script:CurrentJob) { $waiting = "Waiting for '$($script:CurrentJob.Name)' to finish." }
    if (-not $Quiet) { $act = Add-Activity -Status 'Queued' -Action $Name -Details $waiting }
    $job = [pscustomobject]@{
        Name = $Name; Script = $Script; Parameters = $Parameters; OnSuccess = $OnSuccess; OnFailure = $OnFailure; OnStart = $OnStart
        Context = $Context; Activity = $act; Quiet = [bool]$Quiet; PS = $null; Handle = $null; Started = $null; Cancelled = $false
    }
    $script:JobQueue.Enqueue($job)
    Start-NextJob
    Update-BusyState
}

function Start-NextJob {
    if ($script:SigningIn) { return }
    if ($script:CurrentJob -or $script:JobQueue.Count -eq 0) { return }
    $job = $null
    $ps = $null
    try {
        $job = $script:JobQueue.Dequeue()
        if (-not $script:Worker) { throw 'The background worker is not ready yet.' }
        $ps = [powershell]::Create()
        $ps.Runspace = $script:Worker
        [void]$ps.AddScript($job.Script.ToString())
        $bound = Get-JobParameterTable $job.Parameters
        foreach ($k in @($bound.Keys)) { [void]$ps.AddParameter([string]$k, $bound[$k]) }
        $job.PS = $ps
        $job.Started = Get-Date
        Set-Activity $job.Activity 'Running' 'In progress...'
        if ($job.OnStart) { & $job.OnStart $job }
        $job.Handle = $ps.BeginInvoke()
        $script:CurrentJob = $job
    } catch {
        $script:CurrentJob = $null
        if ($ps) { try { $ps.Dispose() } catch { } }
        $msg = $_.Exception.Message
        try {
            if ($job -and $job.Activity) { Set-Activity $job.Activity 'Failed' $msg } elseif ($job) { Write-Log 'ERROR' "$($job.Name) - $msg" }
        } catch { if ($job) { Write-Log 'ERROR' "$($job.Name) - $msg" } }
        if ($job -and $job.OnFailure) { try { & $job.OnFailure $msg $job } catch { Write-Log 'ERROR' $_.Exception.Message } }
    }
}

function Get-ExceptionText($Exception) {
    $e = $Exception
    while ($e -is [System.Management.Automation.MethodInvocationException] -and $e.InnerException) { $e = $e.InnerException }
    if ($e -is [System.Management.Automation.RuntimeException] -and $e.ErrorRecord -and $e.ErrorRecord.Exception -and $e.ErrorRecord.Exception -ne $e) {
        return $e.ErrorRecord.Exception.Message
    }
    if ($e.Message) { return $e.Message }
    return [string]$e
}

function Complete-Job {
    param($Job)
    $script:CurrentJob = $null
    $output = $null
    $err = $null
    try { $output = $Job.PS.EndInvoke($Job.Handle) }
    catch { $err = Get-ExceptionText $_.Exception }
    if (-not $err -and ($null -eq $output -or @($output).Count -eq 0) -and $Job.PS.Streams.Error.Count -gt 0) {
        $err = $Job.PS.Streams.Error[0].ToString()
    }
    if ($Job.Cancelled) { $err = 'Cancelled by user.' }
    try { $Job.PS.Dispose() } catch { }
    if ($err) {
        $status = if ($Job.Cancelled) { 'Warning' } else { 'Failed' }
        if ($Job.Activity) { Set-Activity $Job.Activity $status $err }
        elseif ($Job.Quiet) { Write-Log -Level $(if ($Job.Cancelled) { 'WARN' } else { 'ERROR' }) -Message "$($Job.Name) - $err" }
        if ($Job.OnFailure) { try { & $Job.OnFailure $err $Job } catch { Write-Log 'ERROR' "OnFailure handler: $($_.Exception.Message)" } }
        return
    }
    $items = @($output)
    $result = $null
    if ($items.Count -eq 1) { $result = $items[0] } elseif ($items.Count -gt 1) { $result = $items }
    $handlerFailed = $false
    if ($Job.OnSuccess) {
        try { & $Job.OnSuccess $result $Job }
        catch {
            $handlerFailed = $true
            $msg = "Post-processing error: $($_.Exception.Message)"
            if ($Job.Activity) { Set-Activity $Job.Activity 'Failed' $msg } else { Write-Log 'ERROR' $msg }
        }
    }
    if (-not $handlerFailed -and $Job.Activity -and $Job.Activity.Text -eq 'Running') {
        Set-Activity $Job.Activity 'Success' 'Completed.'
    }
}

function Stop-Jobs {
    param([switch]$IncludeQueued)
    if ($IncludeQueued) {
        while ($script:JobQueue.Count -gt 0) {
            $q = $script:JobQueue.Dequeue()
            if ($q.Activity) { Set-Activity $q.Activity 'Warning' 'Cancelled before it started.' }
            if ($q.OnFailure) { try { & $q.OnFailure 'Cancelled by user.' $q } catch { } }
        }
    }
    if ($script:CurrentJob) {
        $script:CurrentJob.Cancelled = $true
        try { [void]$script:CurrentJob.PS.BeginStop($null, $null) } catch { }
        if ($script:CurrentJob.Activity) { $script:CurrentJob.Activity.SubItems[4].Text = 'Cancelling...' }
    }
}

function Invoke-JobTick {
    if ($script:SigningIn -or $script:InJobTick) { return }
    $script:InJobTick = $true
    try {
        $job = $script:CurrentJob
        if ($job) {
            if ($job.Handle -and $job.Handle.IsCompleted) { Complete-Job $job }
            elseif ($job.Activity -and $job.Started) { $job.Activity.SubItems[2].Text = ('{0:N0}s' -f ((Get-Date) - $job.Started).TotalSeconds) }
        }
        if (-not $script:CurrentJob) { Start-NextJob }
        Update-BusyState
    } catch { Write-Log 'ERROR' "Job timer: $($_.Exception.Message)" }
    finally { $script:InJobTick = $false }
}

function Invoke-Safe {
    param([scriptblock]$Block, [string]$Context = 'UI action')
    try { & $Block }
    catch {
        Write-Activity 'Failed' $Context $_.Exception.Message
        Show-Message $_.Exception.Message $script:AppName 'OK' 'Error' | Out-Null
    }
}

function Close-WorkerRunspace {
    if ($script:WorkerClosed) { return }
    $script:WorkerClosed = $true
    try { if ($script:JobTimer) { $script:JobTimer.Stop() } } catch { }
    try { if ($script:PreviewTimer) { $script:PreviewTimer.Stop() } } catch { }
    try { if ($script:FilterTimer) { $script:FilterTimer.Stop() } } catch { }
    if (-not $script:Worker) { return }
    try {
        $deadline = (Get-Date).AddSeconds(6)
        while ($script:CurrentJob -and (Get-Date) -lt $deadline) {
            if ($script:CurrentJob.Handle -and $script:CurrentJob.Handle.IsCompleted) { Complete-Job $script:CurrentJob }
            else { Start-Sleep -Milliseconds 150 }
        }
    } catch { }
    try {
        $deadline = (Get-Date).AddSeconds(6)
        while ($script:Worker.RunspaceAvailability -ne 'Available' -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 150 }
        if ($script:Worker.RunspaceAvailability -eq 'Available') {
            $ps = [powershell]::Create()
            $ps.Runspace = $script:Worker
            [void]$ps.AddScript($script:WS_DisconnectAll.ToString())
            $handle = $ps.BeginInvoke()
            [void]$handle.AsyncWaitHandle.WaitOne(8000)
            try { $null = $ps.EndInvoke($handle) } catch { }
            $ps.Dispose()
        }
    } catch { }
    try { if ($script:Worker.RunspaceStateInfo.State -eq 'Opened') { $script:Worker.Close() } } catch { }
    try { $script:Worker.Dispose() } catch { }
}
#endregion

#region ---------- Connection dialogs ----------
function New-DialogForm([string]$Title, [int]$Width, [int]$Height) {
    $f = New-Object System.Windows.Forms.Form
    $f.Text = $Title
    $f.ClientSize = New-Object System.Drawing.Size($Width, $Height)
    $f.FormBorderStyle = 'FixedDialog'
    $f.StartPosition = 'CenterParent'
    $f.MaximizeBox = $false; $f.MinimizeBox = $false; $f.ShowInTaskbar = $false
    $f.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $f.BackColor = [System.Drawing.Color]::White
    return $f
}

function Add-DialogRow {
    param($Form, [string]$Label, [int]$Top, [switch]$Password)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Label; $l.Location = New-Object System.Drawing.Point(16, ($Top + 3)); $l.Size = New-Object System.Drawing.Size(180, 20)
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location = New-Object System.Drawing.Point(200, $Top); $t.Size = New-Object System.Drawing.Size(330, 23)
    if ($Password) { $t.UseSystemPasswordChar = $true }
    $Form.Controls.AddRange(@($l, $t))
    return $t
}

function Add-DialogButtons {
    param($Form, [string]$OkText, [int]$Top)
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = $OkText; $ok.Size = New-Object System.Drawing.Size(110, 30); $ok.Location = New-Object System.Drawing.Point(304, $Top)
    $ok.DialogResult = 'OK'; $ok.BackColor = [System.Drawing.Color]::FromArgb(37, 99, 235); $ok.ForeColor = [System.Drawing.Color]::White; $ok.FlatStyle = 'Flat'
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'; $cancel.Size = New-Object System.Drawing.Size(110, 30); $cancel.Location = New-Object System.Drawing.Point(420, $Top)
    $cancel.DialogResult = 'Cancel'
    $Form.Controls.AddRange(@($ok, $cancel))
    $Form.AcceptButton = $ok; $Form.CancelButton = $cancel
}

function Add-DialogNote {
    param($Form, [string]$Text, [int]$Top, [int]$Height = 48)
    $n = New-Object System.Windows.Forms.Label
    $n.Text = $Text; $n.Location = New-Object System.Drawing.Point(16, $Top); $n.Size = New-Object System.Drawing.Size(514, $Height)
    $n.ForeColor = [System.Drawing.Color]::FromArgb(71, 85, 105)
    $Form.Controls.Add($n)
}

function Show-ExoConnectDialog {
    $s = $script:Settings
    $dlg = New-DialogForm 'Connect to Exchange Online' 550 348
    $rbInter = New-Object System.Windows.Forms.RadioButton
    $rbInter.Text = 'Interactive sign-in (modern authentication / MFA)'; $rbInter.Location = New-Object System.Drawing.Point(16, 14); $rbInter.Size = New-Object System.Drawing.Size(510, 22)
    $rbCert = New-Object System.Windows.Forms.RadioButton
    $rbCert.Text = 'App-only (certificate based authentication)'; $rbCert.Location = New-Object System.Drawing.Point(16, 38); $rbCert.Size = New-Object System.Drawing.Size(510, 22)
    $dlg.Controls.AddRange(@($rbInter, $rbCert))
    $txtUpn = Add-DialogRow $dlg 'Admin UPN:' 74
    $txtOrg = Add-DialogRow $dlg 'Organization:' 106
    $txtApp = Add-DialogRow $dlg 'Application (client) ID:' 138
    $txtThumb = Add-DialogRow $dlg 'Certificate thumbprint:' 170
    Add-DialogNote $dlg "Listing and restoring requires the Mailbox Import Export role on the signing-in account, or the app's Exchange role assignment. New role assignments can take up to an hour to apply." 206 64
    Add-DialogButtons $dlg 'Connect' 286
    $txtUpn.Text = $s.AdminUpn; $txtOrg.Text = $s.Organization; $txtApp.Text = $s.ExoAppId; $txtThumb.Text = $s.ExoThumbprint
    $toggle = { $txtUpn.Enabled = $rbInter.Checked; $txtOrg.Enabled = $rbCert.Checked; $txtApp.Enabled = $rbCert.Checked; $txtThumb.Enabled = $rbCert.Checked }
    $rbInter.Add_CheckedChanged($toggle); $rbCert.Add_CheckedChanged($toggle)
    if ($s.ExoMethod -eq 'Certificate') { $rbCert.Checked = $true } else { $rbInter.Checked = $true }
    & $toggle
    while ($true) {
        if ($dlg.ShowDialog($script:Form) -ne 'OK') { $dlg.Dispose(); return $null }
        $method = if ($rbCert.Checked) { 'Certificate' } else { 'Interactive' }
        if ($method -eq 'Certificate') {
            $missing = @()
            if (-not $txtOrg.Text.Trim()) { $missing += 'Organization' }
            if (-not (Test-GuidText $txtApp.Text.Trim())) { $missing += 'a valid application ID' }
            $thumb = ($txtThumb.Text -replace '[^0-9A-Fa-f]', '')
            if ($thumb.Length -ne 40) { $missing += 'a 40-character certificate thumbprint' }
            if ($missing.Count) { Show-Message ("Required: " + ($missing -join ', ')) 'Missing information' 'OK' 'Warning' | Out-Null; continue }
        }
        break
    }
    $thumbClean = ($txtThumb.Text -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    $r = @{ Method = $method; Upn = $txtUpn.Text.Trim(); Organization = $txtOrg.Text.Trim(); AppId = $txtApp.Text.Trim(); Thumbprint = $thumbClean; ExchangeEnvironment = [string](Get-SelectedCloud).ExoEnvironment }
    $s.ExoMethod = $method; $s.AdminUpn = $r.Upn; $s.Organization = $r.Organization; $s.ExoAppId = $r.AppId; $s.ExoThumbprint = $r.Thumbprint
    Save-AppSettings
    $dlg.Dispose()
    return $r
}

function Show-GraphConnectDialog {
    $s = $script:Settings
    $dlg = New-DialogForm 'Connect to Microsoft Graph' 550 420
    $rbDevice = New-Object System.Windows.Forms.RadioButton
    $rbDevice.Text = 'Delegated - device code (admin needs Full Access to the mailbox)'; $rbDevice.Location = New-Object System.Drawing.Point(16, 12); $rbDevice.Size = New-Object System.Drawing.Size(520, 22)
    $rbCert = New-Object System.Windows.Forms.RadioButton
    $rbCert.Text = 'App-only - certificate'; $rbCert.Location = New-Object System.Drawing.Point(16, 36); $rbCert.Size = New-Object System.Drawing.Size(510, 22)
    $rbSecret = New-Object System.Windows.Forms.RadioButton
    $rbSecret.Text = 'App-only - client secret (not saved to disk)'; $rbSecret.Location = New-Object System.Drawing.Point(16, 60); $rbSecret.Size = New-Object System.Drawing.Size(510, 22)
    $dlg.Controls.AddRange(@($rbDevice, $rbCert, $rbSecret))
    $txtTenant = Add-DialogRow $dlg 'Tenant ID or domain:' 96
    $txtClient = Add-DialogRow $dlg 'Application (client) ID:' 128
    $txtThumb = Add-DialogRow $dlg 'Certificate thumbprint:' 160
    $txtSecret = Add-DialogRow $dlg 'Client secret:' 192 -Password
    Add-DialogNote $dlg "Delegated sign-in requests Mail.ReadWrite.Shared and User.Read for Office 365. The default client is Microsoft Graph Command Line Tools. App-only needs Mail.ReadWrite and User.Read.All with admin consent. The secret is kept in memory only." 228 78
    Add-DialogButtons $dlg 'Connect' 348
    $txtTenant.Text = $s.TenantId
    $txtClient.Text = if ($s.GraphClientId) { $s.GraphClientId } else { $script:DefaultGraphClientId }
    $txtThumb.Text = $s.GraphThumbprint
    $toggle = { $txtThumb.Enabled = $rbCert.Checked; $txtSecret.Enabled = $rbSecret.Checked; $txtTenant.Enabled = $true }
    foreach ($rb in $rbDevice, $rbCert, $rbSecret) { $rb.Add_CheckedChanged($toggle) }
    switch ($s.GraphMethod) { 'Certificate' { $rbCert.Checked = $true } 'Secret' { $rbSecret.Checked = $true } default { $rbDevice.Checked = $true } }
    & $toggle
    while ($true) {
        if ($dlg.ShowDialog($script:Form) -ne 'OK') { $dlg.Dispose(); return $null }
        $mode = if ($rbCert.Checked) { 'Certificate' } elseif ($rbSecret.Checked) { 'Secret' } else { 'DeviceCode' }
        $missing = @()
        if (-not (Test-GuidText $txtClient.Text.Trim())) { $missing += 'a valid application ID' }
        if ($mode -ne 'DeviceCode' -and -not $txtTenant.Text.Trim()) { $missing += 'Tenant' }
        if ($mode -eq 'Certificate') {
            $thumb = ($txtThumb.Text -replace '[^0-9A-Fa-f]', '')
            if ($thumb.Length -ne 40) { $missing += 'a 40-character certificate thumbprint' }
        }
        if ($mode -eq 'Secret' -and -not $txtSecret.Text) { $missing += 'Client secret' }
        if ($missing.Count) { Show-Message ("Required: " + ($missing -join ', ')) 'Missing information' 'OK' 'Warning' | Out-Null; continue }
        break
    }
    $tenant = $txtTenant.Text.Trim(); if (-not $tenant) { $tenant = 'organizations' }
    $r = @{
        Mode = $mode; TenantId = $tenant; ClientId = $txtClient.Text.Trim()
        Thumbprint = ($txtThumb.Text -replace '[^0-9A-Fa-f]', '').ToUpperInvariant(); Secret = $txtSecret.Text
        LoginBase = [string](Get-SelectedCloud).Login; GraphBase = [string](Get-SelectedCloud).Graph
    }
    $s.GraphMethod = $mode; $s.TenantId = $txtTenant.Text.Trim(); $s.GraphClientId = $r.ClientId; $s.GraphThumbprint = $r.Thumbprint
    Save-AppSettings
    $dlg.Dispose()
    return $r
}

function Show-SignInDialog {
    $s = $script:Settings
    $dlg = New-DialogForm 'Sign in to Office 365' 560 318
    $intro = New-Object System.Windows.Forms.Label
    $intro.Text = 'Microsoft Graph opens its sign-in window here. Exchange Online then opens in your browser. Use the admin account that can manage the mailbox.'
    $intro.Location = New-Object System.Drawing.Point(16, 12); $intro.Size = New-Object System.Drawing.Size(528, 48)
    $intro.ForeColor = [System.Drawing.Color]::FromArgb(71, 85, 105)
    $dlg.Controls.Add($intro)
    $txtUpn = Add-DialogRow $dlg 'Account (optional):' 68
    $txtUpn.Text = $s.AdminUpn
    $chkExo = New-Object System.Windows.Forms.CheckBox
    $chkExo.Text = 'Exchange Online  —  find and restore mailbox items'
    $chkExo.Location = New-Object System.Drawing.Point(16, 108); $chkExo.Size = New-Object System.Drawing.Size(520, 22); $chkExo.Checked = (Get-SettingFlag 'SignInExo' $true)
    $chkGraph = New-Object System.Windows.Forms.CheckBox
    $chkGraph.Text = 'Microsoft Graph  —  preview, exact folder, and verification'
    $chkGraph.Location = New-Object System.Drawing.Point(16, 134); $chkGraph.Size = New-Object System.Drawing.Size(520, 22); $chkGraph.Checked = (Get-SettingFlag 'SignInGraph' $true)
    $dlg.Controls.AddRange(@($chkExo, $chkGraph))
    Add-DialogNote $dlg "Leave the account blank to pick it in the Microsoft window. Graph needs Full Access to the mailbox you restore. This connects to Office 365 and Azure." 166 48
    Add-DialogButtons $dlg 'Sign in' 246
    $adv = New-Object System.Windows.Forms.Button
    $adv.Text = 'Advanced'; $adv.Size = New-Object System.Drawing.Size(110, 30); $adv.Location = New-Object System.Drawing.Point(16, 246)
    $adv.DialogResult = 'Ignore'
    $dlg.Controls.Add($adv)
    while ($true) {
        $answer = $dlg.ShowDialog($script:Form)
        if ($answer -eq 'Ignore') { $dlg.Dispose(); return 'Advanced' }
        if ($answer -ne 'OK') { $dlg.Dispose(); return $null }
        $upn = $txtUpn.Text.Trim()
        if (-not $chkExo.Checked -and -not $chkGraph.Checked) { Show-Message 'Select Exchange Online, Microsoft Graph, or both.' 'Sign in' 'OK' 'Warning' | Out-Null; continue }
        if ($upn -and $upn -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { Show-Message 'Enter the account as an email address, or leave it blank.' 'Sign in' 'OK' 'Warning' | Out-Null; continue }
        break
    }
    $cloud = Get-SelectedCloud
    $r = @{
        Upn = $txtUpn.Text.Trim()
        ConnectExo = [bool]$chkExo.Checked
        ConnectGraph = [bool]$chkGraph.Checked
        LoginBase = [string]$cloud.Login
        GraphBase = [string]$cloud.Graph
    }
    $s.AdminUpn = $r.Upn
    $s.SignInExo = [string]$r.ConnectExo
    $s.SignInGraph = [string]$r.ConnectGraph
    $s.GraphMethod = 'Interactive'
    $s.ExoMethod = 'Interactive'
    Save-AppSettings
    $dlg.Dispose()
    return $r
}

function Show-AdvancedSignIn {
    $dlg = New-DialogForm 'Advanced sign-in' 460 168
    $rbExo = New-Object System.Windows.Forms.RadioButton
    $rbExo.Text = 'Exchange Online (interactive or certificate)'; $rbExo.Location = New-Object System.Drawing.Point(16, 16); $rbExo.Size = New-Object System.Drawing.Size(420, 22); $rbExo.Checked = $true
    $rbGraph = New-Object System.Windows.Forms.RadioButton
    $rbGraph.Text = 'Microsoft Graph (device code, certificate, or secret)'; $rbGraph.Location = New-Object System.Drawing.Point(16, 44); $rbGraph.Size = New-Object System.Drawing.Size(420, 22)
    $dlg.Controls.AddRange(@($rbExo, $rbGraph))
    Add-DialogButtons $dlg 'Continue' 96
    $ok = $dlg.ShowDialog($script:Form)
    $graph = [bool]$rbGraph.Checked
    $dlg.Dispose()
    if ($ok -ne 'OK') { return }
    if ($graph) { Invoke-ConnectGraph } else { Invoke-ConnectExo }
}
#endregion

#region ---------- Main window ----------
$script:FontUi = New-Object System.Drawing.Font('Segoe UI', 9)
$script:FontBold = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$script:ColAccent = [System.Drawing.Color]::FromArgb(37, 99, 235)
$script:ColGreen = [System.Drawing.Color]::FromArgb(22, 163, 74)
$script:ColMuted = [System.Drawing.Color]::FromArgb(71, 85, 105)
$script:ColBg = [System.Drawing.Color]::FromArgb(248, 250, 252)
$script:tip = New-Object System.Windows.Forms.ToolTip
$script:tipPreview = $script:tip

function New-Sz([int]$W, [int]$H) { New-Object System.Drawing.Size($W, $H) }
function New-Button {
    param([string]$Text, [int]$Width = 120, [switch]$Primary, [switch]$Success)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text; $b.Size = New-Sz $Width 28; $b.Margin = New-Object System.Windows.Forms.Padding(3, 4, 6, 3)
    $b.FlatStyle = 'Flat'; $b.UseVisualStyleBackColor = $false
    if ($Primary -or $Success) {
        $b.BackColor = if ($Success) { $script:ColGreen } else { $script:ColAccent }
        $b.ForeColor = [System.Drawing.Color]::White; $b.FlatAppearance.BorderSize = 0; $b.Font = $script:FontBold
    } else {
        $b.BackColor = [System.Drawing.Color]::White; $b.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(203, 213, 225); $b.Font = $script:FontUi
    }
    return $b
}
function New-FlowLabel([string]$Text, [switch]$Bold) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text; $l.AutoSize = $true; $l.Margin = New-Object System.Windows.Forms.Padding(3, 8, 3, 0)
    if ($Bold) { $l.Font = $script:FontBold } else { $l.Font = $script:FontUi }
    return $l
}
function Set-StatusLabel($Label, [string]$Kind, [string]$Text) {
    if (-not $Label) { return }
    $Label.Image = $script:Icons[$Kind]
    $Label.Text = '      ' + $Text
    $Label.ForeColor = switch ($Kind) {
        'Success' { [System.Drawing.Color]::FromArgb(21, 128, 61) }
        'Failed' { [System.Drawing.Color]::FromArgb(185, 28, 28) }
        'Warning' { [System.Drawing.Color]::FromArgb(180, 83, 9) }
        default { $script:ColMuted }
    }
    try { if ($script:tip) { $script:tip.SetToolTip($Label, $Text) } } catch { }
}
function New-StatusLabel([string]$Text, [int]$Width = 230) {
    $l = New-Object System.Windows.Forms.Label
    $l.AutoSize = $false; $l.Size = New-Sz $Width 24; $l.Margin = New-Object System.Windows.Forms.Padding(3, 6, 8, 0)
    $l.ImageAlign = 'MiddleLeft'; $l.TextAlign = 'MiddleLeft'; $l.AutoEllipsis = $true; $l.Font = $script:FontUi
    Set-StatusLabel $l 'Disconnected' $Text
    return $l
}
function New-Flow {
    $f = New-Object System.Windows.Forms.FlowLayoutPanel
    $f.Dock = 'Top'; $f.Height = 36; $f.WrapContents = $false; $f.AutoScroll = $false
    $f.Padding = New-Object System.Windows.Forms.Padding(4, 0, 4, 0)
    return $f
}
function New-Group([string]$Text, [string]$Dock, [int]$Height = 0) {
    $g = New-Object System.Windows.Forms.GroupBox
    $g.Text = $Text; $g.Dock = $Dock; $g.Font = $script:FontBold
    $g.Padding = New-Object System.Windows.Forms.Padding(6, 2, 6, 4)
    if ($Height) { $g.Height = $Height }
    return $g
}

$script:Form = New-Object System.Windows.Forms.Form
$Form = $script:Form
$Form.Text = "$script:AppName  v$script:AppVersion"
$Form.Size = New-Sz 1500 960
$Form.MinimumSize = New-Sz 1240 800
$Form.StartPosition = 'CenterScreen'
$Form.Font = $script:FontUi
$Form.BackColor = $script:ColBg
$Form.KeyPreview = $true
try {
    $iconBmp = New-StatusBitmap -Kind 'Mail' -Size 32
    $script:FormIcon = [System.Drawing.Icon]::FromHandle($iconBmp.GetHicon())
    $Form.Icon = $script:FormIcon
} catch { }

$menu = New-Object System.Windows.Forms.MenuStrip
$miFile = $menu.Items.Add('File')
$miEdit = $menu.Items.Add('Edit')
$miHelp = $menu.Items.Add('Help')
$script:miConnectExo = $miFile.DropDownItems.Add('Sign in...')
$script:miConnectGraph = $miFile.DropDownItems.Add('Advanced sign-in...')
$script:miDisconnect = $miFile.DropDownItems.Add('Disconnect')
[void]$miFile.DropDownItems.Add('-')
$script:miExport = $miFile.DropDownItems.Add('Export results')
$script:miOpenLog = $miFile.DropDownItems.Add('Open log file')
$script:miOpenFolder = $miFile.DropDownItems.Add('Open log folder')
[void]$miFile.DropDownItems.Add('-')
$script:miExit = $miFile.DropDownItems.Add('Exit')
$script:miCheckAll = $miEdit.DropDownItems.Add('Check visible rows')
$script:miUncheckAll = $miEdit.DropDownItems.Add('Uncheck visible rows')
$script:miCopyIdMenu = $miEdit.DropDownItems.Add('Copy EntryID')
$script:miCopySubMenu = $miEdit.DropDownItems.Add('Copy subject')
$script:miCopyDiag = $miEdit.DropDownItems.Add('Copy diagnostics')
$script:miRequirements = $miHelp.DropDownItems.Add('Requirements')
$script:miAbout = $miHelp.DropDownItems.Add('About')
$Form.MainMenuStrip = $menu

$banner = New-Object System.Windows.Forms.Panel
$banner.Dock = 'Top'; $banner.Height = 52; $banner.BackColor = [System.Drawing.Color]::FromArgb(15, 23, 42)
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = $script:AppName; $lblTitle.ForeColor = [System.Drawing.Color]::White
$lblTitle.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 14); $lblTitle.AutoSize = $true; $lblTitle.Location = New-Object System.Drawing.Point(14, 4)
$lblSub = New-Object System.Windows.Forms.Label
$lblSub.Text = 'Find, preview and restore items from Recoverable Items (Deletions, Purges, DiscoveryHolds) and Deleted Items'
$lblSub.ForeColor = [System.Drawing.Color]::FromArgb(148, 163, 184); $lblSub.AutoSize = $true; $lblSub.Location = New-Object System.Drawing.Point(16, 28)
$banner.Controls.AddRange(@($lblTitle, $lblSub))

$grpConnect = New-Group '1. Connect' 'Top' 64
$flowConnect = New-Flow
$script:btnConnectExo = New-Button 'Sign in' 96 -Primary
$script:lblExo = New-StatusLabel 'Exchange Online: not connected' 250
$script:lblGraph = New-StatusLabel 'Graph: not connected' 230
$script:btnConnectGraph = New-Button 'Advanced' 90
$script:btnDisconnect = New-Button 'Disconnect' 96
$flowConnect.Controls.AddRange(@($btnConnectExo, $lblExo, $lblGraph, $btnConnectGraph, $btnDisconnect))
$grpConnect.Controls.Add($flowConnect)

$grpTarget = New-Group '2. Target mailbox' 'Top' 64
$flowTarget = New-Flow
$script:txtMailbox = New-Object System.Windows.Forms.ComboBox
$txtMailbox.DropDownStyle = 'DropDown'; $txtMailbox.Width = 280; $txtMailbox.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 3); $txtMailbox.Font = $script:FontUi
foreach ($hist in @($script:Settings.MailboxHistory -split ';' | Where-Object { $_ })) { [void]$txtMailbox.Items.Add($hist) }
$txtMailbox.Text = [string]$script:Settings.LastMailbox
$script:btnResolve = New-Button 'Resolve mailbox' 124 -Primary
$script:btnHoldDetails = New-Button 'Hold details' 100
$btnHoldDetails.Enabled = $false
$script:lblMailbox = New-StatusLabel 'No mailbox selected' 460
$flowTarget.Controls.AddRange(@((New-FlowLabel 'User (UPN / email):'), $txtMailbox, $btnResolve, $btnHoldDetails, $lblMailbox))
$grpTarget.Controls.Add($flowTarget)

$grpSearch = New-Group '3. Find items' 'Top' 100
$flowSearch1 = New-Flow
$script:cboSource = New-Object System.Windows.Forms.ComboBox
$cboSource.DropDownStyle = 'DropDownList'; $cboSource.Width = 250; $cboSource.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 3)
[void]$cboSource.Items.Add('All held locations')
foreach ($k in $script:SourceFolderNames.Keys) { [void]$cboSource.Items.Add($script:SourceFolderNames[$k]) }
$srcIdx = 0; try { $srcIdx = [int]$script:Settings.LastSource } catch { $srcIdx = 0 }
if ($srcIdx -lt 0 -or $srcIdx -ge $cboSource.Items.Count) { $srcIdx = 0 }
$cboSource.SelectedIndex = $srcIdx
$script:cboType = New-Object System.Windows.Forms.ComboBox
$cboType.DropDownStyle = 'DropDownList'; $cboType.Width = 130; $cboType.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 3)
$script:ItemTypes = [ordered]@{ 'Email' = 'IPM.Note'; 'All item types' = ''; 'Calendar' = 'IPM.Appointment'; 'Contact' = 'IPM.Contact'; 'Task' = 'IPM.Task' }
$typeIdx = 0; $ti = 0
foreach ($k in $script:ItemTypes.Keys) {
    [void]$cboType.Items.Add($k)
    if ($k -eq [string]$script:Settings.LastItemType) { $typeIdx = $ti }
    $ti++
}
$cboType.SelectedIndex = $typeIdx
$script:txtSubject = New-Object System.Windows.Forms.TextBox
$txtSubject.Width = 200; $txtSubject.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 3)
$script:btnSearch = New-Button 'Search' 100 -Primary
$flowSearch1.Controls.AddRange(@((New-FlowLabel 'Location:'), $cboSource, (New-FlowLabel 'Type:'), $cboType, (New-FlowLabel 'Subject contains:'), $txtSubject, $btnSearch))
$flowSearch2 = New-Flow
$script:dtStart = New-Object System.Windows.Forms.DateTimePicker
$dtStart.Format = 'Short'; $dtStart.ShowCheckBox = $true; $dtStart.Checked = $false; $dtStart.Width = 120; $dtStart.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 3)
$dtStart.Value = (Get-Date).AddDays(-30)
$script:dtEnd = New-Object System.Windows.Forms.DateTimePicker
$dtEnd.Format = 'Short'; $dtEnd.ShowCheckBox = $true; $dtEnd.Checked = $false; $dtEnd.Width = 120; $dtEnd.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 3)
$script:nudMax = New-Object System.Windows.Forms.NumericUpDown
$nudMax.Minimum = 1; $nudMax.Maximum = 100000; $nudMax.Value = 1000; $nudMax.Width = 75; $nudMax.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 3)
$script:txtEntryId = New-Object System.Windows.Forms.TextBox
$txtEntryId.Width = 280; $txtEntryId.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 3)
$flowSearch2.Controls.AddRange(@((New-FlowLabel 'Modified from:'), $dtStart, (New-FlowLabel 'to'), $dtEnd, (New-FlowLabel 'Max / folder:'), $nudMax, (New-FlowLabel 'EntryID:'), $txtEntryId))
$grpSearch.Controls.Add($flowSearch2)
$grpSearch.Controls.Add($flowSearch1)

$split = New-Object System.Windows.Forms.SplitContainer
$script:split = $split
$split.Dock = 'Fill'; $split.Orientation = 'Vertical'; $split.SplitterWidth = 6; $split.BackColor = $script:ColBg

$grpResults = New-Group '4. Items found - tick the items to restore' 'Fill'
$flowResTools = New-Flow
$script:btnCheckAll = New-Button 'Check all' 85
$script:btnUncheckAll = New-Button 'Uncheck all' 96
$script:txtFilter = New-Object System.Windows.Forms.TextBox
$txtFilter.Width = 220; $txtFilter.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 3)
$script:lblCount = New-FlowLabel 'No search yet'
$flowResTools.Controls.AddRange(@($btnCheckAll, $btnUncheckAll, (New-FlowLabel 'Filter list:'), $txtFilter, $lblCount))
$script:lvResults = New-Object System.Windows.Forms.ListView
$lvResults.Dock = 'Fill'; $lvResults.View = 'Details'; $lvResults.CheckBoxes = $true; $lvResults.FullRowSelect = $true
$lvResults.HideSelection = $false; $lvResults.MultiSelect = $true; $lvResults.GridLines = $false; $lvResults.Font = $script:FontUi
$lvResults.SmallImageList = $script:ImageList
$script:ResultColumnNames = @('Subject', 'Location', 'Original folder', 'Folder exists', 'Type', 'Last modified', 'Restore status')
$script:ResultColumnWidths = @(300, 200, 190, 90, 95, 130, 280)
for ($i = 0; $i -lt $script:ResultColumnNames.Count; $i++) { [void]$lvResults.Columns.Add($script:ResultColumnNames[$i], $script:ResultColumnWidths[$i]) }
$script:ResultSorter = New-Object MrcListViewSorter
$lvResults.ListViewItemSorter = $script:ResultSorter
$lvResults.Sorting = 'None'
Enable-ControlBuffer $lvResults
$script:ctxResults = New-Object System.Windows.Forms.ContextMenuStrip
$script:miPreview = $ctxResults.Items.Add('Load full preview')
$script:miCopyId = $ctxResults.Items.Add('Copy EntryID')
$script:miCopySubj = $ctxResults.Items.Add('Copy subject')
$script:miCopyInternet = $ctxResults.Items.Add('Copy internet message ID')
[void]$ctxResults.Items.Add('-')
$script:miCheckSel = $ctxResults.Items.Add('Check selected rows')
$lvResults.ContextMenuStrip = $ctxResults
$grpResults.Controls.Add($lvResults)
$grpResults.Controls.Add($flowResTools)
$split.Panel1.Controls.Add($grpResults)

$grpPreview = New-Group 'Preview' 'Fill'
$tblHeader = New-Object System.Windows.Forms.TableLayoutPanel
$tblHeader.Dock = 'Top'; $tblHeader.AutoSize = $true; $tblHeader.ColumnCount = 2; $tblHeader.Padding = New-Object System.Windows.Forms.Padding(4)
[void]$tblHeader.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Absolute', 110)))
[void]$tblHeader.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
$script:PreviewFields = [ordered]@{}
foreach ($name in 'Subject', 'From', 'To', 'Cc', 'Sent', 'Location', 'Original folder', 'Attachments') {
    $k = New-Object System.Windows.Forms.Label
    $k.Text = "$($name):"; $k.Font = $script:FontBold; $k.AutoSize = $true; $k.Margin = New-Object System.Windows.Forms.Padding(2, 2, 2, 2); $k.ForeColor = $script:ColMuted
    $v = New-Object System.Windows.Forms.Label
    $v.Text = ''; $v.Font = $script:FontUi; $v.AutoSize = $false; $v.AutoEllipsis = $true; $v.Dock = 'Fill'; $v.Height = 18; $v.Margin = New-Object System.Windows.Forms.Padding(2, 2, 2, 2)
    $tblHeader.RowCount++
    [void]$tblHeader.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize')))
    $tblHeader.Controls.Add($k, 0, $tblHeader.RowCount - 1)
    $tblHeader.Controls.Add($v, 1, $tblHeader.RowCount - 1)
    $script:PreviewFields[$name] = $v
}
$script:PreviewFields['Subject'].Font = $script:FontBold
$flowPrevTools = New-Flow
$script:btnPreview = New-Button 'Load full preview' 130
$script:chkAutoPreview = New-Object System.Windows.Forms.CheckBox
$chkAutoPreview.Text = 'Auto-load'; $chkAutoPreview.AutoSize = $true; $chkAutoPreview.Checked = (Get-SettingFlag 'AutoPreview' $true); $chkAutoPreview.Margin = New-Object System.Windows.Forms.Padding(6, 8, 3, 0)
$script:chkPlain = New-Object System.Windows.Forms.CheckBox
$chkPlain.Text = 'Plain text'; $chkPlain.AutoSize = $true; $chkPlain.Checked = (Get-SettingFlag 'PlainPreview' $false); $chkPlain.Margin = New-Object System.Windows.Forms.Padding(6, 8, 3, 0)
$script:chkRemote = New-Object System.Windows.Forms.CheckBox
$chkRemote.Text = 'Remote images'; $chkRemote.AutoSize = $true; $chkRemote.Checked = (Get-SettingFlag 'RemoteImages' $false); $chkRemote.Margin = New-Object System.Windows.Forms.Padding(6, 8, 3, 0)
$script:lblPreviewState = New-StatusLabel 'Select an item' 180
$flowPrevTools.Controls.AddRange(@($btnPreview, $chkAutoPreview, $chkPlain, $chkRemote, $lblPreviewState))
$script:web = New-Object System.Windows.Forms.WebBrowser
$web.Dock = 'Fill'; $web.ScriptErrorsSuppressed = $true; $web.AllowWebBrowserDrop = $false
$web.WebBrowserShortcutsEnabled = $false; $web.IsWebBrowserContextMenuEnabled = $false; $web.AllowNavigation = $true
$grpPreview.Controls.Add($web)
$grpPreview.Controls.Add($flowPrevTools)
$grpPreview.Controls.Add($tblHeader)
$split.Panel2.Controls.Add($grpPreview)

$grpRestore = New-Group '5. Restore' 'Bottom' 118
$flowRestore = New-Object System.Windows.Forms.FlowLayoutPanel
$flowRestore.Dock = 'Fill'; $flowRestore.WrapContents = $true
$script:rbOriginal = New-Object System.Windows.Forms.RadioButton
$rbOriginal.Text = 'Original location'; $rbOriginal.AutoSize = $true; $rbOriginal.Checked = $true; $rbOriginal.Margin = New-Object System.Windows.Forms.Padding(3, 8, 10, 0)
$script:rbExFolder = New-Object System.Windows.Forms.RadioButton
$rbExFolder.Text = 'Specified folder (Exchange)'; $rbExFolder.AutoSize = $true; $rbExFolder.Margin = New-Object System.Windows.Forms.Padding(3, 8, 10, 0)
$script:rbGraphMove = New-Object System.Windows.Forms.RadioButton
$rbGraphMove.Text = 'Exact folder (Graph move)'; $rbGraphMove.AutoSize = $true; $rbGraphMove.Enabled = $false; $rbGraphMove.Margin = New-Object System.Windows.Forms.Padding(3, 8, 10, 0)
$script:cboFolder = New-Object System.Windows.Forms.ComboBox
$cboFolder.DropDownStyle = 'DropDown'; $cboFolder.Width = 280; $cboFolder.Margin = New-Object System.Windows.Forms.Padding(3, 6, 3, 3)
$cboFolder.AutoCompleteMode = 'SuggestAppend'; $cboFolder.AutoCompleteSource = 'ListItems'
$cboFolder.Text = [string]$script:Settings.LastFolder
$script:btnLoadFolders = New-Button 'Load folders' 100
$script:chkVerify = New-Object System.Windows.Forms.CheckBox
$chkVerify.Text = 'Verify after restore'; $chkVerify.AutoSize = $true; $chkVerify.Checked = (Get-SettingFlag 'VerifyRestore' $true); $chkVerify.Margin = New-Object System.Windows.Forms.Padding(8, 8, 8, 0)
$script:btnRestore = New-Button 'Restore checked items' 176 -Success
$script:btnCancel = New-Button 'Cancel' 80
$btnCancel.Enabled = $false
$script:lblRestoreHint = New-Object System.Windows.Forms.Label
$lblRestoreHint.AutoSize = $false; $lblRestoreHint.Size = New-Sz 900 34; $lblRestoreHint.ForeColor = $script:ColMuted; $lblRestoreHint.Margin = New-Object System.Windows.Forms.Padding(6, 0, 3, 0)
$flowRestore.Controls.AddRange(@($rbOriginal, $rbExFolder, $rbGraphMove, (New-FlowLabel 'Folder:'), $cboFolder, $btnLoadFolders, $chkVerify, $btnRestore, $btnCancel, $lblRestoreHint))
$flowRestore.SetFlowBreak($btnCancel, $true)
foreach ($c in $flowRestore.Controls) { if ($c -ne $btnRestore -and $c.Font -ne $script:FontBold) { $c.Font = $script:FontUi } }
$grpRestore.Controls.Add($flowRestore)

$grpActivity = New-Group 'Activity and status' 'Bottom' 200
$flowActTools = New-Flow
$script:btnOpenLog = New-Button 'Open log file' 110
$script:btnExport = New-Button 'Export results (CSV)' 150
$script:btnClearAct = New-Button 'Clear activity' 110
$script:lblSummary = New-StatusLabel 'Ready' 520
$flowActTools.Controls.AddRange(@($btnOpenLog, $btnExport, $btnClearAct, $lblSummary))
$script:lvActivity = New-Object System.Windows.Forms.ListView
$lvActivity.Dock = 'Fill'; $lvActivity.View = 'Details'; $lvActivity.FullRowSelect = $true; $lvActivity.Font = $script:FontUi
$lvActivity.SmallImageList = $script:ImageList
foreach ($col in @(@('Status', 95), @('Time', 70), @('Duration', 70), @('Action', 280), @('Details', 820))) { [void]$lvActivity.Columns.Add($col[0], $col[1]) }
Enable-ControlBuffer $lvActivity
$grpActivity.Controls.Add($lvActivity)
$grpActivity.Controls.Add($flowActTools)

$strip = New-Object System.Windows.Forms.StatusStrip
$strip.SizingGrip = $true
$script:tsStatus = New-Object System.Windows.Forms.ToolStripStatusLabel
$tsStatus.Spring = $true; $tsStatus.TextAlign = 'MiddleLeft'; $tsStatus.Text = 'Ready'
$script:tsProgress = New-Object System.Windows.Forms.ToolStripProgressBar
$tsProgress.Style = 'Marquee'; $tsProgress.MarqueeAnimationSpeed = 30; $tsProgress.Visible = $false; $tsProgress.Width = 180
$script:tsLog = New-Object System.Windows.Forms.ToolStripStatusLabel
$tsLog.Text = "Log: $script:LogPath"; $tsLog.ForeColor = $script:ColMuted
[void]$strip.Items.AddRange(@($tsStatus, $tsProgress, $tsLog))

$Form.Controls.Add($split)
$Form.Controls.Add($grpRestore)
$Form.Controls.Add($grpActivity)
$Form.Controls.Add($strip)
$Form.Controls.Add($grpSearch)
$Form.Controls.Add($grpTarget)
$Form.Controls.Add($grpConnect)
$Form.Controls.Add($banner)
$Form.Controls.Add($menu)

$tip.SetToolTip($rbOriginal, 'Restore-RecoverableItems returns the item to the folder it was deleted from. If that folder is gone, Exchange uses the default folder (Inbox).')
$tip.SetToolTip($rbExFolder, 'Restore-RecoverableItems -RestoreTargetFolder. Use a backslash or slash path such as Inbox\Recovered. Exchange may recreate the original subfolder under the target.')
$tip.SetToolTip($rbGraphMove, 'Microsoft Graph moves the item into this exact folder path and creates missing folders. DiscoveryHolds and Purges often refuse a move.')
$tip.SetToolTip($chkVerify, 'After each restore, confirm the item by internet message ID or subject, or confirm that it left Deletions or Deleted Items.')
$tip.SetToolTip($cboFolder, 'Folder path relative to the mailbox root. Load folders fills this list from the mailbox.')
$tip.SetToolTip($txtEntryId, 'When set, search ignores subject, type and dates and looks up this EntryID directly.')
$tip.SetToolTip($txtSubject, 'Leave this blank, or type *, to search every item. A word matches any subject that contains it. With no subject and no dates, the search covers items modified since 1990-01-01, up to Max / folder.')
$tip.SetToolTip($btnConnectExo, 'Opens the Microsoft sign-in window for Office 365 and the Microsoft Graph module.')
$tip.SetToolTip($btnConnectGraph, 'Certificate, client secret, or device-code sign-in.')
$tip.SetToolTip($chkPlain, 'Show the message as text instead of sanitized HTML.')
$tip.SetToolTip($chkRemote, 'HTML preview blocks remote images unless this is ticked.')
$script:LoadingSettings = $false
#endregion

#region ---------- UI state ----------
function Test-Busy {
    if ($script:SigningIn) { return $true }
    if ($script:CurrentJob -and -not $script:CurrentJob.Quiet) { return $true }
    foreach ($q in @($script:JobQueue)) { if (-not $q.Quiet) { return $true } }
    return $false
}
function Update-BusyState {
    $busy = Test-Busy
    foreach ($b in @($script:btnConnectExo, $script:btnConnectGraph, $script:btnDisconnect, $script:btnResolve, $script:btnSearch, $script:btnRestore, $script:btnLoadFolders)) {
        if ($b) { $b.Enabled = -not $busy }
    }
    if ($script:btnLoadFolders -and -not $busy) { $script:btnLoadFolders.Enabled = -not $script:rbOriginal.Checked }
    if ($script:btnCancel) { $script:btnCancel.Enabled = $busy }
    if ($script:btnPreview) { $script:btnPreview.Enabled = [bool]$script:State.GraphConnected }
    $batch = $script:State.Batch
    if ($script:tsProgress) {
        if ($batch -and $batch.Total -gt 0) {
            $script:tsProgress.Style = 'Continuous'
            $script:tsProgress.Minimum = 0
            $script:tsProgress.Maximum = [int]$batch.Total
            $script:tsProgress.Value = [Math]::Min([int]$batch.Done, [int]$batch.Total)
            $script:tsProgress.Visible = $true
        } elseif ($busy) {
            $script:tsProgress.Style = 'Marquee'
            $script:tsProgress.MarqueeAnimationSpeed = 30
            $script:tsProgress.Visible = $true
        } else { $script:tsProgress.Visible = $false }
    }
    if ($script:tsStatus) {
        if ($script:CurrentJob -and -not $script:CurrentJob.Quiet -and $script:CurrentJob.Started) {
            $queued = @($script:JobQueue | Where-Object { -not $_.Quiet }).Count
            $suffix = if ($queued) { "  ($queued more queued)" } else { '' }
            $script:tsStatus.Text = ('Working: {0}  [{1:N0}s]{2}' -f $script:CurrentJob.Name, ((Get-Date) - $script:CurrentJob.Started).TotalSeconds, $suffix)
        } elseif (-not $busy) { $script:tsStatus.Text = 'Ready' }
    }
}
function Update-RestoreHint {
    $script:cboFolder.Enabled = -not $script:rbOriginal.Checked
    if (-not (Test-Busy)) { $script:btnLoadFolders.Enabled = -not $script:rbOriginal.Checked }
    $script:lblRestoreHint.Text = if ($script:rbOriginal.Checked) {
        'Items go back to the folder they were deleted from. If that folder no longer exists, Exchange restores them to Inbox.'
    } elseif ($script:rbExFolder.Checked) {
        'Exchange restores into the folder you name (created if missing). This works for DiscoveryHolds and Purges. The original subfolder may be recreated underneath it.'
    } else {
        'Microsoft Graph moves the item to this exact path and creates missing folders. Held items in DiscoveryHolds or Purges may refuse the move.'
    }
}
function Update-GraphMoveState {
    $ok = [bool]($script:State.GraphConnected -and $script:State.GraphCanWrite)
    $script:rbGraphMove.Enabled = $ok
    if (-not $ok -and $script:rbGraphMove.Checked) { $script:rbOriginal.Checked = $true }
    Update-RestoreHint
}
function Get-HoldSummary($Mbx) {
    if (-not $Mbx) { return '' }
    $parts = @()
    if ($Mbx.LitigationHoldEnabled) { $parts += 'Litigation hold' }
    $n = @($Mbx.InPlaceHolds | Where-Object { $_ }).Count
    if ($n) { $parts += "$n Purview/In-Place hold(s)" }
    if ($Mbx.ComplianceTagHold) { $parts += 'Retention label hold' }
    if ($Mbx.DelayHold) { $parts += 'Delay hold' }
    if ($parts.Count -eq 0) { return 'No holds' }
    return ($parts -join ', ')
}
function Set-ItemRestoreStatus {
    param($Data, [string]$State, [string]$Text)
    if (-not $Data) { return }
    $Data.RestoreState = $State
    $Data.RestoreText = $Text
    $lvi = $Data.ListItem
    if ($lvi -and $lvi.ListView) {
        $lvi.ImageKey = $State
        $lvi.SubItems[6].Text = $Text
        Set-ActivityColor $lvi $State
        if ($State -eq 'Success') { $lvi.Checked = $false }
    }
}
function Format-ItemType([string]$ItemClass) {
    switch -Wildcard ($ItemClass) {
        'IPM.Note*' { 'Email' }
        'IPM.Appointment*' { 'Calendar' }
        'IPM.Schedule*' { 'Meeting' }
        'IPM.Contact*' { 'Contact' }
        'IPM.Task*' { 'Task' }
        'IPM.StickyNote*' { 'Note' }
        '' { '' }
        default { $ItemClass }
    }
}
function Set-ClipboardText([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return }
    try { [System.Windows.Forms.Clipboard]::SetText($Text) }
    catch { Show-Message "Could not copy to the clipboard.`r`n$($_.Exception.Message)" $script:AppName 'OK' 'Warning' | Out-Null }
}
function Get-DiagnosticsText {
    $m = $script:State.Mailbox
    $mbx = if ($m) { "$($m.DisplayName) <$($m.PrimarySmtpAddress)> $(Get-HoldSummary $m); single-item recovery=$($m.SingleItemRecovery)" } else { '(none)' }
    return @"
$script:AppName $script:AppVersion
Computer: $env:COMPUTERNAME
User: $env:USERDOMAIN\$env:USERNAME
PowerShell: $($PSVersionTable.PSVersion)
Culture: $((Get-Culture).Name)
Service: Office 365 and Azure
Exchange Online: connected=$($script:State.ExoConnected); identity=$($script:State.ExoIdentity); canRestore=$($script:State.CanRestore); module=$($script:State.ExoVersion)
Graph: connected=$($script:State.GraphConnected); identity=$($script:State.GraphIdentity); canWrite=$($script:State.GraphCanWrite)
Mailbox: $mbx
Log: $script:LogPath
"@
}
function Add-MailboxHistory([string]$Value) {
    if (-not $Value) { return }
    $items = @($script:Settings.MailboxHistory -split ';' | Where-Object { $_ -and $_ -ne $Value })
    $items = @($Value) + @($items)
    if ($items.Count -gt 15) { $items = @($items[0..14]) }
    $script:Settings.MailboxHistory = ($items -join ';')
    $keep = $script:txtMailbox.Text
    $script:txtMailbox.BeginUpdate()
    $script:txtMailbox.Items.Clear()
    foreach ($item in $items) { [void]$script:txtMailbox.Items.Add($item) }
    $script:txtMailbox.EndUpdate()
    $script:txtMailbox.Text = $keep
}
function Get-GraphResource {
    $graph = [string](Get-SelectedCloud).Graph
    if ($graph -match '^(https://[^/]+)') { return $Matches[1] }
    return 'https://graph.microsoft.com'
}
#endregion

#region ---------- Connection actions ----------
$script:OnGraphConnected = {
    param($r, $job)
    $script:State.GraphConnected = $true
    $script:State.GraphIdentity = [string]$r.Identity
    $script:State.GraphCanWrite = [bool]$r.HasMailWrite
    $perm = if ($r.Permissions) { $r.Permissions } else { '(none reported)' }
    if (-not $r.HasMail) {
        Set-StatusLabel $script:lblGraph 'Warning' "Graph: $($r.Identity) (no Mail permission)"
        Set-Activity $job.Activity 'Warning' "Connected as $($r.Identity) but the token has no Mail permission. Permissions: $perm"
    } else {
        Set-StatusLabel $script:lblGraph 'Success' "Graph: $($r.Identity)"
        Set-Activity $job.Activity 'Success' "Connected as $($r.Identity). Permissions: $perm"
    }
    Update-GraphMoveState
    Update-BusyState
    if ($script:State.SelectedData) { Show-SelectedItem }
}
$script:OnGraphFailed = {
    param($err, $job)
    $script:State.GraphConnected = $false
    $script:State.GraphCanWrite = $false
    Set-StatusLabel $script:lblGraph 'Failed' 'Graph: connection failed'
    Update-GraphMoveState
}

function Test-ModulePresent([string]$Name) {
    return [bool](Get-Module -ListAvailable -Name $Name | Select-Object -First 1)
}
function Connect-GraphInteractive($Choice) {
    $act = Add-Activity -Status 'Running' -Action 'Microsoft Graph sign-in' -Details 'Opening the Microsoft sign-in window...'
    Set-StatusLabel $script:lblGraph 'Running' 'Graph: opening the Microsoft sign-in window...'
    try { $script:Form.Activate() } catch { }
    [System.Windows.Forms.Application]::DoEvents()
    $oldCursor = $script:Form.Cursor
    $script:Form.Cursor = [System.Windows.Forms.Cursors]::AppStarting
    $prevProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        if (-not (Get-Module Microsoft.Graph.Authentication)) { Import-Module Microsoft.Graph.Authentication -ErrorAction Stop }
        $cmd = Get-Command Connect-MgGraph -ErrorAction Stop
        $scopes = @('Mail.ReadWrite.Shared', 'User.Read')
        $gp = @{ Scopes = $scopes; ErrorAction = 'Stop' }
        if ($cmd.Parameters.ContainsKey('NoWelcome')) { $gp.NoWelcome = $true }
        if ($cmd.Parameters.ContainsKey('Environment')) { $gp.Environment = 'Global' }
        if ($cmd.Parameters.ContainsKey('ContextScope')) { $gp.ContextScope = 'Process' }
        $upn = [string]$Choice.Upn
        if ($upn -match '@([^@\s]+)$' -and $cmd.Parameters.ContainsKey('TenantId')) { $gp.TenantId = $Matches[1] }
        Connect-MgGraph @gp | Out-Null
        $ctx = $null
        if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) { $ctx = Get-MgContext }
        $account = ''
        $scopeNames = @($scopes)
        if ($ctx) {
            if ($ctx.Account) { $account = [string]$ctx.Account }
            if ($ctx.Scopes) { $scopeNames = @($ctx.Scopes | ForEach-Object { [string]$_ } | Where-Object { $_ }) }
        }
        $identity = if ($account) { $account } else { 'Signed in' }
        $perm = $scopeNames -join ' '
        $hasMail = [bool]($scopeNames | Where-Object { $_ -match '(^|/)Mail\.Read' })
        $script:State.GraphConnected = $true
        $script:State.GraphIdentity = $identity
        $script:State.GraphCanWrite = [bool]($scopeNames | Where-Object { $_ -match '(^|/)Mail\.ReadWrite' })
        $script:State.GraphInstalled = $true
        if (-not $hasMail) {
            Set-StatusLabel $script:lblGraph 'Warning' "Graph: $identity (no Mail permission)"
            Set-Activity $act 'Warning' "Signed in as $identity but Mail permission was not granted. Permissions: $perm"
        } else {
            Set-StatusLabel $script:lblGraph 'Success' "Graph: $identity"
            Set-Activity $act 'Success' "Signed in as $identity. Permissions: $perm"
        }
        Update-GraphMoveState
        Add-Job -Quiet -Name 'Attach Microsoft Graph to the background session' -Script $script:WS_AdoptGraph -OnFailure {
            param($err, $job)
            Set-StatusLabel $script:lblGraph 'Warning' "Graph: $($script:State.GraphIdentity) (restart the console)"
            Write-Activity 'Warning' 'Microsoft Graph sign-in' $err
            Update-GraphMoveState
        }
    } catch {
        $script:State.GraphConnected = $false
        $script:State.GraphCanWrite = $false
        Set-StatusLabel $script:lblGraph 'Failed' 'Graph: sign-in failed'
        Set-Activity $act 'Failed' $_.Exception.Message
        Update-GraphMoveState
    } finally {
        $ProgressPreference = $prevProgress
        $script:Form.Cursor = $oldCursor
    }
}
function Start-ExchangeSignIn([string]$Upn) {
    Set-StatusLabel $script:lblExo 'Running' 'Exchange Online: opening the browser sign-in...'
    Add-Job -Name 'Sign in to Exchange Online' -Script $script:WS_SignIn -Parameters @{ Upn = $Upn } -OnStart {
        param($job)
        if ($job.Activity) { $job.Activity.SubItems[4].Text = 'Complete the Exchange Online sign-in in your browser. This console stays open.' }
    } -OnSuccess {
        param($r, $job)
        $script:State.ExoConnected = $true
        $script:State.ExoIdentity = [string]$r.Identity
        $script:State.ExoVersion = [string]$r.ModuleVersion
        $script:State.CanRestore = [bool]$r.HasRestoreRecoverable
        $script:State.ExoInstalled = $true
        if (-not $r.HasGetRecoverable -or -not $r.HasRestoreRecoverable) {
            Set-StatusLabel $script:lblExo 'Warning' "Exchange Online: $($r.Identity) (missing role)"
            Set-Activity $job.Activity 'Warning' "Signed in as $($r.Identity), but Get-RecoverableItems or Restore-RecoverableItems is not available. Assign the Mailbox Import Export role and sign in again."
        } else {
            $org = if ($r.Organization) { " ($($r.Organization))" } else { '' }
            Set-StatusLabel $script:lblExo 'Success' "Exchange Online: $($r.Identity)"
            Set-Activity $job.Activity 'Success' "Signed in as $($r.Identity)$org. Recovery cmdlets are available."
        }
    } -OnFailure {
        param($err, $job)
        $script:State.ExoConnected = $false
        $script:State.CanRestore = $false
        Set-StatusLabel $script:lblExo 'Failed' 'Exchange Online: sign-in failed'
    }
}
function Start-InteractiveSignIn($Choice) {
    if ($Choice.ConnectGraph) {
        $script:SigningIn = $true
        try {
            Update-BusyState
            Connect-GraphInteractive $Choice
        } finally {
            $script:SigningIn = $false
            Update-BusyState
        }
    }
    if ($Choice.ConnectExo) { Start-ExchangeSignIn ([string]$Choice.Upn) }
}
function Invoke-SignIn {
    $choice = Show-SignInDialog
    if ($choice -eq 'Advanced') { Show-AdvancedSignIn; return }
    if (-not $choice) { return }
    $missing = @()
    if ($choice.ConnectExo -and -not $script:State.ExoInstalled -and -not (Test-ModulePresent 'ExchangeOnlineManagement')) { $missing += 'ExchangeOnlineManagement' }
    if ($choice.ConnectGraph -and -not $script:State.GraphInstalled -and -not (Test-ModulePresent 'Microsoft.Graph.Authentication')) { $missing += 'Microsoft.Graph.Authentication' }
    if ($missing.Count) {
        $ans = Show-Message ("These PowerShell modules are not installed for the current user:`r`n`r`n  " + ($missing -join "`r`n  ") + "`r`n`r`nInstall them from the PowerShell Gallery, then open the Microsoft sign-in window?") $script:AppName 'YesNo' 'Question'
        if ($ans -ne 'Yes') { return }
        Add-Job -Name 'Install Office 365 sign-in modules' -Script $script:WS_InstallModules -Parameters @{ Exchange = [bool]($missing -contains 'ExchangeOnlineManagement'); Graph = [bool]($missing -contains 'Microsoft.Graph.Authentication') } -Context $choice -OnSuccess {
            param($r, $job)
            if ($job.Parameters.Exchange) { $script:State.ExoInstalled = $true }
            if ($job.Parameters.Graph) { $script:State.GraphInstalled = $true; if ($r.PSObject.Properties['Microsoft.Graph.Authentication']) { $script:State.GraphVersion = [string]$r.'Microsoft.Graph.Authentication' } }
            $versions = @()
            foreach ($p in $r.PSObject.Properties) { $versions += "$($p.Name) $($p.Value)" }
            Set-Activity $job.Activity 'Success' ("Installed " + ($versions -join ', ') + '. Opening sign-in.')
            Start-InteractiveSignIn $job.Context
        }
        return
    }
    Start-InteractiveSignIn $choice
}
function Invoke-ConnectExo {
    if (-not $script:State.ExoInstalled) {
        $found = Get-Module -ListAvailable -Name ExchangeOnlineManagement | Select-Object -First 1
        $script:State.ExoInstalled = [bool]$found
    }
    if (-not $script:State.ExoInstalled) {
        $ans = Show-Message "The ExchangeOnlineManagement module was not found.`r`n`r`nInstall it now for the current user from the PowerShell Gallery?" $script:AppName 'YesNo' 'Question'
        if ($ans -eq 'Yes') { Invoke-InstallExo }
        return
    }
    $p = Show-ExoConnectDialog
    if (-not $p) { return }
    Set-StatusLabel $script:lblExo 'Running' 'Exchange Online: connecting...'
    Add-Job -Name 'Connect to Exchange Online' -Script $script:WS_ConnectExo -Parameters $p -OnSuccess {
        param($r, $job)
        $script:State.ExoConnected = $true
        $script:State.ExoIdentity = [string]$r.Identity
        $script:State.ExoVersion = [string]$r.ModuleVersion
        $script:State.CanRestore = [bool]$r.HasRestoreRecoverable
        if (-not $r.HasGetRecoverable -or -not $r.HasRestoreRecoverable) {
            Set-StatusLabel $script:lblExo 'Warning' "Exchange Online: $($r.Identity) (missing role)"
            Set-Activity $job.Activity 'Warning' ("Connected as $($r.Identity), but Get-RecoverableItems or Restore-RecoverableItems is not available. Assign the Mailbox Import Export role and reconnect.")
        } else {
            Set-StatusLabel $script:lblExo 'Success' "Exchange Online: $($r.Identity)"
            Set-Activity $job.Activity 'Success' "Connected as $($r.Identity) to $($r.Organization) (module v$($r.ModuleVersion)). Recovery cmdlets are available."
        }
    } -OnFailure {
        param($err, $job)
        $script:State.ExoConnected = $false
        $script:State.CanRestore = $false
        Set-StatusLabel $script:lblExo 'Failed' 'Exchange Online: connection failed'
    }
}
function Invoke-InstallExo {
    Add-Job -Name 'Install ExchangeOnlineManagement module' -Script $script:WS_InstallExo -OnSuccess {
        param($r, $job)
        $script:State.ExoInstalled = $true
        $script:State.ExoVersion = [string]$r
        Set-Activity $job.Activity 'Success' "Installed ExchangeOnlineManagement v$r. You can connect now."
    }
}
function Invoke-ConnectGraph {
    $p = Show-GraphConnectDialog
    if (-not $p) { return }
    Set-StatusLabel $script:lblGraph 'Running' 'Graph: connecting...'
    if ($p.Mode -eq 'DeviceCode') {
        $resource = Get-GraphResource
        $scope = "$resource/Mail.ReadWrite.Shared $resource/User.Read offline_access"
        Add-Job -Name 'Microsoft Graph: request device code' -Script $script:WS_GraphDeviceStart -Parameters @{
            TenantId = $p.TenantId; ClientId = $p.ClientId; Scope = $scope; LoginBase = $p.LoginBase; GraphBase = $p.GraphBase
        } -OnSuccess {
            param($r, $job)
            Add-Job -Name 'Microsoft Graph: waiting for device sign-in' -Script $script:WS_GraphDevicePoll -OnSuccess $script:OnGraphConnected -OnFailure $script:OnGraphFailed
            Set-Activity $job.Activity 'Info' "Code $($r.UserCode) copied to the clipboard. Complete sign-in at $($r.Uri)"
            Set-ClipboardText ([string]$r.UserCode)
            try { Start-Process ([string]$r.Uri) } catch { }
            Show-Message ("Your sign-in code is:`r`n`r`n    $($r.UserCode)`r`n`r`nIt has been copied to the clipboard and $($r.Uri) was opened. Sign in with an account that has Full Access to the target mailbox.`r`n`r`nThe console waits in the background.") 'Microsoft Graph sign-in' 'OK' 'Information' | Out-Null
        } -OnFailure $script:OnGraphFailed
    } else {
        Add-Job -Name "Connect to Microsoft Graph ($($p.Mode.ToLower()))" -Script $script:WS_GraphAppConnect -Parameters $p -OnSuccess $script:OnGraphConnected -OnFailure $script:OnGraphFailed
    }
}
function Invoke-DisconnectAll {
    try { if (Get-Module Microsoft.Graph.Authentication) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } } catch { }
    Add-Job -Name 'Disconnect Exchange Online and Microsoft Graph' -Script $script:WS_DisconnectAll -OnSuccess {
        param($r, $job)
        $script:State.ExoConnected = $false; $script:State.GraphConnected = $false; $script:State.CanRestore = $false; $script:State.GraphCanWrite = $false
        Set-StatusLabel $script:lblExo 'Disconnected' 'Exchange Online: not connected'
        Set-StatusLabel $script:lblGraph 'Disconnected' 'Graph: not connected'
        Set-Activity $job.Activity 'Success' 'All sessions closed.'
        Update-GraphMoveState
        Update-BusyState
    }
}
#endregion

#region ---------- Mailbox, search and folders ----------
function Invoke-ResolveMailbox {
    $id = $script:txtMailbox.Text.Trim()
    if (-not $id) { Show-Message 'Enter the user principal name or email address of the target mailbox.' $script:AppName 'OK' 'Warning' | Out-Null; return }
    if (-not $script:State.ExoConnected) { Show-Message 'Connect to Exchange Online first.' $script:AppName 'OK' 'Warning' | Out-Null; return }
    Set-StatusLabel $script:lblMailbox 'Running' "Resolving $id..."
    Add-Job -Name "Resolve mailbox: $id" -Script $script:WS_ResolveMailbox -Parameters @{ Identity = $id } -OnSuccess {
        param($m, $job)
        $script:State.Mailbox = $m
        $script:State.AllItems = @()
        $script:State.HasSearched = $false
        Update-ResultsList
        Clear-Preview
        $root = @($m.RecoverableStats) | Where-Object { $_.FolderType -eq 'RecoverableItemsRoot' } | Select-Object -First 1
        $dh = @($m.RecoverableStats) | Where-Object { $_.FolderType -eq 'RecoverableItemsDiscoveryHolds' -or $_.Name -eq 'DiscoveryHolds' } | Select-Object -First 1
        $ri = if ($root) { "Recoverable Items: $('{0:N0}' -f $root.TotalItems) items / $($root.TotalSize)" } else { '' }
        $dhText = if ($dh) { "DiscoveryHolds: $('{0:N0}' -f $dh.Items)" } else { '' }
        $info = (@($m.DisplayName, $m.PrimarySmtpAddress, $m.RecipientTypeDetails, (Get-HoldSummary $m), $ri, $dhText) | Where-Object { $_ }) -join '   |   '
        Set-StatusLabel $script:lblMailbox 'Success' $info
        $script:btnHoldDetails.Enabled = $true
        $script:Settings.LastMailbox = $script:txtMailbox.Text.Trim()
        Add-MailboxHistory $script:Settings.LastMailbox
        Save-AppSettings
        $detail = "Target set to $($m.DisplayName) <$($m.PrimarySmtpAddress)>. $(Get-HoldSummary $m)."
        if (-not $m.SingleItemRecovery -and -not $m.LitigationHoldEnabled -and @($m.InPlaceHolds | Where-Object { $_ }).Count -eq 0 -and -not $m.ComplianceTagHold -and -not $m.DelayHold) {
            $detail += ' Single item recovery is off and no hold was detected, so Recoverable Items may be empty.'
        }
        Set-Activity $job.Activity 'Success' $detail
        Invoke-LoadFolders -Quiet
    } -OnFailure {
        param($err, $job)
        $script:State.Mailbox = $null
        $script:btnHoldDetails.Enabled = $false
        Set-StatusLabel $script:lblMailbox 'Failed' 'Mailbox not found'
    }
}
function Show-HoldDetails {
    $m = $script:State.Mailbox
    if (-not $m) { return }
    $lines = @(
        "Mailbox:              $($m.DisplayName) <$($m.PrimarySmtpAddress)>",
        "Type:                 $($m.RecipientTypeDetails)",
        "Graph id:             $($m.GraphId)",
        "Litigation hold:      $($m.LitigationHoldEnabled)",
        "Retention label hold: $($m.ComplianceTagHold)",
        "Delay hold:           $($m.DelayHold)",
        "Retention hold:       $($m.RetentionHoldEnabled)",
        "Single item recovery: $($m.SingleItemRecovery)",
        "Retain deleted for:   $($m.RetainDeletedItemsFor)",
        "Archive:              $($m.ArchiveStatus)",
        '',
        'In-Place / Purview holds:'
    )
    $holds = @($m.InPlaceHolds | Where-Object { $_ })
    if ($holds.Count) { $lines += @($holds | ForEach-Object { "   $_" }) } else { $lines += '   (none)' }
    $lines += ''
    $lines += 'Recoverable Items folders:'
    if (@($m.RecoverableStats).Count) {
        foreach ($f in @($m.RecoverableStats)) { $lines += ('   {0,-28} {1,10:N0} items   {2}' -f $f.Name, $f.Items, $f.Size) }
    } else { $lines += '   (folder statistics were not returned)' }
    Show-TextDialog "Hold details - $($m.DisplayName)" ($lines -join "`r`n") 700 480
}
function Invoke-Search {
    if (-not $script:State.ExoConnected) { Show-Message 'Connect to Exchange Online first.' $script:AppName 'OK' 'Warning' | Out-Null; return }
    if (-not $script:State.Mailbox) { Show-Message 'Resolve a target mailbox first.' $script:AppName 'OK' 'Warning' | Out-Null; return }
    $keys = @($script:SourceFolderNames.Keys)
    $folders = if ($script:cboSource.SelectedIndex -le 0) { $keys } else { @($keys[$script:cboSource.SelectedIndex - 1]) }
    $start = if ($script:dtStart.Checked) { $script:dtStart.Value.Date } else { $null }
    $end = if ($script:dtEnd.Checked) { $script:dtEnd.Value.Date.AddDays(1).AddSeconds(-1) } else { $null }
    if ($start -and $end -and $start -gt $end) { Show-Message 'The start date is after the end date.' $script:AppName 'OK' 'Warning' | Out-Null; return }
    $entry = $script:txtEntryId.Text.Trim()
    $p = Get-JobParameterTable @{
        Mailbox = $script:State.Mailbox.PrimarySmtpAddress
        Folders = [string[]]$folders
        ItemType = [string]$script:ItemTypes[$script:cboType.SelectedItem]
        Subject = $script:txtSubject.Text.Trim()
        Start = $start
        End = $end
        Max = [int]$script:nudMax.Value
        EntryID = $(if ($entry) { $entry } else { $null })
    }
    $script:Settings.LastSource = [string]$script:cboSource.SelectedIndex
    $script:Settings.LastItemType = [string]$script:cboType.SelectedItem
    Save-AppSettings
    $where = if ($entry) { 'EntryID' } elseif ($folders.Count -gt 1) { 'all held locations' } else { Get-LocationName $folders[0] }
    Add-Job -Name "Search $where in $($script:State.Mailbox.PrimarySmtpAddress)" -Script $script:WS_Search -Parameters $p -OnSuccess {
        param($r, $job)
        $items = @($r.Items | Where-Object { $_ })
        foreach ($i in $items) {
            foreach ($prop in 'Checked', 'RestoreState', 'RestoreText', 'ListItem', 'Preview', 'PreviewPending') {
                $value = if ($prop -eq 'Checked' -or $prop -eq 'PreviewPending') { $false } else { $null }
                if ($prop -eq 'RestoreState' -or $prop -eq 'RestoreText') { $value = '' }
                Add-Member -InputObject $i -NotePropertyName $prop -NotePropertyValue $value -Force
            }
        }
        $script:State.AllItems = $items
        $script:State.HasSearched = $true
        Update-ResultsList
        Clear-Preview
        $breakdown = @()
        foreach ($k in @($r.Counts.Keys)) {
            $c = $r.Counts[$k]
            $label = if ($k -eq 'EntryID') { 'EntryID' } else { Get-LocationName $k }
            $breakdown += ('{0}: {1}' -f $label, $(if ($c -lt 0) { 'error' } else { $c }))
        }
        $msg = "Found $($items.Count) item(s). " + ($breakdown -join ', ')
        $truncated = @($r.Truncated | Where-Object { $_ } | ForEach-Object { Get-LocationName $_ })
        if ($truncated.Count) { $msg += '. Result limit reached for ' + ($truncated -join ', ') + '; more items may exist.' }
        if ($r.UsedDefaultDates) { $msg += ' Subject was blank, so every item modified since 1990-01-01 was included, up to Max / folder.' }
        $warn = @($r.Warnings | Where-Object { $_ })
        if ($warn.Count -or $truncated.Count) { Set-Activity $job.Activity 'Warning' ($msg + $(if ($warn.Count) { '. Some locations failed: ' + ($warn -join ' | ') } else { '' })) }
        else { Set-Activity $job.Activity 'Success' $msg }
    }
}
function Update-SortHeaders {
    $names = $script:ResultColumnNames
    for ($i = 0; $i -lt $script:lvResults.Columns.Count; $i++) {
        $mark = ''
        if ($i -eq $script:ResultSorter.Column) { $mark = $(if ($script:ResultSorter.Descending) { '  v' } else { '  ^' }) }
        $script:lvResults.Columns[$i].Text = $names[$i] + $mark
    }
}
function Update-ResultsList {
    $filter = $script:txtFilter.Text.Trim()
    $lv = $script:lvResults
    $script:Rendering = $true
    $previous = $lv.ListViewItemSorter
    $lv.ListViewItemSorter = $null
    $lv.BeginUpdate()
    try {
        $lv.Items.Clear()
        foreach ($d in @($script:State.AllItems)) {
            if ($filter) {
                $hay = "$($d.Subject) $($d.LastParentPath) $(Get-LocationName $d.SourceFolder) $($d.ItemClass)"
                if ($hay.IndexOf($filter, [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
            }
            $subject = if ($d.Subject) { $d.Subject } else { '(no subject)' }
            $lvi = New-Object System.Windows.Forms.ListViewItem($subject)
            [void]$lvi.SubItems.Add((Get-LocationName $d.SourceFolder))
            [void]$lvi.SubItems.Add((ConvertTo-DisplayFolder $d.LastParentPath))
            [void]$lvi.SubItems.Add([string]$d.OriginalFolderExists)
            [void]$lvi.SubItems.Add((Format-ItemType $d.ItemClass))
            [void]$lvi.SubItems.Add($(if ($d.LastModifiedTime) { ([datetime]$d.LastModifiedTime).ToString('yyyy-MM-dd HH:mm') } else { '' }))
            [void]$lvi.SubItems.Add([string]$d.RestoreText)
            $lvi.ImageKey = if ($d.RestoreState) { $d.RestoreState } else { 'Mail' }
            if ($d.RestoreState) { Set-ActivityColor $lvi $d.RestoreState }
            if ([string]$d.OriginalFolderExists -eq 'False') {
                $lvi.UseItemStyleForSubItems = $false
                $lvi.SubItems[3].ForeColor = [System.Drawing.Color]::FromArgb(180, 83, 9)
            }
            $lvi.Checked = [bool]$d.Checked
            $lvi.Tag = $d
            $d.ListItem = $lvi
            [void]$lv.Items.Add($lvi)
        }
    } finally {
        $lv.ListViewItemSorter = $previous
        $lv.EndUpdate()
        $script:Rendering = $false
        try { if ($previous) { $lv.Sort() } } catch { }
    }
    Update-ResultCount
}
function Update-ResultCount {
    $total = @($script:State.AllItems).Count
    $shown = $script:lvResults.Items.Count
    $checked = $script:lvResults.CheckedItems.Count
    if (-not $script:State.HasSearched -and $total -eq 0) { $script:lblCount.Text = 'No search yet' }
    elseif ($shown -ne $total) { $script:lblCount.Text = "$shown of $total items shown, $checked checked" }
    else { $script:lblCount.Text = "$total items, $checked checked" }
}
function Set-VisibleChecks([bool]$Checked) {
    $script:Rendering = $true
    $script:lvResults.BeginUpdate()
    try { foreach ($i in @($script:lvResults.Items)) { $i.Checked = $Checked } }
    finally { $script:lvResults.EndUpdate(); $script:Rendering = $false }
    Update-ResultCount
}
function Invoke-LoadFolders {
    param([switch]$Quiet)
    if (-not $script:State.Mailbox) {
        if (-not $Quiet) { Show-Message 'Resolve a target mailbox first.' $script:AppName 'OK' 'Warning' | Out-Null }
        return
    }
    Add-Job -Name "Load mail folders for $($script:State.Mailbox.PrimarySmtpAddress)" -Script $script:WS_LoadFolders -Parameters @{ Mailbox = $script:State.Mailbox.PrimarySmtpAddress } -Quiet:$Quiet -OnSuccess {
        param($r, $job)
        $names = @($r | Where-Object { $_ } | ForEach-Object { [string]$_ })
        $keep = $script:cboFolder.Text
        $script:cboFolder.BeginUpdate()
        $script:cboFolder.Items.Clear()
        foreach ($n in $names) { [void]$script:cboFolder.Items.Add($n) }
        $script:cboFolder.EndUpdate()
        $script:cboFolder.Text = $keep
        if ($job.Activity) { Set-Activity $job.Activity 'Success' "$($names.Count) mail folders loaded into the destination list." }
        else { Write-Log 'INFO' "$($names.Count) mail folders loaded." }
    }
}
#endregion

#region ---------- Preview ----------
function Clear-Preview {
    $script:State.SelectedData = $null
    foreach ($v in $script:PreviewFields.Values) { $v.Text = '' }
    Set-StatusLabel $script:lblPreviewState 'Disconnected' 'Select an item'
    Show-PreviewMessage 'Select an item in the list to see its details.'
}
function Show-PreviewMessage([string]$Text, [string]$Tone = 'muted') {
    $color = switch ($Tone) { 'error' { '#b91c1c' } 'warn' { '#b45309' } default { '#475569' } }
    $safe = [System.Net.WebUtility]::HtmlEncode([string]$Text) -replace "`r`n", '<br>' -replace "`n", '<br>'
    $inner = '<div style="margin:12px;color:' + $color + '">' + $safe + '</div>'
    $script:web.DocumentText = New-PreviewDocument $inner
}
function Show-ItemMetadata($d) {
    $f = $script:PreviewFields
    $f['Subject'].Text = if ($d.Subject) { $d.Subject } else { '(no subject)' }
    $f['From'].Text = ''; $f['To'].Text = ''; $f['Cc'].Text = ''; $f['Attachments'].Text = ''
    $f['Sent'].Text = if ($d.LastModifiedTime) { 'Last modified ' + ([datetime]$d.LastModifiedTime).ToString('yyyy-MM-dd HH:mm') } else { '' }
    $f['Location'].Text = Get-LocationName $d.SourceFolder
    $orig = ConvertTo-DisplayFolder $d.LastParentPath
    $f['Original folder'].Text = if ($orig) { $orig + $(if ([string]$d.OriginalFolderExists -eq 'False') { '   (folder no longer exists)' } else { '' }) } else { '(unknown)' }
}
function Show-Preview($d) {
    $p = $d.Preview
    if (-not $p) { return }
    $f = $script:PreviewFields
    $f['Subject'].Text = if ($p.Subject) { $p.Subject } else { '(no subject)' }
    $f['From'].Text = [string]$p.From
    $f['To'].Text = [string]$p.To
    $f['Cc'].Text = [string]$p.Cc
    $sent = if ($p.Sent) { ([datetime]$p.Sent).ToString('dddd, yyyy-MM-dd HH:mm') } else { '' }
    if ($p.Importance -and $p.Importance -ne 'normal') { $sent = ($sent + "   Importance: $($p.Importance)").Trim() }
    $f['Sent'].Text = $sent
    $f['Attachments'].Text = if (@($p.Attachments).Count) { (@($p.Attachments) -join '; ') } else { 'None' }
    foreach ($k in 'From', 'To', 'Cc', 'Attachments', 'Subject') { try { $script:tip.SetToolTip($f[$k], $f[$k].Text) } catch { } }
    $banner = ''
    if ($script:chkPlain.Checked -or $p.BodyType -ne 'html') {
        $text = if ($p.BodyType -eq 'html') { ConvertTo-PlainText $p.Body } else { [string]$p.Body }
        $body = '<pre>' + [System.Net.WebUtility]::HtmlEncode($text) + '</pre>'
    } else {
        $body = ConvertTo-SafeHtml $p.Body ([bool]$script:chkRemote.Checked)
        if (-not $script:chkRemote.Checked -and $p.Body -match '(?i)<img\b[^>]*src\s*=\s*["'']?\s*https?:') {
            $banner = '<div style="background:#fef3c7;color:#92400e;padding:6px 10px;margin-bottom:10px;font:12px Segoe UI,Arial">Remote images were blocked. Tick Remote images to show them, or Plain text for a text-only view.</div>'
        }
    }
    if ($body.Length -gt 1500000) { $body = $body.Substring(0, 1500000) + '<p><em>Preview truncated because the message is very large.</em></p>' }
    $script:web.DocumentText = New-PreviewDocument $body $banner
    Set-StatusLabel $script:lblPreviewState 'Success' 'Full preview loaded'
}
function Request-Preview($d) {
    if (-not $d) { return }
    if ($d.Preview) { Show-Preview $d; return }
    if ($d.ItemClass -and $d.ItemClass -notlike 'IPM.Note*') {
        Set-StatusLabel $script:lblPreviewState 'Info' 'Metadata only'
        Show-PreviewMessage "This item is $($d.ItemClass). Full preview loads email messages. You can still restore it with the Exchange options."
        return
    }
    if (-not $script:State.GraphConnected) {
        Set-StatusLabel $script:lblPreviewState 'Info' 'Metadata only - connect Microsoft Graph for the full message'
        Show-PreviewMessage "Exchange Online returns the metadata shown above.`r`n`r`nConnect Microsoft Graph to load the body, sender, recipients and attachments."
        return
    }
    if (-not $d.EntryID -and -not $d.Subject) {
        Set-StatusLabel $script:lblPreviewState 'Warning' 'This item has no EntryID or subject'
        Show-PreviewMessage 'This row has no EntryID and no subject, so Microsoft Graph cannot locate it.' 'warn'
        return
    }
    if ($d.PreviewPending) { return }
    $d.PreviewPending = $true
    Set-StatusLabel $script:lblPreviewState 'Running' 'Loading full preview...'
    Show-PreviewMessage 'Loading message...'
    Add-Job -Quiet -Name "Preview: $($d.Subject)" -Script $script:WS_Preview -Context $d -Parameters (Get-JobParameterTable @{
        GraphUser = $script:State.Mailbox.GraphId; EntryID = $d.EntryID; SourceFolder = $d.SourceFolder; Subject = $d.Subject; LastModified = $d.LastModifiedTime
    }) -OnSuccess {
        param($r, $job)
        $job.Context.PreviewPending = $false
        $job.Context.Preview = $r
        if ([object]::ReferenceEquals($script:State.SelectedData, $job.Context)) { Show-Preview $job.Context }
    } -OnFailure {
        param($err, $job)
        $job.Context.PreviewPending = $false
        if ([object]::ReferenceEquals($script:State.SelectedData, $job.Context)) {
            Set-StatusLabel $script:lblPreviewState 'Failed' 'Preview failed'
            Show-PreviewMessage ("Could not load this message through Microsoft Graph:`r`n`r`n$err`r`n`r`nHeld items can still be restored with the Exchange options.") 'error'
        }
    }
}
function Show-SelectedItem {
    $sel = $script:lvResults.SelectedItems
    if ($sel.Count -eq 0) { return }
    $d = $sel[0].Tag
    $script:State.SelectedData = $d
    Show-ItemMetadata $d
    if ($d.Preview) { Show-Preview $d }
    elseif ($script:State.GraphConnected -and $script:chkAutoPreview.Checked) { Request-Preview $d }
    elseif ($script:State.GraphConnected) {
        Set-StatusLabel $script:lblPreviewState 'Info' 'Click Load full preview to read the message'
        Show-PreviewMessage 'Click Load full preview to read the message body.'
    } else { Request-Preview $d }
}
#endregion

#region ---------- Restore ----------
function Invoke-Restore {
    if (-not $script:State.ExoConnected -and -not $script:rbGraphMove.Checked) { Show-Message 'Connect to Exchange Online first.' $script:AppName 'OK' 'Warning' | Out-Null; return }
    if (-not $script:State.Mailbox) { Show-Message 'Resolve a target mailbox first.' $script:AppName 'OK' 'Warning' | Out-Null; return }
    $items = @($script:lvResults.CheckedItems | ForEach-Object { $_.Tag })
    if ($items.Count -eq 0) { $items = @($script:lvResults.SelectedItems | ForEach-Object { $_.Tag }) }
    $items = @($items | Where-Object { $_ })
    if ($items.Count -eq 0) { Show-Message 'Tick or select at least one item to restore.' $script:AppName 'OK' 'Information' | Out-Null; return }
    $noId = @($items | Where-Object { -not $_.EntryID })
    if ($noId.Count) {
        Show-Message "$($noId.Count) selected item(s) have no EntryID and cannot be restored. They were left unchecked in the request." $script:AppName 'OK' 'Warning' | Out-Null
        $items = @($items | Where-Object { $_.EntryID })
        if ($items.Count -eq 0) { return }
    }
    $mode = if ($script:rbOriginal.Checked) { 'Original' } elseif ($script:rbExFolder.Checked) { 'ExchangeFolder' } else { 'GraphMove' }
    $rawTarget = $script:cboFolder.Text.Trim()
    $target = if ($mode -eq 'GraphMove') { ConvertTo-GraphFolderPath $rawTarget } else { ConvertTo-ExchangeFolderPath $rawTarget }
    if ($mode -ne 'Original' -and -not (Test-FolderPathSafe $target)) { Show-Message 'Enter a destination folder. The path cannot contain : * ? " < > |' $script:AppName 'OK' 'Warning' | Out-Null; return }
    if ($mode -eq 'GraphMove' -and -not $script:State.GraphConnected) { Show-Message 'Exact folder move requires a Microsoft Graph connection with Mail.ReadWrite.' $script:AppName 'OK' 'Warning' | Out-Null; return }
    if ($mode -eq 'GraphMove' -and -not $script:State.GraphCanWrite) { Show-Message 'The Graph token cannot write mail. Reconnect with Mail.ReadWrite or Mail.ReadWrite.Shared.' $script:AppName 'OK' 'Warning' | Out-Null; return }
    if ($mode -ne 'GraphMove' -and -not $script:State.CanRestore) {
        $a = Show-Message "Restore-RecoverableItems is not available to this account (the Mailbox Import Export role is missing). The restore will most likely fail.`r`n`r`nContinue anyway?" $script:AppName 'YesNo' 'Warning'
        if ($a -ne 'Yes') { return }
    }
    $dest = switch ($mode) { 'Original' { 'their original folders' } 'ExchangeFolder' { "'$target' (Exchange restore)" } default { "'$target' (Graph move)" } }
    $held = @($items | Where-Object { $_.SourceFolder -in @('DiscoveryHoldsItems', 'PurgedItems') }).Count
    $missing = @($items | Where-Object { [string]$_.OriginalFolderExists -eq 'False' }).Count
    $msg = "Restore $($items.Count) item(s) for $($script:State.Mailbox.DisplayName) to $dest?"
    if ($mode -eq 'Original' -and $missing) { $msg += "`r`n`r`n$missing item(s) have an original folder that no longer exists. Exchange will place those in Inbox." }
    if ($held -and $mode -ne 'GraphMove') { $msg += "`r`n`r`n$held item(s) come from DiscoveryHolds or Purges. A copy is restored and the held copy remains while the hold is active." }
    if ($mode -eq 'GraphMove' -and $held) { $msg += "`r`n`r`n$held item(s) come from DiscoveryHolds or Purges. Graph often refuses to move those. Use an Exchange option if the move fails." }
    $dupes = @($items | Group-Object { [string]$_.Subject } | Where-Object { $_.Name -and $_.Count -gt 1 })
    if ($dupes.Count) { $msg += "`r`n`r`n$($dupes.Count) subject(s) are shared by more than one selected row. Each row is restored on its own." }
    $msg += "`r`n`r`nRestores run one at a time so the Exchange session stays consistent."
    if ((Show-Message $msg 'Confirm restore' 'YesNo' 'Question') -ne 'Yes') { return }
    if ($mode -ne 'Original') { $script:Settings.LastFolder = $rawTarget; Save-AppSettings }
    $script:State.Batch = @{ Total = $items.Count; Done = 0; Success = 0; Warning = 0; Failed = 0; Start = Get-Date; Destination = $dest }
    Write-Activity 'Info' "Restore batch started ($($items.Count) items)" "Mailbox $($script:State.Mailbox.PrimarySmtpAddress), destination $dest, verify = $($script:chkVerify.Checked)"
    Set-StatusLabel $script:lblSummary 'Running' "Restoring 0 of $($items.Count)..."
    foreach ($d in $items) {
        Set-ItemRestoreStatus $d 'Queued' 'Queued'
        $short = if ($d.Subject -and $d.Subject.Length -gt 60) { $d.Subject.Substring(0, 57) + '...' } elseif ($d.Subject) { $d.Subject } else { '(no subject)' }
        $internet = $null
        if ($d.Preview -and $d.Preview.InternetMessageId) { $internet = [string]$d.Preview.InternetMessageId }
        Add-Job -Name "Restore: $short" -Script $script:WS_Restore -Context $d -Parameters (Get-JobParameterTable @{
            Mailbox = $script:State.Mailbox.PrimarySmtpAddress; GraphUser = $script:State.Mailbox.GraphId
            EntryID = $d.EntryID; SourceFolder = $d.SourceFolder; Mode = $mode; TargetFolder = $target
            Verify = [bool]$script:chkVerify.Checked; Subject = $d.Subject; OriginalPath = $d.LastParentPath
            LastModified = $d.LastModifiedTime; InternetMessageId = $internet
        }) -OnStart {
            param($job)
            Set-ItemRestoreStatus $job.Context 'Running' 'Restoring...'
        } -OnSuccess {
            param($r, $job)
            $state = [string]$r.Status
            if ($state -notin @('Success', 'Warning', 'Failed')) { $state = 'Warning' }
            $text = if ($state -eq 'Success') { "Restored -> $($r.Destination)" + $(if ($r.Verified) { ' (verified)' } else { '' }) } else { [string]$r.Message }
            Set-ItemRestoreStatus $job.Context $state $text
            Set-Activity $job.Activity $state ([string]$r.Message)
            Update-BatchProgress $state
        } -OnFailure {
            param($err, $job)
            $state = if ($err -eq 'Cancelled by user.') { 'Warning' } else { 'Failed' }
            $text = if ($state -eq 'Warning') { 'Cancelled' } else { "Failed: $err" }
            Set-ItemRestoreStatus $job.Context $state $text
            Update-BatchProgress $state
        }
    }
}
function Update-BatchProgress([string]$State) {
    $b = $script:State.Batch
    if (-not $b) { return }
    if ($State -notin @('Success', 'Warning', 'Failed')) { $State = 'Failed' }
    $b.Done++
    $b[$State] = [int]$b[$State] + 1
    Set-StatusLabel $script:lblSummary 'Running' ("Restoring {0} of {1}...  {2} ok, {3} warning, {4} failed" -f $b.Done, $b.Total, $b.Success, $b.Warning, $b.Failed)
    Update-ResultCount
    Update-BusyState
    if ($b.Done -lt $b.Total) { return }
    $elapsed = ((Get-Date) - $b.Start).TotalSeconds
    $summary = '{0} of {1} item(s) restored to {2} in {3:N0}s' -f $b.Success, $b.Total, $b.Destination, $elapsed
    if ($b.Warning) { $summary += ", $($b.Warning) need attention" }
    if ($b.Failed) { $summary += ", $($b.Failed) failed" }
    $kind = if ($b.Failed -eq 0 -and $b.Warning -eq 0) { 'Success' } elseif ($b.Success -eq 0 -and $b.Warning -eq 0) { 'Failed' } else { 'Warning' }
    Write-Activity $kind 'Restore batch complete' $summary
    Set-StatusLabel $script:lblSummary $kind $summary
    $script:State.Batch = $null
    if ($script:Closing) { return }
    $icon = switch ($kind) { 'Success' { 'Information' } 'Failed' { 'Error' } default { 'Warning' } }
    $title = switch ($kind) { 'Success' { 'Restore complete' } 'Failed' { 'Restore failed' } default { 'Restore completed with warnings' } }
    Show-Message "$summary.`r`n`r`nSee the Restore status column and the Activity panel for each item." $title 'OK' $icon | Out-Null
}
function Export-Results {
    if (@($script:State.AllItems).Count -eq 0) { Show-Message 'There are no results to export.' $script:AppName 'OK' 'Information' | Out-Null; return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV files (*.csv)|*.csv'
    $safeName = if ($script:State.Mailbox) { $script:State.Mailbox.PrimarySmtpAddress -replace '[^\w\.-]', '_' } else { 'mailbox' }
    $dlg.FileName = 'RecoverableItems_{0}_{1:yyyyMMdd_HHmm}.csv' -f $safeName, (Get-Date)
    if ($dlg.ShowDialog($script:Form) -ne 'OK') { return }
    @($script:State.AllItems) | Select-Object @{ n = 'Subject'; e = { ConvertTo-CsvSafe $_.Subject } },
        @{ n = 'Location'; e = { ConvertTo-CsvSafe (Get-LocationName $_.SourceFolder) } },
        @{ n = 'SourceFolder'; e = { ConvertTo-CsvSafe $_.SourceFolder } },
        @{ n = 'OriginalFolder'; e = { ConvertTo-CsvSafe (ConvertTo-DisplayFolder $_.LastParentPath) } },
        @{ n = 'OriginalFolderExists'; e = { ConvertTo-CsvSafe $_.OriginalFolderExists } },
        @{ n = 'ItemClass'; e = { ConvertTo-CsvSafe $_.ItemClass } },
        LastModifiedTime,
        @{ n = 'RestoreStatus'; e = { ConvertTo-CsvSafe $_.RestoreState } },
        @{ n = 'RestoreDetails'; e = { ConvertTo-CsvSafe $_.RestoreText } },
        @{ n = 'EntryID'; e = { ConvertTo-CsvSafe $_.EntryID } } |
        Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
    Write-Activity 'Success' 'Export results' "Saved $(@($script:State.AllItems).Count) rows to $($dlg.FileName)"
}
function Show-Requirements {
    $text = @"
Exchange Online
  Install-Module ExchangeOnlineManagement -Scope CurrentUser
  The signing-in account needs the Mailbox Import Export role, for example:
    New-ManagementRoleAssignment -Role 'Mailbox Import Export' -User admin@contoso.com
  Sign out and back in. A new role assignment can take up to 60 minutes.
  Restoring from DiscoveryHolds or Purges copies the item back. The held copy stays while the hold is active.

Microsoft Graph (optional: preview, exact-folder move, verification)
  Sign in uses the Microsoft.Graph.Authentication module and the normal Microsoft window.
  The signed-in admin needs Full Access to the mailbox. Scopes: Mail.ReadWrite.Shared and User.Read.
  Advanced sign-in still supports device code, a certificate, or a client secret.
  App-only needs Mail.ReadWrite and User.Read.All with admin consent, scoped by an application access policy.

Service
  Sign-in uses Office 365 and Azure (commercial). Exchange Online lists and restores mail. Microsoft Graph previews and moves messages.

Run
  powershell.exe -STA -ExecutionPolicy Bypass -File .\MailboxRecoveryConsole.ps1

Log
  $script:LogPath
"@
    Show-TextDialog 'Requirements' $text 760 520
}
function Show-About {
    Show-TextDialog 'About' (Get-DiagnosticsText) 680 360
}
function Save-UiSettings {
    try {
        if ($script:Form.WindowState -eq 'Normal') {
            $script:Settings.WindowX = [string]$script:Form.Location.X
            $script:Settings.WindowY = [string]$script:Form.Location.Y
            $script:Settings.WindowW = [string]$script:Form.Size.Width
            $script:Settings.WindowH = [string]$script:Form.Size.Height
        }
        if ($script:split -and $script:split.Width -gt 0) { $script:Settings.Splitter = [string]([Math]::Round($script:split.SplitterDistance / $script:split.Width, 3)) }
        $script:Settings.Cloud = 'Commercial'
        $script:Settings.LastFolder = $script:cboFolder.Text.Trim()
        $script:Settings.LastMailbox = $script:txtMailbox.Text.Trim()
        $script:Settings.LastSource = [string]$script:cboSource.SelectedIndex
        $script:Settings.LastItemType = [string]$script:cboType.SelectedItem
        $script:Settings.VerifyRestore = [string][bool]$script:chkVerify.Checked
        $script:Settings.AutoPreview = [string][bool]$script:chkAutoPreview.Checked
        $script:Settings.PlainPreview = [string][bool]$script:chkPlain.Checked
        $script:Settings.RemoteImages = [string][bool]$script:chkRemote.Checked
        Save-AppSettings
    } catch { }
}
#endregion

#region ---------- Events and startup ----------
$script:Rendering = $false
try { [System.Windows.Forms.Application]::SetUnhandledExceptionMode('CatchException') } catch { }
try {
    [System.Windows.Forms.Application]::add_ThreadException({
        param($sender, $e)
        try { Write-Log 'ERROR' $e.Exception.ToString() } catch { }
        try { Show-Message $e.Exception.Message $script:AppName 'OK' 'Error' | Out-Null } catch { }
    })
} catch { }

$btnConnectExo.Add_Click({ Invoke-Safe { Invoke-SignIn } 'Sign in' })
$btnConnectGraph.Add_Click({ Invoke-Safe { Show-AdvancedSignIn } 'Advanced sign-in' })
$btnDisconnect.Add_Click({ Invoke-Safe { Invoke-DisconnectAll } 'Disconnect' })
$btnResolve.Add_Click({ Invoke-Safe { Invoke-ResolveMailbox } 'Resolve mailbox' })
$btnHoldDetails.Add_Click({ Invoke-Safe { Show-HoldDetails } 'Hold details' })
$btnSearch.Add_Click({ Invoke-Safe { Invoke-Search } 'Search' })
$btnLoadFolders.Add_Click({ Invoke-Safe { Invoke-LoadFolders } 'Load folders' })
$btnRestore.Add_Click({ Invoke-Safe { Invoke-Restore } 'Restore' })
$btnExport.Add_Click({ Invoke-Safe { Export-Results } 'Export results' })
$btnOpenLog.Add_Click({ Invoke-Safe { if (Test-Path $script:LogPath) { Start-Process notepad.exe -ArgumentList "`"$script:LogPath`"" } else { Start-Process explorer.exe $script:DataDir } } 'Open log' })
$btnClearAct.Add_Click({ $script:lvActivity.Items.Clear() })
$btnPreview.Add_Click({ Invoke-Safe { if ($script:State.SelectedData) { $script:State.SelectedData.Preview = $null; Request-Preview $script:State.SelectedData } } 'Preview' })
$btnCancel.Add_Click({
    if ((Show-Message 'Cancel the running action and everything still queued?' $script:AppName 'YesNo' 'Question') -eq 'Yes') { Stop-Jobs -IncludeQueued }
})
$btnCheckAll.Add_Click({ Set-VisibleChecks $true })
$btnUncheckAll.Add_Click({ Set-VisibleChecks $false })
$miConnectExo.Add_Click({ Invoke-Safe { Invoke-SignIn } 'Sign in' })
$miConnectGraph.Add_Click({ Invoke-Safe { Show-AdvancedSignIn } 'Advanced sign-in' })
$miDisconnect.Add_Click({ Invoke-Safe { Invoke-DisconnectAll } 'Disconnect' })
$miExport.Add_Click({ Invoke-Safe { Export-Results } 'Export results' })
$miOpenLog.Add_Click({ Invoke-Safe { if (Test-Path $script:LogPath) { Start-Process notepad.exe -ArgumentList "`"$script:LogPath`"" } } 'Open log' })
$miOpenFolder.Add_Click({ Invoke-Safe { Start-Process explorer.exe $script:DataDir } 'Open log folder' })
$miExit.Add_Click({ $script:Form.Close() })
$miCheckAll.Add_Click({ Set-VisibleChecks $true })
$miUncheckAll.Add_Click({ Set-VisibleChecks $false })
$miCopyIdMenu.Add_Click({ $s = $script:lvResults.SelectedItems; if ($s.Count) { Set-ClipboardText ([string]$s[0].Tag.EntryID) } })
$miCopySubMenu.Add_Click({ $s = $script:lvResults.SelectedItems; if ($s.Count) { Set-ClipboardText ([string]$s[0].Tag.Subject) } })
$miCopyDiag.Add_Click({ Set-ClipboardText (Get-DiagnosticsText) })
$miRequirements.Add_Click({ Show-Requirements })
$miAbout.Add_Click({ Show-About })

foreach ($rb in $rbOriginal, $rbExFolder, $rbGraphMove) { $rb.Add_CheckedChanged({ Update-RestoreHint }) }
$chkRemote.Add_CheckedChanged({ if ($script:State.SelectedData -and $script:State.SelectedData.Preview) { Show-Preview $script:State.SelectedData } })
$chkPlain.Add_CheckedChanged({ if ($script:State.SelectedData -and $script:State.SelectedData.Preview) { Show-Preview $script:State.SelectedData } })
$script:FilterTimer = New-Object System.Windows.Forms.Timer
$FilterTimer.Interval = 200
$FilterTimer.Add_Tick({ $script:FilterTimer.Stop(); Update-ResultsList })
$txtFilter.Add_TextChanged({ $script:FilterTimer.Stop(); $script:FilterTimer.Start() })
$grpRestore.Add_SizeChanged({ try { $script:lblRestoreHint.Width = [Math]::Max(400, $script:grpRestore.ClientSize.Width - 36) } catch { } })

$txtMailbox.Add_KeyDown({ param($s, $e) if ($e.KeyCode -eq 'Enter') { $e.SuppressKeyPress = $true; Invoke-Safe { Invoke-ResolveMailbox } 'Resolve mailbox' } })
$txtSubject.Add_KeyDown({ param($s, $e) if ($e.KeyCode -eq 'Enter') { $e.SuppressKeyPress = $true; Invoke-Safe { Invoke-Search } 'Search' } })
$txtEntryId.Add_KeyDown({ param($s, $e) if ($e.KeyCode -eq 'Enter') { $e.SuppressKeyPress = $true; Invoke-Safe { Invoke-Search } 'Search' } })
$Form.Add_KeyDown({
    param($s, $e)
    if ($e.KeyCode -eq 'F5' -and $script:btnSearch.Enabled) { $e.Handled = $true; Invoke-Safe { Invoke-Search } 'Search' }
    elseif ($e.KeyCode -eq 'Escape' -and $script:btnCancel.Enabled) { $e.Handled = $true; if ((Show-Message 'Cancel the running action and everything still queued?' $script:AppName 'YesNo' 'Question') -eq 'Yes') { Stop-Jobs -IncludeQueued } }
    elseif ($e.Control -and $e.KeyCode -eq 'Enter' -and $script:btnRestore.Enabled) { $e.Handled = $true; Invoke-Safe { Invoke-Restore } 'Restore' }
})

$lvResults.Add_ItemChecked({
    param($s, $e)
    if ($e.Item.Tag) { $e.Item.Tag.Checked = $e.Item.Checked }
    if (-not $script:Rendering) { Update-ResultCount }
})
$lvResults.Add_ColumnClick({
    param($s, $e)
    if ($script:ResultSorter.Column -eq $e.Column) { $script:ResultSorter.Descending = -not $script:ResultSorter.Descending }
    else { $script:ResultSorter.Column = $e.Column; $script:ResultSorter.Descending = $false }
    Update-SortHeaders
    $script:lvResults.Sort()
})
$lvResults.Add_MouseDown({
    param($s, $e)
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Right) {
        $hit = $script:lvResults.HitTest($e.X, $e.Y)
        if ($hit.Item -and -not $hit.Item.Selected) {
            $script:lvResults.SelectedItems.Clear()
            $hit.Item.Selected = $true
            $hit.Item.Focused = $true
        }
    }
})
$script:PreviewTimer = New-Object System.Windows.Forms.Timer
$PreviewTimer.Interval = 300
$PreviewTimer.Add_Tick({ $script:PreviewTimer.Stop(); Invoke-Safe { Show-SelectedItem } 'Preview' })
$lvResults.Add_SelectedIndexChanged({ $script:PreviewTimer.Stop(); $script:PreviewTimer.Start() })
$lvResults.Add_DoubleClick({ Invoke-Safe { if ($script:State.SelectedData) { Request-Preview $script:State.SelectedData } } 'Preview' })
$miPreview.Add_Click({ Invoke-Safe { if ($script:State.SelectedData) { Request-Preview $script:State.SelectedData } } 'Preview' })
$miCopyId.Add_Click({ $s = $script:lvResults.SelectedItems; if ($s.Count) { Set-ClipboardText ([string]$s[0].Tag.EntryID) } })
$miCopySubj.Add_Click({ $s = $script:lvResults.SelectedItems; if ($s.Count) { Set-ClipboardText ([string]$s[0].Tag.Subject) } })
$miCopyInternet.Add_Click({
    $s = $script:lvResults.SelectedItems
    if ($s.Count -and $s[0].Tag.Preview) { Set-ClipboardText ([string]$s[0].Tag.Preview.InternetMessageId) }
})
$miCheckSel.Add_Click({ foreach ($i in @($script:lvResults.SelectedItems)) { $i.Checked = $true } })
$lvActivity.Add_DoubleClick({
    $sel = $script:lvActivity.SelectedItems
    if ($sel.Count -eq 0) { return }
    $i = $sel[0]
    Show-TextDialog 'Activity detail' ("{0}`r`n{1}   {2}   {3}`r`n`r`n{4}" -f $i.SubItems[3].Text, $i.Text, $i.SubItems[1].Text, $i.SubItems[2].Text, $i.SubItems[4].Text) 760 360
})
$web.Add_Navigating({
    param($s, $e)
    $u = [string]$e.Url
    if ($u -and -not $u.StartsWith('about:', [StringComparison]::OrdinalIgnoreCase)) {
        $e.Cancel = $true
        Set-StatusLabel $script:lblPreviewState 'Warning' "Link blocked in preview: $u"
    }
})
$web.Add_NewWindow({ param($s, $e) $e.Cancel = $true })
try { $web.Add_FileDownload({ param($s, $e) try { $e.Cancel = $true } catch { } }) } catch { }

$script:JobTimer = New-Object System.Windows.Forms.Timer
$JobTimer.Interval = 200
$JobTimer.Add_Tick({ Invoke-JobTick })

function Initialize-WorkerRunspace {
    $script:Worker = [runspacefactory]::CreateRunspace()
    $script:Worker.ApartmentState = [System.Threading.ApartmentState]::MTA
    $script:Worker.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $script:Worker.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $script:Worker
    [void]$ps.AddScript($script:SharedFunctions.ToString())
    $null = $ps.Invoke()
    $errors = @($ps.Streams.Error)
    $ps.Dispose()
    if ($errors.Count -gt 0) { throw "The background worker could not load its helpers. $($errors[0])" }
}
function Hide-ConsoleWindow {
    try {
        if (-not ('MrcConsoleNative' -as [type])) {
            Add-Type -Namespace MrcConsoleNative -Name Win32 -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern System.IntPtr GetConsoleWindow();
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool ShowWindow(System.IntPtr hWnd, int nCmdShow);
'@
        }
        $hwnd = [MrcConsoleNative.Win32]::GetConsoleWindow()
        if ($hwnd -ne [IntPtr]::Zero) { [void][MrcConsoleNative.Win32]::ShowWindow($hwnd, 0) }
    } catch { }
}
function Restore-WindowPlacement {
    $s = $script:Settings
    if ($s.WindowW -match '^\d+$' -and [int]$s.WindowW -ge 1100 -and $s.WindowH -match '^\d+$' -and [int]$s.WindowH -ge 700) {
        $x = if ($s.WindowX -match '^-?\d+$') { [int]$s.WindowX } else { 40 }
        $y = if ($s.WindowY -match '^-?\d+$') { [int]$s.WindowY } else { 40 }
        $area = [System.Windows.Forms.SystemInformation]::VirtualScreen
        if ($x -ge $area.Left -and $y -ge $area.Top -and ($x + 200) -lt $area.Right -and ($y + 100) -lt $area.Bottom) {
            $script:Form.StartPosition = 'Manual'
            $script:Form.Location = New-Object System.Drawing.Point($x, $y)
            $script:Form.Size = New-Object System.Drawing.Size([int]$s.WindowW, [int]$s.WindowH)
        }
    }
}

$Form.Add_Shown({
    try {
        $ratio = 0.56
        if ($script:Settings.Splitter -match '^[0-9.]+$') { $ratio = [double]$script:Settings.Splitter }
        $max = $script:split.Width - $script:split.Panel2MinSize - $script:split.SplitterWidth
        $dist = [int]($script:split.Width * $ratio)
        if ($dist -lt $script:split.Panel1MinSize) { $dist = $script:split.Panel1MinSize }
        if ($dist -gt $max) { $dist = $max }
        if ($dist -gt 0) { $script:split.SplitterDistance = $dist }
    } catch { }
    Update-RestoreHint
    Clear-Preview
    Hide-ConsoleWindow
    $script:JobTimer.Start()
    Write-Log 'INFO' "==== $script:AppName v$script:AppVersion started by $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME ===="
    Add-Job -Name 'Initialize background worker' -Script $script:WS_Init -OnSuccess {
        param($r, $job)
        $exo = Get-Module -ListAvailable -Name ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1
        $graphModule = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication | Sort-Object Version -Descending | Select-Object -First 1
        $script:State.ExoInstalled = [bool]$exo
        $script:State.ExoVersion = if ($exo) { $exo.Version.ToString() } else { '' }
        $script:State.GraphInstalled = [bool]$graphModule
        $script:State.GraphVersion = if ($graphModule) { $graphModule.Version.ToString() } else { '' }
        $ready = @()
        if ($exo) { $ready += "ExchangeOnlineManagement v$($exo.Version)" }
        if ($graphModule) { $ready += "Microsoft.Graph.Authentication v$($graphModule.Version)" }
        if ($ready.Count -eq 2) { Set-Activity $job.Activity 'Success' "PowerShell $($r.PSVersion). $($ready -join ', '). Use Sign in to open the Microsoft window." }
        elseif ($ready.Count -eq 1) { Set-Activity $job.Activity 'Warning' "PowerShell $($r.PSVersion). Found $($ready[0]). Sign in can install the other module." }
        else { Set-Activity $job.Activity 'Warning' "PowerShell $($r.PSVersion). Exchange Online and Microsoft Graph modules are not installed. Sign in can install them." }
    } -OnFailure {
        param($err, $job)
        Set-Activity $job.Activity 'Failed' $err
    }
})
$Form.Add_FormClosing({
    param($s, $e)
    if ($script:Closing) { return }
    if (Test-Busy) {
        if ((Show-Message 'An action is still running. Cancel it and close the console?' $script:AppName 'YesNo' 'Warning') -ne 'Yes') { $e.Cancel = $true; return }
        $script:Closing = $true
        Stop-Jobs -IncludeQueued
    } else { $script:Closing = $true }
    Save-UiSettings
    Write-Log 'INFO' "==== $script:AppName closed ===="
    Close-WorkerRunspace
})

Initialize-WorkerRunspace
Restore-WindowPlacement
Update-RestoreHint
[void]$Form.ShowDialog()
} catch {
    $startup = $_.Exception.ToString()
    try { Write-Log 'ERROR' $startup } catch { }
    try { [System.Windows.Forms.MessageBox]::Show($startup, $script:AppName, 'OK', 'Error') } catch { }
} finally {
    try { Save-UiSettings } catch { }
    try { Close-WorkerRunspace } catch { }
    try { if ($script:Form) { $script:Form.Dispose() } } catch { }
}
#endregion
