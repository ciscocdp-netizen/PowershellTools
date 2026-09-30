#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Find-CommonADGroups.ps1'
. $scriptPath

$failures = New-Object System.Collections.Generic.List[string]
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { [void]$script:failures.Add($Message) }
}
function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    if ($Actual -ne $Expected) {
        [void]$script:failures.Add("$Message | expected [$Expected] actual [$Actual]")
    }
}

$json = ConvertTo-JsonString "a\b`"<'>&`n"
Assert-True ($json -eq '"a\\b\"\u003c''\u003e\u0026\n"') 'JSON escapes backslash, quote, brackets, ampersand, and newline'

$lineSep = ConvertTo-JsonString ([string]([char]0x2028))
Assert-True ($lineSep -eq '"\u2028"') 'JSON escapes U+2028'

$one = ConvertTo-ObjectList 'Domain Users'
Assert-Equal $one.Count 1 'A single group name stays one value'
Assert-Equal $one[0] 'Domain Users' 'A single group name is not split into characters'
$empty = ConvertTo-ObjectList $null
Assert-Equal $empty.Count 0 'Null becomes an empty list'
$many = ConvertTo-ObjectList @('a', 'b')
Assert-Equal $many.Count 2 'Two values stay two values'

Assert-Equal (ConvertTo-LdapFilterLiteral 'a*(b)\') 'a\2a\28b\29\5c' 'LDAP filter escapes special characters'
Assert-Equal (Get-CnFromDistinguishedName 'CN=Sales\, West,OU=Groups,DC=contoso,DC=com') 'Sales, West' 'CN parser honors escaped commas'

$params = New-AdCommonParameter -ServerName '' -AdCredential $null
Assert-True ($params -is [System.Collections.IDictionary]) 'AD parameter helper returns the hashtable itself'
Assert-Equal @($params.Keys).Count 0 'Empty AD parameters stay empty'

$root = Join-Path ([System.IO.Path]::GetTempPath()) ('ad-groups-' + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $root | Out-Null
try {
    $userCsv = Join-Path $root 'users.csv'
    $semiCsv = Join-Path $root 'semi.csv'
    $quotedCsv = Join-Path $root 'quoted.csv'
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($userCsv, "Username,Department`r`nalice ,IT`r`nBob`r`nalice`r`n`r`n", $utf8)
    [System.IO.File]::WriteAllText($semiCsv, "SamAccountName;Department`r`njose`r`n", $utf8)
    [System.IO.File]::WriteAllText($quotedCsv, "LoginName,Department`r`n`"Smith, Alice`",Finance`r`nbob,IT`r`n", $utf8)
    $unicodePath = Join-Path $root 'unicode.csv'
    [System.IO.File]::WriteAllText($unicodePath, "User`r`njosé`r`n", $utf8)

    $users = Import-NameCsv -Path $userCsv -Aliases @('SamAccountName', 'Username', 'User') -Label 'Users'
    Assert-Equal $users.Count 2 'Trimmed unique user names'
    Assert-Equal $users[0] 'alice' 'First user keeps trimmed text'
    Assert-Equal $users[1] 'Bob' 'Second user is intact'

    $semi = Import-NameCsv -Path $semiCsv -Aliases @('SamAccountName') -Label 'Users'
    Assert-Equal $semi.Count 1 'Semicolon CSV yields one account'
    Assert-Equal $semi[0] 'jose' 'Semicolon value is intact'

    $quoted = Import-NameCsv -Path $quotedCsv -Aliases @('LoginName') -Label 'Users'
    Assert-Equal $quoted.Count 2 'Quoted CSV keeps both rows'
    Assert-Equal $quoted[0] 'Smith, Alice' 'Comma inside quotes stays one name'

    $unicode = Import-NameCsv -Path $unicodePath -Aliases @('User') -Label 'Users'
    Assert-Equal $unicode.Count 1 'UTF-8 name is one row'
    Assert-Equal $unicode[0] 'josé' 'UTF-8 name round-trips'

    $model = New-DemoReportModel
    $stats = Get-MembershipStats $model
    Assert-Equal $stats.Input 6 'Demo input count'
    Assert-Equal $stats.Resolved 5 'Demo resolved count'
    Assert-Equal $stats.NotFound 1 'Demo not-found count'
    Assert-Equal $stats.InScope 5 'Disabled accounts start in scope'
    Assert-Equal $stats.Groups 9 'Distinct groups with a member'
    Assert-Equal $stats.SharedByAll 1 'Only Domain Users is universal'
    Assert-Equal $stats.Threshold 4 'Four groups meet the default threshold'
    Assert-Equal $stats.Matched 5 'Comparison matches include both Admins groups'
    Assert-Equal $stats.NoMembers 1 'Archive Mail has no members'
    Assert-Equal $stats.Missing 1 'Ghost Group is not in AD'
    Assert-Equal $stats.AdOnly 4 'Unlisted groups stay AD only'

    $eve = $model.Users | Where-Object { $_.Sam -eq 'eve' }
    Assert-Equal $eve.GroupDns.Count 1 'A user with one group keeps one group'
    Assert-Equal $eve.GroupDns[0] 'CN=Domain Users,CN=Users,DC=contoso,DC=com' 'The single group is the full DN'

    $adminGroups = @($model.GroupMeta.Keys | Where-Object { $_ -like 'CN=Admins,*' })
    Assert-Equal $adminGroups.Count 2 'Same CN in two OUs stays two groups'

    $model.ExcludeDisabled = $true
    $excluded = Get-MembershipStats $model
    Assert-Equal $excluded.InScope 4 'Disabled account leaves the scope'
    Assert-Equal $excluded.SharedByAll 1 'Domain Users is still universal'
    Assert-Equal $excluded.Groups 8 'Legacy App drops out of membership rows'
    Assert-Equal $excluded.Matched 4 'Legacy App is no longer a membership match'
    Assert-Equal $excluded.NoMembers 2 'Legacy App and Archive Mail have nobody in scope'
    Assert-Equal $excluded.AdOnly 4 'AD-only groups are unchanged'

    $htmlPath = Join-Path $root 'report.html'
    $html = New-CommonAdGroupsHtml -Model (New-DemoReportModel)
    Write-Utf8NoBomFile -Path $htmlPath -Content $html
    $bytes = [System.IO.File]::ReadAllBytes($htmlPath)
    Assert-True (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) 'Report is UTF-8 without a BOM'
    $raw = [System.IO.File]::ReadAllText($htmlPath)
    $longest = 0
    foreach ($line in ($raw -split "`n")) { if ($line.Length -gt $longest) { $longest = $line.Length } }
    Assert-True ($longest -gt 500) "Report JSON stays on one line (longest was $longest)"
    $openScripts = ([regex]::Matches($raw, '<script\b')).Count
    $closeScripts = ([regex]::Matches($raw, '</script>')).Count
    Assert-Equal $openScripts $closeScripts 'Embedded data does not close the script early'
    Assert-True ($raw.Contains('\u003c/script\u003e')) 'Dangerous markup is JSON-escaped'

    $nodeScript = Join-Path $root 'check-report.js'
    @'
const fs = require('fs');
const html = fs.readFileSync(process.argv[2], 'utf8');
const start = html.indexOf('var REPORT = ');
if (start < 0) throw new Error('missing REPORT');
const end = html.indexOf('\n', start);
let literal = html.slice(start + 'var REPORT = '.length, end).trim();
if (literal.endsWith(';')) literal = literal.slice(0, -1);
const report = JSON.parse(literal);
const eve = report.users.find((user) => user.sam === 'eve');
if (!Array.isArray(eve.groups) || eve.groups.length !== 1) {
  throw new Error('eve groups were unwrapped: ' + JSON.stringify(eve.groups));
}
if (eve.groups[0] !== 'CN=Domain Users,CN=Users,DC=contoso,DC=com') {
  throw new Error('unexpected eve group ' + eve.groups[0]);
}
const weirdDn = 'CN=Weird,OU=Groups,DC=contoso,DC=com';
const weird = report.groupMeta[weirdDn];
if (!weird || weird.name.indexOf('</script>') < 0) throw new Error('script payload did not round-trip');
if (weird.description !== 'Use \\\\fileserver\\sales <b>not html</b>') {
  throw new Error('description round-trip failed: ' + JSON.stringify(weird.description));
}
const finance = report.groupMeta['CN=Finance,OU=Groups,DC=contoso,DC=com'];
if (!finance.description.includes('\n')) throw new Error('newline description was lost');
const carol = report.users.find((user) => user.sam === 'carol');
if (carol.display !== "Carol O'Neil" || carol.dept !== 'R&D') throw new Error('carol text changed');
const admins = report.compare.entries.find((entry) => entry.name === 'Admins');
if (!admins || !Array.isArray(admins.dns) || admins.dns.length !== 2) throw new Error('Admins comparison collapsed');
console.log('NODE_OK');
'@ | Set-Content -LiteralPath $nodeScript -Encoding utf8
    $node = & node $nodeScript $htmlPath
    Assert-Equal $node 'NODE_OK' 'Node parsed the embedded report'

    $extracted = Join-Path $root 'report-script.js'
    $marker = '<script>' + [Environment]::NewLine + 'var REPORT = '
    $scriptStart = $raw.LastIndexOf('<script>')
    $scriptEnd = $raw.LastIndexOf('</script>')
    $body = $raw.Substring($scriptStart + 8, $scriptEnd - ($scriptStart + 8))
    [System.IO.File]::WriteAllText($extracted, $body, $utf8)
    & node --check $extracted
    if ($LASTEXITCODE -ne 0) { Assert-True $false 'Generated report script failed node --check' }
}
finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count) {
    Write-Host 'FAILURES:'
    foreach ($failure in $failures) { Write-Host " - $failure" }
    exit 1
}
Write-Host "Passed $($failures.Count) failures, all assertions held."
exit 0
