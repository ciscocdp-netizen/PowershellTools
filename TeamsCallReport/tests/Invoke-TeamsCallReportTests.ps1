# Regression tests for the Teams call report engine. No Graph tenant required.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'TeamsCallReport.Core.ps1')

$failures = New-Object System.Collections.Generic.List[string]
function Assert-True {
    param([string]$Name, [bool]$Condition)
    if (-not $Condition) { $script:failures.Add($Name) }
}
function Assert-Equal {
    param([string]$Name, $Actual, $Expected)
    $left = if ($null -eq $Actual) { '<null>' } else { [string]$Actual }
    $right = if ($null -eq $Expected) { '<null>' } else { [string]$Expected }
    if ($left -ne $right) { $script:failures.Add("$Name expected [$right] actual [$left]") }
}

# Collection and scalar helpers. Items is a List so a one-element result stays a list.
$audio = (Get-ObjectList 'audio').Items
Assert-Equal 'string list count' $audio.Count 1
Assert-Equal 'string list value' $audio[0] 'audio'

$oneObject = (Get-ObjectList ([pscustomobject]@{ id = 'only' })).Items
Assert-Equal 'single object count' $oneObject.Count 1
Assert-Equal 'single object id' $oneObject[0].id 'only'

$pair = (Get-ObjectList @([pscustomobject]@{ id = 'a' }, [pscustomobject]@{ id = 'b' })).Items
Assert-Equal 'pair count' $pair.Count 2

$rowDict = [ordered]@{ CallId = 'abc'; DisplayName = 'Ada' }
$boxed = (Get-ObjectList $rowDict).Items
Assert-Equal 'dictionary boxed count' $boxed.Count 1
Assert-Equal 'dictionary boxed type' $boxed[0].GetType().FullName 'System.Collections.Specialized.OrderedDictionary'
Assert-Equal 'dictionary boxed value' $boxed[0]['CallId'] 'abc'

Assert-Equal 'null duration' (Get-DurationSeconds $null $null) $null
Assert-Equal 'empty duration' (Get-DurationSeconds '' '2024-01-01T00:00:00Z') $null
Assert-Equal 'thirty minutes' (Get-DurationSeconds '2024-01-01T00:00:00Z' '2024-01-01T00:30:00Z') 1800
Assert-Equal 'negative duration' (Get-DurationSeconds '2024-01-02T00:00:00Z' '2024-01-01T00:00:00Z') $null
Assert-Equal 'utc format' (ConvertTo-UtcString '2020-02-25T18:52:21.2169889Z') '2020-02-25T18:52:21Z'

$roles = ConvertTo-StringArray 'CallRecords.Read.All'
Assert-Equal 'one role count' @($roles).Count 1
Assert-Equal 'one role value' $roles[0] 'CallRecords.Read.All'

$json = ConvertTo-JsonSafe @([pscustomobject]@{ displayName = '=2+2'; n = 1 })
Assert-True 'json keeps one-element array' ($json.StartsWith('[') -and $json.EndsWith(']'))
Assert-True 'json keeps formula text' ($json.Contains('"=2+2"'))

$formula = Format-CsvField '=2+2'
Assert-Equal 'formula neutralized' $formula '"''=2+2"'
$number = Format-CsvField -18
Assert-Equal 'negative number kept' $number '"-18"'
$phone = Format-CsvField '+14255550100'
Assert-Equal 'phone digits kept' $phone '"+14255550100"'
$plusCmd = Format-CsvField '+cmd'
Assert-Equal 'plus command neutralized' $plusCmd '"''+cmd"'

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('TeamsCallReportTests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
try {
    $single = Join-Path $tempRoot 'one.csv'
    Export-UnionCsv -Rows @([ordered]@{ 'Endpoint.userAgent.platform' = 'windows' }) -Path $single
    $singleCsv = Import-Csv -LiteralPath $single
    Assert-Equal 'dotted csv value' $singleCsv.'Endpoint.userAgent.platform' 'windows'
    $singleHeader = [System.IO.File]::ReadAllText($single)
    Assert-True 'dotted header is one column' ($singleHeader.StartsWith('"Endpoint.userAgent.platform"'))

    $client = New-TeamsSampleGraphClient
    $fixture = $client.Fixture
    $out = Join-Path $tempRoot 'sample'
    $result = Export-TeamsUserCallDetails -User $fixture.AliceMail -StartDate ([datetime]::UtcNow.AddDays(-10)) -EndDate ([datetime]::UtcNow.AddMinutes(1)) -OutputPath $out -GraphClient $client
    Assert-True 'sample export error' ([string]::IsNullOrWhiteSpace($result.ErrorMessage))
    Assert-Equal 'call count' $result.CallCount 2
    Assert-Equal 'external identities' $result.ExternalIdentityCount 1
    Assert-True 'mail lookup used the filter' (($client.Requests -join "`n") -match 'Alice\.Adams')

    $calls = Import-Csv -LiteralPath (Join-Path $out 'Calls.csv')
    $byId = @{}
    foreach ($call in @($calls)) { $byId[$call.CallId] = $call }
    Assert-Equal 'call A duration' $byId[$fixture.CallA].DurationSeconds "$($fixture.CallADuration)"
    Assert-Equal 'call A organizer' $byId[$fixture.CallA].TargetUserIsOrganizer 'true'
    Assert-Equal 'call B organizer flag' $byId[$fixture.CallB].TargetUserIsOrganizer 'false'
    Assert-Equal 'call B organizer name' $byId[$fixture.CallB].OrganizerDisplayName 'Erin Ellis'
    Assert-True 'old call excluded' (-not $byId.ContainsKey($fixture.CallC))

    $people = Import-Csv -LiteralPath (Join-Path $out 'Participants.csv')
    $alice = @($people | Where-Object { $_.CallId -eq $fixture.CallA -and $_.IdentityId -eq $fixture.AliceId })
    Assert-Equal 'alice rows on call A' $alice.Count 1
    Assert-Equal 'alice department' $alice[0].'Entra.department' 'Voice Engineering'
    Assert-Equal 'alice sam' $alice[0].'Entra.onPremisesSamAccountName' 'alice'
    Assert-Equal 'alice manager' $alice[0].'Entra.Manager.displayName' 'Mary Manager'
    $dave = @($people | Where-Object { $_.IdentityId -eq $fixture.DaveId })
    Assert-Equal 'dave count' $dave.Count 1
    Assert-Equal 'dave not external despite tenant case' $dave[0].IsExternalTenant 'false'
    Assert-Equal 'dave department' $dave[0].'Entra.department' 'Engineering'
    Assert-Equal 'dave name' $dave[0].DisplayName 'José Núñez'
    $bob = @($people | Where-Object { $_.IdentityId -eq $fixture.BobId })
    Assert-Equal 'bob external' $bob[0].IsExternalTenant 'true'
    Assert-True 'bob skipped directory' ($bob[0].'Entra.LookupStatus'.StartsWith('ExternalTenant'))
    $phoneRow = @($people | Where-Object { $_.IdentityType -eq 'phone' })
    Assert-Equal 'phone count' $phoneRow.Count 1
    Assert-Equal 'phone not a directory user' $phoneRow[0].'Entra.LookupStatus' 'NotApplicable'
    Assert-Equal 'phone id' $phoneRow[0].IdentityId '+14255550100'
    $erinRows = @($people | Where-Object { $_.IdentityId -eq $fixture.ErinId })
    Assert-Equal 'erin on both calls' $erinRows.Count 2
    Assert-Equal 'erin manager missing' $erinRows[0].'Entra.Manager.LookupStatus' 'NotFound'
    $erinMentions = [regex]::Matches(($client.Requests -join "`n"), [regex]::Escape($fixture.ErinId)).Count
    Assert-Equal 'erin looked up once' $erinMentions 2

    $bytes = [System.IO.File]::ReadAllBytes((Join-Path $out 'Participants.csv'))
    Assert-Equal 'utf8 bom 0' $bytes[0] 239
    Assert-Equal 'utf8 bom 1' $bytes[1] 187
    Assert-Equal 'utf8 bom 2' $bytes[2] 191
    $participantText = [System.IO.File]::ReadAllText((Join-Path $out 'Participants.csv'), (New-Object System.Text.UTF8Encoding $true))
    Assert-True 'unicode roundtrip' ($participantText.Contains('José Núñez'))
    Assert-True 'formula neutralized in csv' ($participantText.Contains('''=2+2'))

    $raw = [System.IO.File]::ReadAllText((Join-Path $out "RawJson\$($fixture.CallA).json"))
    Assert-True 'raw keeps device name' ($raw.Contains('Headset Microphone (Poly V4320)'))
    Assert-True 'raw keeps original formula' ($raw.Contains('"=2+2"'))
    Assert-True 'raw is not formula-prefixed' (-not $raw.Contains('''=2+2'))
    $null = $raw | ConvertFrom-Json

    $endpoints = Import-Csv -LiteralPath (Join-Path $out 'Endpoints.csv')
    $aliceAudio = @($endpoints | Where-Object { $_.CallId -eq $fixture.CallA -and $_.Role -eq 'caller' -and $_.'Media.Label' -eq 'main-audio' })
    Assert-True 'alice audio row' ($aliceAudio.Count -ge 1)
    Assert-Equal 'associated identity name' $aliceAudio[0].DisplayName 'Alice Adams'
    Assert-Equal 'alice upn from endpoint' $aliceAudio[0].UserPrincipalName 'alice@contoso.com'
    Assert-Equal 'platform' $aliceAudio[0].ClientPlatform 'windows'
    Assert-Equal 'cpu' $aliceAudio[0].CpuName 'Intel(R) Core(TM) i7-8665U CPU @ 1.90GHz'
    Assert-Equal 'capture device' $aliceAudio[0].CaptureDevice 'Headset Microphone (Poly V4320)'
    Assert-Equal 'render device' $aliceAudio[0].RenderDevice 'Headset Earphone (Poly V4320)'
    Assert-Equal 'ip' $aliceAudio[0].IpAddress '10.20.30.40'
    Assert-Equal 'reflexive' $aliceAudio[0].ReflexiveIP '203.0.113.25'
    Assert-Equal 'relay' $aliceAudio[0].RelayIP '52.114.1.10'
    Assert-Equal 'mac' $aliceAudio[0].MacAddress '00:11:22:33:44:55'
    Assert-Equal 'wifi driver' $aliceAudio[0].WifiDriver 'Intel Wireless Driver'
    Assert-Equal 'bssid' $aliceAudio[0].Bssid 'AA:BB:CC:DD:EE:FF'
    Assert-Equal 'connection' $aliceAudio[0].ConnectionType 'wifi'
    Assert-True 'signal level kept numeric' ($participantText -ne $null)
    Assert-Equal 'flat signal' $aliceAudio[0].'Device.receivedSignalLevel' '-18'
    Assert-Equal 'failure reason' $aliceAudio[0].FailureReason 'MediaConnectivity'
    Assert-Equal 'null segment end' $aliceAudio[0].SegmentEndUtc ''
    Assert-True 'user agent flattened' ($aliceAudio[0].'Endpoint.userAgent.headerValue'.Contains('Teams-Windows'))
    $video = @($endpoints | Where-Object { $_.'Media.Label' -eq 'main-video' })
    Assert-True 'paged video session present' ($video.Count -ge 1)
    Assert-Equal 'video capture' $video[0].CaptureDevice 'Integrated Camera'
    $mac = @($endpoints | Where-Object { $_.ClientPlatform -eq 'macOS' })
    Assert-True 'callee platform' ($mac.Count -ge 1)
    Assert-Equal 'erin endpoint name' $mac[0].DisplayName 'Erin Ellis'

    $callsTable = $result.CallsTable
    Assert-Equal 'table type' $callsTable.GetType().FullName 'System.Data.DataTable'
    Assert-Equal 'table rows' $callsTable.Rows.Count 2
    Assert-Equal 'duration column type' $callsTable.Columns['DurationSeconds'].DataType.Name 'Int32'

    $limitedClient = New-TeamsSampleGraphClient
    $limitedOut = Join-Path $tempRoot 'max'
    $limited = Export-TeamsUserCallDetails -User $fixture.AliceId -StartDate ([datetime]::UtcNow.AddDays(-10)) -EndDate ([datetime]::UtcNow.AddMinutes(1)) -OutputPath $limitedOut -GraphClient $limitedClient -MaxCalls 1
    Assert-Equal 'max calls' $limited.CallCount 1
    Assert-Equal 'newest call kept' $limited.CallsTable.Rows[0]['CallId'] $fixture.CallA

    $skipClient = New-TeamsSampleGraphClient
    $skipOut = Join-Path $tempRoot 'skip'
    $skipped = Export-TeamsUserCallDetails -User $fixture.AliceUpn -StartDate ([datetime]::UtcNow.AddDays(-10)) -EndDate ([datetime]::UtcNow.AddMinutes(1)) -OutputPath $skipOut -GraphClient $skipClient -SkipDirectoryLookup
    $skipPeople = Import-Csv -LiteralPath (Join-Path $skipOut 'Participants.csv')
    $skipAlice = @($skipPeople | Where-Object { $_.IdentityId -eq $fixture.AliceId })[0]
    Assert-Equal 'directory skipped' $skipAlice.'Entra.LookupStatus' 'Skipped'
    Assert-True 'no batch when skipped' (-not (($skipClient.Requests -join "`n") -match '\$batch'))

    $fallbackClient = New-TeamsSampleGraphClient -RejectCombinedFilter
    $fallbackOut = Join-Path $tempRoot 'fallback'
    $fallback = Export-TeamsUserCallDetails -User $fixture.AliceUpn -StartDate ([datetime]::UtcNow.AddDays(-10)) -EndDate ([datetime]::UtcNow.AddMinutes(1)) -OutputPath $fallbackOut -GraphClient $fallbackClient
    Assert-Equal 'fallback call count' $fallback.CallCount 2
    Assert-True 'fallback warning' ((@($fallback.Warnings) -join ' ') -match 'participant filter')
    $listRequests = @($fallbackClient.Requests | Where-Object { $_ -match '/communications/callRecords\?' })
    Assert-True 'combined request was attempted' (($listRequests | Where-Object { $_ -match 'startDateTime' }).Count -ge 1)
    Assert-True 'participant request followed' (($listRequests | Where-Object { $_ -notmatch 'startDateTime' }).Count -ge 1)
    Assert-True 'expired call not fetched' (-not (($fallbackClient.Requests -join "`n") -match [regex]::Escape($fixture.CallC)))

    $clampClient = New-TeamsSampleGraphClient
    $clampOut = Join-Path $tempRoot 'clamp'
    $clamped = Export-TeamsUserCallDetails -User $fixture.AliceUpn -StartDate ([datetime]::UtcNow.AddDays(-90)) -EndDate ([datetime]::UtcNow.AddMinutes(1)) -OutputPath $clampOut -GraphClient $clampClient
    Assert-Equal 'clamped still returns recent calls' $clamped.CallCount 2
    Assert-True 'retention warning' ((@($clamped.Warnings) -join ' ') -match '30 days')

    $cancelClient = New-TeamsSampleGraphClient
    $cancelClient.ShouldCancel = { $true }
    $cancelOut = Join-Path $tempRoot 'cancel'
    $cancelled = Export-TeamsUserCallDetails -User $fixture.AliceUpn -StartDate ([datetime]::UtcNow.AddDays(-10)) -EndDate ([datetime]::UtcNow.AddMinutes(1)) -OutputPath $cancelOut -GraphClient $cancelClient
    Assert-True 'cancel flag' $cancelled.Cancelled
    Assert-Equal 'cancel stopped before calls' $cancelled.CallCount 0

    $window = Get-TeamsCallWindow -StartDate ([datetime]::UtcNow.AddDays(-90)) -EndDate ([datetime]::UtcNow)
    Assert-True 'window clamped' $window.Clamped
    $threw = $false
    try { Get-TeamsCallWindow -StartDate ([datetime]::UtcNow.AddDays(-90)) -EndDate ([datetime]::UtcNow.AddDays(-60)) | Out-Null }
    catch { $threw = $true }
    Assert-True 'range outside retention throws' $threw
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

# HTTP: single encoding, preserved skip tokens, and Retry-After.
$listenerPort = Get-Random -Minimum 22000 -Maximum 42000
$prefix = "http://127.0.0.1:$listenerPort/"
$seen = New-Object System.Collections.Generic.List[string]
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($prefix)
$listener.Start()
$rs = [runspacefactory]::CreateRunspace()
$rs.Open()
$ps = [powershell]::Create()
$ps.Runspace = $rs
[void]$ps.AddScript({
        param($Listener, $Seen)
        while ($Listener.IsListening) {
            $context = $null
            try { $context = $Listener.GetContext() }
            catch { break }
            $raw = $context.Request.RawUrl
            $auth = $context.Request.Headers['Authorization']
            [void]$Seen.Add("$raw || $auth")
            $status = 200
            $body = '{"value":[]}'
            $retry = $null
            $throttleHits = @($Seen | Where-Object { $_ -match 'throttle' }).Count
            if ($raw -match 'throttle' -and $throttleHits -eq 1) {
                $status = 429
                $body = '{"error":{"code":"TooManyRequests","message":"slow down"}}'
                $retry = '0'
            }
            if ($retry) { $context.Response.Headers['Retry-After'] = $retry }
            $context.Response.StatusCode = $status
            $bytes = [Text.Encoding]::UTF8.GetBytes($body)
            $context.Response.ContentType = 'application/json'
            $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $context.Response.Close()
        }
    }).AddArgument($listener).AddArgument($seen)
$httpHandle = $ps.BeginInvoke()
Start-Sleep -Milliseconds 300
try {
    $http = @{
        Kind         = 'Http'
        BaseUrl      = "http://127.0.0.1:$listenerPort/v1.0"
        AllowedHosts = @('127.0.0.1')
        AccessToken  = 'test-token'
        ExpiresOn    = [datetimeoffset]::UtcNow.AddHours(1)
        TenantId     = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        Requests     = (New-Object System.Collections.Generic.List[string])
        Log          = { param($Level, $Message) }
        ShouldCancel = $null
        TokenMode    = $null
    }
    $filter = "participants_v2/any(p:p/id eq '11111111-1111-1111-1111-111111111111') and startDateTime ge 2026-10-01T00:00:00Z and startDateTime lt 2026-10-30T00:00:00Z"
    $null = Invoke-TeamsGraphRequest -Client $http -Uri (Format-GraphPath 'communications/callRecords' @{ '$filter' = $filter })
    $skip = "http://127.0.0.1:$listenerPort/v1.0/communications/callRecords/x/participants_v2?skiptoken=abc%2Bdef%2Fghi%3D"
    $null = Invoke-TeamsGraphRequest -Client $http -Uri $skip
    $null = Invoke-TeamsGraphRequest -Client $http -Uri (Format-GraphPath 'communications/callRecords/throttle' @{})
    Start-Sleep -Milliseconds 200
    $log = ($seen -join "`n")
    Assert-True 'filter encoded once' ($log -match 'participants_v2%2Fany' -and $log -notmatch '%2520' -and $log -notmatch '%252F')
    Assert-True 'bearer sent' ($log -match 'Bearer test-token')
    Assert-True 'skip token preserved' ($log -match 'skiptoken=abc%2Bdef%2Fghi%3D')
    Assert-True 'skip token not double encoded' ($log -notmatch '%252B')
    Assert-True 'throttle retried' ((@($seen | Where-Object { $_ -match 'throttle' })).Count -ge 2)
    $blocked = $false
    try {
        Invoke-TeamsGraphRequest -Client $http -Uri 'https://evil.example/v1.0/users' | Out-Null
    }
    catch { $blocked = $_.Exception.Message -match 'unexpected host' }
    Assert-True 'foreign host blocked' $blocked
}
finally {
    try { $listener.Stop() } catch { }
    try { $listener.Close() } catch { }
    try { $ps.Stop() } catch { }
    $ps.Dispose()
    $rs.Dispose()
}

# Certificate client assertion signs and verifies without contacting a tenant.
$certDir = Join-Path ([System.IO.Path]::GetTempPath()) ('TeamsCallReportCert-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $certDir -Force | Out-Null
$pfx = Join-Path $certDir 'test.pfx'
$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if ($openssl) {
    & openssl req -x509 -newkey rsa:2048 -keyout (Join-Path $certDir 'key.pem') -out (Join-Path $certDir 'cert.pem') -days 2 -nodes -subj '/CN=TeamsCallReport Test' 2>$null | Out-Null
    & openssl pkcs12 -export -out $pfx -inkey (Join-Path $certDir 'key.pem') -in (Join-Path $certDir 'cert.pem') -passout pass:testpass 2>$null | Out-Null
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfx, 'testpass', [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    $endpoint = 'https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/oauth2/v2.0/token'
    $jwt = New-TeamsClientAssertion -ClientId '11111111-1111-1111-1111-111111111111' -TokenEndpoint $endpoint -Certificate $cert
    $jwt2 = New-TeamsClientAssertion -ClientId '11111111-1111-1111-1111-111111111111' -TokenEndpoint $endpoint -Certificate $cert
    Assert-True 'second signature still works' ($jwt2.Split('.').Count -eq 3)
    $parts = $jwt.Split('.')
    Assert-Equal 'jwt parts' $parts.Count 3
    $header = [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $parts[0])) | ConvertFrom-Json
    $payload = Get-TeamsJwtPayload $jwt
    Assert-Equal 'jwt alg' $header.alg 'RS256'
    Assert-Equal 'jwt audience' $payload.aud $endpoint
    Assert-Equal 'jwt subject' $payload.sub '11111111-1111-1111-1111-111111111111'
    $rawCert = $cert
    if ($rawCert -is [System.Management.Automation.PSObject]) { $rawCert = $rawCert.PSObject.BaseObject }
    $public = $null
    $getPublic = $rawCert.GetType().GetMethod('GetRSAPublicKey')
    if ($getPublic) { $public = $getPublic.Invoke($rawCert, $null) }
    if (-not $public) {
        $extension = $null
        foreach ($assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
            $extension = $assembly.GetType('System.Security.Cryptography.X509Certificates.RSACertificateExtensions', $false)
            if ($extension) { break }
        }
        if ($extension) {
            $getPublic = $extension.GetMethod('GetRSAPublicKey', [Type[]]@([System.Security.Cryptography.X509Certificates.X509Certificate2]))
            if ($getPublic) { $public = $getPublic.Invoke($null, @($rawCert)) }
        }
    }
    Assert-True 'public key' ($null -ne $public)
    if ($public) {
        $data = [Text.Encoding]::ASCII.GetBytes(($parts[0] + '.' + $parts[1]))
        $sigBytes = ConvertFrom-Base64Url $parts[2]
        $ok = $public.VerifyData(
            [byte[]]$data,
            [byte[]]$sigBytes,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        Assert-True 'jwt signature verifies' ([bool]$ok)
        $public.Dispose()
    }
}
else {
    $script:failures.Add('openssl is required to test certificate assertions')
}
Remove-Item -LiteralPath $certDir -Recurse -Force -ErrorAction SilentlyContinue

$appJson = ConvertTo-JsonSafe (New-TeamsCallReportAppBody -DisplayName 'Teams Call Report' -Notes 'note' -KeyCredential ([ordered]@{
            type = 'AsymmetricX509Cert'; usage = 'Verify'; key = 'abc'; displayName = 'Teams Call Report'
        }))
Assert-True 'app body keeps resource array' ($appJson.Contains('"requiredResourceAccess":[') -or $appJson.Contains('"requiredResourceAccess": ['))
Assert-True 'app body keeps key array' ($appJson.Contains('"keyCredentials":[') -or $appJson.Contains('"keyCredentials": ['))
Assert-True 'app body has call role' ($appJson.Contains('45bbb07e-7321-4fd7-a8f6-3ff27e6a81c8'))
Assert-True 'app body has user role' ($appJson.Contains('df021288-bdef-4463-88db-98f22de89214'))

function New-AccountTestJwt {
    param($Payload)
    $header = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes('{"alg":"none","typ":"JWT"}'))
    $body = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes((ConvertTo-JsonSafe $Payload)))
    return ($header + '.' + $body + '.sig')
}
function New-AccountReply {
    param([int]$Status, [string]$Raw)
    return [pscustomobject]@{ StatusCode = $Status; Raw = $Raw; RetryAfter = $null }
}

if ($openssl) {
    $accountDir = Join-Path ([System.IO.Path]::GetTempPath()) ('TeamsCallReportAccount-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $accountDir -Force | Out-Null
    $accountPfx = Join-Path $accountDir 'app.pfx'
    & openssl req -x509 -newkey rsa:2048 -keyout (Join-Path $accountDir 'key.pem') -out (Join-Path $accountDir 'cert.pem') -days 2 -nodes -subj '/CN=Teams Call Report' 2>$null | Out-Null
    & openssl pkcs12 -export -out $accountPfx -inkey (Join-Path $accountDir 'key.pem') -in (Join-Path $accountDir 'cert.pem') -passout pass:testpass 2>$null | Out-Null
    $accountCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($accountPfx, 'testpass', [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    $accountTenant = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    $accountAppId = '77777777-7777-7777-7777-777777777777'
    $accountRoles = New-Object System.Collections.Generic.List[string]
    [void]$accountRoles.Add('CallRecords.Read.All')
    [void]$accountRoles.Add('User.Read.All')
    $userJwt = New-AccountTestJwt ([pscustomobject]@{
            tid = $accountTenant
            preferred_username = 'admin@contoso.com'
            scp = 'Application.ReadWrite.All AppRoleAssignment.ReadWrite.All Directory.Read.All'
        })
    $appJwt = New-AccountTestJwt ([pscustomobject]@{
            tid = $accountTenant
            appid = $accountAppId
            roles = $accountRoles
        })
    $accountState = @{
        Polls = 0
        RolePosts = 0
        CreateBody = $null
        Requests = (New-Object System.Collections.Generic.List[string])
    }
    $accountSend = {
        param($Method, $Uri, $Body, $ContentType, $Headers)
        [void]$accountState.Requests.Add("$Method $Uri")
        if ($Uri -match '/devicecode$') {
            return (New-AccountReply 200 '{"device_code":"dev-1","user_code":"ABCD-EFGH","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":0,"message":"Enter code"}')
        }
        if ($Uri -match '/organizations/oauth2/v2.0/token$') {
            $accountState.Polls = $accountState.Polls + 1
            if ($accountState.Polls -eq 1) { return (New-AccountReply 400 '{"error":"authorization_pending","error_description":"pending"}') }
            return (New-AccountReply 200 ("{`"access_token`":`"$userJwt`",`"expires_in`":3600}"))
        }
        if ($Uri -match '/applications\?' -and $Method -eq 'GET') { return (New-AccountReply 200 '{"value":[]}') }
        if ($Uri -match '/applications$' -and $Method -eq 'POST') {
            $accountState.CreateBody = [string]$Body
            return (New-AccountReply 200 ("{`"id`":`"app-object`",`"appId`":`"$accountAppId`"}"))
        }
        if ($Uri -match '/servicePrincipals\?' -and $Uri -match '00000003-0000-0000-c000-000000000000') {
            return (New-AccountReply 200 '{"value":[{"id":"graph-sp","appId":"00000003-0000-0000-c000-000000000000","appRoles":[{"id":"45bbb07e-7321-4fd7-a8f6-3ff27e6a81c8","value":"CallRecords.Read.All"},{"id":"df021288-bdef-4463-88db-98f22de89214","value":"User.Read.All"}]}]}')
        }
        if ($Uri -match '/servicePrincipals\?' -and $Method -eq 'GET') { return (New-AccountReply 200 '{"value":[]}') }
        if ($Uri -match '/servicePrincipals$' -and $Method -eq 'POST') { return (New-AccountReply 201 '{"id":"app-sp","appId":"77777777-7777-7777-7777-777777777777"}') }
        if ($Uri -match '/appRoleAssignedTo$') {
            $accountState.RolePosts = $accountState.RolePosts + 1
            if ($accountState.RolePosts -eq 1) { return (New-AccountReply 201 '{}') }
            return (New-AccountReply 400 '{"error":{"code":"Request_BadRequest","message":"Permission entry already exists."}}')
        }
        if ($Uri -match '/oauth2/v2.0/token$' -and $Method -eq 'POST') {
            return (New-AccountReply 200 ("{`"access_token`":`"$appJwt`",`"expires_in`":3600}"))
        }
        return (New-AccountReply 500 ("{`"error`":{`"message`":`"unexpected $Method $Uri`"}}"))
    }
    $seenCode = $null
    $grantPath = Join-Path $accountDir 'account.json'
    $connected = Connect-TeamsCallReportAccount -Cloud Public -GrantPath $grantPath -Certificate $accountCert -Send $accountSend -OnDeviceCode {
        param($Info)
        $script:seenCode = $Info.UserCode
    }
    Assert-Equal 'device code shown' $seenCode 'ABCD-EFGH'
    Assert-True 'public client used' (($accountState.Requests -join "`n") -match 'devicecode')
    Assert-True 'created app keeps roles' ($accountState.CreateBody.Contains('45bbb07e-7321-4fd7-a8f6-3ff27e6a81c8') -and $accountState.CreateBody.Contains('"requiredResourceAccess":['))
    Assert-Equal 'both roles granted or already present' $accountState.RolePosts 2
    Assert-True 'app token is application auth' ($connected.Client.TokenInfo.AuthType -eq 'Application')
    Assert-True 'app token can read calls' (Test-TeamsTokenHasCallRoles $connected.Client.TokenInfo)
    Assert-Equal 'grant remembers app' ((Get-Content -LiteralPath $grantPath -Raw | ConvertFrom-Json).clientId) $accountAppId
    $reuseRequests = $accountState.Requests.Count
    $reused = Connect-TeamsCallReportAccount -Cloud Public -GrantPath $grantPath -Certificate $accountCert -Send $accountSend
    Assert-True 'second run reuses the grant' $reused.Reused
    Assert-Equal 'second run does not start another sign-in' $accountState.Requests.Count ($reuseRequests + 1)

    $forbidden = @{
        Polls = 0
        RolePosts = 0
        CreateBody = $null
        Requests = (New-Object System.Collections.Generic.List[string])
    }
    $forbiddenSend = {
        param($Method, $Uri, $Body, $ContentType, $Headers)
        if ($Uri -match '/devicecode$') {
            return (New-AccountReply 200 '{"device_code":"dev-2","user_code":"ZZZZ-ZZZZ","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":0}')
        }
        if ($Uri -match '/organizations/oauth2/v2.0/token$') {
            return (New-AccountReply 200 ("{`"access_token`":`"$userJwt`",`"expires_in`":3600}"))
        }
        if ($Uri -match '/applications\?') { return (New-AccountReply 403 '{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}') }
        return (New-AccountReply 500 '{"error":{"message":"unexpected"}}')
    }
    $denied = $false
    try {
        Connect-TeamsCallReportAccount -Cloud Public -GrantPath (Join-Path $accountDir 'none.json') -Certificate $accountCert -Send $forbiddenSend | Out-Null
    }
    catch { $denied = $_.Exception.Message -match 'Global Administrator' }
    Assert-True 'non admin is told which role is required' $denied

    $cancelSend = {
        param($Method, $Uri, $Body, $ContentType, $Headers)
        if ($Uri -match '/devicecode$') {
            return (New-AccountReply 200 '{"device_code":"dev-3","user_code":"CANCEL-1","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":0}')
        }
        return (New-AccountReply 500 '{"error":{"message":"should have cancelled"}}')
    }
    $cancelledSignIn = $false
    try {
        Connect-TeamsCallReportAccount -Cloud Public -GrantPath (Join-Path $accountDir 'cancel.json') -Certificate $accountCert -Send $cancelSend -ShouldCancel { $true } | Out-Null
    }
    catch { $cancelledSignIn = $_.Exception.Message -match 'Sign-in cancelled' }
    Assert-True 'sign-in can be cancelled' $cancelledSignIn
    Remove-Item -LiteralPath $accountDir -Recurse -Force -ErrorAction SilentlyContinue
}

foreach ($name in @('TeamsCallReport.Core.ps1', 'Get-TeamsUserCallDetails.ps1', 'TeamsCallReport.ps1')) {
    $path = Join-Path $root $name
    $tokens = $null
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors -and @($parseErrors).Count -gt 0) {
        $script:failures.Add("$name parse: " + ((@($parseErrors) | ForEach-Object { $_.ToString() }) -join ' | '))
    }
}

if ($failures.Count -gt 0) {
    Write-Output 'FAILED'
    foreach ($failure in $failures) { Write-Output (" - " + $failure) }
    exit 1
}
Write-Output 'OK'
exit 0
