#Requires -Version 5.1
# Self-contained tests for Set-EntraDeviceCAExemption.ps1 helper logic.
# Run: pwsh -NoProfile -File ./Tests/Set-EntraDeviceCAExemption.Tests.ps1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Failed = 0
$script:Passed = 0
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Split-Path -Parent $here
$tool = Join-Path $repo 'Set-EntraDeviceCAExemption.ps1'

. $tool -SkipMain

function Assert-True {
    param([bool]$Condition, [string]$Name, [string]$Detail = '')
    if ($Condition) {
        $script:Passed++
        Write-Host "  PASS  $Name" -ForegroundColor Green
    }
    else {
        $script:Failed++
        $suffix = if ($Detail) { " :: $Detail" } else { '' }
        Write-Host "  FAIL  $Name$suffix" -ForegroundColor Red
    }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Name)
    $ok = [System.Object]::Equals($Expected, $Actual)
    if (-not $ok -and $null -ne $Expected -and $null -ne $Actual) {
        $ok = [string]$Expected -ceq [string]$Actual
    }
    Assert-True -Condition $ok -Name $Name -Detail "expected '$Expected' actual '$Actual'"
}

function New-GraphDeviceHashtable {
    param(
        [string]$DisplayName = 'KIOSK-01',
        [string]$TrustType = 'Workplace',
        [string]$Os = 'Windows',
        [string]$DeviceId = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
        [string]$ObjectId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
        $ExtensionAttribute1 = $null
    )
    $attrs = @{ extensionAttribute1 = $ExtensionAttribute1 }
    return @{
        id                           = $ObjectId
        deviceId                     = $DeviceId
        displayName                  = $DisplayName
        trustType                    = $TrustType
        operatingSystem              = $Os
        operatingSystemVersion       = '10.0.19045'
        accountEnabled               = $true
        approximateLastSignInDateTime = '2026-01-15T12:00:00Z'
        extensionAttributes          = $attrs
        isManagementRestricted       = $false
    }
}

Write-Host 'Set-EntraDeviceCAExemption helper tests' -ForegroundColor Cyan

# --- Text / value helpers ---
Assert-Equal -Expected 'abc' -Actual (Limit-Text 'abc' 10) -Name 'Limit-Text leaves short text'
Assert-Equal -Expected 'Hello...' -Actual (Limit-Text 'Hello world' 8) -Name 'Limit-Text truncates with ellipsis'
Assert-Equal -Expected '' -Actual (Limit-Text $null 10) -Name 'Limit-Text null is empty'
Assert-Equal -Expected '<empty>' -Actual (Format-Value $null) -Name 'Format-Value null'
Assert-Equal -Expected '<empty>' -Actual (Format-Value '') -Name 'Format-Value empty'
Assert-True (Test-SameValue $null '') 'Test-SameValue treats null and empty as equal'
Assert-True (Test-SameValue 'CAExempt' 'CAExempt') 'Test-SameValue equal values'
Assert-True (-not (Test-SameValue 'CAExempt' 'caexempt')) 'Test-SameValue is case-sensitive (CA filters are)'
Assert-True ($null -eq (Get-ValueValidationError 'CAExempt')) 'Valid value has no error'
Assert-True ($null -ne (Get-ValueValidationError '')) 'Empty value is invalid'
Assert-True ($null -ne (Get-ValueValidationError ('x' * 1025))) 'Overlong value is invalid'

# --- GUIDs ---
Assert-Equal -Expected '1a2b3c4d-1111-2222-3333-444455556666' -Actual (ConvertTo-CanonicalGuid '{1A2B3C4D-1111-2222-3333-444455556666}') -Name 'GUID braces and case are normalised'
Assert-Equal -Expected $null -Actual (ConvertTo-CanonicalGuid 'KIOSK-01') -Name 'Non-GUID returns null'
Assert-Equal -Expected 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' -Actual (ConvertTo-CanonicalGuid ([guid]'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA')) -Name 'ConvertTo-CanonicalGuid accepts Guid objects'
Assert-True (Test-LooksLikeGuid 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb') 'Test-LooksLikeGuid accepts a GUID'

# --- Graph 5.1 output type ---
Assert-Equal -Expected 'PSObject' -Actual (Get-PreferredGraphOutputType @('HashTable', 'PSObject', 'Json')) -Name 'Graph output prefers PSObject over HashTable'
Assert-Equal -Expected 'Json' -Actual (Get-PreferredGraphOutputType @('HashTable', 'Json')) -Name 'Graph output falls back to Json'
Assert-Equal -Expected 'PSObject' -Actual (Get-PreferredGraphOutputType @()) -Name 'Graph output defaults to PSObject'
Assert-Equal -Expected $null -Actual (Get-PreferredGraphOutputType @('HashTable')) -Name 'Graph output skips HashTable-only'
try { throw 'Argument types do not match' } catch {
    Assert-True (Test-ArgumentTypesMismatch $_) 'Detects Argument types do not match'
    Assert-True ((Format-CaughtError $_) -like 'Argument types do not match*') 'Format-CaughtError keeps the mismatch message'
}
Assert-True (-not (Test-ArgumentTypesMismatch (New-Object System.Management.Automation.ErrorRecord ([Exception]'nope'), 'x', 'NotSpecified', $null))) 'Other errors are not treated as type mismatch'

# --- Join types / eligibility ---
Assert-Equal -Expected 'Entra registered' -Actual (Get-JoinTypeLabel 'Workplace') -Name 'Workplace label'
Assert-Equal -Expected 'Unknown' -Actual (Get-JoinTypeLabel $null) -Name 'Get-JoinTypeLabel null is Unknown'
Assert-Equal -Expected 'Entra joined' -Actual (Get-JoinTypeLabel 'AzureAd') -Name 'AzureAd label'
Assert-Equal -Expected 'Hybrid joined' -Actual (Get-JoinTypeLabel 'ServerAd') -Name 'ServerAd label'
Assert-Equal -Expected 'Unknown' -Actual (Get-JoinTypeLabel '') -Name 'Empty trustType label'

$script:Settings.RegisteredOnly = $true
$registered = ConvertTo-DeviceRecord (New-GraphDeviceHashtable)
Assert-True $registered.Eligible 'Workplace Windows device is eligible when RegisteredOnly'
$joined = ConvertTo-DeviceRecord (New-GraphDeviceHashtable -TrustType 'AzureAd' -DisplayName 'LAPTOP-01')
Assert-True (-not $joined.Eligible) 'Entra joined device is not eligible when RegisteredOnly'
$ios = ConvertTo-DeviceRecord (New-GraphDeviceHashtable -Os 'iOS' -DisplayName 'PHONE-01')
Assert-True (-not $ios.Eligible) 'iOS device is not eligible'

$script:Settings.RegisteredOnly = $false
$joinedAll = ConvertTo-DeviceRecord (New-GraphDeviceHashtable -TrustType 'AzureAd' -DisplayName 'LAPTOP-01')
Assert-True $joinedAll.Eligible 'Entra joined Windows device is eligible when RegisteredOnly is off'
$script:Settings.RegisteredOnly = $true

# --- Graph property access ---
$ht = @{ id = 'abc'; DisplayName = 'from-ht'; '@odata.nextLink' = 'https://next' }
Assert-Equal -Expected 'abc' -Actual (Get-GraphProperty $ht 'id') -Name 'Get-GraphProperty hashtable exact key'
Assert-Equal -Expected 'from-ht' -Actual (Get-GraphProperty $ht 'displayname') -Name 'Get-GraphProperty hashtable case-insensitive'
Assert-Equal -Expected 'https://next' -Actual (Get-GraphProperty $ht '@odata.nextLink') -Name 'Get-GraphProperty odata nextLink'

$obj = [pscustomobject]@{ id = 'xyz'; displayName = 'from-obj' }
Assert-Equal -Expected 'xyz' -Actual (Get-GraphProperty $obj 'id') -Name 'Get-GraphProperty PSCustomObject'
Assert-Equal -Expected 'from-obj' -Actual (Get-GraphProperty $obj 'DisplayName') -Name 'Get-GraphProperty PSCustomObject case-insensitive'

$page = @{
    value            = @( (New-GraphDeviceHashtable), (New-GraphDeviceHashtable -DisplayName 'KIOSK-02' -DeviceId 'cccccccc-cccc-cccc-cccc-cccccccccccc' -ObjectId 'dddddddd-dddd-dddd-dddd-dddddddddddd') )
    '@odata.nextLink' = 'https://graph.microsoft.com/next'
}
$collection = Get-GraphCollection $page
Assert-Equal -Expected 2 -Actual $collection.Count -Name 'Get-GraphCollection reads value array'

$single = Get-GraphCollection (New-GraphDeviceHashtable)
Assert-True ($single -is [System.Array]) 'Get-GraphCollection returns an array for one device'
Assert-Equal -Expected 1 -Actual $single.Count -Name 'Get-GraphCollection single device Count is 1 not hashtable key count'
Assert-Equal -Expected 'KIOSK-01' -Actual (Get-GraphProperty $single[0] 'displayName') -Name 'Get-GraphCollection does not enumerate hashtable keys'

$fromHt = ConvertTo-DeviceRecord (New-GraphDeviceHashtable -ExtensionAttribute1 'CAExempt')
Assert-Equal -Expected 'KIOSK-01' -Actual $fromHt.DisplayName -Name 'ConvertTo-DeviceRecord hashtable displayName'
Assert-Equal -Expected 'CAExempt' -Actual $fromHt.ExtensionAttribute1 -Name 'ConvertTo-DeviceRecord hashtable extensionAttribute1'
Assert-Equal -Expected 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' -Actual $fromHt.DeviceId -Name 'ConvertTo-DeviceRecord canonical deviceId'

$guidHt = New-GraphDeviceHashtable
$guidHt['deviceId'] = [guid]'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
$guidHt['id'] = [guid]'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
$fromGuidIds = ConvertTo-DeviceRecord $guidHt
Assert-Equal -Expected 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' -Actual $fromGuidIds.DeviceId -Name 'ConvertTo-DeviceRecord accepts Guid-typed deviceId'
Assert-Equal -Expected 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' -Actual $fromGuidIds.ObjectId -Name 'ConvertTo-DeviceRecord accepts Guid-typed id'

$psItem = [pscustomobject]@{
    id                            = 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA'
    deviceId                      = '{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}'
    displayName                   = 'KIOSK-PS'
    trustType                     = 'Workplace'
    operatingSystem               = 'Windows 11'
    operatingSystemVersion        = '10.0.22631'
    accountEnabled                = $true
    approximateLastSignInDateTime = '2026-02-01T08:00:00Z'
    extensionAttributes           = [pscustomobject]@{ extensionAttribute1 = 'Tagged' }
    isManagementRestricted        = $true
}
$fromPs = ConvertTo-DeviceRecord $psItem
Assert-Equal -Expected 'KIOSK-PS' -Actual $fromPs.DisplayName -Name 'ConvertTo-DeviceRecord PSCustomObject displayName'
Assert-Equal -Expected 'Tagged' -Actual $fromPs.ExtensionAttribute1 -Name 'ConvertTo-DeviceRecord nested PSCustomObject attribute'
Assert-Equal -Expected 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' -Actual $fromPs.DeviceId -Name 'ConvertTo-DeviceRecord normalises braced deviceId'
Assert-True $fromPs.Eligible 'Windows 11 Workplace device is eligible'
Assert-True $fromPs.IsManagementRestricted 'Restricted AU flag is preserved'

$records = @(ConvertTo-DeviceRecords (New-GraphDeviceHashtable -DisplayName 'SOLO'))
Assert-Equal -Expected 1 -Actual $records.Count -Name 'ConvertTo-DeviceRecords single hashtable is one device'
Assert-Equal -Expected 'SOLO' -Actual $records[0].DisplayName -Name 'ConvertTo-DeviceRecords does not iterate hashtable keys'

# --- JSON patch body ---
Assert-Equal -Expected '{"extensionAttributes":{"extensionAttribute1":null}}' -Actual (New-ExtensionAttributePatchJson $null) -Name 'PATCH JSON clears with null'
Assert-Equal -Expected '{"extensionAttributes":{"extensionAttribute1":null}}' -Actual (New-ExtensionAttributePatchJson '') -Name 'PATCH JSON empty string clears with null'
$quoted = New-ExtensionAttributePatchJson 'CA"Exempt'
Assert-True ($quoted -eq '{"extensionAttributes":{"extensionAttribute1":"CA\"Exempt"}}') 'PATCH JSON escapes quotes'
$slash = New-ExtensionAttributePatchJson "line1`nline2"
Assert-True ($slash -match '\\n') 'PATCH JSON escapes newlines'

# --- Error parsing / scopes / retry ---
$err429 = [System.Management.Automation.ErrorRecord]::new(
    [System.Exception]::new('Too Many Requests (429)'),
    'GraphThrottle',
    [System.Management.Automation.ErrorCategory]::ProtocolError,
    $null
)
Assert-Equal -Expected 429 -Actual (Get-GraphExceptionStatusCode $err429) -Name '429 detected from exception message'
$errJson = [System.Management.Automation.ErrorRecord]::new(
    [System.Exception]::new('{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}'),
    'GraphDenied',
    [System.Management.Automation.ErrorCategory]::PermissionDenied,
    $null
)
Assert-Equal -Expected 'Insufficient privileges to complete the operation.' -Actual (Get-GraphErrorMessage $errJson) -Name 'Graph error message extracted from JSON'
Assert-True (Test-HasGraphScope ([pscustomobject]@{ Scopes = @('User.Read', 'Device.ReadWrite.All') })) 'Scope match exact'
Assert-True (Test-HasGraphScope ([pscustomobject]@{ Scopes = @('https://graph.microsoft.com/Device.ReadWrite.All') })) 'Scope match with resource prefix'
Assert-True (-not (Test-HasGraphScope ([pscustomobject]@{ Scopes = @('User.Read') }))) 'Missing scope is false'
Assert-Equal -Expected 2 -Actual (Get-RetryDelaySeconds $null 1) -Name 'Retry delay attempt 1 is 2s'
Assert-Equal -Expected 16 -Actual (Get-RetryDelaySeconds $null 4) -Name 'Retry delay attempt 4 is 16s'
Assert-Equal -Expected 60 -Actual (Get-RetryDelaySeconds $null 10) -Name 'Retry delay is capped at 60s'

# --- Graph URI builder ---
$uri = New-GraphDeviceListUri -Filter "startswith(operatingSystem,'Windows') and trustType eq 'Workplace'"
Assert-True ($uri -match [regex]::Escape('$filter=')) 'URI contains $filter'
Assert-True ($uri -notmatch '`\$filter') 'URI does not contain a backtick before $filter'
Assert-True ($uri -match [regex]::Escape('$select=')) 'URI contains $select'
Assert-True ($uri -match [regex]::Escape('$top=999')) 'URI contains $top'
Assert-True ($uri -match 'trustType') 'URI filter includes trustType'

$searchUri = New-GraphDeviceListUri -Filter $null -ExtraQuery @{
    '$search' = 'encoded'
    '$count'  = 'true'
}
Assert-True ($searchUri -match [regex]::Escape('$search=encoded')) 'Search URI contains $search'
Assert-True ($searchUri -notmatch '\$filter=') 'Search URI omits empty $filter'

# --- CSV delimiter / columns / import ---
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('caexemption-tests-' + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tempRoot | Out-Null
try {
    $commaPath = Join-Path $tempRoot 'comma.csv'
    Set-Content -LiteralPath $commaPath -Value "DeviceId,DisplayName,Value,Action`n11111111-1111-1111-1111-111111111111,KIOSK-01,CAExempt,Set" -Encoding UTF8
    Assert-Equal -Expected ',' -Actual (Get-CsvDelimiter $commaPath) -Name 'Detect comma delimiter'

    $semiPath = Join-Path $tempRoot 'semi.csv'
    Set-Content -LiteralPath $semiPath -Value "sep=;`nDevice ID;Name;ExtensionAttribute1;Operation`n{22222222-2222-2222-2222-222222222222};KIOSK-02;CAExempt;Set" -Encoding UTF8
    Assert-Equal -Expected ';' -Actual (Get-CsvDelimiter $semiPath) -Name 'Detect semicolon delimiter from sep= line'

    $semiRows = @(Import-DeviceCsv $semiPath)
    Assert-Equal -Expected 1 -Actual $semiRows.Count -Name 'Import-DeviceCsv skips Excel sep= line'
    $headerNames = @($semiRows[0].PSObject.Properties | ForEach-Object { $_.Name })
    $semiMap = Resolve-CsvColumnMap -Headers $headerNames
    Assert-Equal -Expected 'Device ID' -Actual $semiMap['DeviceId'] -Name 'Alias Device ID maps to DeviceId'
    Assert-Equal -Expected 'Name' -Actual $semiMap['DisplayName'] -Name 'Alias Name maps to DisplayName'
    Assert-Equal -Expected 'ExtensionAttribute1' -Actual $semiMap['Value'] -Name 'Alias ExtensionAttribute1 maps to Value'
    Assert-Equal -Expected 'Operation' -Actual $semiMap['Action'] -Name 'Alias Operation maps to Action'
    Assert-Equal -Expected '{22222222-2222-2222-2222-222222222222}' -Actual (Get-MappedRowField $semiRows[0] $semiMap 'DeviceId') -Name 'Mapped DeviceId value is read'

    $tabPath = Join-Path $tempRoot 'tab.csv'
    Set-Content -LiteralPath $tabPath -Value ("DeviceId`tDisplayName`n33333333-3333-3333-3333-333333333333`tKIOSK-03") -Encoding UTF8
    Assert-Equal -Expected "`t" -Actual (Get-CsvDelimiter $tabPath) -Name 'Detect tab delimiter'

    $map = Resolve-CsvColumnMap @('DeviceId', 'ObjectId', 'DisplayName', 'Value', 'Action')
    $setRow = [pscustomobject]@{ Action = 'set' }
    $clearRow = [pscustomobject]@{ Action = 'Remove' }
    $badRow = [pscustomobject]@{ Action = 'frobnicate' }
    $emptyRow = [pscustomobject]@{ Action = '' }
    Assert-Equal -Expected 'Set' -Actual (Get-RowAction $setRow $map) -Name 'Action set'
    Assert-Equal -Expected 'Clear' -Actual (Get-RowAction $clearRow $map) -Name 'Action remove means Clear'
    Assert-Equal -Expected 'Invalid' -Actual (Get-RowAction $badRow $map) -Name 'Unknown action is Invalid'
    Assert-Equal -Expected 'Set' -Actual (Get-RowAction $emptyRow $map) -Name 'Blank action defaults to Set'

    $settingsPath = Join-Path $tempRoot 'settings.json'
    $script:SettingsFile = $settingsPath
    $script:Settings.DefaultValue = 'PAW'
    $script:Settings.DryRun = $true
    $script:Settings.RegisteredOnly = $false
    Export-ToolSettings -Path $settingsPath
    $script:Settings.DefaultValue = 'CAExempt'
    $script:Settings.DryRun = $false
    $script:Settings.RegisteredOnly = $true
    Import-ToolSettings -Path $settingsPath
    Assert-Equal -Expected 'PAW' -Actual $script:Settings.DefaultValue -Name 'Settings persist DefaultValue'
    Assert-True $script:Settings.DryRun 'Settings persist DryRun'
    Assert-True (-not $script:Settings.RegisteredOnly) 'Settings persist RegisteredOnly'
    $script:Settings.DefaultValue = 'CAExempt'
    $script:Settings.DryRun = $false
    $script:Settings.RegisteredOnly = $true
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Bulk plan ---
$script:Settings.RegisteredOnly = $true
$devA = ConvertTo-DeviceRecord (New-GraphDeviceHashtable -DisplayName 'KIOSK-01' -ExtensionAttribute1 $null)
$devB = ConvertTo-DeviceRecord (New-GraphDeviceHashtable -DisplayName 'KIOSK-02' -DeviceId 'cccccccc-cccc-cccc-cccc-cccccccccccc' -ObjectId 'dddddddd-dddd-dddd-dddd-dddddddddddd' -ExtensionAttribute1 'CAExempt')
$devC = ConvertTo-DeviceRecord (New-GraphDeviceHashtable -DisplayName 'KIOSK-03' -DeviceId '56565656-5656-5656-5656-565656565656' -ObjectId '78787878-7878-7878-7878-787878787878' -ExtensionAttribute1 $null)
$devDupName1 = ConvertTo-DeviceRecord (New-GraphDeviceHashtable -DisplayName 'DUP' -DeviceId 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee' -ObjectId 'ffffffff-ffff-ffff-ffff-ffffffffffff')
$devDupName2 = ConvertTo-DeviceRecord (New-GraphDeviceHashtable -DisplayName 'DUP' -DeviceId '12121212-1212-1212-1212-121212121212' -ObjectId '34343434-3434-3434-3434-343434343434')
$index = New-DeviceIndex @($devA, $devB, $devC, $devDupName1, $devDupName2)

$joinedLookup = ConvertTo-DeviceRecord (New-GraphDeviceHashtable -DisplayName 'HYBRID-01' -TrustType 'ServerAd' -DeviceId '99999999-9999-9999-9999-999999999999' -ObjectId '88888888-8888-8888-8888-888888888888')
$lookup = {
    param($DeviceId, $ObjectId, $DisplayName)
    if ($DeviceId -eq '99999999-9999-9999-9999-999999999999') { return $joinedLookup }
    return $null
}

$rows = @(
    [pscustomobject]@{ DeviceId = '{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}'; ObjectId = ''; DisplayName = ''; Value = 'CAExempt'; Action = 'Set' }
    [pscustomobject]@{ DeviceId = ''; ObjectId = ''; DisplayName = 'KIOSK-02'; Value = 'CAExempt'; Action = 'Set' }
    [pscustomobject]@{ DeviceId = ''; ObjectId = ''; DisplayName = 'DUP'; Value = 'CAExempt'; Action = 'Set' }
    [pscustomobject]@{ DeviceId = ''; ObjectId = ''; DisplayName = ''; Value = 'CAExempt'; Action = 'Set' }
    [pscustomobject]@{ DeviceId = '00000000-0000-0000-0000-000000000000'; ObjectId = ''; DisplayName = ''; Value = 'CAExempt'; Action = 'Set' }
    [pscustomobject]@{ DeviceId = '99999999-9999-9999-9999-999999999999'; ObjectId = ''; DisplayName = ''; Value = 'CAExempt'; Action = 'Set' }
    [pscustomobject]@{ DeviceId = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'; ObjectId = ''; DisplayName = ''; Value = 'CAExempt'; Action = 'Set' }
    [pscustomobject]@{ DeviceId = '56565656-5656-5656-5656-565656565656'; ObjectId = ''; DisplayName = ''; Value = ''; Action = 'Clear' }
    [pscustomobject]@{ DeviceId = ''; ObjectId = ''; DisplayName = 'KIOSK-02'; Value = ''; Action = 'explode' }
    [pscustomobject]@{ DeviceId = 'cccccccc-cccc-cccc-cccc-cccccccccccc'; ObjectId = ''; DisplayName = ''; Value = ''; Action = 'Set' }
)

$plan = @(New-BulkUpdatePlan -Rows $rows -DeviceIndex $index -FallbackValue 'CAExempt' -SkipMissing $true -LookupMissingDevice $lookup)
function Get-PlanStatus {
    param($Plan, [int]$Row)
    $item = @($Plan | Where-Object { $_.Row -eq $Row } | Select-Object -First 1)
    if ($item.Count -eq 0) { return "<missing row $Row, plan count=$($Plan.Count)>" }
    return [string]$item[0].Status
}

Assert-Equal -Expected 'Ready' -Actual (Get-PlanStatus $plan 2) -Name 'Braced DeviceId row is Ready'
Assert-Equal -Expected 'NoChange' -Actual (Get-PlanStatus $plan 3) -Name 'Existing value is NoChange'
Assert-Equal -Expected 'Ambiguous' -Actual (Get-PlanStatus $plan 4) -Name 'Duplicate names are Ambiguous'
Assert-Equal -Expected 'Invalid' -Actual (Get-PlanStatus $plan 5) -Name 'Missing identifier is Invalid'
Assert-Equal -Expected 'NotFound' -Actual (Get-PlanStatus $plan 6) -Name 'Unknown GUID is NotFound'
Assert-Equal -Expected 'NotEligible' -Actual (Get-PlanStatus $plan 7) -Name 'Found hybrid device is NotEligible not NotFound'
Assert-Equal -Expected 'Duplicate' -Actual (Get-PlanStatus $plan 8) -Name 'Second row for same device is Duplicate'
Assert-Equal -Expected 'NoChange' -Actual (Get-PlanStatus $plan 9) -Name 'Clear on already empty is NoChange'
Assert-Equal -Expected 'Invalid' -Actual (Get-PlanStatus $plan 10) -Name 'Unknown Action is Invalid'
Assert-Equal -Expected 'Skipped' -Actual (Get-PlanStatus $plan 11) -Name 'Missing Value is Skipped when requested'

$planFallback = @(New-BulkUpdatePlan -Rows @(
        [pscustomobject]@{ DeviceId = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'; ObjectId = ''; DisplayName = ''; Value = ''; Action = 'Set' }
    ) -DeviceIndex $index -FallbackValue 'CAExempt' -SkipMissing $false)
Assert-Equal -Expected 'Ready' -Actual $planFallback[0].Status -Name 'Missing Value uses fallback'
Assert-Equal -Expected 'CAExempt' -Actual $planFallback[0].NewValue -Name 'Fallback value is applied'

# --- PS 5.1 pscustomobject / Generic.List helper ---
$listUsers = New-Object System.Collections.Generic.List[object]
$listUsers.Add('jane.doe@contoso.com')
$listUsers.Add('alex.smith@contoso.com')
$listMissing = New-Object System.Collections.Generic.List[string]
$fromList = New-PsObjectFromHashtable @{ Users = $listUsers; Missing = $listMissing }
Assert-Equal -Expected 2 -Actual @($fromList.Users).Count -Name 'New-PsObjectFromHashtable accepts Generic.List users'
Assert-Equal -Expected 0 -Actual @($fromList.Missing).Count -Name 'New-PsObjectFromHashtable accepts empty Generic.List'
Assert-Equal -Expected 'jane.doe@contoso.com' -Actual @($fromList.Users)[0] -Name 'New-PsObjectFromHashtable preserves list items'

$nestedInner = New-ToolObject @('Name', 'KIOSK-01')
$nestedOuter = New-ToolObject @('Device', $nestedInner, 'Relationship', 'Registered')
$nestedList = New-Object System.Collections.Generic.List[object]
$nestedList.Add($nestedOuter)
$nestedArr = ConvertTo-ObjectArray $nestedList
Assert-Equal -Expected 1 -Actual $nestedArr.Count -Name 'ConvertTo-ObjectArray preserves Generic.List of nested objects'
Assert-Equal -Expected 'KIOSK-01' -Actual $nestedArr[0].Device.Name -Name 'ConvertTo-ObjectArray keeps nested PSCustomObject properties'
Assert-Equal -Expected 'KIOSK-01' -Actual $nestedOuter.Device.Name -Name 'New-ToolObject can nest PSCustomObject values'
Assert-Equal -Expected 'Registered' -Actual $nestedOuter.Relationship -Name 'New-ToolObject keeps sibling properties'
Assert-Equal -Expected $true -Actual (ConvertTo-PlainValue $true) -Name 'ConvertTo-PlainValue leaves bools'
Assert-Equal -Expected 'Windows' -Actual (ConvertTo-PlainValue 'Windows') -Name 'ConvertTo-PlainValue leaves strings'

# --- User search / bulk CSV from users ---
Assert-Equal -Expected 0 -Actual @(Split-UserSearchTokens '').Count -Name 'Split-UserSearchTokens empty'
$split = @(Split-UserSearchTokens "jane.doe@contoso.com, alex.smith@contoso.com;`nJane Doe")
Assert-Equal -Expected 3 -Actual $split.Count -Name 'Split-UserSearchTokens splits comma, semicolon and newline'
Assert-Equal -Expected 'jane.doe@contoso.com' -Actual $split[0] -Name 'Split-UserSearchTokens first token'
$deduped = @(Split-UserSearchTokens "Jane.Doe@contoso.com, jane.doe@contoso.com")
Assert-Equal -Expected 1 -Actual $deduped.Count -Name 'Split-UserSearchTokens de-duplicates case-insensitively'

$userHt = @{
    id                = 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA'
    displayName       = 'Jane Doe'
    userPrincipalName = 'jane.doe@contoso.com'
    mail              = 'jane.doe@contoso.com'
    accountEnabled    = $true
}
$userRec = ConvertTo-UserRecord $userHt
Assert-Equal -Expected 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' -Actual $userRec.ObjectId -Name 'ConvertTo-UserRecord canonical object id'
Assert-Equal -Expected 'Jane Doe' -Actual $userRec.DisplayName -Name 'ConvertTo-UserRecord display name'
Assert-Equal -Expected 'jane.doe@contoso.com' -Actual $userRec.UserPrincipalName -Name 'ConvertTo-UserRecord UPN'

$userUri = New-GraphUserListUri -Filter "userPrincipalName eq 'jane.doe@contoso.com'"
Assert-True ($userUri -match [regex]::Escape('$filter=')) 'User URI contains $filter'
Assert-True ($userUri -match 'users\?') 'User URI targets /users'
Assert-True ($userUri -notmatch '`\$filter') 'User URI has no backtick before $filter'

$userMap = Resolve-UserCsvColumnMap @('UPN', 'Email', 'FullName', 'UserObjectId')
Assert-Equal -Expected 'UPN' -Actual $userMap['UserPrincipalName'] -Name 'User CSV alias UPN'
Assert-Equal -Expected 'Email' -Actual $userMap['Mail'] -Name 'User CSV alias Email'
Assert-Equal -Expected 'FullName' -Actual $userMap['DisplayName'] -Name 'User CSV alias FullName'
Assert-Equal -Expected 'UserObjectId' -Actual $userMap['ObjectId'] -Name 'User CSV alias UserObjectId'

$userCsvRow = [pscustomobject]@{ UPN = 'jane.doe@contoso.com'; Email = ''; FullName = ''; UserObjectId = '' }
Assert-Equal -Expected 'jane.doe@contoso.com' -Actual (Get-UserRowSearchToken $userCsvRow $userMap) -Name 'User CSV row prefers UPN'

$pair = New-ToolObject @('Device', $devA, 'User', $userRec, 'Relationship', 'Registered')
Assert-Equal -Expected $devA.DeviceId -Actual $pair.Device.DeviceId -Name 'User/device pair can nest PSCustomObject Device'
Assert-Equal -Expected 'jane.doe@contoso.com' -Actual $pair.User.UserPrincipalName -Name 'User/device pair can nest PSCustomObject User'

$bulkRow = New-UserDeviceBulkRow -Device $devA -User $userRec -Relationship 'Registered' -Value 'CAExempt' -Action 'Set'
Assert-Equal -Expected $devA.DeviceId -Actual $bulkRow.DeviceId -Name 'User bulk row DeviceId'
Assert-Equal -Expected 'Set' -Actual $bulkRow.Action -Name 'User bulk row Action'
Assert-Equal -Expected 'CAExempt' -Actual $bulkRow.Value -Name 'User bulk row Value'
Assert-Equal -Expected 'jane.doe@contoso.com' -Actual $bulkRow.UserPrincipalName -Name 'User bulk row UPN'

$clearRow = New-UserDeviceBulkRow -Device $devA -User $userRec -Relationship 'Owned' -Value 'ignored' -Action 'Clear'
Assert-Equal -Expected '' -Actual $clearRow.Value -Name 'Clear bulk row blanks Value'

$otherUser = [pscustomobject]@{ ObjectId = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'; DisplayName = 'Alex Smith'; UserPrincipalName = 'alex.smith@contoso.com'; Mail = ''; Enabled = $true }
$merged = @(Merge-UserDeviceBulkRows @(
        (New-UserDeviceBulkRow -Device $devA -User $userRec -Relationship 'Registered' -Value 'CAExempt' -Action 'Set'),
        (New-UserDeviceBulkRow -Device $devA -User $userRec -Relationship 'Owned' -Value 'CAExempt' -Action 'Set'),
        (New-UserDeviceBulkRow -Device $devB -User $otherUser -Relationship 'Registered' -Value 'CAExempt' -Action 'Set')
    ))
Assert-Equal -Expected 2 -Actual $merged.Count -Name 'Merge-UserDeviceBulkRows de-duplicates the same device'
$mergedA = @($merged | Where-Object { $_.DeviceId -eq $devA.DeviceId })[0]
Assert-True ($mergedA.Relationship -match 'Registered') 'Merged relationship keeps Registered'
Assert-True ($mergedA.Relationship -match 'Owned') 'Merged relationship keeps Owned'

$userExportPlan = @(New-BulkUpdatePlan -Rows @($bulkRow) -DeviceIndex $index -FallbackValue 'CAExempt' -SkipMissing $false)
Assert-Equal -Expected 'Ready' -Actual $userExportPlan[0].Status -Name 'User-exported bulk CSV is ready for bulk update'

$bulkHeaders = @($bulkRow.PSObject.Properties | ForEach-Object { $_.Name })
$bulkMap = Resolve-CsvColumnMap $bulkHeaders
$dupRow = New-UserDeviceBulkRow -Device $devA -User $userRec -Relationship 'Owned' -Value 'CAExempt' -Action 'Set'
$nameOnly = [pscustomobject]@{ DeviceId = ''; ObjectId = ''; DisplayName = 'KIOSK-02'; Value = 'CAExempt'; Action = 'Set' }
$targets = Get-BulkCsvLookupTargets -Rows @($bulkRow, $dupRow, $nameOnly) -ColumnMap $bulkMap
Assert-Equal -Expected 2 -Actual @($targets).Count -Name 'Bulk CSV lookup de-duplicates DeviceId and keeps a name-only row'
Assert-Equal -Expected $devA.DeviceId -Actual $targets[0].Search -Name 'Bulk CSV lookup prefers DeviceId'
Assert-Equal -Expected 'KIOSK-02' -Actual $targets[1].Search -Name 'Bulk CSV lookup uses DisplayName when no GUID'

Write-Host ''
Write-Host ("Passed: {0}  Failed: {1}" -f $script:Passed, $script:Failed) -ForegroundColor $(if ($script:Failed -eq 0) { 'Green' } else { 'Red' })
if ($script:Failed -gt 0) { exit 1 }
exit 0
