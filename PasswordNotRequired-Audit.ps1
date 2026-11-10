#Requires -Version 5.1

<#
.SYNOPSIS
    Interactive (Windows Forms) investigator for the Semperis "Password Not Required" (PASSWD_NOTREQD) finding.

.DESCRIPTION
    Tab 1 - Bulk audit
        Pick the Semperis CSV export and an output folder. For every account it collects:
          * Full replication metadata (equivalent of: repadmin /showobjmeta <DC> "<DN>")
          * Who/when/where userAccountControl and the password were last written
          * Account, password, Kerberos and delegation settings
          * True last logon (queried on every DC - lastLogon is not replicated)
          * Direct + nested group membership and privileged-group exposure (tokenGroups)
          * Whether the server an IUSR_/IWAM_/USbms_ account belongs to still exists
          * Optional: whether the password is actually blank
        It writes Summary.csv, ReplicationMetadata.csv, Rollback.csv, Errors.csv and Objects\<sam>.txt.

    Tab 2 - Object metadata
        repadmin /showobjmeta for any single object (DN, sAMAccountName or GUID), with CSV export.

    Tab 3 - Remediate
        Load results (or a previous Summary.csv), tick accounts, preview, then clear PASSWD_NOTREQD
        (and optionally disable). Original userAccountControl values are written to a rollback CSV
        BEFORE each change. A rollback CSV can be restored from the same tab.

    Tabs 1 and 2 are read-only. Tab 3 changes AD only after you confirm.

.PARAMETER CsvPath
    Optional. Pre-fills the Semperis CSV picker.

.PARAMETER Server
    Optional. Pre-fills the domain controller box.

.PARAMETER OutputFolder
    Optional. Pre-fills the output folder picker.

.PARAMETER StaleDays
    Optional. Pre-fills the stale-account threshold. Default 90.

.PARAMETER SelfTest
    Run built-in helper/CSV tests and exit (no GUI, no Active Directory).

.EXAMPLE
    .\PasswordNotRequired-Audit.ps1

.EXAMPLE
    .\PasswordNotRequired-Audit.ps1 -CsvPath .\PasswordNotRequired.csv -Server DC01.kci-net.karmanos.org

.EXAMPLE
    .\PasswordNotRequired-Audit.ps1 -SelfTest

.NOTES
    Version: 1.3
    Requires: Windows PowerShell 5.1, RSAT ActiveDirectory module, STA (auto-relaunched).
    Keep PasswordNotRequired-Audit.Gui.ps1 in the same folder as this script.
#>

[CmdletBinding()]
param(
    [string]$CsvPath,
    [string]$Server,
    [string]$OutputFolder,
    [int]$StaleDays = 90,
    [switch]$SelfTest
)

$script:PnrVersion = '1.3'
$script:WinFormsLoaded = $false
$script:LdapTypesLoaded = $false
$script:TxtLog = $null
$script:Form = $null

# Domain Admins, Domain Controllers, Schema Admins, Enterprise Admins, GPO Creator Owners, RODCs,
# Key Admins, Enterprise Key Admins, BUILTIN\Administrators, Account/Server/Print/Backup Operators
$script:PrivSidPattern = '^S-1-5-21-.+-(512|516|518|519|520|521|526|527)$|^S-1-5-32-(544|548|549|550|551)$'
$script:AutoDcText     = '(Auto-discover writable DC per domain)'
$script:PasswdNotReqdBit = 0x0020
$script:AccountDisableBit = 0x0002

$script:UacFlags = @(
    @{ Bit = 0x0001;    Name = 'SCRIPT' }
    @{ Bit = 0x0002;    Name = 'ACCOUNTDISABLE' }
    @{ Bit = 0x0008;    Name = 'HOMEDIR_REQUIRED' }
    @{ Bit = 0x0010;    Name = 'LOCKOUT' }
    @{ Bit = 0x0020;    Name = 'PASSWD_NOTREQD' }
    @{ Bit = 0x0040;    Name = 'PASSWD_CANT_CHANGE' }
    @{ Bit = 0x0080;    Name = 'ENCRYPTED_TEXT_PWD_ALLOWED' }
    @{ Bit = 0x0100;    Name = 'TEMP_DUPLICATE_ACCOUNT' }
    @{ Bit = 0x0200;    Name = 'NORMAL_ACCOUNT' }
    @{ Bit = 0x0800;    Name = 'INTERDOMAIN_TRUST_ACCOUNT' }
    @{ Bit = 0x1000;    Name = 'WORKSTATION_TRUST_ACCOUNT' }
    @{ Bit = 0x2000;    Name = 'SERVER_TRUST_ACCOUNT' }
    @{ Bit = 0x10000;   Name = 'DONT_EXPIRE_PASSWORD' }
    @{ Bit = 0x20000;   Name = 'MNS_LOGON_ACCOUNT' }
    @{ Bit = 0x40000;   Name = 'SMARTCARD_REQUIRED' }
    @{ Bit = 0x80000;   Name = 'TRUSTED_FOR_DELEGATION' }
    @{ Bit = 0x100000;  Name = 'NOT_DELEGATED' }
    @{ Bit = 0x200000;  Name = 'USE_DES_KEY_ONLY' }
    @{ Bit = 0x400000;  Name = 'DONT_REQ_PREAUTH' }
    @{ Bit = 0x800000;  Name = 'PASSWORD_EXPIRED' }
    @{ Bit = 0x1000000; Name = 'TRUSTED_TO_AUTH_FOR_DELEGATION' }
    @{ Bit = 0x4000000; Name = 'PARTIAL_SECRETS_ACCOUNT' }
)

$script:ColumnAliases = @{
    DistinguishedName = @(
        'Distinguished name', 'DistinguishedName', 'Distinguished Name',
        'DN', 'ObjectDN', 'Object DN', 'objectDistinguishedName'
    )
    ObjectGuid = @(
        'Object guid', 'ObjectGUID', 'Object GUID', 'GUID', 'objectGuid', 'ObjectGuid'
    )
    SamAccountName = @(
        'sAMAccountName', 'SamAccountName', 'Sam account name', 'sAM Account Name',
        'Name', 'Account'
    )
    ObjectClass = @(
        'Object class', 'ObjectClass', 'Object Class', 'Class', 'objectClass'
    )
    UserAccountControl = @(
        'User account control', 'UserAccountControl', 'userAccountControl', 'UAC'
    )
    ManagedBy = @(
        'Managed by', 'ManagedBy', 'Manager'
    )
    LastChanged = @(
        'Last changed', 'LastChanged', 'Modified', 'whenChanged', 'When changed'
    )
    Created = @(
        'Created', 'whenCreated', 'When created'
    )
    Ignored = @(
        'Ignored', 'Ignore'
    )
}

# =============================================================================================
# Pure helpers (no WinForms / no AD module) - used by -SelfTest
# =============================================================================================

function Test-IsWindowsOs {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        return [bool]$IsWindows
    }
    return ($env:OS -match 'Windows')
}

function Test-IsStaThread {
    return ([System.Threading.Thread]::CurrentThread.ApartmentState -eq 'STA')
}

function Get-NormalizedHeaderName {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return '' }
    return ($Name.TrimStart([char]0xFEFF).Trim())
}

function ConvertTo-ProcessArgument {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '""' }
    if ($Value -match '[\s"]') {
        return ('"{0}"' -f ($Value -replace '"', '\"'))
    }
    return $Value
}

function ConvertTo-UacText {
    param($Value)
    $n = 0
    try { $n = [int]$Value } catch { return '' }
    ($script:UacFlags | Where-Object { $n -band $_.Bit } | ForEach-Object { $_.Name }) -join ', '
}

function ConvertFrom-FileTime {
    param($Value)
    if ($null -eq $Value -or $Value -eq '') { return $null }
    if ($Value -is [datetime]) {
        $dt = [datetime]$Value
        if ($dt.Year -le 1601) { return $null }
        return $dt
    }
    $v = $null
    try { $v = [int64]$Value } catch { return $null }
    if ($v -le 0 -or $v -eq [int64]::MaxValue) { return $null }
    try { return [DateTime]::FromFileTime($v) } catch { return $null }
}

function Get-PwdLastSetRaw {
    param($Value)
    if ($null -eq $Value -or $Value -eq '') { return [int64]0 }
    if ($Value -is [datetime]) {
        $dt = [datetime]$Value
        if ($dt.Year -le 1601) { return [int64]0 }
        try { return [int64]$dt.ToFileTime() } catch { return [int64]0 }
    }
    try {
        $v = [int64]$Value
        if ($v -lt 0) { return [int64]0 }
        return $v
    }
    catch { return [int64]0 }
}

function Get-DomainFromDN {
    param([string]$DN)
    if ([string]::IsNullOrWhiteSpace($DN)) { return '' }
    (($DN -split '(?<!\\),') | Where-Object { $_ -like 'DC=*' } | ForEach-Object { $_.Substring(3) }) -join '.'
}

function Get-DsaName {
    # "CN=NTDS Settings,CN=DC01,CN=Servers,CN=Site,..." -> "DC01". Deleted DSAs come back as a GUID.
    param([string]$Identity)
    if ([string]::IsNullOrWhiteSpace($Identity)) { return $Identity }
    if ($Identity -match '^CN=NTDS Settings,CN=([^,]+),') { return $Matches[1] }
    $Identity
}

function Get-DaysSince {
    param($Date)
    if ($Date) { [int]((Get-Date) - [datetime]$Date).TotalDays } else { $null }
}

function Get-RdnValue {
    param([string]$DN)
    if ([string]::IsNullOrWhiteSpace($DN)) { return '' }
    (($DN -split '(?<!\\),')[0] -replace '^(CN|OU|DC)=', '') -replace '\\', ''
}

function Get-DcHostName {
    # Get-ADDomainController.HostName is a STRING. Indexing [0] on it returns the first
    # character ('D' of DC01...), which then gets used as -Server and breaks discovery.
    param($DcObject)
    if ($null -eq $DcObject) { return $null }
    if ($DcObject -is [string]) {
        $s = $DcObject.Trim()
        if (-not $s) { return $null }
        return $s
    }
    $name = $null
    foreach ($prop in 'HostName', 'Name', 'Host') {
        if ($DcObject.PSObject.Properties[$prop] -and $DcObject.$prop) {
            $name = $DcObject.$prop
            break
        }
    }
    if ($null -eq $name) { return $null }
    [string](@($name)[0])
}

function Get-PrimaryGroupSid {
    param([string]$ObjectSid, [int]$PrimaryGroupId)
    if ([string]::IsNullOrWhiteSpace($ObjectSid) -or $PrimaryGroupId -le 0) { return $null }
    $cut = $ObjectSid.LastIndexOf('-')
    if ($cut -lt 0) { return $null }
    return ($ObjectSid.Substring(0, $cut) + '-' + $PrimaryGroupId)
}

function Test-PrivilegedSid {
    param([string]$Sid)
    if ([string]::IsNullOrWhiteSpace($Sid)) { return $false }
    return [bool]($Sid -match $script:PrivSidPattern)
}

function Clear-PasswdNotReqdBit {
    param([int]$UserAccountControl, [switch]$AlsoDisable)
    $new = $UserAccountControl -band (-bnot $script:PasswdNotReqdBit)
    if ($AlsoDisable) { $new = $new -bor $script:AccountDisableBit }
    [int]$new
}

function Get-PnrAccountCategory {
    param([string]$Sam, [switch]$IsComputer)
    if ($IsComputer) { return 'Computer account - confirm whether PASSWD_NOTREQD is still required' }
    if ([string]::IsNullOrWhiteSpace($Sam)) { return 'Unclassified - confirm owner/purpose' }
    switch -Regex ($Sam) {
        '^IUSR_'                 { return 'Legacy IIS 5/6 anonymous web user (auto-created per server)' }
        '^IWAM_'                 { return 'Legacy IIS 5/6 out-of-process application account (auto-created per server)' }
        '^MSOL_[0-9a-fA-F]{12}$' { return 'Azure AD / Entra Connect AD DS connector account' }
        '^AAD_[0-9a-fA-F]{12}$'  { return 'Azure AD Connect sync service account (legacy)' }
        '^TsInternetUser$'       { return 'Legacy Windows 2000 Terminal Services Internet Connector account' }
        '^SUPPORT_388945a0$'     { return 'Legacy Help and Support Center account' }
        '^USbms_'                { return 'Likely Cisco Unity messaging-system mailbox account' }
        default                  { return 'Unclassified - confirm owner/purpose' }
    }
}

function Get-PnrAssociatedServerName {
    param([string]$Sam)
    if ($Sam -match '^(IUSR|IWAM|USbms)_(.+)$') { return $Matches[2] }
    return $null
}

function ConvertFrom-SemperisUac {
    param($Value)
    if ($null -eq $Value -or $Value -eq '') { return $null }
    if ($Value -is [int] -or $Value -is [int64] -or $Value -is [long]) { return [int]$Value }
    $text = [string]$Value
    if ($text -match '^\s*(-?\d+)') {
        $n = 0
        if ([int]::TryParse($Matches[1], [ref]$n)) { return $n }
    }
    return $null
}

function Get-PnrCsvRecommendation {
    param([string]$Sam, [string]$Category, [string]$AssociatedServer, $Enabled)
    if ($Sam -match '^MSOL_') {
        return 'Confirm this is the CURRENT AD DS connector account on the Entra Connect server (Synchronization Service Manager > Connectors > AD connector > Properties > Connect to AD forest). If current: clear the flag (no password change, no outage). If not current: disable, then delete after a hold period.'
    }
    if ($AssociatedServer) {
        return "Named after server '$AssociatedServer'. If that host is gone, disable, quarantine, and delete after a hold period. Run the AD audit to confirm whether the computer object still exists."
    }
    if ($Sam -match '^(TsInternetUser|SUPPORT_388945a0)$') {
        return 'Legacy built-in account. Clearing the flag has no operational value; disable and delete after a hold period unless something still depends on it.'
    }
    if ($Enabled -eq $false) {
        return 'Already disabled in the spreadsheet UAC. Clearing the flag has zero impact; consider deleting if no longer required.'
    }
    return 'Enabled PASSWD_NOTREQD account. Run the AD audit for last logon, groups and password metadata before changing it.'
}

function Get-PnrSummaryTemplate {
    [pscustomobject][ordered]@{
        SamAccountName             = $null
        DisplayName                = $null
        Enabled                    = $null
        Category                   = $null
        RiskFlags                  = $null
        Recommendation             = $null
        Description                = $null
        Info                       = $null
        UserAccountControl         = $null
        UacFlags                   = $null
        UacLastChanged             = $null
        UacChangedOnDC             = $null
        UacVersion                 = $null
        BlankPasswordTest          = $null
        PasswordLastSet            = $null
        PwdLastSetRaw              = $null
        PasswordAgeDays            = $null
        PasswordSetCount_Approx    = $null
        PasswordWrittenOn          = $null
        PasswordWrittenByDC        = $null
        PasswordNeverExpires       = $null
        CannotChangePassword       = $null
        FineGrainedPSO             = $null
        LastLogon_AllDCs           = $null
        LastLogonDC                = $null
        LastLogonTimestamp         = $null
        EffectiveLastLogon         = $null
        DaysSinceLastLogon         = $null
        LogonCount_MaxDC           = $null
        LastBadPasswordTime        = $null
        BadLogonCount              = $null
        LockedOut                  = $null
        AccountExpires             = $null
        Created                    = $null
        Modified                   = $null
        LastChangedAttributes      = $null
        LastChangedOnDC            = $null
        DirectGroups               = $null
        AllGroups_Nested           = $null
        PrivilegedGroups           = $null
        AdminCount                 = $null
        PrimaryGroupID             = $null
        SPNs                       = $null
        TrustedForDelegation       = $null
        TrustedToAuthForDelegation = $null
        DoesNotRequirePreAuth      = $null
        ReversibleEncryption       = $null
        UseDESKeyOnly              = $null
        SupportedEncryptionTypes   = $null
        LogonWorkstations          = $null
        ScriptPath                 = $null
        HomeDirectory              = $null
        Manager                    = $null
        AssociatedServer           = $null
        AssociatedServerInAD       = $null
        AssociatedServerInDNS      = $null
        SIDHistory                 = $null
        ProtectedFromDeletion      = $null
        ObjectSID                  = $null
        ObjectGUID                 = $null
        DistinguishedName          = $null
        QueriedDC                  = $null
        DCsUnreachable             = $null
    }
}

function New-PnrStubRecord {
    param($CsvRow, [string]$LookupError)
    $sam = [string]$CsvRow.SamAccountName
    if (-not $sam) { $sam = Get-RdnValue $CsvRow.DistinguishedName }
    $uac = ConvertFrom-SemperisUac $CsvRow.UserAccountControl
    $enabled = $null
    if ($null -ne $uac) { $enabled = -not ($uac -band $script:AccountDisableBit) }
    $assoc = Get-PnrAssociatedServerName $sam
    $category = Get-PnrAccountCategory -Sam $sam
    $flags = New-Object System.Collections.Generic.List[string]
    if ($LookupError) { $flags.Add('LOOKUP_FAILED') } else { $flags.Add('CSV_ONLY') }
    if ($enabled -eq $true) { $flags.Add('ENABLED') } elseif ($enabled -eq $false) { $flags.Add('DISABLED') }
    if ($null -ne $uac -and ($uac -band $script:PasswdNotReqdBit)) { $flags.Add('PASSWD_NOTREQD') }
    if ($null -ne $uac -and ($uac -band 0x10000)) { $flags.Add('DONT_EXPIRE_PASSWORD') }
    if ($assoc) { $flags.Add('NAMED_FOR_SERVER') }
    $rec = Get-PnrSummaryTemplate
    $rec.SamAccountName     = $sam
    $rec.Enabled            = $enabled
    $rec.Category           = $category
    $rec.RiskFlags          = ($flags -join ', ')
    $rec.UserAccountControl = $uac
    $rec.UacFlags           = if ($null -ne $uac) { ConvertTo-UacText $uac } else { $null }
    $rec.PasswordNeverExpires = if ($null -ne $uac) { [bool]($uac -band 0x10000) } else { $null }
    $rec.Created            = $CsvRow.Created
    $rec.Modified           = $CsvRow.LastChanged
    $rec.Manager            = $CsvRow.ManagedBy
    $rec.AssociatedServer   = $assoc
    $rec.ObjectGUID         = $CsvRow.ObjectGuid
    $rec.DistinguishedName  = $CsvRow.DistinguishedName
    $rec.BlankPasswordTest  = 'Not tested'
    if ($LookupError) {
        $rec.Description     = "AD lookup failed. Showing Semperis CSV values. $LookupError"
        $rec.Recommendation  = "AD lookup failed: $LookupError Spreadsheet identity is still usable for a retry or for remediation by ObjectGUID."
    }
    else {
        $rec.Description     = 'Loaded from Semperis CSV. Click Run audit to pull live AD replication, logon, group and password metadata.'
        $rec.Recommendation  = Get-PnrCsvRecommendation -Sam $sam -Category $category -AssociatedServer $assoc -Enabled $enabled
    }
    $rec
}

function Get-RowField {
    param($Row, [string]$LogicalName)
    if ($null -eq $Row) { return '' }
    $aliases = @($script:ColumnAliases[$LogicalName])
    if (-not $aliases) { $aliases = @($LogicalName) }
    $props = @($Row.PSObject.Properties)
    foreach ($alias in $aliases) {
        foreach ($prop in $props) {
            $header = Get-NormalizedHeaderName -Name $prop.Name
            if ($header -ieq $alias) { return [string]$prop.Value }
            if (($header -replace '\s', '') -ieq ($alias -replace '\s', '')) { return [string]$prop.Value }
        }
    }
    # Direct property (already-normalized objects from Import-PnrCsv)
    if ($Row.PSObject.Properties[$LogicalName]) { return [string]$Row.$LogicalName }
    return ''
}

function Test-PnrCsvHasDnColumn {
    param($Row)
    $dn = Get-RowField -Row $Row -LogicalName 'DistinguishedName'
    if ($dn) { return $true }
    foreach ($prop in $Row.PSObject.Properties) {
        $header = Get-NormalizedHeaderName -Name $prop.Name
        foreach ($alias in $script:ColumnAliases.DistinguishedName) {
            if ($header -ieq $alias -or (($header -replace '\s', '') -ieq ($alias -replace '\s', ''))) { return $true }
        }
    }
    return $false
}

function Import-PnrCsv {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "CSV file not found: $Path"
    }

    $encodings = @('UTF8', 'Unicode', 'Default')
    $lastError = $null
    $bestRows = $null
    $bestHasDn = $false

    foreach ($encoding in $encodings) {
        try {
            $rows = @(Import-Csv -LiteralPath $Path -Encoding $encoding -ErrorAction Stop)
            if ($rows.Count -eq 0) { continue }
            $hasDn = Test-PnrCsvHasDnColumn -Row $rows[0]
            if ($hasDn) {
                $bestRows = $rows
                $bestHasDn = $true
                break
            }
            if ($null -eq $bestRows) { $bestRows = $rows }
        }
        catch {
            $lastError = $_
        }
    }

    if (-not $bestHasDn) {
        $present = ''
        if ($bestRows) {
            $present = (($bestRows[0].PSObject.Properties.Name | ForEach-Object { Get-NormalizedHeaderName $_ }) -join ', ')
        }
        $msg = "The CSV must contain a Distinguished name / DistinguishedName column."
        if ($present) { $msg += " Present columns: $present" }
        if ($lastError) { $msg += " Last read error: $($lastError.Exception.Message)" }
        throw $msg
    }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($row in $bestRows) {
        $dn = (Get-RowField -Row $row -LogicalName 'DistinguishedName').Trim().Trim('"')
        if (-not $dn) { continue }
        $sam = (Get-RowField -Row $row -LogicalName 'SamAccountName').Trim().Trim('"')
        if (-not $sam) { $sam = Get-RdnValue $dn }
        $out.Add([pscustomobject]@{
                DistinguishedName  = $dn
                ObjectGuid         = (Get-RowField -Row $row -LogicalName 'ObjectGuid').Trim().Trim('"')
                SamAccountName     = $sam
                ObjectClass        = (Get-RowField -Row $row -LogicalName 'ObjectClass').Trim().Trim('"')
                UserAccountControl = (Get-RowField -Row $row -LogicalName 'UserAccountControl').Trim()
                ManagedBy          = (Get-RowField -Row $row -LogicalName 'ManagedBy').Trim()
                Created            = (Get-RowField -Row $row -LogicalName 'Created').Trim()
                LastChanged        = (Get-RowField -Row $row -LogicalName 'LastChanged').Trim()
                Ignored            = (Get-RowField -Row $row -LogicalName 'Ignored').Trim()
            })
    }
    if ($out.Count -eq 0) { throw "No rows with a distinguished name were found in $Path" }
    # Return a plain object[] — wrapping a generic List in @() throws
    # "Argument types do not match" on PowerShell 7.
    return [object[]]$out.ToArray()
}

function Format-Cell {
    param($Value)
    if ($null -eq $Value) { return [DBNull]::Value }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { return (@($Value) -join '; ') }
    [string]$Value
}

function ConvertTo-DataTable {
    param([object[]]$InputObject)
    $dt = New-Object System.Data.DataTable
    if (-not $InputObject) { return , $dt }
    foreach ($p in $InputObject[0].PSObject.Properties) { [void]$dt.Columns.Add($p.Name, [string]) }
    foreach ($o in $InputObject) {
        $row = $dt.NewRow()
        foreach ($p in $o.PSObject.Properties) { if ($dt.Columns.Contains($p.Name)) { $row[$p.Name] = Format-Cell $p.Value } }
        $dt.Rows.Add($row)
    }
    , $dt
}

function Get-Val {
    param($Item, [string]$Name)
    if ($null -eq $Item) { return '' }
    if ($Item -is [System.Data.DataRowView]) { $Item = $Item.Row }
    if ($Item -is [System.Data.DataRow]) {
        if ($Item.Table.Columns.Contains($Name)) {
            $v = $Item[$Name]
            if ($v -is [DBNull]) { return '' }
            return [string]$v
        }
        return ''
    }
    $prop = $Item.PSObject.Properties[$Name]
    if ($prop) { return [string]$prop.Value }
    return (Get-RowField -Row $Item -LogicalName $Name)
}

function Get-AdChangeErrorMessage {
    param($ErrorRecord)
    $msg = $null
    if ($ErrorRecord -is [string]) { $msg = $ErrorRecord }
    elseif ($ErrorRecord.Exception) { $msg = $ErrorRecord.Exception.Message }
    else { $msg = [string]$ErrorRecord }
    $inner = ''
    if ($ErrorRecord.Exception -and $ErrorRecord.Exception.InnerException) {
        $inner = $ErrorRecord.Exception.InnerException.Message
    }
    $blob = "$msg $inner"
    if ($blob -match 'password|0x52[Dd]|1325|CONSTRAINT_ATT_TYPE|will not perform|complexity|history requirement') {
        return "AD refused to clear PASSWD_NOTREQD because the current password does not meet policy (often blank). Reset the password first, then clear the flag. Original error: $msg"
    }
    return $msg
}

function Get-UnknownAdPropertyName {
    # Get-ADObject validates -Properties against its property map and throws
    # ArgumentException with ParamName set to the unknown LDAP name
    # (e.g. badPwdTime — the real attribute is badPasswordTime).
    param($ErrorRecord)
    if ($null -eq $ErrorRecord) { return $null }
    $ex = $ErrorRecord
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ex = $ErrorRecord.Exception }
    while ($ex) {
        if ($ex -is [ArgumentException] -and -not [string]::IsNullOrWhiteSpace($ex.ParamName) -and $ex.ParamName -ne 'Properties') {
            return $ex.ParamName
        }
        $msg = [string]$ex.Message
        if ($msg -match '(?im)Parameter name:\s*(\S+)') {
            $name = $Matches[1].Trim().TrimEnd('.')
            if ($name -and $name -ne 'Properties') { return $name }
        }
        $ex = $ex.InnerException
    }
    return $null
}

function Get-AdPropertyValue {
    param($Object, [string[]]$Names)
    if ($null -eq $Object) { return $null }
    foreach ($n in $Names) {
        if ([string]::IsNullOrWhiteSpace($n)) { continue }
        $prop = $Object.PSObject.Properties[$n]
        if ($prop -and $null -ne $prop.Value) { return $prop.Value }
    }
    return $null
}

$script:PnrLdapProperties = @(
    'sAMAccountName', 'displayName', 'description', 'info', 'userAccountControl',
    'pwdLastSet', 'lastLogonTimestamp', 'lastLogon', 'logonCount', 'badPasswordTime',
    'badPwdCount', 'accountExpires', 'whenCreated', 'whenChanged', 'memberOf',
    'adminCount', 'primaryGroupID', 'servicePrincipalName',
    'msDS-SupportedEncryptionTypes', 'userWorkstations', 'scriptPath',
    'homeDirectory', 'manager', 'sIDHistory',
    'msDS-UserPasswordExpiryTimeComputed', 'msDS-ResultantPSO',
    'objectSid', 'lockoutTime', 'userPrincipalName'
)

function Get-FilterExpression {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $f = ($Text -replace "'", "''") -replace '([\[\]\*%#])', '[$1]'
    return "SamAccountName LIKE '%$f%' OR RiskFlags LIKE '%$f%' OR Category LIKE '%$f%' OR DistinguishedName LIKE '%$f%' OR Description LIKE '%$f%'"
}

function Invoke-PnrSelfTest {
    $failed = New-Object System.Collections.Generic.List[string]
    $passed = 0
    function Ok([string]$Name, $Actual, $Expected) {
        $a = [string]$Actual
        $e = [string]$Expected
        if ($a -ne $e) { $script:SelfTestFailed.Add("$Name : expected '$e' got '$a'") }
        else { $script:SelfTestPassed++ }
    }
    $script:SelfTestFailed = $failed
    $script:SelfTestPassed = 0

    Ok 'uac-passwd-notreqd' ((ConvertTo-UacText 0x22) -match 'PASSWD_NOTREQD') $true
    Ok 'uac-disable' ((ConvertTo-UacText 0x22) -match 'ACCOUNTDISABLE') $true
    Ok 'uac-clear-bit' ((Clear-PasswdNotReqdBit -UserAccountControl 0x10220) -band 0x20) 0
    Ok 'uac-clear-keeps-normal' ((Clear-PasswdNotReqdBit -UserAccountControl 0x10220) -band 0x0200) 512
    Ok 'uac-also-disable' ((Clear-PasswdNotReqdBit -UserAccountControl 0x10220 -AlsoDisable) -band 0x2) 2

    Ok 'filetime-null' (ConvertFrom-FileTime $null) $null
    Ok 'filetime-zero' (ConvertFrom-FileTime 0) $null
    Ok 'filetime-max' (ConvertFrom-FileTime ([int64]::MaxValue)) $null
    $dt = Get-Date '2020-06-15 12:00:00'
    $round = ConvertFrom-FileTime $dt.ToFileTime()
    Ok 'filetime-roundtrip' $round.ToString('yyyy-MM-dd HH:mm:ss') $dt.ToString('yyyy-MM-dd HH:mm:ss')
    Ok 'filetime-datetime' ((ConvertFrom-FileTime $dt).ToString('yyyy-MM-dd')) '2020-06-15'
    Ok 'pwdlastset-zero' (Get-PwdLastSetRaw 0) 0
    Ok 'pwdlastset-datetime-not-zero' ((Get-PwdLastSetRaw $dt) -gt 0) $true
    Ok 'pwdlastset-filetime' (Get-PwdLastSetRaw ([int64]12345)) 12345

    Ok 'domain-from-dn' (Get-DomainFromDN 'CN=User,OU=A,DC=kci-net,DC=karmanos,DC=org') 'kci-net.karmanos.org'
    Ok 'domain-escaped-comma' (Get-DomainFromDN "CN=O'Shea\, Mike,OU=Users,DC=contoso,DC=com") 'contoso.com'
    Ok 'rdn-escaped-comma' (Get-RdnValue "CN=O'Shea\, Mike,OU=Users,DC=contoso,DC=com") "O'Shea, Mike"
    Ok 'dsa-name' (Get-DsaName 'CN=NTDS Settings,CN=DC01,CN=Servers,CN=Site,CN=Sites,CN=Configuration,DC=contoso,DC=com') 'DC01'
    Ok 'dsa-guid-passthrough' (Get-DsaName '4c2a0e3a-1111-2222-3333-444444444444') '4c2a0e3a-1111-2222-3333-444444444444'

    $fakeDc = [pscustomobject]@{ HostName = 'DC01.kci-net.karmanos.org' }
    Ok 'dc-hostname-not-first-char' (Get-DcHostName $fakeDc) 'DC01.kci-net.karmanos.org'
    Ok 'dc-hostname-string' (Get-DcHostName 'DC02.contoso.com') 'DC02.contoso.com'
    Ok 'dc-hostname-bug-repro' ($fakeDc.HostName[0]) 'D'

    Ok 'priv-da' (Test-PrivilegedSid 'S-1-5-21-1-2-3-512') $true
    Ok 'priv-admins' (Test-PrivilegedSid 'S-1-5-32-544') $true
    Ok 'priv-domain-users' (Test-PrivilegedSid 'S-1-5-21-1-2-3-513') $false
    Ok 'primary-group-sid' (Get-PrimaryGroupSid -ObjectSid 'S-1-5-21-1-2-3-1111' -PrimaryGroupId 512) 'S-1-5-21-1-2-3-512'

    Ok 'header-bom' (Get-NormalizedHeaderName ([string]([char]0xFEFF) + 'Distinguished name')) 'Distinguished name'
    Ok 'process-arg-spaces' (ConvertTo-ProcessArgument 'C:\My Path\a.csv') '"C:\My Path\a.csv"'
    Ok 'filter-quote' ((Get-FilterExpression "O'Brien") -match "O''Brien") $true

    $policy = Get-AdChangeErrorMessage 'The password does not meet the length, complexity, or history requirement'
    Ok 'policy-error' ($policy -match 'blank') $true

    $ae = New-Object System.ArgumentException('The specified directory service attribute or value does not exist', 'badPwdTime')
    Ok 'unknown-prop-name' (Get-UnknownAdPropertyName $ae) 'badPwdTime'
    Ok 'ldap-has-badPasswordTime' ($script:PnrLdapProperties -contains 'badPasswordTime') $true
    Ok 'ldap-no-badPwdTime' ($script:PnrLdapProperties -contains 'badPwdTime') $false
    $probe = [pscustomobject]@{ badPasswordTime = 123; LastBadPasswordAttempt = $null }
    Ok 'prop-alias-badPasswordTime' (Get-AdPropertyValue $probe @('badPwdTime', 'badPasswordTime', 'LastBadPasswordAttempt')) 123

    Ok 'category-iusr' (Get-PnrAccountCategory 'IUSR_DC4100') 'Legacy IIS 5/6 anonymous web user (auto-created per server)'
    Ok 'category-iwam' ((Get-PnrAccountCategory 'IWAM_EXCH2000') -match 'IIS') $true
    Ok 'category-msol' ((Get-PnrAccountCategory 'MSOL_2a09c4e0405a') -match 'Entra Connect') $true
    Ok 'category-tsinternet' ((Get-PnrAccountCategory 'TsInternetUser') -match 'Terminal Services') $true
    Ok 'category-usbms' ((Get-PnrAccountCategory 'USbms_UNITY') -match 'Unity') $true
    Ok 'assoc-iusr' (Get-PnrAssociatedServerName 'IUSR_DC4100') 'DC4100'
    Ok 'assoc-usbms' (Get-PnrAssociatedServerName 'USbms_UNITY') 'UNITY'
    Ok 'semperis-uac' (ConvertFrom-SemperisUac '66080 [PasswordNotRequired, NormalAccount, PasswordDoesNotExpire]') 66080
    Ok 'semperis-uac-usbms' (ConvertFrom-SemperisUac '544 [PasswordNotRequired, NormalAccount]') 544
    Ok 'semperis-uac-enabled' (-not (66080 -band 2)) $true

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('pnr-selftest-' + [guid]::NewGuid().ToString('n'))
    New-Item -Path $tmp -ItemType Directory -Force | Out-Null
    try {
        $semperis = @(
            'Distinguished name,Object guid,Object class,Name'
            '"CN=IUSR_WEB01,OU=SA,DC=contoso,DC=com",11111111-1111-1111-1111-111111111111,User,IUSR_WEB01'
            '"CN=O''Shea\, Mike,OU=Users,DC=contoso,DC=com",22222222-2222-2222-2222-222222222222,User,moshea'
        ) -join [Environment]::NewLine
        $p1 = Join-Path $tmp 'semperis.csv'
        [IO.File]::WriteAllText($p1, $semperis)
        $rows = @(Import-PnrCsv -Path $p1)
        Ok 'csv-count' $rows.Count 2
        Ok 'csv-dn' $rows[0].DistinguishedName 'CN=IUSR_WEB01,OU=SA,DC=contoso,DC=com'
        Ok 'csv-escaped' ($rows[1].DistinguishedName -match 'O''Shea') $true
        Ok 'csv-guid' $rows[0].ObjectGuid '11111111-1111-1111-1111-111111111111'

        $alt = @(
            'DistinguishedName,ObjectGUID,sAMAccountName'
            '"CN=svc-batch,OU=SA,DC=fabrikam,DC=com",33333333-3333-3333-3333-333333333333,svc-batch'
        ) -join [Environment]::NewLine
        $p2 = Join-Path $tmp 'alternate.csv'
        [IO.File]::WriteAllText($p2, $alt)
        $rows2 = @(Import-PnrCsv -Path $p2)
        Ok 'csv-alias-header' $rows2[0].SamAccountName 'svc-batch'
        Ok 'csv-alias-domain' (Get-DomainFromDN $rows2[0].DistinguishedName) 'fabrikam.com'

        $bomPath = Join-Path $tmp 'bom.csv'
        $utf8bom = New-Object System.Text.UTF8Encoding $true
        [IO.File]::WriteAllText($bomPath, $semperis, $utf8bom)
        $rows3 = @(Import-PnrCsv -Path $bomPath)
        Ok 'csv-bom' $rows3.Count 2

        $bad = Join-Path $tmp 'bad.csv'
        [IO.File]::WriteAllText($bad, "Foo,Bar`n1,2")
        $threw = $false
        try { $null = Import-PnrCsv -Path $bad } catch { $threw = ($_.Exception.Message -match 'Distinguished') }
        Ok 'csv-missing-column' $threw $true

        if ($PSScriptRoot) {
            $sample = Join-Path $PSScriptRoot 'Samples/PasswordNotRequired.sample.csv'
            if (Test-Path -LiteralPath $sample) {
                $sampleRows = @(Import-PnrCsv -Path $sample)
                Ok 'sample-min-rows' ($sampleRows.Count -ge 5) $true
                Ok 'sample-iusr' ($sampleRows[0].DistinguishedName -match 'IUSR_WEB01') $true
                Ok 'sample-sam-header' $sampleRows[0].SamAccountName 'IUSR_WEB01'
                Ok 'sample-uac-header' ($sampleRows[0].UserAccountControl -match '66080') $true
                $stub = New-PnrStubRecord $sampleRows[0]
                Ok 'stub-category' ($stub.Category -match 'IIS') $true
                Ok 'stub-server' $stub.AssociatedServer 'WEB01'
                Ok 'stub-enabled' ([string]$stub.Enabled) 'True'
            }
        }

        $kci = @(
            'Distinguished name,Object guid,Sam account name,User account control,Managed by,Last changed,Created,Ignored'
            '"CN=IUSR_DC4100,CN=Users,DC=contoso,DC=com",62f4ec5d-ab82-4109-8c97-9348e192b2b4,IUSR_DC4100,"66080 [PasswordNotRequired, NormalAccount, PasswordDoesNotExpire]",,2024-08-17T13:53:22Z,2008-04-24T15:39:59Z,FALSE'
            '"CN=MSOL_2a09c4e0405a,CN=Users,DC=contoso,DC=com",A13f1ed0-1ca4-4f45-ae91-3887af990efa,MSOL_2a09c4e0405a,"66080 [PasswordNotRequired, NormalAccount, PasswordDoesNotExpire]",,2024-08-17T13:54:14Z,2015-03-02T14:51:21Z,FALSE'
            '"CN=USbms_UNITY,CN=Users,DC=contoso,DC=com",4abca282-f87d-4b4e-93eb-b0c7eddffb8b,USbms_UNITY,"544 [PasswordNotRequired, NormalAccount]",,2024-08-17T13:54:32Z,2006-09-30T06:32:53Z,FALSE'
        ) -join [Environment]::NewLine
        $pKci = Join-Path $tmp 'kci-layout.csv'
        [IO.File]::WriteAllText($pKci, $kci)
        $kciRows = @(Import-PnrCsv -Path $pKci)
        Ok 'kci-count' $kciRows.Count 3
        Ok 'kci-sam' $kciRows[0].SamAccountName 'IUSR_DC4100'
        $k0 = New-PnrStubRecord $kciRows[0]
        $k1 = New-PnrStubRecord $kciRows[1]
        $k2 = New-PnrStubRecord $kciRows[2]
        Ok 'kci-iusr-server' $k0.AssociatedServer 'DC4100'
        Ok 'kci-msol-cat' ($k1.Category -match 'Entra Connect') $true
        Ok 'kci-usbms-server' $k2.AssociatedServer 'UNITY'
        Ok 'kci-usbms-uac' $k2.UserAccountControl 544
        Ok 'kci-fail-flag' ((New-PnrStubRecord $kciRows[0] -LookupError 'badPwdTime').RiskFlags -match 'LOOKUP_FAILED') $true
    }
    finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    $script:SelfTestPassed = $passed + $script:SelfTestPassed
    $passCount = $script:SelfTestPassed
    Write-Host ("SelfTest: {0} passed, {1} failed" -f $passCount, $failed.Count)
    foreach ($f in $failed) { Write-Host "  FAIL $f" -ForegroundColor Red }
    if ($failed.Count) { return 1 }
    return 0
}

if ($SelfTest) {
    $code = Invoke-PnrSelfTest
    exit $code
}

# =============================================================================================
# Windows / STA / modules (must run here so STA relaunch targets THIS file, not the GUI)
# =============================================================================================
if (-not (Test-IsWindowsOs)) {
    throw 'This script requires Windows PowerShell 5.1 with WinForms. Use -SelfTest on other platforms.'
}

if (-not (Test-IsStaThread)) {
    if (-not $PSCommandPath) { throw 'Run this script from a .ps1 file in an STA session (powershell.exe -STA).' }
    $exe = $null
    try { $exe = (Get-Process -Id $PID).Path } catch { }
    if (-not $exe) { $exe = 'powershell.exe' }

    $parts = New-Object System.Collections.Generic.List[string]
    [void]$parts.Add('-NoProfile')
    [void]$parts.Add('-STA')
    [void]$parts.Add('-ExecutionPolicy')
    [void]$parts.Add('Bypass')
    [void]$parts.Add('-File')
    [void]$parts.Add((ConvertTo-ProcessArgument -Value $PSCommandPath))
    foreach ($key in $PSBoundParameters.Keys) {
        $val = $PSBoundParameters[$key]
        if ($val -is [System.Management.Automation.SwitchParameter]) {
            if ($val) { [void]$parts.Add("-$key") }
        }
        else {
            [void]$parts.Add("-$key")
            [void]$parts.Add((ConvertTo-ProcessArgument -Value ([string]$val)))
        }
    }
    $wd = $PSScriptRoot
    if (-not $wd) { $wd = (Get-Location).Path }
    $proc = Start-Process -FilePath $exe -ArgumentList ($parts -join ' ') -WorkingDirectory $wd -Wait -PassThru
    if ($proc) { exit $proc.ExitCode }
    return
}

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$script:WinFormsLoaded = $true

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    [void][System.Windows.Forms.MessageBox]::Show(
        "The ActiveDirectory module could not be loaded.`r`n`r`nInstall RSAT: Active Directory Domain Services tools, then run again.`r`n`r`n$($_.Exception.Message)",
        'Missing prerequisite', 'OK', 'Error')
    return
}

# =============================================================================================
# Windows GUI (dot-sourced so -SelfTest never loads WinForms / System.Drawing)
# =============================================================================================
$guiPath = Join-Path $PSScriptRoot 'PasswordNotRequired-Audit.Gui.ps1'
if (-not (Test-Path -LiteralPath $guiPath)) {
    throw "GUI script not found: $guiPath"
}
. $guiPath
