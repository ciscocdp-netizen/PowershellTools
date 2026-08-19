#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    AD Report Tool - Interactive GUI for querying Active Directory and Entra ID.
.DESCRIPTION
    Filter Users, Groups, Computers, and OUs by any combination of attributes,
    group membership, and account status. Build grouped AND/OR filter logic with
    smart value inputs, export results to CSV, view a summary, and choose which
    columns to display.

    Optional Entra ID (Microsoft Graph) enrichment for users: assigned directory
    roles, registered/owned devices, authentication methods, and last failed
    sign-in (error code, time, application, location, IP).
.NOTES
    Requires the ActiveDirectory RSAT module and read access to AD.
    Entra enrichment uses Microsoft Graph (device-code sign-in); needs Graph
    permissions such as User.Read.All, Directory.Read.All, AuditLog.Read.All,
    UserAuthenticationMethod.Read.All, Device.Read.All, RoleManagement.Read.Directory.
    Sign-in logs require Entra ID P1/P2. PowerShell 5.1 | WinForms GUI.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# EnableVisualStyles / SetCompatibleTextRenderingDefault must run before ANY
# Win32 window exists in the process. In the PowerShell ISE (or when the script
# is re-run in the same console session) a window already exists, so these calls
# throw. They are optional niceties, so run them best-effort and keep going.
try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch {}
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch {}

# ===========================================================================
# WINDOWS 10 THEME PALETTE  (3-5 core colors + neutrals)
# ===========================================================================
$Theme = @{
    Accent       = [System.Drawing.Color]::FromArgb(0,120,215)    # #0078D7  Win10 blue
    AccentDark   = [System.Drawing.Color]::FromArgb(0,99,177)     # hover/pressed
    AccentLight  = [System.Drawing.Color]::FromArgb(204,229,255)  # selection tint
    Window       = [System.Drawing.Color]::FromArgb(243,243,243)  # #F3F3F3 app background
    Card         = [System.Drawing.Color]::White
    CardAlt      = [System.Drawing.Color]::FromArgb(249,249,249)
    Border       = [System.Drawing.Color]::FromArgb(213,213,213)
    BorderDark   = [System.Drawing.Color]::FromArgb(160,160,160)
    Text         = [System.Drawing.Color]::FromArgb(32,31,30)
    TextMuted    = [System.Drawing.Color]::FromArgb(96,94,92)
    GridAlt      = [System.Drawing.Color]::FromArgb(247,247,247)
    Danger       = [System.Drawing.Color]::FromArgb(196,43,28)
}

# ---------------------------------------------------------------------------
# ATTRIBUTE DEFINITIONS PER OBJECT TYPE
# ---------------------------------------------------------------------------
$ATTR = @{
    Users = [ordered]@{
        "Display Name"            = "DisplayName"
        "SAM Account Name"        = "SamAccountName"
        "User Principal Name"     = "UserPrincipalName"
        "Email Address"           = "EmailAddress"
        "Employee ID"             = "EmployeeID"
        "First Name"              = "GivenName"
        "Last Name"               = "Surname"
        "Department"              = "Department"
        "Title"                   = "Title"
        "Company"                 = "Company"
        "Manager"                 = "Manager"
        "Office"                  = "Office"
        "Phone"                   = "telephoneNumber"
        "Mobile"                  = "mobile"
        "Description"             = "Description"
        "Account Enabled"         = "Enabled"
        "Password Never Expires"  = "PasswordNeverExpires"
        "Password Last Set"       = "PasswordLastSet"
        "Last Logon"              = "LastLogonDate"
        "Created"                 = "whenCreated"
        "Modified"                = "whenChanged"
        "Extension Attr 1"        = "extensionAttribute1"
        "Extension Attr 2"        = "extensionAttribute2"
        "Extension Attr 3"        = "extensionAttribute3"
        "Extension Attr 4"        = "extensionAttribute4"
        "Extension Attr 5"        = "extensionAttribute5"
        "Extension Attr 6"        = "extensionAttribute6"
        "Extension Attr 7"        = "extensionAttribute7"
        "Extension Attr 8"        = "extensionAttribute8"
        "Extension Attr 9"        = "extensionAttribute9"
        "Extension Attr 10"       = "extensionAttribute10"
        "OU / Distinguished Name" = "DistinguishedName"
        # --- Entra ID (populated by Graph enrichment; not LDAP-filterable) ---
        "Entra Assigned Roles"           = "EntraAssignedRoles"
        "Entra Devices"                  = "EntraDevices"
        "Entra Auth Methods"             = "EntraAuthMethods"
        "Entra Last Fail Sign-In Code"   = "EntraLastSignInErrorCode"
        "Entra Last Fail Sign-In Time"   = "EntraLastSignInErrorTime"
        "Entra Last Fail Sign-In App"    = "EntraLastSignInErrorApp"
        "Entra Last Fail Sign-In Loc"    = "EntraLastSignInErrorLocation"
        "Entra Last Fail Sign-In IP"     = "EntraLastSignInErrorIP"
    }
    Groups = [ordered]@{
        "Name"                    = "Name"
        "SAM Account Name"        = "SamAccountName"
        "Display Name"            = "DisplayName"
        "Description"             = "Description"
        "Group Scope"             = "GroupScope"
        "Group Category"          = "GroupCategory"
        "Email Address"           = "mail"
        "Created"                 = "whenCreated"
        "Modified"                = "whenChanged"
        "Managed By"              = "ManagedBy"
        "OU / Distinguished Name" = "DistinguishedName"
    }
    Computers = [ordered]@{
        "Name"                    = "Name"
        "DNS Host Name"           = "DNSHostName"
        "Operating System"        = "OperatingSystem"
        "OS Version"              = "OperatingSystemVersion"
        "Description"             = "Description"
        "Account Enabled"         = "Enabled"
        "Last Logon"              = "LastLogonDate"
        "Created"                 = "whenCreated"
        "Modified"                = "whenChanged"
        "IPv4 Address"            = "IPv4Address"
        "OU / Distinguished Name" = "DistinguishedName"
    }
    OUs = [ordered]@{
        "Name"                    = "Name"
        "Description"             = "Description"
        "Created"                 = "whenCreated"
        "Modified"                = "whenChanged"
        "OU / Distinguished Name" = "DistinguishedName"
    }
}

# Keep a copy of the curated friendly map so schema load can merge instead of wipe.
$script:CuratedAttr = @{
    Users     = [ordered]@{}
    Groups    = [ordered]@{}
    Computers = [ordered]@{}
    OUs       = [ordered]@{}
}
foreach ($ot in @("Users","Groups","Computers","OUs")) {
    foreach ($k in $ATTR[$ot].Keys) { $script:CuratedAttr[$ot][$k] = $ATTR[$ot][$k] }
}

# Expanded operator sets (see Get-OpList for how they are selected per attribute)
$OPERATORS = @{
    String  = @("contains","equals","not equals","not contains","starts with","ends with","in list","regex match","is empty","is set","is not set")
    Boolean = @("is true","is false")
    Date    = @("on","before","after","on or before","on or after","in last N days","is set","is not set")
}
# Operators that need NO value input
$NOVAL_OPS = @("is set","is not set","is empty","is true","is false")

$BOOL_ATTRS = @("Enabled","PasswordNeverExpires","PasswordNotRequired","LockedOut","CannotChangePassword","PasswordExpired","SmartcardLogonRequired","TrustedForDelegation")
$DATE_ATTRS = @("PasswordLastSet","LastLogonDate","whenCreated","whenChanged")

# PowerShell convenience / alias properties that are NOT raw LDAP attribute names.
# Used when building LDAP filters (and for client-side post-filters when needed).
$PS_PROP_MAP = @{
    Enabled                = @{ Kind = "UAC"; Bit = 2; Invert = $true }          # ACCOUNTDISABLE
    PasswordNeverExpires   = @{ Kind = "UAC"; Bit = 65536 }                      # DONT_EXPIRE_PASSWORD
    PasswordNotRequired    = @{ Kind = "UAC"; Bit = 32 }                         # PASSWD_NOTREQD
    SmartcardLogonRequired = @{ Kind = "UAC"; Bit = 262144 }                     # SMARTCARD_REQUIRED
    TrustedForDelegation   = @{ Kind = "UAC"; Bit = 524288 }                     # TRUSTED_FOR_DELEGATION
    LockedOut              = @{ Kind = "Lockout" }
    EmailAddress           = @{ Kind = "Alias"; Ldap = "mail" }
    Office                 = @{ Kind = "Alias"; Ldap = "physicalDeliveryOfficeName" }
    Surname                = @{ Kind = "Alias"; Ldap = "sn" }
    # Enum / computed — not valid as raw LDAP assertion values
    GroupScope             = @{ Kind = "ClientOnly"; PsProp = "GroupScope" }
    GroupCategory          = @{ Kind = "ClientOnly"; PsProp = "GroupCategory" }
    IPv4Address            = @{ Kind = "ClientOnly"; PsProp = "IPv4Address" }
    CannotChangePassword   = @{ Kind = "ClientOnly"; PsProp = "CannotChangePassword" }
    PasswordExpired        = @{ Kind = "ClientOnly"; PsProp = "PasswordExpired" }
    EntraAssignedRoles           = @{ Kind = "ClientOnly"; PsProp = "EntraAssignedRoles" }
    EntraDevices                 = @{ Kind = "ClientOnly"; PsProp = "EntraDevices" }
    EntraAuthMethods             = @{ Kind = "ClientOnly"; PsProp = "EntraAuthMethods" }
    EntraLastSignInErrorCode     = @{ Kind = "ClientOnly"; PsProp = "EntraLastSignInErrorCode" }
    EntraLastSignInErrorTime     = @{ Kind = "ClientOnly"; PsProp = "EntraLastSignInErrorTime" }
    EntraLastSignInErrorApp      = @{ Kind = "ClientOnly"; PsProp = "EntraLastSignInErrorApp" }
    EntraLastSignInErrorLocation = @{ Kind = "ClientOnly"; PsProp = "EntraLastSignInErrorLocation" }
    EntraLastSignInErrorIP       = @{ Kind = "ClientOnly"; PsProp = "EntraLastSignInErrorIP" }
}

# Entra-only property names (never request these from on-prem Get-AD*)
$script:EntraPropNames = @(
    "EntraAssignedRoles","EntraDevices","EntraAuthMethods",
    "EntraLastSignInErrorCode","EntraLastSignInErrorTime","EntraLastSignInErrorApp",
    "EntraLastSignInErrorLocation","EntraLastSignInErrorIP"
)

$DEFAULT_COLS = @{
    Users     = @("DisplayName","SamAccountName","UserPrincipalName","EmailAddress","EmployeeID","extensionAttribute3","Enabled")
    Groups    = @("Name","SamAccountName","GroupScope","GroupCategory","Description")
    Computers = @("Name","DNSHostName","OperatingSystem","Enabled","LastLogonDate")
    OUs       = @("Name","Description","DistinguishedName")
}

# ---------------------------------------------------------------------------
# GLOBAL STATE
# ---------------------------------------------------------------------------
$script:Results        = @()
# Grouped filter model: list of groups; each group = @{ Join="AND"/"OR"; Rows=List[hashtable] }
$script:FilterGroups   = [System.Collections.Generic.List[hashtable]]::new()
# Client-side predicates applied after the LDAP query returns.
$script:PostFilters    = [System.Collections.Generic.List[hashtable]]::new()
$script:VisibleColumns = [System.Collections.Generic.List[string]]::new()
# Properties actually retrieved from AD for the current result set. Used by the
# column chooser — ADUser's property adapter exposes many names even when the
# values were never loaded, so a null check on the sample object is unreliable.
$script:LoadedProperties = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:CurrentObjType = "Users"
$script:IsRunning      = $false
# Entra / Microsoft Graph session (device-code token)
$script:EntraAccessToken = $null
$script:EntraTokenExpires = [datetime]::MinValue
$script:EntraAccountUpn = ""
$script:EntraTenant = ""

$DEFAULT_COLS["Users"] | ForEach-Object { $script:VisibleColumns.Add($_) }

# ---------------------------------------------------------------------------
# FONTS  (Segoe UI is the Windows 10 system font)
# ---------------------------------------------------------------------------
$fntNormal  = New-Object System.Drawing.Font("Segoe UI", 9)
$fntBold    = New-Object System.Drawing.Font("Segoe UI", 9,  [System.Drawing.FontStyle]::Bold)
$fntTitle   = New-Object System.Drawing.Font("Segoe UI Semibold", 14, [System.Drawing.FontStyle]::Regular)
$fntSub     = New-Object System.Drawing.Font("Segoe UI", 9)
$fntMono    = New-Object System.Drawing.Font("Consolas", 8.5)
$fntSmall   = New-Object System.Drawing.Font("Segoe UI", 8)
$fntHeading = New-Object System.Drawing.Font("Segoe UI Semibold", 9, [System.Drawing.FontStyle]::Regular)

# ---------------------------------------------------------------------------
# THEME HELPERS
# ---------------------------------------------------------------------------
function Set-PrimaryButtonStyle ([System.Windows.Forms.Button]$b) {
    $b.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $b.FlatAppearance.BorderSize = 0
    $b.BackColor = $Theme.Accent
    $b.ForeColor = [System.Drawing.Color]::White
    $b.Font      = $fntBold
    $b.FlatAppearance.MouseOverBackColor = $Theme.AccentDark
    $b.FlatAppearance.MouseDownBackColor = $Theme.AccentDark
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
}
function Set-SecondaryButtonStyle ([System.Windows.Forms.Button]$b) {
    $b.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $b.FlatAppearance.BorderSize  = 1
    $b.FlatAppearance.BorderColor = $Theme.Border
    $b.BackColor = $Theme.Card
    $b.ForeColor = $Theme.Text
    $b.Font      = $fntNormal
    $b.FlatAppearance.MouseOverBackColor = $Theme.AccentLight
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
}
function Set-SubtleButtonStyle ([System.Windows.Forms.Button]$b) {
    $b.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $b.FlatAppearance.BorderSize  = 1
    $b.FlatAppearance.BorderColor = $Theme.Border
    $b.BackColor = $Theme.CardAlt
    $b.ForeColor = $Theme.TextMuted
    $b.Font      = $fntSmall
    $b.FlatAppearance.MouseOverBackColor = $Theme.AccentLight
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
}
function Set-GroupStyle ([System.Windows.Forms.GroupBox]$gb) {
    $gb.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $gb.BackColor = $Theme.Card
    $gb.ForeColor = $Theme.Accent
    $gb.Font      = $fntHeading
}
# Enable double-buffering on a control via reflection (smoother resize/scroll)
function Enable-DoubleBuffer ([System.Windows.Forms.Control]$ctrl) {
    try {
        $prop = $ctrl.GetType().GetProperty("DoubleBuffered",
                    [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
        if ($prop) { $prop.SetValue($ctrl, $true, $null) }
    } catch { }
}

# ---------------------------------------------------------------------------
# SAFE PROPERTY ACCESS (StrictMode Latest)
# ---------------------------------------------------------------------------
function Get-ObjectPropValue {
    param(
        [Parameter(Mandatory)] $Object,
        [Parameter(Mandatory)][string] $Name
    )
    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if (-not $prop) { return $null }
    return $prop.Value
}

function Test-ObjectHasProp {
    param(
        [Parameter(Mandatory)] $Object,
        [Parameter(Mandatory)][string] $Name
    )
    if ($null -eq $Object) { return $false }
    return [bool]$Object.PSObject.Properties[$Name]
}

# ---------------------------------------------------------------------------
# LDAP / AD FILTER ESCAPING
# ---------------------------------------------------------------------------
function Escape-LdapFilterValue ([string]$Value) {
    # RFC 4515: escape \, *, (, ), and NUL
    if ($null -eq $Value) { return "" }
    $sb = [System.Text.StringBuilder]::new($Value.Length * 2)
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int][char]$ch
        switch ($code) {
            0x5C { [void]$sb.Append("\5c") }   # \
            0x2A { [void]$sb.Append("\2a") }   # *
            0x28 { [void]$sb.Append("\28") }   # (
            0x29 { [void]$sb.Append("\29") }   # )
            0x00 { [void]$sb.Append("\00") }   # NUL
            default { [void]$sb.Append($ch) }
        }
    }
    return $sb.ToString()
}

function Escape-ADFilterValue ([string]$Value) {
    # PowerShell AD provider -Filter uses single-quoted string literals; escape '
    if ($null -eq $Value) { return "" }
    return ($Value -replace "'", "''")
}

function Get-UacLdapClause ([int]$Bit, [bool]$WantSet, [bool]$InvertMeaning = $false) {
    # OID 1.2.840.113556.1.4.803 = LDAP_MATCHING_RULE_BIT_AND
    $want = $WantSet
    if ($InvertMeaning) { $want = -not $want }
    if ($want) { return "(userAccountControl:1.2.840.113556.1.4.803:=$Bit)" }
    return "(!(userAccountControl:1.2.840.113556.1.4.803:=$Bit))"
}

# ---------------------------------------------------------------------------
# HELPER: attr list / operator list for current object type
# ---------------------------------------------------------------------------
function Get-AttrList  { $ATTR[$script:CurrentObjType].Keys | ForEach-Object { $_ } }
function Get-LDAPAttr  ([string]$Label) {
    $map = $ATTR[$script:CurrentObjType]
    if (-not $Label -or -not $map.Contains($Label)) { return $null }
    return $map[$Label]
}

function Test-IsDateAttr ([string]$LDAPAttr) {
    if ($DATE_ATTRS -contains $LDAPAttr) { return $true }
    return ($LDAPAttr -match '(?i)(date|when.*ed|timestamp|expires|logon|pwdlastset|badpasswordtime|lockouttime)')
}
function Get-OpList ([string]$LDAPAttr) {
    if ($BOOL_ATTRS -contains $LDAPAttr) { return $OPERATORS.Boolean }
    if (Test-IsDateAttr $LDAPAttr)       { return $OPERATORS.Date }
    return $OPERATORS.String
}
# What kind of value control does this attr/operator combination need?
function Get-ValKind ([string]$LDAPAttr, [string]$Op) {
    if ($NOVAL_OPS -contains $Op) { return "none" }
    if (Test-IsDateAttr $LDAPAttr) {
        if ($Op -eq "in last N days") { return "num" }
        return "date"
    }
    return "text"
}

# ---------------------------------------------------------------------------
# DATE / TIME CONVERSION  (display)
# ---------------------------------------------------------------------------
$FILETIME_ATTRS = @(
    "pwdLastSet","lastLogon","lastLogonTimestamp","accountExpires",
    "badPasswordTime","lockoutTime","ms-Mcs-AdmPwdExpirationTime",
    "msDS-UserPasswordExpiryTimeComputed","createTimeStamp","modifyTimeStamp",
    "PasswordLastSet","LastLogonDate"
)
$DATE_FORMAT = "yyyy-MM-dd HH:mm:ss"

function Convert-AdValue {
    param([string]$Name, $Value)

    if ($null -eq $Value) { return "" }
    if ($Value -is [datetime]) { return $Value.ToString($DATE_FORMAT) }

    if ($Value -is [System.__ComObject]) {
        try {
            $t    = $Value.GetType()
            $high = [int64]$t.InvokeMember("HighPart","GetProperty",$null,$Value,$null)
            $low  = [int64]$t.InvokeMember("LowPart", "GetProperty",$null,$Value,$null)
            $Value = ($high -shl 32) -bor ($low -band 0xFFFFFFFF)
        } catch { return $Value.ToString() }
    }

    $long = [int64]0
    $isLong = [int64]::TryParse($Value.ToString(), [ref]$long)
    if ($isLong) {
        $isFileTimeAttr = $FILETIME_ATTRS -contains $Name
        $inFileTimeRange = ($long -ge 100000000000000000 -and $long -le 2650467744000000000)
        if ($isFileTimeAttr -or $inFileTimeRange) {
            if ($long -eq 0 -or $long -eq 9223372036854775807) { return "Never" }
            try   { return ([datetime]::FromFileTime($long)).ToString($DATE_FORMAT) }
            catch { return $Value.ToString() }
        }
    }
    return $Value.ToString()
}

# ---------------------------------------------------------------------------
# DATE -> LDAP filter value conversion (for building queries)
# ---------------------------------------------------------------------------
# Map friendly PowerShell date property names to the real LDAP attribute used
# inside an LDAP filter, and remember whether it is stored as a FileTime integer
# or a Generalized-Time string.
$DATE_LDAP_MAP = @{
    PasswordLastSet   = @{ Ldap = "pwdLastSet";         Kind = "FileTime"    }
    LastLogonDate     = @{ Ldap = "lastLogonTimestamp"; Kind = "FileTime"    }
    whenCreated       = @{ Ldap = "whenCreated";        Kind = "Generalized" }
    whenChanged       = @{ Ldap = "whenChanged";        Kind = "Generalized" }
    createTimeStamp   = @{ Ldap = "createTimeStamp";    Kind = "Generalized" }
    modifyTimeStamp   = @{ Ldap = "modifyTimeStamp";    Kind = "Generalized" }
}
function Resolve-DateLdap ([string]$psAttr) {
    if ($DATE_LDAP_MAP.ContainsKey($psAttr)) { return $DATE_LDAP_MAP[$psAttr] }
    if ($psAttr -match '(?i)(when|timestamp)') { return @{ Ldap = $psAttr; Kind = "Generalized" } }
    return @{ Ldap = $psAttr; Kind = "FileTime" }
}
function ConvertTo-LdapDate ([datetime]$dt, [string]$Kind) {
    # DateTimePicker values are local wall-clock. ToFileTime() treats Unspecified/Local
    # as local time; ToFileTimeUtc() would mis-read local as UTC.
    if ($Kind -eq "FileTime") { return $dt.ToFileTime().ToString() }
    return ($dt.ToUniversalTime().ToString("yyyyMMddHHmmss.0") + "Z")
}

# ===========================================================================
# MAIN FORM
# ===========================================================================
$Form = New-Object System.Windows.Forms.Form
$Form.Text          = "AD Report Tool"
$Form.Size          = New-Object System.Drawing.Size(1280, 820)
$Form.MinimumSize   = New-Object System.Drawing.Size(980, 640)
$Form.StartPosition = "CenterScreen"
$Form.Font          = $fntNormal
$Form.BackColor     = $Theme.Window
$Form.ForeColor     = $Theme.Text
$Form.Icon          = [System.Drawing.SystemIcons]::Shield

# ---------------------------------------------------------------------------
# HEADER BAR
# ---------------------------------------------------------------------------
$Header = New-Object System.Windows.Forms.Panel
$Header.Dock      = "Top"
$Header.Height    = 60
$Header.BackColor = $Theme.Accent
$Form.Controls.Add($Header)

# Title and subtitle are stacked vertically at fixed positions. Fixed layout is
# used deliberately: AutoSize labels do not have a valid Width until the first
# paint, so any positioning that depends on $lblTitle.Right would misfire on the
# initial layout and overlap the title (which is exactly what we are fixing).
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text      = "AD Report Tool"
$lblTitle.Font      = $fntTitle
$lblTitle.ForeColor = [System.Drawing.Color]::White
$lblTitle.AutoSize  = $true
$lblTitle.BackColor = [System.Drawing.Color]::Transparent
$lblTitle.Location  = New-Object System.Drawing.Point(16, 7)
$Header.Controls.Add($lblTitle)

$lblSubtitle = New-Object System.Windows.Forms.Label
$lblSubtitle.Text      = "Query & report on Active Directory objects"
$lblSubtitle.Font      = $fntSub
$lblSubtitle.ForeColor = $Theme.AccentLight
$lblSubtitle.AutoSize  = $true
$lblSubtitle.BackColor = [System.Drawing.Color]::Transparent
$lblSubtitle.Location  = New-Object System.Drawing.Point(18, 36)
$Header.Controls.Add($lblSubtitle)

# ---------------------------------------------------------------------------
# STATUS STRIP
# ---------------------------------------------------------------------------
$StatusStrip = New-Object System.Windows.Forms.StatusStrip
$StatusStrip.BackColor = $Theme.Card
$StatusStrip.SizingGrip = $true

$sState = New-Object System.Windows.Forms.ToolStripStatusLabel
$sState.Text = "Ready"; $sState.Width = 160; $sState.BorderSides = "Right"; $sState.ForeColor = $Theme.Text

$sSep1 = New-Object System.Windows.Forms.ToolStripStatusLabel; $sSep1.Width = 10
$sTotal = New-Object System.Windows.Forms.ToolStripStatusLabel
$sTotal.Text = "Total: 0"; $sTotal.Width = 90; $sTotal.BorderSides = "Right"
$sSep2 = New-Object System.Windows.Forms.ToolStripStatusLabel; $sSep2.Width = 10
$sEnabled = New-Object System.Windows.Forms.ToolStripStatusLabel
$sEnabled.Text = "Enabled: 0"; $sEnabled.Width = 90; $sEnabled.BorderSides = "Right"
$sSep3 = New-Object System.Windows.Forms.ToolStripStatusLabel; $sSep3.Width = 10
$sDisabled = New-Object System.Windows.Forms.ToolStripStatusLabel
$sDisabled.Text = "Disabled: 0"; $sDisabled.Width = 90

$sProgress = New-Object System.Windows.Forms.ToolStripProgressBar
$sProgress.Width = 160; $sProgress.Minimum = 0; $sProgress.Maximum = 100
$sProgress.Value = 0; $sProgress.Visible = $false; $sProgress.Style = "Marquee"

$sLive = New-Object System.Windows.Forms.ToolStripStatusLabel
$sLive.Text = ""; $sLive.Width = 140; $sLive.Visible = $false; $sLive.ForeColor = $Theme.Accent

[void]$StatusStrip.Items.AddRange(@($sState,$sSep1,$sTotal,$sSep2,$sEnabled,$sSep3,$sDisabled,$sProgress,$sLive))
$Form.Controls.Add($StatusStrip)

function Set-Status ([string]$State,[int]$Total=0,[int]$En=0,[int]$Dis=0) {
    $sState.Text = $State; $sTotal.Text = "Total: $Total"
    $sEnabled.Text = "Enabled: $En"; $sDisabled.Text = "Disabled: $Dis"
    $StatusStrip.Refresh()
}
function Start-Progress ([string]$Label) {
    $sProgress.Visible = $true; $sLive.Text = $Label; $sLive.Visible = $true; $StatusStrip.Refresh()
}
function Update-Progress ([string]$Label) {
    $sLive.Text = $Label; $StatusStrip.Refresh(); [System.Windows.Forms.Application]::DoEvents()
}
function Stop-Progress {
    $sProgress.Visible = $false; $sLive.Text = ""; $sLive.Visible = $false; $StatusStrip.Refresh()
}

# ---------------------------------------------------------------------------
# SPLIT CONTAINER  (both panels resize with the window)
# ---------------------------------------------------------------------------
$Split = New-Object System.Windows.Forms.SplitContainer
$Split.Dock             = "Fill"
$Split.SplitterWidth    = 6
$Split.BackColor        = $Theme.Window
$Form.Controls.Add($Split)
$Split.BringToFront()

# IMPORTANT: Do NOT set Panel1MinSize / Panel2MinSize / SplitterDistance here.
# Before the control is laid out its Width is the tiny default (~150), so the
# combined min sizes exceed the width and WinForms throws. Apply the constraints
# once, after the splitter has a real width, from a SizeChanged handler.
$script:SplitInit = $false
$Split.Add_SizeChanged({
    if ($script:SplitInit) { return }
    if ($Split.Width -lt 760) { return }   # wait until we have room for both min sizes
    try {
        $Split.Panel1MinSize = 340
        $Split.Panel2MinSize = 360
        $Split.SplitterDistance = 420
        $script:SplitInit = $true
    } catch {}
})

# ===========================================================================
# LEFT PANEL  — scrollable, single-column TableLayout that stretches to width
# ===========================================================================
$LeftScroll = New-Object System.Windows.Forms.Panel
$LeftScroll.Dock       = "Fill"
$LeftScroll.AutoScroll = $true
$LeftScroll.BackColor  = $Theme.Window
$LeftScroll.Padding    = New-Object System.Windows.Forms.Padding(10,10,10,10)
$Split.Panel1.Controls.Add($LeftScroll)

$LeftTable = New-Object System.Windows.Forms.TableLayoutPanel
$LeftTable.AutoSize       = $true
$LeftTable.AutoSizeMode   = "GrowAndShrink"
$LeftTable.Dock           = "Top"
$LeftTable.ColumnCount    = 1
$LeftTable.BackColor      = $Theme.Window
$LeftTable.Padding        = New-Object System.Windows.Forms.Padding(0)
$LeftTable.Margin         = New-Object System.Windows.Forms.Padding(0)
$LeftTable.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
$LeftScroll.Controls.Add($LeftTable)
# Keep inner table width matched to the scroll viewport so children stretch
$LeftScroll.Add_SizeChanged({
    $w = $LeftScroll.ClientSize.Width - $LeftScroll.Padding.Horizontal
    if ($w -gt 0) { $LeftTable.Width = $w }
})

function Add-LeftRow ([System.Windows.Forms.Control]$ctrl, [int]$topPad = 0, [int]$botPad = 8) {
    $ctrl.Margin = New-Object System.Windows.Forms.Padding(0, $topPad, 0, $botPad)
    # Dock=Top (not Fill) so this control fills the column width but reports its
    # own Height to the auto-sizing TableLayoutPanel row. A Fill-docked child in
    # an AutoSize row collapses because it has no intrinsic preferred height.
    $ctrl.Dock   = "Top"
    $LeftTable.Controls.Add($ctrl)
}
function New-GroupBox ([string]$Title, [int]$Height) {
    $gb = New-Object System.Windows.Forms.GroupBox
    $gb.Text   = $Title
    $gb.Height = $Height
    Set-GroupStyle $gb
    return $gb
}

# ---------------------------------------------------------------------------
# 1. OBJECT TYPE  (segmented pivot buttons)
# ---------------------------------------------------------------------------
$gbObjType = New-GroupBox "Object Type" 62
Add-LeftRow $gbObjType

$ObjTypeFlow = New-Object System.Windows.Forms.FlowLayoutPanel
$ObjTypeFlow.Dock          = "Fill"
$ObjTypeFlow.FlowDirection = "LeftToRight"
$ObjTypeFlow.WrapContents  = $false
$ObjTypeFlow.BackColor     = $Theme.Card
$ObjTypeFlow.Padding       = New-Object System.Windows.Forms.Padding(8, 6, 0, 0)
$gbObjType.Controls.Add($ObjTypeFlow)

$script:ObjTypeButtons = @{}
foreach ($ot in @("Users","Groups","Computers","OUs")) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text   = $ot
    $b.Width  = 92
    $b.Height = 30
    $b.Margin = New-Object System.Windows.Forms.Padding(0,0,6,0)
    $b.Tag    = $ot
    if ($ot -eq "Users") { Set-PrimaryButtonStyle $b } else { Set-SecondaryButtonStyle $b }
    $ObjTypeFlow.Controls.Add($b)
    $script:ObjTypeButtons[$ot] = $b
}

# ---------------------------------------------------------------------------
# 2. SEARCH SCOPE
# ---------------------------------------------------------------------------
$gbScope = New-GroupBox "Search Scope" 90
Add-LeftRow $gbScope

$rdoDomain = New-Object System.Windows.Forms.RadioButton
$rdoDomain.Text = "Entire Domain"; $rdoDomain.Checked = $true; $rdoDomain.AutoSize = $true
$rdoDomain.Location = New-Object System.Drawing.Point(12,22); $rdoDomain.BackColor = $Theme.Card

$rdoOU = New-Object System.Windows.Forms.RadioButton
$rdoOU.Text = "Specific OU"; $rdoOU.AutoSize = $true
$rdoOU.Location = New-Object System.Drawing.Point(140,22); $rdoOU.BackColor = $Theme.Card

$cmbOU = New-Object System.Windows.Forms.ComboBox
$cmbOU.Location      = New-Object System.Drawing.Point(12,48)
$cmbOU.Width         = 340
$cmbOU.Anchor        = "Left,Right,Top"
$cmbOU.Font          = $fntMono
$cmbOU.DropDownStyle = "DropDown"
$cmbOU.Text          = "OU=Corp,DC=contoso,DC=com"
$cmbOU.ForeColor     = $Theme.TextMuted
$cmbOU.Enabled       = $false
$cmbOU.FlatStyle     = "Flat"

$gbScope.Controls.AddRange(@($rdoDomain, $rdoOU, $cmbOU))

function Load-OUList {
    $cmbOU.Items.Clear()
    try {
        $ous = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName -ResultSetSize $null -ErrorAction Stop |
               Sort-Object DistinguishedName
        foreach ($ou in $ous) { [void]$cmbOU.Items.Add($ou.DistinguishedName) }
        if ($cmbOU.Items.Count -gt 0) { $cmbOU.SelectedIndex = 0; $cmbOU.ForeColor = $Theme.Text }
    } catch { $cmbOU.Text = "(failed to load OUs: $_)" }
}
$rdoOU.Add_CheckedChanged({
    $cmbOU.Enabled = $rdoOU.Checked
    if ($rdoOU.Checked) {
        $cmbOU.ForeColor = $Theme.Text
        if ($cmbOU.Items.Count -eq 0) { Load-OUList }
    } else { $cmbOU.ForeColor = $Theme.TextMuted }
    Update-FilterPreview
})

# ---------------------------------------------------------------------------
# 3. ACCOUNT STATUS  (Users / Computers only)
# ---------------------------------------------------------------------------
$gbStatus = New-GroupBox "Account Status" 62
Add-LeftRow $gbStatus

$chkEnabled = New-Object System.Windows.Forms.CheckBox
$chkEnabled.Text = "Enabled"; $chkEnabled.Checked = $true; $chkEnabled.AutoSize = $true
$chkEnabled.Location = New-Object System.Drawing.Point(12,26); $chkEnabled.BackColor = $Theme.Card

$chkDisabled = New-Object System.Windows.Forms.CheckBox
$chkDisabled.Text = "Disabled"; $chkDisabled.AutoSize = $true
$chkDisabled.Location = New-Object System.Drawing.Point(110,26); $chkDisabled.BackColor = $Theme.Card

$chkEnabled.Add_CheckedChanged({ Update-FilterPreview })
$chkDisabled.Add_CheckedChanged({ Update-FilterPreview })
$gbStatus.Controls.AddRange(@($chkEnabled, $chkDisabled))

# ---------------------------------------------------------------------------
# 4. ATTRIBUTE FILTERS  (grouped AND/OR builder)
# ---------------------------------------------------------------------------
$gbFilters = New-GroupBox "Attribute Filters" 72
Add-LeftRow $gbFilters

$btnAddGroup = New-Object System.Windows.Forms.Button
$btnAddGroup.Text = "+ Add Filter Group"; $btnAddGroup.Width = 150; $btnAddGroup.Height = 28
$btnAddGroup.Location = New-Object System.Drawing.Point(12,26)
Set-SecondaryButtonStyle $btnAddGroup

$lblFilterCount = New-Object System.Windows.Forms.Label
$lblFilterCount.Text = "0 conditions"; $lblFilterCount.AutoSize = $true; $lblFilterCount.Font = $fntSmall
$lblFilterCount.ForeColor = $Theme.TextMuted; $lblFilterCount.BackColor = $Theme.Card
$lblFilterCount.Location = New-Object System.Drawing.Point(172,32)
$gbFilters.Controls.AddRange(@($btnAddGroup, $lblFilterCount))

# Container that holds the group cards (lives outside the group box so it grows)
$FilterContainer = New-Object System.Windows.Forms.Panel
$FilterContainer.Height    = 0
$FilterContainer.BackColor = $Theme.Window
$FilterContainer.Margin    = New-Object System.Windows.Forms.Padding(0)
Add-LeftRow $FilterContainer

# ---------------------------------------------------------------------------
# 5. FILTER LOGIC  (how groups combine)
# ---------------------------------------------------------------------------
$gbLogic = New-GroupBox "Combine Groups With" 72
Add-LeftRow $gbLogic

$rdoAND = New-Object System.Windows.Forms.RadioButton
$rdoAND.Text = "Match ALL groups (AND)"; $rdoAND.AutoSize = $true; $rdoAND.Checked = $true
$rdoAND.Location = New-Object System.Drawing.Point(12,22); $rdoAND.BackColor = $Theme.Card

$rdoOR = New-Object System.Windows.Forms.RadioButton
$rdoOR.Text = "Match ANY group (OR)"; $rdoOR.AutoSize = $true
$rdoOR.Location = New-Object System.Drawing.Point(12,44); $rdoOR.BackColor = $Theme.Card

$rdoAND.Add_CheckedChanged({ if ($rdoAND.Checked) { Sync-FilterModel; Rebuild-FilterContainer } })
$rdoOR.Add_CheckedChanged({  if ($rdoOR.Checked)  { Sync-FilterModel; Rebuild-FilterContainer } })
$gbLogic.Controls.AddRange(@($rdoAND,$rdoOR))

# ---------------------------------------------------------------------------
# 6. GROUP MEMBERSHIP
# ---------------------------------------------------------------------------
$gbGroup = New-GroupBox "Group Membership (member of ANY selected)" 190
Add-LeftRow $gbGroup

$rdoMemberOf = New-Object System.Windows.Forms.RadioButton
$rdoMemberOf.Text = "Member of"; $rdoMemberOf.AutoSize = $true; $rdoMemberOf.Checked = $true
$rdoMemberOf.Location = New-Object System.Drawing.Point(12,22); $rdoMemberOf.BackColor = $Theme.Card

$rdoNotMember = New-Object System.Windows.Forms.RadioButton
$rdoNotMember.Text = "NOT member of"; $rdoNotMember.AutoSize = $true
$rdoNotMember.Location = New-Object System.Drawing.Point(115,22); $rdoNotMember.BackColor = $Theme.Card

$rdoNoGroup = New-Object System.Windows.Forms.RadioButton
$rdoNoGroup.Text = "No group filter"; $rdoNoGroup.AutoSize = $true
$rdoNoGroup.Location = New-Object System.Drawing.Point(240,22); $rdoNoGroup.BackColor = $Theme.Card

$txtGroupSearch = New-Object System.Windows.Forms.TextBox
$txtGroupSearch.Location = New-Object System.Drawing.Point(12,50); $txtGroupSearch.Width = 258
$txtGroupSearch.Anchor = "Left,Right,Top"; $txtGroupSearch.Text = "Search groups..."
$txtGroupSearch.ForeColor = $Theme.TextMuted; $txtGroupSearch.BorderStyle = "FixedSingle"

$btnGroupSearch = New-Object System.Windows.Forms.Button
$btnGroupSearch.Text = "Search"; $btnGroupSearch.Width = 78; $btnGroupSearch.Height = 24
$btnGroupSearch.Location = New-Object System.Drawing.Point(276,49); $btnGroupSearch.Anchor = "Right,Top"
Set-SecondaryButtonStyle $btnGroupSearch

$lstGroups = New-Object System.Windows.Forms.CheckedListBox
$lstGroups.Location = New-Object System.Drawing.Point(12,80); $lstGroups.Width = 342; $lstGroups.Height = 78
$lstGroups.Anchor = "Left,Right,Top"; $lstGroups.CheckOnClick = $true; $lstGroups.Font = $fntSmall
$lstGroups.BorderStyle = "FixedSingle"

$lnkClear = New-Object System.Windows.Forms.LinkLabel
$lnkClear.Text = "Clear selection"; $lnkClear.AutoSize = $true
$lnkClear.Location = New-Object System.Drawing.Point(12,164); $lnkClear.BackColor = $Theme.Card
$lnkClear.LinkColor = $Theme.Accent

$gbGroup.Controls.AddRange(@($rdoMemberOf,$rdoNotMember,$rdoNoGroup,$txtGroupSearch,$btnGroupSearch,$lstGroups,$lnkClear))

# ---------------------------------------------------------------------------
# 7. ENTRA ID (Microsoft Graph enrichment — Users only)
# ---------------------------------------------------------------------------
$gbEntra = New-GroupBox "Entra ID Enrichment" 198
Add-LeftRow $gbEntra

$chkEntraEnrich = New-Object System.Windows.Forms.CheckBox
$chkEntraEnrich.Text = "Enrich Users with Entra ID after query"; $chkEntraEnrich.AutoSize = $true
$chkEntraEnrich.Location = New-Object System.Drawing.Point(12,20); $chkEntraEnrich.BackColor = $Theme.Card
$chkEntraEnrich.Checked = $false

$lblTenant = New-Object System.Windows.Forms.Label
$lblTenant.Text = "Tenant:"; $lblTenant.AutoSize = $true; $lblTenant.Font = $fntSmall
$lblTenant.ForeColor = $Theme.TextMuted; $lblTenant.BackColor = $Theme.Card
$lblTenant.Location = New-Object System.Drawing.Point(12,48)

$txtEntraTenant = New-Object System.Windows.Forms.TextBox
$txtEntraTenant.Location = New-Object System.Drawing.Point(58,45); $txtEntraTenant.Width = 280; $txtEntraTenant.Height = 22
$txtEntraTenant.Anchor = "Left,Right,Top"; $txtEntraTenant.BorderStyle = "FixedSingle"; $txtEntraTenant.Font = $fntSmall
$txtEntraTenant.Text = "contoso.onmicrosoft.com"
$txtEntraTenant.ForeColor = $Theme.TextMuted
# Placeholder hint — cleared on focus if still default
$script:EntraTenantPlaceholder = "contoso.onmicrosoft.com  (or Directory/Tenant ID GUID)"
$txtEntraTenant.Text = $script:EntraTenantPlaceholder

$btnEntraConnect = New-Object System.Windows.Forms.Button
$btnEntraConnect.Text = "Connect Graph"; $btnEntraConnect.Width = 110; $btnEntraConnect.Height = 24
$btnEntraConnect.Location = New-Object System.Drawing.Point(12,74)
Set-SecondaryButtonStyle $btnEntraConnect

$btnEntraDisconnect = New-Object System.Windows.Forms.Button
$btnEntraDisconnect.Text = "Disconnect"; $btnEntraDisconnect.Width = 90; $btnEntraDisconnect.Height = 24
$btnEntraDisconnect.Location = New-Object System.Drawing.Point(128,74)
Set-SubtleButtonStyle $btnEntraDisconnect

$lblEntraStatus = New-Object System.Windows.Forms.Label
$lblEntraStatus.Text = "Not connected"; $lblEntraStatus.AutoSize = $true; $lblEntraStatus.Font = $fntSmall
$lblEntraStatus.ForeColor = $Theme.TextMuted; $lblEntraStatus.BackColor = $Theme.Card
$lblEntraStatus.Location = New-Object System.Drawing.Point(226,78)

$chkEntraRoles = New-Object System.Windows.Forms.CheckBox
$chkEntraRoles.Text = "Assigned roles"; $chkEntraRoles.AutoSize = $true; $chkEntraRoles.Checked = $true
$chkEntraRoles.Location = New-Object System.Drawing.Point(12,106); $chkEntraRoles.BackColor = $Theme.Card

$chkEntraDevices = New-Object System.Windows.Forms.CheckBox
$chkEntraDevices.Text = "Devices"; $chkEntraDevices.AutoSize = $true; $chkEntraDevices.Checked = $true
$chkEntraDevices.Location = New-Object System.Drawing.Point(130,106); $chkEntraDevices.BackColor = $Theme.Card

$chkEntraAuth = New-Object System.Windows.Forms.CheckBox
$chkEntraAuth.Text = "Auth methods"; $chkEntraAuth.AutoSize = $true; $chkEntraAuth.Checked = $true
$chkEntraAuth.Location = New-Object System.Drawing.Point(210,106); $chkEntraAuth.BackColor = $Theme.Card

$chkEntraFailSignIn = New-Object System.Windows.Forms.CheckBox
$chkEntraFailSignIn.Text = "Last failed sign-in (code, time, app, location, IP)"; $chkEntraFailSignIn.AutoSize = $true
$chkEntraFailSignIn.Checked = $true
$chkEntraFailSignIn.Location = New-Object System.Drawing.Point(12,132); $chkEntraFailSignIn.BackColor = $Theme.Card

$btnEntraEnrichNow = New-Object System.Windows.Forms.Button
$btnEntraEnrichNow.Text = "Enrich Current Results"; $btnEntraEnrichNow.Width = 160; $btnEntraEnrichNow.Height = 26
$btnEntraEnrichNow.Location = New-Object System.Drawing.Point(12,160)
Set-SecondaryButtonStyle $btnEntraEnrichNow

$gbEntra.Controls.AddRange(@(
    $chkEntraEnrich,$lblTenant,$txtEntraTenant,$btnEntraConnect,$btnEntraDisconnect,$lblEntraStatus,
    $chkEntraRoles,$chkEntraDevices,$chkEntraAuth,$chkEntraFailSignIn,$btnEntraEnrichNow
))

$txtEntraTenant.Add_GotFocus({
    if ($txtEntraTenant.Text -eq $script:EntraTenantPlaceholder) {
        $txtEntraTenant.Text = ""; $txtEntraTenant.ForeColor = $Theme.Text
    }
})
$txtEntraTenant.Add_LostFocus({
    if ([string]::IsNullOrWhiteSpace($txtEntraTenant.Text)) {
        $txtEntraTenant.Text = $script:EntraTenantPlaceholder; $txtEntraTenant.ForeColor = $Theme.TextMuted
    }
})

# ---------------------------------------------------------------------------
# 8. LIVE FILTER PREVIEW
# ---------------------------------------------------------------------------
$gbPreview = New-GroupBox "Filter Preview" 176
Add-LeftRow $gbPreview

$txtEnglish = New-Object System.Windows.Forms.TextBox
$txtEnglish.Location = New-Object System.Drawing.Point(12,22); $txtEnglish.Width = 342; $txtEnglish.Height = 66
$txtEnglish.Anchor = "Left,Right,Top"; $txtEnglish.Multiline = $true; $txtEnglish.ReadOnly = $true
$txtEnglish.BorderStyle = "FixedSingle"; $txtEnglish.BackColor = $Theme.CardAlt
$txtEnglish.ScrollBars = "Vertical"; $txtEnglish.Font = $fntSmall

$lblLdapCap = New-Object System.Windows.Forms.Label
$lblLdapCap.Text = "LDAP filter"; $lblLdapCap.AutoSize = $true; $lblLdapCap.Font = $fntSmall
$lblLdapCap.ForeColor = $Theme.TextMuted; $lblLdapCap.BackColor = $Theme.Card
$lblLdapCap.Location = New-Object System.Drawing.Point(12,92)

$txtLdap = New-Object System.Windows.Forms.TextBox
$txtLdap.Location = New-Object System.Drawing.Point(12,108); $txtLdap.Width = 342; $txtLdap.Height = 56
$txtLdap.Anchor = "Left,Right,Top"; $txtLdap.Multiline = $true; $txtLdap.ReadOnly = $true
$txtLdap.BorderStyle = "FixedSingle"; $txtLdap.BackColor = $Theme.CardAlt
$txtLdap.ScrollBars = "Vertical"; $txtLdap.Font = $fntMono

$gbPreview.Controls.AddRange(@($txtEnglish,$lblLdapCap,$txtLdap))

# ---------------------------------------------------------------------------
# 9. ACTION BUTTONS
# ---------------------------------------------------------------------------
$ActPanel = New-Object System.Windows.Forms.Panel
$ActPanel.Height = 44; $ActPanel.BackColor = $Theme.Window
Add-LeftRow $ActPanel 4 4

$btnRun = New-Object System.Windows.Forms.Button
$btnRun.Text = "Run Query  (F5)"; $btnRun.Width = 130; $btnRun.Height = 32
$btnRun.Location = New-Object System.Drawing.Point(0,6)
Set-PrimaryButtonStyle $btnRun

$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text = "Clear"; $btnClear.Width = 80; $btnClear.Height = 32
$btnClear.Location = New-Object System.Drawing.Point(140,6)
Set-SecondaryButtonStyle $btnClear

$ActPanel.Controls.AddRange(@($btnRun,$btnClear))

# ===========================================================================
# RIGHT PANEL  — Toolbar + DataGridView (fills remaining space)
# ===========================================================================
$RightOuter = New-Object System.Windows.Forms.Panel
$RightOuter.Dock    = "Fill"
$RightOuter.BackColor = $Theme.Card
$RightOuter.Padding = New-Object System.Windows.Forms.Padding(0)
$Split.Panel2.Controls.Add($RightOuter)

# --- Toolbar ---
$Toolbar = New-Object System.Windows.Forms.Panel
$Toolbar.Dock = "Top"; $Toolbar.Height = 46; $Toolbar.BackColor = $Theme.Card

$lblResults = New-Object System.Windows.Forms.Label
$lblResults.Text = "Results"; $lblResults.Font = $fntBold; $lblResults.ForeColor = $Theme.Text
$lblResults.AutoSize = $true; $lblResults.Location = New-Object System.Drawing.Point(12,14)

$txtSearch = New-Object System.Windows.Forms.TextBox
$txtSearch.Location = New-Object System.Drawing.Point(74,11); $txtSearch.Width = 220; $txtSearch.Height = 24
$txtSearch.Text = "Search results..."; $txtSearch.ForeColor = $Theme.TextMuted; $txtSearch.BorderStyle = "FixedSingle"

$btnColumns = New-Object System.Windows.Forms.Button
$btnColumns.Text = "Columns"; $btnColumns.Width = 84; $btnColumns.Height = 26; $btnColumns.Top = 10; $btnColumns.Anchor = "Top,Right"
Set-SecondaryButtonStyle $btnColumns

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text = "Export CSV"; $btnExport.Width = 90; $btnExport.Height = 26; $btnExport.Top = 10; $btnExport.Anchor = "Top,Right"
Set-SecondaryButtonStyle $btnExport

$btnSummary = New-Object System.Windows.Forms.Button
$btnSummary.Text = "Summary"; $btnSummary.Width = 84; $btnSummary.Height = 26; $btnSummary.Top = 10; $btnSummary.Anchor = "Top,Right"
Set-SecondaryButtonStyle $btnSummary

$Toolbar.Add_SizeChanged({
    $btnSummary.Left = $Toolbar.ClientSize.Width - $btnSummary.Width - 12
    $btnExport.Left  = $btnSummary.Left - $btnExport.Width - 8
    $btnColumns.Left = $btnExport.Left  - $btnColumns.Width - 8
})
$Toolbar.Controls.AddRange(@($lblResults,$txtSearch,$btnColumns,$btnExport,$btnSummary))

# --- DataGridView ---
$Grid = New-Object System.Windows.Forms.DataGridView
$Grid.Dock                        = "Fill"
$Grid.ReadOnly                    = $true
$Grid.AllowUserToAddRows          = $false
$Grid.AllowUserToDeleteRows       = $false
$Grid.AllowUserToResizeRows       = $false
$Grid.RowHeadersVisible           = $false
$Grid.ColumnHeadersVisible        = $true
$Grid.MultiSelect                 = $true
$Grid.SelectionMode               = "FullRowSelect"
$Grid.AutoSizeColumnsMode         = "None"
$Grid.ScrollBars                  = "Both"
$Grid.RowTemplate.Height          = 24
$Grid.BorderStyle                 = "None"
$Grid.BackgroundColor             = $Theme.Card
$Grid.GridColor                   = $Theme.Border
$Grid.CellBorderStyle             = "SingleHorizontal"
$Grid.ColumnHeadersHeight         = 32
$Grid.ColumnHeadersHeightSizeMode = "DisableResizing"
$Grid.EnableHeadersVisualStyles   = $false
$Grid.Font                        = $fntNormal
# Header styling (Win10 accent)
$Grid.ColumnHeadersDefaultCellStyle.BackColor = $Theme.Accent
$Grid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
$Grid.ColumnHeadersDefaultCellStyle.Font      = $fntBold
$Grid.ColumnHeadersDefaultCellStyle.Padding   = New-Object System.Windows.Forms.Padding(6,0,6,0)
$Grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = $Theme.Accent
# Cell styling
$Grid.DefaultCellStyle.SelectionBackColor = $Theme.AccentLight
$Grid.DefaultCellStyle.SelectionForeColor = $Theme.Text
$Grid.DefaultCellStyle.Padding            = New-Object System.Windows.Forms.Padding(6,0,6,0)
$Grid.AlternatingRowsDefaultCellStyle.BackColor = $Theme.GridAlt
Enable-DoubleBuffer $Grid

$GridDivider = New-Object System.Windows.Forms.Panel
$GridDivider.Dock = "Top"; $GridDivider.Height = 1; $GridDivider.BackColor = $Theme.Border

# Dock order matters: add Fill first, then the Top-docked controls from
# bottom-most to top-most so the stack renders Toolbar > divider > Grid.
$RightOuter.Controls.Add($Grid)
$RightOuter.Controls.Add($GridDivider)
$RightOuter.Controls.Add($Toolbar)

# Right-click context menu
$GridMenu   = New-Object System.Windows.Forms.ContextMenuStrip
$mCopyCell  = $GridMenu.Items.Add("Copy Cell")
$mCopyRow   = $GridMenu.Items.Add("Copy Row (tab-separated)")
[void]$GridMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
$mSelectAll = $GridMenu.Items.Add("Select All")
$Grid.ContextMenuStrip = $GridMenu

# ===========================================================================
# GROUPED FILTER MODEL HELPERS
# ===========================================================================
function New-FilterRow {
    return @{
        AttrLabel = (Get-AttrList | Select-Object -First 1)
        Operator  = "contains"
        Value     = ""
        Negate    = $false
        # control refs (populated during render)
        CmbAttr = $null; CmbOp = $null; ChkNot = $null; ValCtrl = $null; ValKind = "text"
    }
}
function New-FilterGroup {
    $g = @{ Join = "AND"; Rows = [System.Collections.Generic.List[hashtable]]::new() }
    $g.Rows.Add((New-FilterRow))
    return $g
}

# Read the current values out of the live controls back into the model so a
# rebuild (or query) never loses what the user typed/selected.
function Sync-FilterModel {
    foreach ($g in $script:FilterGroups) {
        foreach ($r in $g.Rows) {
            if ($r.CmbAttr -and $r.CmbAttr.SelectedItem) { $r.AttrLabel = $r.CmbAttr.SelectedItem.ToString() }
            if ($r.CmbOp   -and $r.CmbOp.SelectedItem)   { $r.Operator  = $r.CmbOp.SelectedItem.ToString() }
            if ($r.ChkNot) { $r.Negate = $r.ChkNot.Checked }
            if ($r.ValCtrl) {
                switch ($r.ValKind) {
                    "date" { $r.Value = ([System.Windows.Forms.DateTimePicker]$r.ValCtrl).Value.ToString("yyyy-MM-dd") }
                    "num"  { $r.Value = ([System.Windows.Forms.NumericUpDown]$r.ValCtrl).Value.ToString() }
                    "text" { $r.Value = $r.ValCtrl.Text }
                    default { }
                }
            }
        }
    }
}

# Count total conditions across all groups
function Get-ConditionCount {
    $n = 0
    foreach ($g in $script:FilterGroups) { $n += $g.Rows.Count }
    return $n
}

# ===========================================================================
# FILTER CONTAINER RENDERER  (grouped cards, smart value inputs)
# ===========================================================================
function Rebuild-FilterContainer {
    $FilterContainer.SuspendLayout()
    $FilterContainer.Controls.Clear()

    $containerW = $FilterContainer.ClientSize.Width
    if ($containerW -le 0) { $containerW = $LeftTable.Width }
    if ($containerW -le 0) { $containerW = 360 }

    $y = 0
    $gap = 8

    for ($gi = 0; $gi -lt $script:FilterGroups.Count; $gi++) {
        $group = $script:FilterGroups[$gi]

        # Connector label between groups (reflects top-level AND/OR)
        if ($gi -gt 0) {
            $joinTxt = if ($rdoAND.Checked) { "AND" } else { "OR" }
            $lblJoin = New-Object System.Windows.Forms.Label
            $lblJoin.Text = $joinTxt; $lblJoin.Font = $fntBold; $lblJoin.ForeColor = $Theme.Accent
            $lblJoin.TextAlign = "MiddleCenter"; $lblJoin.AutoSize = $false
            $lblJoin.SetBounds(0, $y, $containerW, 20)
            $lblJoin.Anchor = "Left,Right,Top"; $lblJoin.BackColor = $Theme.Window
            $FilterContainer.Controls.Add($lblJoin)
            $y += 22
        }

        # ---- Group card ----
        $rowH   = 34
        $headH  = 30
        $addH   = 30
        $pad    = 8
        $cardH  = $headH + ($group.Rows.Count * $rowH) + $addH + ($pad * 2)

        $card = New-Object System.Windows.Forms.Panel
        $card.SetBounds(0, $y, $containerW, $cardH)
        $card.Anchor    = "Left,Right,Top"
        $card.BackColor = $Theme.Card
        $card.BorderStyle = "FixedSingle"
        $FilterContainer.Controls.Add($card)

        $cardW = $card.ClientSize.Width

        # Header: connector toggle + label + remove-group
        $btnJoin = New-Object System.Windows.Forms.Button
        $btnJoin.Text = if ($group.Join -eq "AND") { "ALL (AND)" } else { "ANY (OR)" }
        $btnJoin.Width = 90; $btnJoin.Height = 24
        $btnJoin.Location = New-Object System.Drawing.Point($pad, $pad)
        Set-SubtleButtonStyle $btnJoin
        $btnJoin.ForeColor = $Theme.Accent
        $btnJoin.Tag = $group
        $btnJoin.Add_Click({
            Sync-FilterModel
            $g = $this.Tag
            $g.Join = if ($g.Join -eq "AND") { "OR" } else { "AND" }
            Rebuild-FilterContainer
        })

        $lblGrp = New-Object System.Windows.Forms.Label
        $lblGrp.Text = "Group $($gi + 1) - match"; $lblGrp.AutoSize = $true; $lblGrp.Font = $fntSmall
        $lblGrp.ForeColor = $Theme.TextMuted; $lblGrp.BackColor = $Theme.Card
        $lblGrp.Location = New-Object System.Drawing.Point(($pad + 96), ($pad + 4))

        $btnDelGrp = New-Object System.Windows.Forms.Button
        $btnDelGrp.Text = "Delete Group"; $btnDelGrp.Width = 96; $btnDelGrp.Height = 24
        $btnDelGrp.Location = New-Object System.Drawing.Point(($cardW - 104), $pad)
        $btnDelGrp.Anchor = "Right,Top"
        Set-SubtleButtonStyle $btnDelGrp
        $btnDelGrp.ForeColor = $Theme.Danger
        $btnDelGrp.Tag = $group
        $btnDelGrp.Add_Click({
            Sync-FilterModel
            [void]$script:FilterGroups.Remove($this.Tag)
            Rebuild-FilterContainer
        })

        $card.Controls.AddRange(@($btnJoin,$lblGrp,$btnDelGrp))

        # ---- Condition rows ----
        for ($ri = 0; $ri -lt $group.Rows.Count; $ri++) {
            $row  = $group.Rows[$ri]
            $rowY = $pad + $headH + ($ri * $rowH)

            $cmbAttr = New-Object System.Windows.Forms.ComboBox
            $cmbAttr.SetBounds(($pad), $rowY, 140, 23)
            $cmbAttr.DropDownStyle = "DropDownList"; $cmbAttr.FlatStyle = "Flat"; $cmbAttr.Font = $fntSmall
            Get-AttrList | ForEach-Object { [void]$cmbAttr.Items.Add($_) }
            if ($row.AttrLabel -ne "" -and $cmbAttr.Items.Contains($row.AttrLabel)) { $cmbAttr.SelectedItem = $row.AttrLabel }
            elseif ($cmbAttr.Items.Count -gt 0) { $cmbAttr.SelectedIndex = 0 }

            $la  = Get-LDAPAttr $cmbAttr.SelectedItem.ToString()
            $ops = Get-OpList $la

            $cmbOp = New-Object System.Windows.Forms.ComboBox
            $cmbOp.SetBounds(($pad + 146), $rowY, 116, 23)
            $cmbOp.DropDownStyle = "DropDownList"; $cmbOp.FlatStyle = "Flat"; $cmbOp.Font = $fntSmall
            $ops | ForEach-Object { [void]$cmbOp.Items.Add($_) }
            if ($row.Operator -ne "" -and $cmbOp.Items.Contains($row.Operator)) { $cmbOp.SelectedItem = $row.Operator }
            elseif ($cmbOp.Items.Count -gt 0) { $cmbOp.SelectedIndex = 0 }

            $op = $cmbOp.SelectedItem.ToString()

            $chkNot = New-Object System.Windows.Forms.CheckBox
            $chkNot.Text = "NOT"; $chkNot.AutoSize = $true; $chkNot.Font = $fntSmall
            $chkNot.BackColor = $Theme.Card; $chkNot.Checked = $row.Negate
            $chkNot.Location = New-Object System.Drawing.Point(($pad + 266), ($rowY + 3))

            $btnRem = New-Object System.Windows.Forms.Button
            $btnRem.Text = "X"; $btnRem.Width = 26; $btnRem.Height = 23
            $btnRem.Location = New-Object System.Drawing.Point(($cardW - 34), $rowY)
            $btnRem.Anchor = "Right,Top"
            Set-SubtleButtonStyle $btnRem
            $btnRem.ForeColor = $Theme.Danger; $btnRem.Font = $fntBold

            # Value control depends on attr/operator
            $kind = Get-ValKind $la $op
            $valX = $pad + 316
            $valW = $cardW - $valX - 44
            if ($valW -lt 60) { $valW = 60 }

            $valCtrl = $null
            switch ($kind) {
                "date" {
                    $dtp = New-Object System.Windows.Forms.DateTimePicker
                    $dtp.SetBounds($valX, $rowY, $valW, 23)
                    $dtp.Anchor = "Left,Right,Top"; $dtp.Format = "Short"; $dtp.Font = $fntSmall
                    $parsed = [datetime]::Now
                    if ($row.Value -and [datetime]::TryParse($row.Value, [ref]$parsed)) { $dtp.Value = $parsed }
                    $dtp.Add_ValueChanged({ Sync-FilterModel; Update-FilterPreview })
                    $valCtrl = $dtp
                }
                "num" {
                    $nud = New-Object System.Windows.Forms.NumericUpDown
                    $nud.SetBounds($valX, $rowY, $valW, 23)
                    $nud.Anchor = "Left,Right,Top"; $nud.Minimum = 1; $nud.Maximum = 3650; $nud.Font = $fntSmall
                    $nval = 30; [void][int]::TryParse($row.Value, [ref]$nval)
                    if ($nval -lt 1) { $nval = 30 }
                    $nud.Value = $nval
                    $nud.Add_ValueChanged({ Sync-FilterModel; Update-FilterPreview })
                    $valCtrl = $nud
                }
                "none" {
                    $lblNo = New-Object System.Windows.Forms.Label
                    $lblNo.SetBounds($valX, ($rowY + 3), $valW, 20)
                    $lblNo.Anchor = "Left,Right,Top"; $lblNo.Text = "(no value)"; $lblNo.Font = $fntSmall
                    $lblNo.ForeColor = $Theme.TextMuted; $lblNo.BackColor = $Theme.Card
                    $valCtrl = $lblNo
                }
                default {
                    $txtV = New-Object System.Windows.Forms.TextBox
                    $txtV.SetBounds($valX, $rowY, $valW, 23)
                    $txtV.Anchor = "Left,Right,Top"; $txtV.BorderStyle = "FixedSingle"; $txtV.Font = $fntSmall
                    $txtV.Text = $row.Value
                    $txtV.Add_TextChanged({ Sync-FilterModel; Update-FilterPreview })
                    $valCtrl = $txtV
                }
            }

            $row.CmbAttr = $cmbAttr; $row.CmbOp = $cmbOp; $row.ChkNot = $chkNot
            $row.ValCtrl = $valCtrl; $row.ValKind = $kind

            # Handlers
            $chkNot.Add_CheckedChanged({ Sync-FilterModel; Update-FilterPreview })
            $cmbAttr.Tag = $row
            $cmbAttr.Add_SelectedIndexChanged({
                Sync-FilterModel
                $r = $this.Tag
                $r.AttrLabel = $this.SelectedItem.ToString()
                # Reset operator to first valid one for the new attribute type
                $newLa  = Get-LDAPAttr $r.AttrLabel
                $newOps = Get-OpList $newLa
                if ($newOps -notcontains $r.Operator) { $r.Operator = $newOps[0] }
                Rebuild-FilterContainer
            })
            $cmbOp.Tag = $row
            $cmbOp.Add_SelectedIndexChanged({
                Sync-FilterModel
                $r = $this.Tag
                $r.Operator = $this.SelectedItem.ToString()
                Rebuild-FilterContainer   # value control type may change
            })
            $btnRem.Tag = @{ G = $group; R = $row }
            $btnRem.Add_Click({
                Sync-FilterModel
                $ctx = $this.Tag
                [void]$ctx.G.Rows.Remove($ctx.R)
                if ($ctx.G.Rows.Count -eq 0) { [void]$script:FilterGroups.Remove($ctx.G) }
                Rebuild-FilterContainer
            })

            $card.Controls.AddRange(@($cmbAttr,$cmbOp,$chkNot,$valCtrl,$btnRem))
        }

        # ---- Add condition button ----
        $btnAddCond = New-Object System.Windows.Forms.Button
        $btnAddCond.Text = "+ Add Condition"; $btnAddCond.Width = 130; $btnAddCond.Height = 24
        $btnAddCond.Location = New-Object System.Drawing.Point($pad, ($pad + $headH + ($group.Rows.Count * $rowH) + 2))
        Set-SubtleButtonStyle $btnAddCond
        $btnAddCond.ForeColor = $Theme.Accent
        $btnAddCond.Tag = $group
        $btnAddCond.Add_Click({
            Sync-FilterModel
            $this.Tag.Rows.Add((New-FilterRow))
            Rebuild-FilterContainer
        })
        $card.Controls.Add($btnAddCond)

        $y += $cardH + $gap
    }

    $FilterContainer.Height = [Math]::Max(0, $y)
    $FilterContainer.ResumeLayout()
    Update-FilterPreview
}

$btnAddGroup.Add_Click({
    Sync-FilterModel
    $script:FilterGroups.Add((New-FilterGroup))
    Rebuild-FilterContainer
})

# ===========================================================================
# BUILD LDAP FILTER  (grouped + client-side post-filters for regex / computed)
# ===========================================================================
# Ops that need a non-empty value. Blank values must NOT become LDAP `(attr=)` —
# Active Directory rejects empty equality assertions with
# "The search filter cannot be recognized".
$VALUE_REQUIRED_OPS = @("equals","not equals","contains","not contains","starts with","ends with","in list","regex match","on","before","after","on or before","on or after","in last N days")

function Test-LdapFilterSyntax ([string]$Filter) {
    if ([string]::IsNullOrWhiteSpace($Filter)) { return $false }
    # ADSI rejects empty equality assertions like (mail=)
    if ($Filter -match '\([A-Za-z0-9.;-]+=\)') { return $false }
    $depth = 0
    foreach ($ch in $Filter.ToCharArray()) {
        if ($ch -eq '(') { $depth++ }
        elseif ($ch -eq ')') {
            $depth--
            if ($depth -lt 0) { return $false }
        }
    }
    return ($depth -eq 0 -and $Filter.StartsWith('(') -and $Filter.EndsWith(')'))
}

function Build-StringClause ([string]$la, [string]$op, [string]$valT) {
    # Presence-only operators (no value)
    switch ($op) {
        "is set"     { return "($la=*)" }
        "is not set" { return "(!($la=*))" }
        # AD does not store empty strings; treat "is empty" as not present.
        # Do NOT emit ($la=) — ADSI returns "search filter cannot be recognized".
        "is empty"   { return "(!($la=*))" }
    }

    # Value-required ops with blank input → skip (caller omits clause)
    if (($VALUE_REQUIRED_OPS -contains $op) -and [string]::IsNullOrWhiteSpace($valT) -and $op -ne "in list") {
        return ""
    }

    $esc = Escape-LdapFilterValue $valT
    switch ($op) {
        "equals"       { if ($esc -eq "") { return "" }; return "($la=$esc)" }
        "not equals"   { if ($esc -eq "") { return "" }; return "(!($la=$esc))" }
        "contains"     { if ($esc -eq "") { return "" }; return "($la=*$esc*)" }
        "not contains" { if ($esc -eq "") { return "" }; return "(!($la=*$esc*))" }
        "starts with"  { if ($esc -eq "") { return "" }; return "($la=$esc*)" }
        "ends with"    { if ($esc -eq "") { return "" }; return "($la=*$esc)" }
        "in list" {
            $items = @($valT -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
            if ($items.Count -eq 0) { return "" }
            $ors = ($items | ForEach-Object { "($la=$(Escape-LdapFilterValue $_))" }) -join ""
            if ($items.Count -eq 1) { return $ors } else { return "(|$ors)" }
        }
        default {
            if ($esc -eq "") { return "" }
            return "($la=*$esc*)"
        }
    }
}

function Build-ConditionClause ([hashtable]$row) {
    # Returns a hashtable: @{ Ldap = "<clause or empty>"; Post = <hashtable or $null> }
    $label  = $row.AttrLabel
    $la     = Get-LDAPAttr $label
    if (-not $la) { return @{ Ldap = ""; Post = $null } }
    $op     = $row.Operator
    $val     = if ($null -ne $row.Value) { [string]$row.Value } else { "" }
    # Strip CRs/LFs — they break LDAP filter parsing
    $valT    = ($val -replace '[\r\n]+', ' ').Trim()
    $negate = [bool]$row.Negate
    $post   = $null
    $clause = ""

    # Skip incomplete value-required conditions (blank text / date / list)
    if (($VALUE_REQUIRED_OPS -contains $op) -and [string]::IsNullOrWhiteSpace($valT) -and $op -ne "in last N days") {
        # in last N days has a numeric default; other value ops with blank → no clause
        if ($op -ne "in list") { return @{ Ldap = ""; Post = $null } }
    }

    # ---- Computed / alias PowerShell properties ----
    if ($PS_PROP_MAP.ContainsKey($la)) {
        $map = $PS_PROP_MAP[$la]
        switch ($map.Kind) {
            "UAC" {
                $wantTrue = ($op -eq "is true")
                $invert = $false
                if ($map.ContainsKey('Invert')) { $invert = [bool]$map.Invert }
                $clause = Get-UacLdapClause -Bit ([int]$map.Bit) -WantSet $wantTrue -InvertMeaning $invert
            }
            "Lockout" {
                # LockedOut ≈ lockoutTime >= 1 (and typically != 0)
                if ($op -eq "is true") { $clause = "(lockoutTime>=1)" }
                else { $clause = "(|(!(lockoutTime=*))(lockoutTime=0))" }
            }
            "Alias" {
                $real = $map.Ldap
                if ($op -eq "regex match") {
                    if ($valT -eq "") { return @{ Ldap = ""; Post = $null } }
                    $clause = "($real=*)"
                    $post = @{ Kind = "Regex"; PsProp = $la; Pattern = $valT; Negate = $negate }
                } else {
                    $clause = Build-StringClause $real $op $valT
                }
            }
            "ClientOnly" {
                # No LDAP clause (avoid (objectClass=*) blowing out OR groups).
                # Filter entirely client-side after the query returns.
                if (($VALUE_REQUIRED_OPS -contains $op) -and [string]::IsNullOrWhiteSpace($valT)) {
                    return @{ Ldap = ""; Post = $null }
                }
                $clause = ""
                $post = @{
                    Kind     = "BoolOrString"
                    PsProp   = $map.PsProp
                    Operator = $op
                    Value    = $valT
                    Negate   = $negate
                }
            }
        }
        if ($negate -and $op -ne "regex match" -and $map.Kind -ne "ClientOnly" -and $clause -ne "") {
            $clause = "(!$clause)"
        }
        return @{ Ldap = $clause; Post = $post }
    }

    if ((Test-IsDateAttr $la) -and ($OPERATORS.Date -contains $op)) {
        # ---- Date operators ----
        $info = Resolve-DateLdap $la
        $real = $info.Ldap; $kind = $info.Kind
        switch ($op) {
            "is set"     { $clause = "($real=*)" }
            "is not set" { $clause = "(!($real=*))" }
            "in last N days" {
                $n = 30; [void][int]::TryParse($valT, [ref]$n)
                if ($n -lt 1) { $n = 30 }
                $cut = (Get-Date).AddDays(-$n)
                $clause = "($real>=$(ConvertTo-LdapDate $cut $kind))"
            }
            default {
                if ([string]::IsNullOrWhiteSpace($valT)) { return @{ Ldap = ""; Post = $null } }
                $dt = [datetime]::Now
                if (-not [datetime]::TryParse($valT, [ref]$dt)) { return @{ Ldap = ""; Post = $null } }
                $start = $dt.Date
                $endOfDay = $start.AddDays(1).AddSeconds(-1)
                $nextDay  = $start.AddDays(1)
                switch ($op) {
                    "on"           { $clause = "(&($real>=$(ConvertTo-LdapDate $start $kind))($real<=$(ConvertTo-LdapDate $endOfDay $kind)))" }
                    # Require the attribute to be present so missing values do not match "before"
                    "before"       { $clause = "(&($real=*)(!($real>=$(ConvertTo-LdapDate $start $kind))))" }
                    "after"        { $clause = "($real>=$(ConvertTo-LdapDate $nextDay $kind))" }
                    "on or before" { $clause = "(&($real=*)($real<=$(ConvertTo-LdapDate $endOfDay $kind)))" }
                    "on or after"  { $clause = "($real>=$(ConvertTo-LdapDate $start $kind))" }
                    default        { $clause = "($real=*)" }
                }
            }
        }
    }
    else {
        # ---- String / boolean operators ----
        switch ($op) {
            "is true"      { $clause = "($la=TRUE)" }
            "is false"     { $clause = "($la=FALSE)" }
            "regex match" {
                if ($valT -eq "") { return @{ Ldap = ""; Post = $null } }
                # LDAP cannot do regex — require the attribute to exist, then
                # filter client-side against the PS property.
                $clause = "($la=*)"
                $post = @{ Kind = "Regex"; PsProp = $la; Pattern = $valT; Negate = $negate }
            }
            default { $clause = Build-StringClause $la $op $valT }
        }
    }

    # regex / ClientOnly negation is handled in the post-filter, not the LDAP clause
    if ($negate -and $op -ne "regex match" -and $clause -ne "") { $clause = "(!$clause)" }
    return @{ Ldap = $clause; Post = $post }
}

function Build-LDAPFilter {
    $script:PostFilters.Clear()
    $groupClauses = [System.Collections.Generic.List[string]]::new()

    foreach ($group in $script:FilterGroups) {
        $rowClauses = [System.Collections.Generic.List[string]]::new()
        foreach ($row in $group.Rows) {
            $res = Build-ConditionClause $row
            if ($res.Ldap -ne "") { $rowClauses.Add($res.Ldap) }
            if ($res.Post)        { [void]$script:PostFilters.Add($res.Post) }
        }
        if ($rowClauses.Count -eq 0) { continue }
        $gjoin = if ($group.Join -eq "AND") { "&" } else { "|" }
        if ($rowClauses.Count -eq 1) { $groupClauses.Add($rowClauses[0]) }
        else { $groupClauses.Add("($gjoin$($rowClauses -join ''))") }
    }

    if ($groupClauses.Count -eq 0) { return "(objectClass=*)" }
    $tjoin = if ($rdoAND.Checked) { "&" } else { "|" }
    if ($groupClauses.Count -eq 1) { return $groupClauses[0] }
    return "($tjoin$($groupClauses -join ''))"
}

function Test-PostFilterMatch {
    param($Object, [hashtable]$Filter)
    $prop = $Filter.PsProp
    $cell = ""
    $raw = Get-ObjectPropValue -Object $Object -Name $prop
    if ($null -ne $raw) { $cell = [string]$raw }

    $kind = if ($Filter.ContainsKey('Kind') -and $Filter.Kind) { $Filter.Kind } else { "Regex" }
    $match = $false

    switch ($kind) {
        "Regex" {
            try { $match = [System.Text.RegularExpressions.Regex]::IsMatch($cell, $Filter.Pattern) }
            catch { $match = $false }
        }
        "BoolOrString" {
            $op = $Filter.Operator
            if ($op -eq "is true") {
                $match = ($raw -eq $true -or $cell -eq "True")
            } elseif ($op -eq "is false") {
                $match = ($raw -eq $false -or $cell -eq "False")
            } else {
                # Fallback string ops for client-only props
                $val = [string]$Filter.Value
                switch ($op) {
                    "equals"       { $match = ($cell -eq $val) }
                    "not equals"   { $match = ($cell -ne $val) }
                    "contains"     { $match = ($cell.IndexOf($val, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) }
                    "not contains" { $match = ($cell.IndexOf($val, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) }
                    "starts with"  { $match = $cell.StartsWith($val, [System.StringComparison]::OrdinalIgnoreCase) }
                    "ends with"    { $match = $cell.EndsWith($val, [System.StringComparison]::OrdinalIgnoreCase) }
                    "is set"       { $match = (Test-ObjectHasProp -Object $Object -Name $prop) -and ($null -ne $raw) -and ($cell -ne "") }
                    "is not set"   { $match = (-not (Test-ObjectHasProp -Object $Object -Name $prop)) -or ($null -eq $raw) }
                    "is empty"     { $match = (-not (Test-ObjectHasProp -Object $Object -Name $prop)) -or ($null -eq $raw) -or ($cell -eq "") }
                    default        { $match = ($cell.IndexOf($val, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) }
                }
            }
        }
        default {
            try { $match = [System.Text.RegularExpressions.Regex]::IsMatch($cell, $Filter.Pattern) }
            catch { $match = $false }
        }
    }

    if ($Filter.Negate) { return (-not $match) }
    return $match
}

# ===========================================================================
# LIVE FILTER PREVIEW
# ===========================================================================
function Get-ConditionEnglish ([hashtable]$row) {
    $attr = $row.AttrLabel
    $op   = $row.Operator
    $val  = if ($null -ne $row.Value) { [string]$row.Value } else { "" }
    $neg  = if ($row.Negate) { "NOT " } else { "" }
    if ($NOVAL_OPS -contains $op) { return "$neg$attr $op" }
    if ($op -eq "in last N days") { $n = if ($val) { $val } else { "N" }; return "$neg$attr in last $n days" }
    return "$neg$attr $op '$val'"
}
function Update-FilterPreview {
    Sync-FilterModel
    $count = Get-ConditionCount
    $gcount = $script:FilterGroups.Count
    $lblFilterCount.Text = "$count condition(s) in $gcount group(s)"

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("Object type: $script:CurrentObjType")

    if ($gbStatus.Visible) {
        if (-not $chkEnabled.Checked -and -not $chkDisabled.Checked) {
            [void]$sb.AppendLine("Status: none selected (query will return 0 rows)")
        } else {
            $st = @()
            if ($chkEnabled.Checked)  { $st += "enabled" }
            if ($chkDisabled.Checked) { $st += "disabled" }
            if ($st.Count -gt 0) { [void]$sb.AppendLine("Status: $($st -join ' or ')") }
        }
    }
    if ($rdoOU.Checked -and $cmbOU.Text.Trim() -ne "") {
        [void]$sb.AppendLine("Scope: under $($cmbOU.Text.Trim())")
    } else {
        [void]$sb.AppendLine("Scope: entire domain")
    }

    if ($count -eq 0) {
        [void]$sb.AppendLine("Filters: none (returns all $script:CurrentObjType)")
    } else {
        $topJoin = if ($rdoAND.Checked) { "AND" } else { "OR" }
        for ($gi = 0; $gi -lt $script:FilterGroups.Count; $gi++) {
            $g = $script:FilterGroups[$gi]
            if ($g.Rows.Count -eq 0) { continue }
            $prefix = if ($gi -gt 0) { "$topJoin " } else { "" }
            $parts = @($g.Rows | ForEach-Object { Get-ConditionEnglish $_ })
            $inner = $parts -join "  $($g.Join)  "
            [void]$sb.AppendLine("$prefix($inner)")
        }
    }
    if ($gbGroup.Visible -and -not $rdoNoGroup.Checked) {
        $sel = @()
        for ($i = 0; $i -lt $lstGroups.Items.Count; $i++) {
            if ($lstGroups.GetItemChecked($i)) { $sel += $lstGroups.Items[$i].ToString() }
        }
        if ($sel.Count -gt 0) {
            $mode = if ($rdoMemberOf.Checked) { "member of ANY of" } else { "NOT member of ANY of" }
            [void]$sb.AppendLine("Groups: $mode $($sel -join ', ')")
        }
    }
    if ($gbEntra.Visible -and $chkEntraEnrich.Checked) {
        $bits = @()
        if ($chkEntraRoles.Checked) { $bits += "roles" }
        if ($chkEntraDevices.Checked) { $bits += "devices" }
        if ($chkEntraAuth.Checked) { $bits += "auth methods" }
        if ($chkEntraFailSignIn.Checked) { $bits += "last failed sign-in" }
        if ($bits.Count -gt 0) {
            [void]$sb.AppendLine("Entra enrich: $($bits -join ', ')")
        }
    }
    $txtEnglish.Text = $sb.ToString().TrimEnd()

    # Raw LDAP (attribute portion only; status is appended at query time)
    try { $txtLdap.Text = Build-LDAPFilter } catch { $txtLdap.Text = "(error building filter)" }
    if ($script:PostFilters.Count -gt 0) {
        $txtLdap.Text += "`r`n+ $($script:PostFilters.Count) client-side post-filter(s)"
    }
}

# ===========================================================================
# OBJECT TYPE SWITCH
# ===========================================================================
function Update-GroupMembershipPanel {
    # OUs are not group members; hide the panel. Groups/Users/Computers can use it.
    $supported = $script:CurrentObjType -in @("Users","Computers","Groups")
    $gbGroup.Visible = $supported
    if (-not $supported) {
        $rdoNoGroup.Checked = $true
        for ($i = 0; $i -lt $lstGroups.Items.Count; $i++) { $lstGroups.SetItemChecked($i, $false) }
    }
}

function Switch-ObjectType ([string]$ObjType) {
    $script:CurrentObjType = $ObjType
    foreach ($kv in $script:ObjTypeButtons.GetEnumerator()) {
        if ($kv.Key -eq $ObjType) { Set-PrimaryButtonStyle $kv.Value }
        else { Set-SecondaryButtonStyle $kv.Value }
    }
    $gbStatus.Visible = ($ObjType -in @("Users","Computers"))
    $gbEntra.Visible  = ($ObjType -eq "Users")
    Update-GroupMembershipPanel
    # Attributes differ per type — start the grouped builder fresh with one group
    $script:FilterGroups.Clear()
    $script:FilterGroups.Add((New-FilterGroup))
    Rebuild-FilterContainer
    $script:VisibleColumns.Clear()
    $DEFAULT_COLS[$ObjType] | ForEach-Object { $script:VisibleColumns.Add($_) }
    $script:LoadedProperties.Clear()
    $script:Results = @()
}
foreach ($kv in $script:ObjTypeButtons.GetEnumerator()) {
    $kv.Value.Add_Click({ Switch-ObjectType $this.Tag })
}

# ===========================================================================
# GROUP SEARCH
# ===========================================================================
function Search-ADGroups ([string]$Term) {
    $lstGroups.Items.Clear()
    try {
        # Escape single quotes for the AD PowerShell filter language
        $safe = Escape-ADFilterValue $Term
        $groups = Get-ADGroup -Filter "Name -like '$safe'" -ResultSetSize 200 -ErrorAction Stop | Sort-Object Name
        if ($groups) { foreach ($g in $groups) { [void]$lstGroups.Items.Add($g.Name) } }
        else { [void]$lstGroups.Items.Add("(no groups found)") }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Group search failed:`n$_","Search Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
    }
}
$txtGroupSearch.Add_GotFocus({
    if ($txtGroupSearch.Text -eq "Search groups...") { $txtGroupSearch.Text = ""; $txtGroupSearch.ForeColor = $Theme.Text }
})
$txtGroupSearch.Add_LostFocus({
    if ($txtGroupSearch.Text -eq "") { $txtGroupSearch.Text = "Search groups..."; $txtGroupSearch.ForeColor = $Theme.TextMuted }
})
$txtGroupSearch.Add_KeyDown({
    if ($_.KeyCode -eq "Return") {
        $t = if ($txtGroupSearch.Text -notin @("","Search groups...")) { "*$($txtGroupSearch.Text)*" } else { "*" }
        Search-ADGroups $t
    }
})
$btnGroupSearch.Add_Click({
    $t = if ($txtGroupSearch.Text -notin @("","Search groups...")) { "*$($txtGroupSearch.Text)*" } else { "*" }
    Search-ADGroups $t
})
$lnkClear.Add_LinkClicked({ for ($i=0;$i -lt $lstGroups.Items.Count;$i++) { $lstGroups.SetItemChecked($i,$false) } })

# ===========================================================================
# RESULTS SEARCH BOX  (rebinds filtered view from $script:Results)
# ===========================================================================
function Apply-ResultsSearch {
    $term = if ($txtSearch.Text -notin @("","Search results...")) { $txtSearch.Text.Trim() } else { "" }
    if ($term -eq "") {
        Populate-Grid $script:Results
        return
    }
    $termLower = $term.ToLowerInvariant()
    $filtered = @(
        $script:Results | Where-Object {
            $obj = $_
            foreach ($colName in $script:VisibleColumns) {
                $v = Get-ObjectPropValue -Object $obj -Name $colName
                if ($null -eq $v) { continue }
                $text = if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
                    (@($v) | ForEach-Object { Convert-AdValue -Name $colName -Value $_ }) -join "; "
                } else {
                    Convert-AdValue -Name $colName -Value $v
                }
                if ($text.ToLowerInvariant().Contains($termLower)) { return $true }
            }
            return $false
        }
    )
    Populate-Grid $filtered
}

$txtSearch.Add_GotFocus({
    if ($txtSearch.Text -eq "Search results...") { $txtSearch.Text = ""; $txtSearch.ForeColor = $Theme.Text }
})
$txtSearch.Add_LostFocus({
    if ($txtSearch.Text -eq "") { $txtSearch.Text = "Search results..."; $txtSearch.ForeColor = $Theme.TextMuted }
})
$txtSearch.Add_TextChanged({
    if ($script:IsRunning) { return }
    Apply-ResultsSearch
})

# ===========================================================================
# POPULATE GRID
# ===========================================================================
function Populate-Grid {
    param([array]$Data)
    $Grid.SuspendLayout()
    $Grid.Columns.Clear()
    $Grid.Rows.Clear()
    if (-not $Data -or $Data.Count -eq 0) { $Grid.ResumeLayout(); return }

    $wideAttrs   = @("DistinguishedName","CanonicalName","HomeDirectory","ScriptPath","ProfilePath","Description","DisplayName","Mail","EmailAddress","EntraAssignedRoles","EntraDevices","EntraAuthMethods","EntraLastSignInErrorLocation","EntraLastSignInErrorApp")
    $narrowAttrs = @("Enabled","PasswordNeverExpires","PasswordNotRequired","LockedOut","SmartcardLogonRequired","TrustedForDelegation","SID","ObjectGUID","objectClass","objectCategory","AdminCount","EntraLastSignInErrorCode","EntraLastSignInErrorIP")

    foreach ($col in $script:VisibleColumns) {
        $gc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $gc.Name = $col; $gc.HeaderText = $col; $gc.SortMode = "Automatic"; $gc.MinimumWidth = 50
        if ($wideAttrs -contains $col -or $col -match "DN$|Path$|Directory$|Address$") { $gc.Width = 280 }
        elseif ($narrowAttrs -contains $col -or $col -match "^(Enabled|Locked|Password|Smart|Trusted|Admin)") { $gc.Width = 80 }
        else { $gc.Width = 160 }
        [void]$Grid.Columns.Add($gc)
    }

    foreach ($obj in $Data) {
        if ($null -eq $obj) { continue }
        $cells = foreach ($colName in $script:VisibleColumns) {
            $v = Get-ObjectPropValue -Object $obj -Name $colName
            if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
                (@($v) | ForEach-Object { Convert-AdValue -Name $colName -Value $_ }) -join "; "
            } else { Convert-AdValue -Name $colName -Value $v }
        }
        [void]$Grid.Rows.Add($cells)
    }

    $Grid.AutoSizeColumnsMode = "AllCells"
    $Grid.AutoSizeColumnsMode = "None"
    foreach ($gc in $Grid.Columns) {
        if ($gc.Width -lt 120) { $gc.Width = 120 }
        if ($gc.Width -gt 500) { $gc.Width = 500 }
    }
    $Grid.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
    $Grid.ResumeLayout()
}

# ===========================================================================
# ENTRA ID / MICROSOFT GRAPH
# ===========================================================================
# Uses the public Microsoft Graph PowerShell client id for device-code auth
# (same app used by Connect-MgGraph). No app registration required for
# interactive delegated access; admin consent may still be needed for scopes.
$script:GraphClientId = "14d82eec-204b-4c2f-b113-9d477e6ee18c"
$script:GraphScopes = @(
    "User.Read.All",
    "Directory.Read.All",
    "AuditLog.Read.All",
    "UserAuthenticationMethod.Read.All",
    "Device.Read.All",
    "RoleManagement.Read.Directory",
    "offline_access"
) -join " "

function Test-EntraConnected {
    if (-not $script:EntraAccessToken) { return $false }
    if ([datetime]::UtcNow -ge $script:EntraTokenExpires.AddMinutes(-2)) { return $false }
    return $true
}

function Update-EntraStatusLabel {
    if (Test-EntraConnected) {
        $who = if ($script:EntraAccountUpn) { $script:EntraAccountUpn } else { "connected" }
        $lblEntraStatus.Text = $who
        $lblEntraStatus.ForeColor = $Theme.Accent
    } else {
        $lblEntraStatus.Text = "Not connected"
        $lblEntraStatus.ForeColor = $Theme.TextMuted
        $script:EntraAccessToken = $null
        $script:EntraAccountUpn = ""
    }
}

function Get-EntraTenantId {
    $t = if ($null -ne $txtEntraTenant.Text) { $txtEntraTenant.Text.Trim() } else { "" }
    if (-not $t -or $t -eq $script:EntraTenantPlaceholder) { return $null }
    # Accept GUID or domain (contoso.onmicrosoft.com / contoso.com)
    if ($t -match '^[0-9a-fA-F-]{36}$') { return $t.ToLowerInvariant() }
    if ($t -match '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$') { return $t.ToLowerInvariant() }
    return $null
}

function Connect-EntraGraph {
    # Device-code flow against a specific tenant (AADSTS50059 if tenant is missing)
    try {
        $tenant = Get-EntraTenantId
        if (-not $tenant) {
            throw "Enter your Entra tenant domain (e.g. contoso.onmicrosoft.com) or Directory (tenant) ID GUID in the Tenant box, then Connect again."
        }

        $authority = "https://login.microsoftonline.com/$tenant"
        $dcBody = @{
            client_id = $script:GraphClientId
            scope     = $script:GraphScopes
        }
        $dc = Invoke-RestMethod -Method Post -Uri "$authority/oauth2/v2.0/devicecode" `
            -ContentType "application/x-www-form-urlencoded" -Body $dcBody -ErrorAction Stop

        try { [System.Windows.Forms.Clipboard]::SetText([string]$dc.user_code) } catch { }

        $msg = "Sign in to Microsoft Graph for Entra enrichment.`r`n`r`n" +
               "Tenant: $tenant`r`n" +
               "1. Open: $($dc.verification_uri)`r`n" +
               "2. Enter code: $($dc.user_code)  (copied to clipboard)`r`n`r`n" +
               "Click OK to start waiting (up to $([int]($dc.expires_in / 60)) min) while you finish in the browser."
        [System.Windows.Forms.MessageBox]::Show($msg, "Connect to Entra ID",
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null

        $deadline = [datetime]::UtcNow.AddSeconds([int]$dc.expires_in)
        $interval = [Math]::Max(5, [int]$dc.interval)
        $token = $null
        Start-Progress "Waiting for Graph device sign-in..."
        while ([datetime]::UtcNow -lt $deadline) {
            Start-Sleep -Seconds $interval
            Update-Progress "Waiting for Graph device sign-in..."
            try {
                $tokBody = @{
                    grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
                    client_id   = $script:GraphClientId
                    device_code = $dc.device_code
                }
                $token = Invoke-RestMethod -Method Post -Uri "$authority/oauth2/v2.0/token" `
                    -ContentType "application/x-www-form-urlencoded" -Body $tokBody -ErrorAction Stop
                break
            } catch {
                $errText = "$_"
                try {
                    $resp = $_.Exception.Response
                    if ($resp) {
                        $stream = $resp.GetResponseStream()
                        if ($stream) {
                            $reader = New-Object System.IO.StreamReader($stream)
                            $errText += " " + $reader.ReadToEnd()
                            $reader.Close()
                        }
                    }
                } catch { }
                if ($errText -match 'authorization_pending' -or $errText -match 'slow_down') { continue }
                throw
            }
        }
        Stop-Progress
        if (-not $token -or -not $token.access_token) {
            throw "Device sign-in timed out or was cancelled."
        }

        $script:EntraAccessToken = $token.access_token
        $script:EntraTokenExpires = [datetime]::UtcNow.AddSeconds([int]$token.expires_in)
        $script:EntraAccountUpn = ""
        $script:EntraTenant = $tenant
        try {
            $me = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/me?`$select=userPrincipalName,displayName"
            if ($me.userPrincipalName) { $script:EntraAccountUpn = [string]$me.userPrincipalName }
            elseif ($me.displayName) { $script:EntraAccountUpn = [string]$me.displayName }
        } catch { }

        Update-EntraStatusLabel
        [System.Windows.Forms.MessageBox]::Show("Connected to Microsoft Graph ($tenant).", "Entra ID",
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
    } catch {
        Stop-Progress
        $script:EntraAccessToken = $null
        Update-EntraStatusLabel
        [System.Windows.Forms.MessageBox]::Show("Graph connect failed:`r`n$_", "Entra ID",
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
    }
}

function Disconnect-EntraGraph {
    $script:EntraAccessToken = $null
    $script:EntraTokenExpires = [datetime]::MinValue
    $script:EntraAccountUpn = ""
    Update-EntraStatusLabel
}

function Invoke-GraphGet {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [int]$MaxPages = 5
    )
    if (-not (Test-EntraConnected)) { throw "Not connected to Microsoft Graph. Click Connect Graph first." }
    $headers = @{
        Authorization = "Bearer $($script:EntraAccessToken)"
        ConsistencyLevel = "eventual"
    }
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    $page = 0
    $last = $null
    while ($next -and $page -lt $MaxPages) {
        $page++
        $resp = Invoke-RestMethod -Method Get -Uri $next -Headers $headers -ErrorAction Stop
        $last = $resp
        if ($resp.PSObject.Properties['value']) {
            foreach ($v in @($resp.value)) { $items.Add($v) }
            if ($resp.PSObject.Properties['@odata.nextLink'] -and $resp.'@odata.nextLink') {
                $next = [string]$resp.'@odata.nextLink'
            } else { $next = $null }
        } else {
            return $resp
        }
    }
    return @{ value = @($items); _raw = $last }
}

function Escape-ODataString ([string]$Value) {
    if ($null -eq $Value) { return "" }
    return ($Value -replace "'", "''")
}

function Get-AuthMethodLabel ($method) {
    if (-not $method) { return "unknown" }
    $type = [string]$method.'@odata.type'
    switch -Regex ($type) {
        'passwordAuthenticationMethod'          { return "Password" }
        'microsoftAuthenticatorAuthenticationMethod' { return "Microsoft Authenticator" }
        'phoneAuthenticationMethod' {
            $num = if ($method.phoneNumber) { $method.phoneNumber } else { "" }
            return ("Phone " + $num).Trim()
        }
        'fido2AuthenticationMethod'             { return "FIDO2" }
        'windowsHelloForBusinessAuthenticationMethod' { return "Windows Hello" }
        'emailAuthenticationMethod' {
            $em = if ($method.emailAddress) { $method.emailAddress } else { "" }
            return ("Email " + $em).Trim()
        }
        'softwareOathAuthenticationMethod'      { return "Software OATH" }
        'temporaryAccessPassAuthenticationMethod' { return "Temporary Access Pass" }
        'platformCredentialAuthenticationMethod' { return "Platform credential" }
        default {
            $short = $type -replace '#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', ''
            if ($short) { return $short }
            return "Other"
        }
    }
}

function ConvertTo-EnrichableRow {
    param($Object)
    $ordered = [ordered]@{}
    # Prefer currently visible + loaded props so we keep AD values
    $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $script:LoadedProperties) { [void]$names.Add($p) }
    foreach ($p in $script:VisibleColumns) { [void]$names.Add($p) }
    foreach ($p in @("DistinguishedName","SamAccountName","UserPrincipalName","EmailAddress","Enabled","DisplayName")) {
        [void]$names.Add($p)
    }
    foreach ($p in $names) {
        $ordered[$p] = Get-ObjectPropValue -Object $Object -Name $p
    }
    # Preserve any already-enriched Entra fields
    foreach ($p in $script:EntraPropNames) {
        if (Test-ObjectHasProp -Object $Object -Name $p) {
            $ordered[$p] = Get-ObjectPropValue -Object $Object -Name $p
        }
    }
    return [pscustomobject]$ordered
}

function Resolve-EntraUserId {
    param([string]$Upn, [string]$Mail, [string]$Sam)
    $candidates = @($Upn, $Mail) | Where-Object { $_ -and $_.Trim() -ne "" } | Select-Object -Unique
    foreach ($c in $candidates) {
        $safe = Escape-ODataString $c.Trim()
        try {
            $uri = "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$safe' or mail eq '$safe'&`$select=id,userPrincipalName,mail&`$top=1"
            $resp = Invoke-GraphGet -Uri $uri -MaxPages 1
            $val = @($resp.value)
            if ($val.Count -gt 0 -and $val[0].id) { return [string]$val[0].id }
        } catch { }
        # Direct lookup by UPN path
        try {
            $enc = [uri]::EscapeDataString($c.Trim())
            $u = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/users/$enc`?`$select=id" -MaxPages 1
            if ($u -and $u.id) { return [string]$u.id }
        } catch { }
    }
    return $null
}

function Get-EntraAssignedRoles ([string]$UserId) {
    $roles = [System.Collections.Generic.List[string]]::new()
    try {
        $uri = "https://graph.microsoft.com/v1.0/users/$UserId/memberOf/microsoft.graph.directoryRole?`$select=displayName"
        $resp = Invoke-GraphGet -Uri $uri
        foreach ($r in @($resp.value)) {
            if ($r.displayName) { $roles.Add([string]$r.displayName) }
        }
    } catch { }
    # App / unified role assignments (directory)
    try {
        $uri2 = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$UserId'&`$expand=roleDefinition(`$select=displayName)&`$top=50"
        $resp2 = Invoke-GraphGet -Uri $uri2
        foreach ($a in @($resp2.value)) {
            $dn = $null
            if ($a.roleDefinition -and $a.roleDefinition.displayName) { $dn = [string]$a.roleDefinition.displayName }
            if ($dn -and -not $roles.Contains($dn)) { $roles.Add($dn) }
        }
    } catch { }
    if ($roles.Count -eq 0) { return "" }
    return (($roles | Select-Object -Unique | Sort-Object) -join "; ")
}

function Get-EntraDevices ([string]$UserId) {
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($nav in @("registeredDevices","ownedDevices")) {
        try {
            $uri = "https://graph.microsoft.com/v1.0/users/$UserId/$nav`?`$select=displayName,operatingSystem,deviceId&`$top=50"
            $resp = Invoke-GraphGet -Uri $uri
            foreach ($d in @($resp.value)) {
                $label = if ($d.displayName) { [string]$d.displayName } else { [string]$d.deviceId }
                if ($d.operatingSystem) { $label = "$label ($($d.operatingSystem))" }
                if ($label -and -not $names.Contains($label)) { $names.Add($label) }
            }
        } catch { }
    }
    if ($names.Count -eq 0) { return "" }
    return ($names -join "; ")
}

function Get-EntraAuthMethods ([string]$UserId) {
    try {
        # authentication/methods is complete on v1.0 for most method types
        $uri = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/methods"
        $resp = Invoke-GraphGet -Uri $uri
        $labels = @($resp.value | ForEach-Object { Get-AuthMethodLabel $_ }) | Where-Object { $_ } | Select-Object -Unique
        return ($labels -join "; ")
    } catch {
        return ""
    }
}

function Get-EntraLastFailedSignIn ([string]$Upn) {
    $empty = @{
        Code = ""; Time = ""; App = ""; Location = ""; IP = ""
    }
    if (-not $Upn) { return $empty }
    $safe = Escape-ODataString $Upn.Trim()
    try {
        $filter = [uri]::EscapeDataString("userPrincipalName eq '$safe' and status/errorCode ne 0")
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter&`$orderby=createdDateTime desc&`$top=1"
        $resp = Invoke-GraphGet -Uri $uri -MaxPages 1
        $row = @($resp.value) | Select-Object -First 1
        if (-not $row) { return $empty }

        $locParts = @()
        if ($row.location) {
            if ($row.location.city) { $locParts += [string]$row.location.city }
            if ($row.location.state) { $locParts += [string]$row.location.state }
            if ($row.location.countryOrRegion) { $locParts += [string]$row.location.countryOrRegion }
        }
        $code = ""
        if ($row.status -and $null -ne $row.status.errorCode) { $code = [string]$row.status.errorCode }
        $time = ""
        if ($row.createdDateTime) {
            try { $time = ([datetime]$row.createdDateTime).ToLocalTime().ToString($DATE_FORMAT) }
            catch { $time = [string]$row.createdDateTime }
        }
        return @{
            Code     = $code
            Time     = $time
            App      = if ($row.appDisplayName) { [string]$row.appDisplayName } else { "" }
            Location = ($locParts -join ", ")
            IP       = if ($row.ipAddress) { [string]$row.ipAddress } else { "" }
        }
    } catch {
        return $empty
    }
}

function Get-SelectedEntraColumns {
    $cols = [System.Collections.Generic.List[string]]::new()
    if ($chkEntraRoles.Checked) { $cols.Add("EntraAssignedRoles") }
    if ($chkEntraDevices.Checked) { $cols.Add("EntraDevices") }
    if ($chkEntraAuth.Checked) { $cols.Add("EntraAuthMethods") }
    if ($chkEntraFailSignIn.Checked) {
        $cols.Add("EntraLastSignInErrorCode")
        $cols.Add("EntraLastSignInErrorTime")
        $cols.Add("EntraLastSignInErrorApp")
        $cols.Add("EntraLastSignInErrorLocation")
        $cols.Add("EntraLastSignInErrorIP")
    }
    return @($cols)
}

function Ensure-EntraColumnsVisible {
    $added = $false
    foreach ($c in (Get-SelectedEntraColumns)) {
        if (-not ($script:VisibleColumns -contains $c)) {
            $script:VisibleColumns.Add($c)
            $added = $true
        }
        [void]$script:LoadedProperties.Add($c)
    }
    return $added
}

function Invoke-EntraEnrichment {
    param([switch]$Force)

    if ($script:CurrentObjType -ne "Users") {
        if ($Force) {
            [System.Windows.Forms.MessageBox]::Show("Entra enrichment is only available for Users.", "Entra ID",
                [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        }
        return
    }
    if (-not $chkEntraRoles.Checked -and -not $chkEntraDevices.Checked -and -not $chkEntraAuth.Checked -and -not $chkEntraFailSignIn.Checked) {
        if ($Force) {
            [System.Windows.Forms.MessageBox]::Show("Select at least one Entra data type to enrich.", "Entra ID",
                [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        }
        return
    }
    if (-not (Test-EntraConnected)) {
        Connect-EntraGraph
        if (-not (Test-EntraConnected)) { return }
    }
    if ($script:Results.Count -eq 0) {
        if ($Force) {
            [System.Windows.Forms.MessageBox]::Show("Run a query first.", "Entra ID",
                [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        }
        return
    }

    [void](Ensure-EntraColumnsVisible)
    $wantRoles = $chkEntraRoles.Checked
    $wantDev = $chkEntraDevices.Checked
    $wantAuth = $chkEntraAuth.Checked
    $wantFail = $chkEntraFailSignIn.Checked

    $newRows = [System.Collections.Generic.List[object]]::new()
    $i = 0
    $total = $script:Results.Count
    Start-Progress "Enriching with Entra ID (0 / $total)..."
    foreach ($obj in $script:Results) {
        $i++
        if ($i % 5 -eq 0 -or $i -eq $total) {
            Update-Progress "Enriching with Entra ID ($i / $total)..."
        }
        $row = ConvertTo-EnrichableRow -Object $obj
        $upn = [string](Get-ObjectPropValue -Object $row -Name "UserPrincipalName")
        $mail = [string](Get-ObjectPropValue -Object $row -Name "EmailAddress")
        if (-not $mail) { $mail = [string](Get-ObjectPropValue -Object $row -Name "mail") }
        $sam = [string](Get-ObjectPropValue -Object $row -Name "SamAccountName")

        # Defaults
        if ($wantRoles) { $row | Add-Member -NotePropertyName EntraAssignedRoles -NotePropertyValue "" -Force }
        if ($wantDev)   { $row | Add-Member -NotePropertyName EntraDevices -NotePropertyValue "" -Force }
        if ($wantAuth)  { $row | Add-Member -NotePropertyName EntraAuthMethods -NotePropertyValue "" -Force }
        if ($wantFail) {
            $row | Add-Member -NotePropertyName EntraLastSignInErrorCode -NotePropertyValue "" -Force
            $row | Add-Member -NotePropertyName EntraLastSignInErrorTime -NotePropertyValue "" -Force
            $row | Add-Member -NotePropertyName EntraLastSignInErrorApp -NotePropertyValue "" -Force
            $row | Add-Member -NotePropertyName EntraLastSignInErrorLocation -NotePropertyValue "" -Force
            $row | Add-Member -NotePropertyName EntraLastSignInErrorIP -NotePropertyValue "" -Force
        }

        try {
            $uid = Resolve-EntraUserId -Upn $upn -Mail $mail -Sam $sam
            if ($uid) {
                if ($wantRoles) { $row.EntraAssignedRoles = Get-EntraAssignedRoles -UserId $uid }
                if ($wantDev)   { $row.EntraDevices = Get-EntraDevices -UserId $uid }
                if ($wantAuth)  { $row.EntraAuthMethods = Get-EntraAuthMethods -UserId $uid }
                if ($wantFail) {
                    $lookupUpn = if ($upn) { $upn } else { $mail }
                    $fail = Get-EntraLastFailedSignIn -Upn $lookupUpn
                    $row.EntraLastSignInErrorCode = $fail.Code
                    $row.EntraLastSignInErrorTime = $fail.Time
                    $row.EntraLastSignInErrorApp = $fail.App
                    $row.EntraLastSignInErrorLocation = $fail.Location
                    $row.EntraLastSignInErrorIP = $fail.IP
                }
            }
        } catch {
            # leave blanks on per-user failure; continue
        }
        $newRows.Add($row)
    }
    Stop-Progress
    $script:Results = @($newRows)
    foreach ($c in (Get-SelectedEntraColumns)) { [void]$script:LoadedProperties.Add($c) }
    Apply-ResultsSearch
    Set-Status "Entra enrichment done - $($script:Results.Count) user(s)" $script:Results.Count `
        @($script:Results | Where-Object { (Get-ObjectPropValue -Object $_ -Name 'Enabled') -eq $true }).Count `
        @($script:Results | Where-Object { (Get-ObjectPropValue -Object $_ -Name 'Enabled') -eq $false }).Count
}

foreach ($c in @($chkEntraEnrich,$chkEntraRoles,$chkEntraDevices,$chkEntraAuth,$chkEntraFailSignIn)) {
    $c.Add_CheckedChanged({ Update-FilterPreview })
}
$btnEntraConnect.Add_Click({ Connect-EntraGraph })
$btnEntraDisconnect.Add_Click({ Disconnect-EntraGraph })
$btnEntraEnrichNow.Add_Click({
    if ($script:IsRunning) { return }
    $script:IsRunning = $true
    $btnRun.Enabled = $false
    $btnEntraEnrichNow.Enabled = $false
    try { Invoke-EntraEnrichment -Force } finally {
        $script:IsRunning = $false
        $btnRun.Enabled = $true
        $btnEntraEnrichNow.Enabled = $true
    }
})

# ===========================================================================
# QUERY ENGINE
# ===========================================================================
function Invoke-Query {
    if ($script:IsRunning) { return }
    Sync-FilterModel
    $script:IsRunning = $true
    $btnRun.Enabled = $false
    Set-Status "Running..."
    $Grid.Rows.Clear(); $Grid.Columns.Clear()

    try {
        # Account status: neither box checked → empty result set (explicit choice)
        if ($gbStatus.Visible -and -not $chkEnabled.Checked -and -not $chkDisabled.Checked) {
            $script:Results = @()
            $script:LoadedProperties.Clear()
            Populate-Grid $script:Results
            Stop-Progress
            Set-Status "Done - 0 result(s) (no account status selected)" 0 0 0
            return
        }

        $ldap    = Build-LDAPFilter
        if ([string]::IsNullOrWhiteSpace($ldap)) { $ldap = "(objectClass=*)" }
        $objType = $script:CurrentObjType
        $useOU   = $rdoOU.Checked
        $ouDN    = $cmbOU.Text.Trim()

        $neededProps = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $colSource = if ($script:VisibleColumns.Count -gt 0) { $script:VisibleColumns } else { $DEFAULT_COLS[$objType] }
        foreach ($col in $colSource) { [void]$neededProps.Add($col) }

        foreach ($group in $script:FilterGroups) {
            foreach ($row in $group.Rows) {
                $la = Get-LDAPAttr $row.AttrLabel
                if ($la) { [void]$neededProps.Add($la) }
                # Alias props still need the LDAP name for retrieval
                if ($la -and $PS_PROP_MAP.ContainsKey($la) -and $PS_PROP_MAP[$la].Kind -eq "Alias") {
                    [void]$neededProps.Add($PS_PROP_MAP[$la].Ldap)
                }
            }
        }
        # Ensure post-filter properties are fetched
        foreach ($pf in $script:PostFilters) { if ($pf.PsProp) { [void]$neededProps.Add($pf.PsProp) } }

        [void]$neededProps.Add("DistinguishedName")
        [void]$neededProps.Add("SamAccountName")
        if ($objType -in @("Users","Computers","Groups")) {
            [void]$neededProps.Add("SID")
        }
        if ($objType -in @("Users","Computers")) {
            [void]$neededProps.Add("Enabled")
        }
        if ($objType -eq "Users") {
            [void]$neededProps.Add("UserPrincipalName")
            [void]$neededProps.Add("EmailAddress")
            [void]$neededProps.Add("mail")
        }

        $props = @($neededProps | Where-Object { $_ -and ($script:EntraPropNames -notcontains $_) })

        $finalLdap = $ldap
        if ($gbStatus.Visible) {
            if ($chkEnabled.Checked -and -not $chkDisabled.Checked) {
                $finalLdap = "(&{0}(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" -f $ldap
            } elseif ($chkDisabled.Checked -and -not $chkEnabled.Checked) {
                $finalLdap = "(&{0}(userAccountControl:1.2.840.113556.1.4.803:=2))" -f $ldap
            }
        }

        if (-not (Test-LdapFilterSyntax $finalLdap)) {
            throw "Generated LDAP filter is invalid:`r`n$finalLdap"
        }
        # Keep preview textbox in sync with the exact filter we send
        $txtLdap.Text = $finalLdap
        if ($script:PostFilters.Count -gt 0) {
            $txtLdap.Text += "`r`n+ $($script:PostFilters.Count) client-side post-filter(s)"
        }

        $queryParams = @{ LDAPFilter = $finalLdap; Properties = $props; ResultSetSize = $null; ErrorAction = "Stop" }
        if ($useOU -and $ouDN -ne "") { $queryParams.SearchBase = $ouDN }

        Start-Progress "Querying AD..."
        $streamCount = 0
        $rawResults  = [System.Collections.Generic.List[object]]::new()

        $adStream = switch ($objType) {
            "Users"     { Get-ADUser               @queryParams }
            "Groups"    { Get-ADGroup              @queryParams }
            "Computers" { Get-ADComputer           @queryParams }
            "OUs"       { Get-ADOrganizationalUnit @queryParams }
        }
        foreach ($obj in $adStream) {
            $rawResults.Add($obj); $streamCount++
            if ($streamCount % 50 -eq 0) { Update-Progress "Retrieved $streamCount objects..." }
        }
        Update-Progress "Retrieved $streamCount objects."
        $rawResults = @($rawResults)

        # ---- Client-side post-filters (regex / computed props) ----
        if ($script:PostFilters.Count -gt 0) {
            Update-Progress "Applying client-side filter(s)..."
            $rawResults = @(
                $rawResults | Where-Object {
                    $obj = $_
                    foreach ($pf in $script:PostFilters) {
                        if (-not (Test-PostFilterMatch -Object $obj -Filter $pf)) { return $false }
                    }
                    return $true
                }
            )
        }

        # ---- Group membership filter (OR across selected groups) ----
        $groupFilter = $false
        $mfaMembers  = @{}
        $selectedGroups = @()
        if ($gbGroup.Visible) {
            for ($gi = 0; $gi -lt $lstGroups.Items.Count; $gi++) {
                if ($lstGroups.GetItemChecked($gi)) { $selectedGroups += $lstGroups.Items[$gi].ToString() }
            }
        }
        if ($selectedGroups.Count -gt 0 -and -not $rdoNoGroup.Checked) {
            $groupFilter = $true
            foreach ($gn in $selectedGroups) {
                Update-Progress "Resolving group: $gn..."
                try {
                    $groupMembers = @(Get-ADGroupMember -Identity $gn -Recursive -ErrorAction Stop)
                } catch {
                    $groupMembers = @()
                    $bfsQueue   = [System.Collections.Generic.Queue[string]]::new()
                    $bfsVisited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    $bfsQueue.Enqueue($gn)
                    while ($bfsQueue.Count -gt 0) {
                        $cur = $bfsQueue.Dequeue()
                        if (-not $bfsVisited.Add($cur)) { continue }
                        try {
                            $g = Get-ADGroup -Identity $cur -Properties member -ErrorAction Stop
                            foreach ($mDN in @($g.member)) {
                                if (-not $mDN) { continue }
                                try {
                                    $o = Get-ADObject -Identity $mDN -Properties objectClass,SamAccountName,objectSid -ErrorAction Stop
                                    if ($o.objectClass -eq 'group') { $bfsQueue.Enqueue($mDN) } else { $groupMembers += $o }
                                } catch { continue }
                            }
                        } catch { continue }
                    }
                }
                foreach ($m in @($groupMembers)) {
                    if (-not $m) { continue }
                    $sid = $null
                    if ((Test-ObjectHasProp -Object $m -Name 'SID') -and (Get-ObjectPropValue -Object $m -Name 'SID')) {
                        $sid = (Get-ObjectPropValue -Object $m -Name 'SID').ToString()
                    }
                    elseif ((Test-ObjectHasProp -Object $m -Name 'objectSid') -and (Get-ObjectPropValue -Object $m -Name 'objectSid')) {
                        $sid = (Get-ObjectPropValue -Object $m -Name 'objectSid').ToString()
                    }
                    if ($sid) { $mfaMembers[$sid] = $true }
                }
            }
        }
        if ($groupFilter) {
            $rawResults = @(
                $rawResults | Where-Object {
                    $sid = $null
                    if ((Test-ObjectHasProp -Object $_ -Name 'SID') -and (Get-ObjectPropValue -Object $_ -Name 'SID')) {
                        $sid = (Get-ObjectPropValue -Object $_ -Name 'SID').ToString()
                    }
                    elseif ((Test-ObjectHasProp -Object $_ -Name 'objectSid') -and (Get-ObjectPropValue -Object $_ -Name 'objectSid')) {
                        $sid = (Get-ObjectPropValue -Object $_ -Name 'objectSid').ToString()
                    }
                    if (-not $sid) { return $false }
                    if ($rdoMemberOf.Checked) { $mfaMembers.ContainsKey($sid) } else { -not $mfaMembers.ContainsKey($sid) }
                }
            )
        }

        $script:Results = @($rawResults)
        # Record what AD actually returned so the column chooser can re-hydrate later
        $script:LoadedProperties.Clear()
        foreach ($p in $props) { if ($p) { [void]$script:LoadedProperties.Add($p) } }

        $total    = $script:Results.Count
        $enabled  = @($script:Results | Where-Object { (Get-ObjectPropValue -Object $_ -Name 'Enabled') -eq $true }).Count
        $disabled = @($script:Results | Where-Object { (Get-ObjectPropValue -Object $_ -Name 'Enabled') -eq $false }).Count

        if ($txtSearch.Text -notin @("","Search results...")) {
            Apply-ResultsSearch
        } else {
            Populate-Grid $script:Results
        }
        Stop-Progress
        Set-Status "Done - $total result(s)" $total $enabled $disabled

        # Optional Entra ID enrichment (Users only)
        if ($objType -eq "Users" -and $chkEntraEnrich.Checked -and $total -gt 0) {
            Invoke-EntraEnrichment
        }
    } catch {
        Stop-Progress
        $filterHint = ""
        try {
            if ($txtLdap -and $txtLdap.Text) {
                $filterHint = "`r`n`r`nLDAP filter:`r`n$($txtLdap.Text)"
            }
        } catch { }
        [System.Windows.Forms.MessageBox]::Show("Query failed:`r`n$_$filterHint","Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        Set-Status "Error"
    } finally {
        $script:IsRunning = $false
        $btnRun.Enabled   = $true
    }
}
$btnRun.Add_Click({ Invoke-Query })
$Form.Add_KeyDown({ if ($_.KeyCode -eq "F5") { Invoke-Query } })
$Form.KeyPreview = $true

# ===========================================================================
# CLEAR
# ===========================================================================
function Clear-Form {
    Switch-ObjectType "Users"
    $script:FilterGroups.Clear()
    $script:FilterGroups.Add((New-FilterGroup))
    Rebuild-FilterContainer
    for ($i=0;$i -lt $lstGroups.Items.Count;$i++) { $lstGroups.SetItemChecked($i,$false) }
    $lstGroups.Items.Clear()
    $rdoDomain.Checked   = $true
    $cmbOU.Enabled       = $false
    $cmbOU.ForeColor     = $Theme.TextMuted
    $rdoMemberOf.Checked = $true   # restore default mode radio
    $rdoNoGroup.Checked  = $true   # clear = no group filter active
    $rdoAND.Checked      = $true
    $chkEnabled.Checked  = $true
    $chkDisabled.Checked = $false
    $txtSearch.Text = "Search results..."; $txtSearch.ForeColor = $Theme.TextMuted
    $txtGroupSearch.Text = "Search groups..."; $txtGroupSearch.ForeColor = $Theme.TextMuted
    $Grid.Rows.Clear(); $Grid.Columns.Clear()
    $script:Results = @()
    $script:LoadedProperties.Clear()
    Set-Status "Ready"
    Update-FilterPreview
}
$btnClear.Add_Click({ Clear-Form })

# ===========================================================================
# EXPORT CSV
# ===========================================================================
$btnExport.Add_Click({
    if ($script:Results.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No results to export.","Export",
            [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return
    }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Title = "Export Results to CSV"; $dlg.Filter = "CSV Files (*.csv)|*.csv"
    $dlg.FileName = "AD_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $dlg.InitialDirectory = [System.Environment]::GetFolderPath("Desktop")
    if ($dlg.ShowDialog() -eq "OK") {
        try {
            $export = foreach ($obj in $script:Results) {
                $ordered = [ordered]@{}
                foreach ($colName in $script:VisibleColumns) {
                    $v = Get-ObjectPropValue -Object $obj -Name $colName
                    if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
                        $ordered[$colName] = (@($v) | ForEach-Object { Convert-AdValue -Name $colName -Value $_ }) -join "; "
                    } else { $ordered[$colName] = Convert-AdValue -Name $colName -Value $v }
                }
                [pscustomobject]$ordered
            }
            $export | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
            $ask = [System.Windows.Forms.MessageBox]::Show("Exported $($script:Results.Count) row(s) to:`n$($dlg.FileName)`n`nOpen file?",
                "Export Complete",[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Information)
            if ($ask -eq "Yes") { Start-Process $dlg.FileName }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed:`n$_","Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        }
    }
})

# ===========================================================================
# SUMMARY DIALOG
# ===========================================================================
$btnSummary.Add_Click({
    if ($script:Results.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Run a query first.","Summary",
            [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return
    }
    $total   = $script:Results.Count
    $enabled = @($script:Results | Where-Object { (Get-ObjectPropValue -Object $_ -Name 'Enabled') -eq $true }).Count
    $dis     = @($script:Results | Where-Object { (Get-ObjectPropValue -Object $_ -Name 'Enabled') -eq $false }).Count
    $ouBreak = $script:Results | ForEach-Object {
        $dn = Get-ObjectPropValue -Object $_ -Name 'DistinguishedName'
        if ($dn) { ($dn -split ",",2)[1] }
    } | Group-Object | Sort-Object Count -Descending | Select-Object -First 10

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("=== Summary ===")
    [void]$sb.AppendLine("Total:    $total")
    [void]$sb.AppendLine("Enabled:  $enabled")
    [void]$sb.AppendLine("Disabled: $dis")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Top OUs:")
    foreach ($ou in $ouBreak) { [void]$sb.AppendLine("  ($($ou.Count))  $($ou.Name)") }

    $sumForm = New-Object System.Windows.Forms.Form
    $sumForm.Text = "Query Summary"; $sumForm.Size = New-Object System.Drawing.Size(560,380)
    $sumForm.StartPosition = "CenterParent"; $sumForm.Font = $fntNormal
    $sumForm.FormBorderStyle = "Sizable"; $sumForm.MaximizeBox = $true; $sumForm.BackColor = $Theme.Card

    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.Dock = "Fill"; $rtb.ReadOnly = $true; $rtb.Font = $fntMono
    $rtb.Text = $sb.ToString(); $rtb.BackColor = $Theme.Card; $rtb.BorderStyle = "None"

    $btnCloseSum = New-Object System.Windows.Forms.Button
    $btnCloseSum.Text = "Close"; $btnCloseSum.Dock = "Bottom"; $btnCloseSum.Height = 34; $btnCloseSum.DialogResult = "OK"
    Set-PrimaryButtonStyle $btnCloseSum

    $sumForm.Controls.AddRange(@($rtb,$btnCloseSum))
    $sumForm.AcceptButton = $btnCloseSum
    [void]$sumForm.ShowDialog($Form)
})

# ===========================================================================
# COLUMN CHOOSER / RESULT RE-HYDRATION
# ===========================================================================
# AD cmdlet objects use a property adapter: names like PasswordLastSet often
# appear on PSObject even when never requested (value stays $null), and
# Add-Member cannot override them. Track LoadedProperties and REPLACE each
# result object with a fresh Get-AD* call that requests the full property set.
function Update-ResultsWithProperties {
    param([Parameter(Mandatory)][string[]]$NeededProps)

    if ($script:Results.Count -eq 0) { return }

    $adNeeded = @($NeededProps | Where-Object { $_ -and ($script:EntraPropNames -notcontains $_) })
    $entraNeeded = @($NeededProps | Where-Object { $_ -and ($script:EntraPropNames -contains $_) })

    $missing = @($adNeeded | Where-Object { -not $script:LoadedProperties.Contains($_) })
    $entraMissing = @($entraNeeded | Where-Object { -not $script:LoadedProperties.Contains($_) })

    if ($missing.Count -eq 0 -and $entraMissing.Count -eq 0) { return }

    if ($missing.Count -gt 0) {
        $fetchSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($p in $script:LoadedProperties) {
            if ($script:EntraPropNames -notcontains $p) { [void]$fetchSet.Add($p) }
        }
        foreach ($p in $adNeeded) { if ($p) { [void]$fetchSet.Add($p) } }
        [void]$fetchSet.Add("DistinguishedName")
        # Ensure alias LDAP names are also requested when the PS name is needed
        foreach ($p in @($adNeeded)) {
            if ($p -and $PS_PROP_MAP.ContainsKey($p) -and $PS_PROP_MAP[$p].Kind -eq "Alias") {
                [void]$fetchSet.Add($PS_PROP_MAP[$p].Ldap)
            }
        }
        # Date convenience props need their underlying LDAP attrs too
        foreach ($p in @($adNeeded)) {
            if ($p -and $DATE_LDAP_MAP.ContainsKey($p)) { [void]$fetchSet.Add($DATE_LDAP_MAP[$p].Ldap) }
        }

        $fetchAttrs = @($fetchSet)
        $fetchCmd = switch ($script:CurrentObjType) {
            "Users"     { { param($dn,$p) Get-ADUser     -Identity $dn -Properties $p -ErrorAction Stop } }
            "Computers" { { param($dn,$p) Get-ADComputer -Identity $dn -Properties $p -ErrorAction Stop } }
            "Groups"    { { param($dn,$p) Get-ADGroup    -Identity $dn -Properties $p -ErrorAction Stop } }
            default     { { param($dn,$p) Get-ADObject   -Identity $dn -Properties $p -ErrorAction Stop } }
        }

        Start-Progress "Fetching $($missing.Count) attribute(s) for $($script:Results.Count) object(s)..."
        $Form.Refresh()

        $newResults = [System.Collections.Generic.List[object]]::new()
        $fetched = 0
        $errors  = 0
        foreach ($r in $script:Results) {
            $dn = Get-ObjectPropValue -Object $r -Name 'DistinguishedName'
            if (-not $dn) {
                $newResults.Add($r)
                $fetched++
                continue
            }
            try {
                # Replace the whole object — do NOT Add-Member onto AD* instances
                $fresh = & $fetchCmd $dn $fetchAttrs
                # Preserve any Entra fields already on the prior row
                $row = ConvertTo-EnrichableRow -Object $fresh
                foreach ($ep in $script:EntraPropNames) {
                    if (Test-ObjectHasProp -Object $r -Name $ep) {
                        $row | Add-Member -NotePropertyName $ep -NotePropertyValue (Get-ObjectPropValue -Object $r -Name $ep) -Force
                    }
                }
                $newResults.Add($row)
            } catch {
                $newResults.Add($r)
                $errors++
            }
            $fetched++
            if ($fetched % 25 -eq 0) {
                Update-Progress "Fetching attributes: $fetched / $($script:Results.Count)..."
            }
        }

        $script:Results = @($newResults)
        foreach ($p in $fetchAttrs) { if ($p) { [void]$script:LoadedProperties.Add($p) } }
        Stop-Progress
        if ($errors -gt 0) {
            Set-Status "Columns updated ($errors object(s) failed to refresh)"
        }
    }

    # Entra columns selected in the chooser → pull from Graph
    if ($entraMissing.Count -gt 0 -and $script:CurrentObjType -eq "Users") {
        if ($entraMissing -contains "EntraAssignedRoles") { $chkEntraRoles.Checked = $true }
        if ($entraMissing -contains "EntraDevices") { $chkEntraDevices.Checked = $true }
        if ($entraMissing -contains "EntraAuthMethods") { $chkEntraAuth.Checked = $true }
        if ($entraMissing | Where-Object { $_ -like "EntraLastSignInError*" }) { $chkEntraFailSignIn.Checked = $true }
        Invoke-EntraEnrichment
    }
}

$btnColumns.Add_Click({
    $allCols = @($ATTR[$script:CurrentObjType].Values)

    $colForm = New-Object System.Windows.Forms.Form
    $colForm.Text = "Choose Columns"; $colForm.Size = New-Object System.Drawing.Size(320,440)
    $colForm.StartPosition = "CenterParent"; $colForm.Font = $fntNormal
    $colForm.FormBorderStyle = "Sizable"; $colForm.MaximizeBox = $true; $colForm.BackColor = $Theme.Card

    $clb = New-Object System.Windows.Forms.CheckedListBox
    $clb.Dock = "Fill"; $clb.CheckOnClick = $true; $clb.BorderStyle = "None"
    foreach ($c in $allCols) {
        $idx = $clb.Items.Add($c)
        if ($script:VisibleColumns -contains $c) { $clb.SetItemChecked($idx,$true) }
    }

    $pnlBtn = New-Object System.Windows.Forms.Panel
    $pnlBtn.Dock = "Bottom"; $pnlBtn.Height = 44; $pnlBtn.BackColor = $Theme.Card

    $btnApply = New-Object System.Windows.Forms.Button
    $btnApply.Text = "Apply"; $btnApply.Width = 84; $btnApply.Height = 30
    $btnApply.Location = New-Object System.Drawing.Point(8,7); $btnApply.DialogResult = "OK"
    Set-PrimaryButtonStyle $btnApply

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"; $btnCancel.Width = 84; $btnCancel.Height = 30
    $btnCancel.Location = New-Object System.Drawing.Point(100,7); $btnCancel.DialogResult = "Cancel"
    Set-SecondaryButtonStyle $btnCancel

    $pnlBtn.Controls.AddRange(@($btnApply,$btnCancel))
    $colForm.Controls.AddRange(@($clb,$pnlBtn))
    $colForm.AcceptButton = $btnApply; $colForm.CancelButton = $btnCancel

    if ($colForm.ShowDialog($Form) -eq "OK") {
        $script:VisibleColumns.Clear()
        for ($i = 0; $i -lt $clb.Items.Count; $i++) {
            if ($clb.GetItemChecked($i)) { $script:VisibleColumns.Add($clb.Items[$i].ToString()) }
        }
        if ($script:Results.Count -gt 0) {
            try {
                Update-ResultsWithProperties -NeededProps @($script:VisibleColumns)
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to load column data:`r`n$_","Columns",
                    [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
            }
            Apply-ResultsSearch
        }
    }
})

# ===========================================================================
# GRID CONTEXT MENU
# ===========================================================================
$mCopyCell.Add_Click({
    if (-not $Grid.CurrentCell) { return }
    $val = $Grid.CurrentCell.Value
    if ($null -eq $val) { [System.Windows.Forms.Clipboard]::Clear(); return }
    [System.Windows.Forms.Clipboard]::SetText($val.ToString())
})
$mCopyRow.Add_Click({
    if ($Grid.CurrentRow) {
        $vals = $Grid.CurrentRow.Cells | ForEach-Object {
            if ($null -eq $_.Value) { "" } else { $_.Value.ToString() }
        }
        [System.Windows.Forms.Clipboard]::SetText(($vals -join "`t"))
    }
})
$mSelectAll.Add_Click({ $Grid.SelectAll() })

# ===========================================================================
# DYNAMIC ATTRIBUTE LOADER  (merges live AD schema into curated $ATTR)
# ===========================================================================
function Load-SchemaAttributes {
    $schemaDN = $null
    try { $schemaDN = (Get-ADRootDSE -ErrorAction Stop).schemaNamingContext } catch { return }

    $sState.Text = "Loading schema: reading attributeSchema objects..."
    $Form.Refresh()

    $attrIndex = @{}  # cn / ldapDisplayName -> lDAPDisplayName
    try {
        Get-ADObject -SearchBase $schemaDN -LDAPFilter "(objectClass=attributeSchema)" `
            -Properties cn,lDAPDisplayName -ResultSetSize $null -ErrorAction Stop |
        ForEach-Object {
            if ($_.lDAPDisplayName) {
                $attrIndex[$_.lDAPDisplayName] = $_.lDAPDisplayName
                if ($_.cn) { $attrIndex[$_.cn] = $_.lDAPDisplayName }
            }
        }
    } catch { return }

    $classIndex = @{}
    try {
        Get-ADObject -SearchBase $schemaDN -LDAPFilter "(objectClass=classSchema)" `
            -Properties cn,lDAPDisplayName,subClassOf,auxiliaryClass,systemAuxiliaryClass,mustContain,mayContain,systemMustContain,systemMayContain `
            -ResultSetSize $null -ErrorAction Stop |
        ForEach-Object { $classIndex[$_.lDAPDisplayName] = $_ }
    } catch { return }

    function Get-AllAttrsForClass ([string]$className) {
        $collected = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $toVisit   = [System.Collections.Generic.Queue[string]]::new()
        $visited   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $toVisit.Enqueue($className)
        while ($toVisit.Count -gt 0) {
            $cn = $toVisit.Dequeue()
            if (-not $visited.Add($cn)) { continue }
            $classDef = $classIndex[$cn]
            if (-not $classDef) { continue }
            $attrCNs  = @()
            $attrCNs += @($classDef.mustContain); $attrCNs += @($classDef.mayContain)
            $attrCNs += @($classDef.systemMustContain); $attrCNs += @($classDef.systemMayContain)
            foreach ($aCN in $attrCNs) {
                if (-not $aCN) { continue }
                $ldapName = if ($attrIndex.ContainsKey($aCN)) { $attrIndex[$aCN] } else { $aCN }
                [void]$collected.Add($ldapName)
            }
            if ($classDef.subClassOf -and $classDef.subClassOf -ne $cn) { $toVisit.Enqueue($classDef.subClassOf) }
            foreach ($aux in @($classDef.auxiliaryClass) + @($classDef.systemAuxiliaryClass)) {
                if ($aux) { $toVisit.Enqueue($aux) }
            }
        }
        return $collected
    }
    function ConvertTo-Label ([string]$ldapName) {
        $s = [System.Text.RegularExpressions.Regex]::Replace($ldapName,'(?<=[a-z])(?=[A-Z0-9])',' ')
        return $s.Substring(0,1).ToUpper() + $s.Substring(1)
    }
    function Merge-AttrDict ([string]$objType, [string]$className) {
        $sState.Text = "Loading schema: merging $objType attributes..."
        $Form.Refresh()

        # Start from curated friendly attributes (preserve labels + computed props)
        $merged = [ordered]@{}
        $knownLdap = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($k in $script:CuratedAttr[$objType].Keys) {
            $merged[$k] = $script:CuratedAttr[$objType][$k]
            [void]$knownLdap.Add($script:CuratedAttr[$objType][$k])
        }

        $ldapNames = Get-AllAttrsForClass $className
        foreach ($ldapName in ($ldapNames | Sort-Object)) {
            if (-not $ldapName) { continue }
            if ($knownLdap.Contains($ldapName)) { continue }
            # Skip names that collide with computed PS props we already expose
            if ($PS_PROP_MAP.ContainsKey($ldapName)) { continue }

            $label = ConvertTo-Label $ldapName
            $safeLabel = $label; $suffix = 2
            while ($merged.Contains($safeLabel)) { $safeLabel = "$label ($suffix)"; $suffix++ }
            $merged[$safeLabel] = $ldapName
            [void]$knownLdap.Add($ldapName)
        }

        if (-not ($knownLdap.Contains("DistinguishedName"))) {
            $merged["OU / Distinguished Name"] = "DistinguishedName"
        }
        $ATTR[$objType] = $merged
    }
    Merge-AttrDict "Users"     "user"
    Merge-AttrDict "Computers" "computer"
    Merge-AttrDict "Groups"    "group"
    Merge-AttrDict "OUs"       "organizationalUnit"
}

# ===========================================================================
# STARTUP
# ===========================================================================
$Form.Add_Shown({
    Load-SchemaAttributes
    $script:VisibleColumns.Clear()
    foreach ($col in $DEFAULT_COLS[$script:CurrentObjType]) { $script:VisibleColumns.Add($col) }
    $sState.Text = "Ready"
    if ($script:FilterGroups.Count -eq 0) { $script:FilterGroups.Add((New-FilterGroup)) }
    Update-GroupMembershipPanel
    $gbEntra.Visible = ($script:CurrentObjType -eq "Users")
    # Prefill tenant from AD DNS root when possible (e.g. contoso.com)
    try {
        if ($txtEntraTenant.Text -eq $script:EntraTenantPlaceholder) {
            $dns = [string](Get-ADDomain -ErrorAction Stop).DNSRoot
            if ($dns) {
                $txtEntraTenant.Text = $dns
                $txtEntraTenant.ForeColor = $Theme.Text
            }
        }
    } catch { }
    Update-EntraStatusLabel
    Rebuild-FilterContainer
})

# Rebuild filter rows on resize so the value inputs stretch to the new width
$FilterContainer.Add_SizeChanged({
    foreach ($c in $FilterContainer.Controls) {
        if ($c -is [System.Windows.Forms.Panel] -or $c -is [System.Windows.Forms.Label]) {
            $c.Width = $FilterContainer.ClientSize.Width
        }
    }
})

# ===========================================================================
# LAUNCH
# ===========================================================================
[void]$Form.ShowDialog()
