<#
.SYNOPSIS
    AD Delta Compare & Restore - Modern GUI to compare a PDC Emulator against two
    delayed-replication domain controllers and restore attributes back to the PDC.

.DESCRIPTION
    Windows PowerShell 5.1 compatible. Uses Windows Forms with a modern flat UI.

    - Discovers the PDC Emulator and all DCs in the domain.
    - Performs a 3-way, attribute-level comparison (PDC + Replica1 + Replica2)
      for Users, Computers, Groups, DNS, Group Policy, and Replication Metadata.
    - Restores individual attributes on existing directory objects FROM either
      delayed replica TO the PDC Emulator (Set-ADObject -Replace / -Clear).
    - Every restore is preceded by a before/after confirmation dialog.

    Restore is enabled for directory objects only (Users / Computers / Groups).
    DNS, Group Policy, and Replication Metadata targets are compare-only.

.REQUIREMENTS
    - Windows PowerShell 5.1 (STA). RSAT: ActiveDirectory, DnsServer, GroupPolicy.
    - Rights to read target partitions and write to the PDC for restore.

.USAGE
    powershell -ExecutionPolicy Bypass -STA -File .\AD-Delta-Compare-FIXED.ps1

.NOTES
    Version: 1.9
    - Pick-and-choose restore: checkbox column, Check Differences / Clear Checks
    - Restore Checked only restores ticked restorable changes
    - Details dialog: Check for Restore or Restore This Change
#>

# ---------------------------------------------------------------------------
# Assemblies
# ---------------------------------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch { }
# Do NOT call SetCompatibleTextRenderingDefault — it throws if any WinForms
# window already exists in this process (e.g. DHCPManager still open).

# ---------------------------------------------------------------------------
# Theme (modern flat — teal accent on cool slate, light shell)
# Use "Segoe UI" + Bold — "Segoe UI Semibold" is missing on many Server 2016 installs
# and causes wrong metrics / clipped text.
# ---------------------------------------------------------------------------
$script:Theme = @{
    BgApp       = [System.Drawing.Color]::FromArgb(236, 240, 244)
    BgPanel     = [System.Drawing.Color]::FromArgb(255, 255, 255)
    BgHeader    = [System.Drawing.Color]::FromArgb(28, 42, 56)
    BgStatus    = [System.Drawing.Color]::FromArgb(35, 48, 62)
    Accent      = [System.Drawing.Color]::FromArgb(14, 122, 130)
    AccentHover = [System.Drawing.Color]::FromArgb(18, 145, 154)
    AccentDim   = [System.Drawing.Color]::FromArgb(10, 95, 102)
    Danger      = [System.Drawing.Color]::FromArgb(180, 62, 62)
    TextPrimary = [System.Drawing.Color]::FromArgb(28, 36, 44)
    TextMuted   = [System.Drawing.Color]::FromArgb(100, 112, 125)
    TextOnDark  = [System.Drawing.Color]::FromArgb(236, 242, 246)
    Border      = [System.Drawing.Color]::FromArgb(210, 218, 226)
    GridAlt     = [System.Drawing.Color]::FromArgb(248, 250, 252)
    DiffBg      = [System.Drawing.Color]::FromArgb(255, 228, 228)
    MissingBg   = [System.Drawing.Color]::FromArgb(255, 243, 214)
    MatchBg     = [System.Drawing.Color]::FromArgb(226, 245, 230)
    InputBg     = [System.Drawing.Color]::FromArgb(255, 255, 255)
    FontUi      = New-Object System.Drawing.Font('Segoe UI', 9.0)
    FontUiBold  = New-Object System.Drawing.Font('Segoe UI', 9.0, [System.Drawing.FontStyle]::Bold)
    FontTitle   = New-Object System.Drawing.Font('Segoe UI', 15.0, [System.Drawing.FontStyle]::Bold)
    FontSub     = New-Object System.Drawing.Font('Segoe UI', 8.5)
    FontMono    = New-Object System.Drawing.Font('Consolas', 8.5)
    FontSection = New-Object System.Drawing.Font('Segoe UI', 9.0, [System.Drawing.FontStyle]::Bold)
    FontSync    = New-Object System.Drawing.Font('Segoe UI', 7.5)
}

# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------
function New-FlatButton {
    param(
        [string]$Text,
        [System.Drawing.Point]$Location,
        [System.Drawing.Size]$Size,
        [System.Drawing.Color]$BackColor,
        [System.Drawing.Color]$ForeColor,
        [switch]$Secondary
    )
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $Text
    $btn.Location = $Location
    $btn.Size = $Size
    $btn.FlatStyle = 'Flat'
    $btn.FlatAppearance.BorderSize = 0
    $btn.Font = $script:Theme.FontUiBold
    $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    if ($Secondary) {
        $btn.BackColor = $script:Theme.BgPanel
        $btn.ForeColor = $script:Theme.TextPrimary
        $btn.FlatAppearance.BorderSize = 1
        $btn.FlatAppearance.BorderColor = $script:Theme.Border
    } else {
        $btn.BackColor = $BackColor
        $btn.ForeColor = $ForeColor
    }
    $btn.Add_MouseEnter({
        if (-not $this.Enabled) { return }
        if ($this.Tag -eq 'secondary') {
            $this.BackColor = $script:Theme.BgApp
        } else {
            $this.BackColor = $script:Theme.AccentHover
        }
    })
    $btn.Add_MouseLeave({
        if (-not $this.Enabled) { return }
        if ($this.Tag -eq 'secondary') {
            $this.BackColor = $script:Theme.BgPanel
        } else {
            $this.BackColor = $script:Theme.Accent
        }
    })
    if ($Secondary) { $btn.Tag = 'secondary' }
    return $btn
}

function New-ThemedLabel {
    param([string]$Text, [System.Drawing.Point]$Location, [switch]$Muted, [switch]$Section)
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Text
    $lbl.Location = $Location
    $lbl.AutoSize = $true
    $lbl.BackColor = [System.Drawing.Color]::Transparent
    if ($Section) {
        $lbl.Font = $script:Theme.FontSection
        $lbl.ForeColor = $script:Theme.TextPrimary
    } elseif ($Muted) {
        $lbl.Font = $script:Theme.FontUi
        $lbl.ForeColor = $script:Theme.TextMuted
    } else {
        $lbl.Font = $script:Theme.FontUi
        $lbl.ForeColor = $script:Theme.TextPrimary
    }
    return $lbl
}

function New-ThemedTextBox {
    param([System.Drawing.Point]$Location, [System.Drawing.Size]$Size, [switch]$ReadOnly)
    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Location = $Location
    $tb.Size = $Size
    $tb.Font = $script:Theme.FontUi
    $tb.BorderStyle = 'FixedSingle'
    $tb.BackColor = $script:Theme.InputBg
    $tb.ForeColor = $script:Theme.TextPrimary
    if ($ReadOnly) {
        $tb.ReadOnly = $true
        $tb.BackColor = $script:Theme.BgApp
    }
    return $tb
}

function New-ThemedCombo {
    param([System.Drawing.Point]$Location, [System.Drawing.Size]$Size)
    $cmb = New-Object System.Windows.Forms.ComboBox
    $cmb.Location = $Location
    $cmb.Size = $Size
    $cmb.Font = $script:Theme.FontUi
    $cmb.DropDownStyle = 'DropDownList'
    $cmb.FlatStyle = 'Flat'
    $cmb.BackColor = $script:Theme.InputBg
    $cmb.ForeColor = $script:Theme.TextPrimary
    return $cmb
}

function Add-GridColumns {
    # PS 5.1: @(col1,col2) is Object[] — AddRange needs DataGridViewColumn[]
    param(
        [System.Windows.Forms.DataGridView]$Grid,
        [System.Windows.Forms.DataGridViewColumn[]]$Columns
    )
    foreach ($c in $Columns) {
        [void]$Grid.Columns.Add($c)
    }
}

function New-GridColumn {
    param([string]$Header, [string]$Name, [int]$Width, [int]$FillWeight = 100, [switch]$Hidden)
    $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $col.HeaderText = $Header
    $col.Name = $Name
    $col.Width = $Width
    $col.FillWeight = $FillWeight
    $col.MinimumWidth = 50
    if ($Hidden) { $col.Visible = $false }
    return $col
}

function Set-ModernGridStyle {
    param([System.Windows.Forms.DataGridView]$Grid)
    $Grid.BackgroundColor = $script:Theme.BgPanel
    $Grid.BorderStyle = 'None'
    $Grid.CellBorderStyle = 'SingleHorizontal'
    $Grid.GridColor = $script:Theme.Border
    $Grid.EnableHeadersVisualStyles = $false
    $Grid.ColumnHeadersBorderStyle = 'None'
    $Grid.ColumnHeadersDefaultCellStyle.BackColor = $script:Theme.BgHeader
    $Grid.ColumnHeadersDefaultCellStyle.ForeColor = $script:Theme.TextOnDark
    $Grid.ColumnHeadersDefaultCellStyle.Font = $script:Theme.FontUiBold
    $Grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = $script:Theme.BgHeader
    $Grid.ColumnHeadersDefaultCellStyle.WrapMode = 'False'
    $Grid.ColumnHeadersHeight = 34
    $Grid.ColumnHeadersHeightSizeMode = 'DisableResizing'
    $Grid.DefaultCellStyle.BackColor = $script:Theme.BgPanel
    $Grid.DefaultCellStyle.ForeColor = $script:Theme.TextPrimary
    $Grid.DefaultCellStyle.Font = $script:Theme.FontUi
    $Grid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(200, 230, 232)
    $Grid.DefaultCellStyle.SelectionForeColor = $script:Theme.TextPrimary
    $Grid.AlternatingRowsDefaultCellStyle.BackColor = $script:Theme.GridAlt
    $Grid.RowTemplate.Height = 26
    $Grid.AllowUserToAddRows = $false
    $Grid.AllowUserToDeleteRows = $false
    $Grid.AllowUserToResizeRows = $false
    $Grid.ReadOnly = $false   # checkbox column must be editable
    $Grid.EditMode = 'EditOnEnter'
    $Grid.SelectionMode = 'FullRowSelect'
    $Grid.MultiSelect = $true
    $Grid.AutoSizeColumnsMode = 'Fill'
    $Grid.RowHeadersVisible = $false
    $Grid.ScrollBars = 'Both'
    try {
        $flags = [System.Reflection.BindingFlags]'Instance, NonPublic'
        $prop = $Grid.GetType().GetProperty('DoubleBuffered', $flags)
        if ($prop) { $prop.SetValue($Grid, $true, $null) }
    } catch { }
}

# ---------------------------------------------------------------------------
# Global configuration
# ---------------------------------------------------------------------------
$script:Config = [ordered]@{
    Users = @(
        'sAMAccountName','userPrincipalName','givenName','sn','displayName','mail',
        'description','department','title','telephoneNumber','company','manager',
        'userAccountControl','accountExpires','pwdLastSet','lockoutTime',
        'memberOf','whenChanged','distinguishedName'
    )
    Computers = @(
        'sAMAccountName','dNSHostName','operatingSystem','operatingSystemVersion',
        'operatingSystemServicePack','description','userAccountControl',
        'servicePrincipalName','memberOf','whenChanged','distinguishedName'
    )
    Groups = @(
        'sAMAccountName','description','groupType','mail','managedBy',
        'member','memberOf','whenChanged','distinguishedName'
    )
}

$script:NonRestorable = @(
    'whenChanged','distinguishedName','memberOf','objectGUID','objectSid',
    'canonicalName','whenCreated','uSNChanged','uSNCreated'
)

$script:AuditLog = Join-Path -Path $env:TEMP -ChildPath 'AD-Delta-Restore-Audit.log'
$script:AuditLogFailureReported = $false
$script:Runspace   = $null
$script:PowerShell = $null
$script:Handle     = $null

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Escape-LdapFilter {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    # Use string Replace overloads only — Char Replace('\00') throws on PS 5.1
    $Value = $Value.Replace('\', '\5c')
    $Value = $Value.Replace('*', '\2a')
    $Value = $Value.Replace('(', '\28')
    $Value = $Value.Replace(')', '\29')
    $Value = $Value.Replace([string][char]0, '\00')
    $Value = $Value.Replace('/', '\2f')
    return $Value
}

function Test-DistinguishedName {
    param([string]$DN)
    if ([string]::IsNullOrWhiteSpace($DN)) { return $false }
    return $DN -match '^(CN|OU|DC)=.+' -and $DN -match '='
}

function Sanitize-LogValue {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    $Value = $Value -replace '[\r\n\t]', ' '
    $Value = $Value -replace '[^\x20-\x7E]', '?'
    if ($Value.Length -gt 200) { $Value = $Value.Substring(0, 197) + '...' }
    return $Value
}

$script:ConvertAdValueDef = {
    param($Value, [int]$Depth = 0)
    if ($Depth -gt 10) { return '[Too Deep]' }
    if ($null -eq $Value) { return '' }
    if ($Value -is [byte[]]) { return ([System.BitConverter]::ToString($Value)) }
    if ($Value -is [datetime]) { return ($Value.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")) }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = @()
        foreach ($v in $Value) {
            $items += (& $script:ConvertAdValueDef $v ($Depth + 1))
        }
        if ($items.Count -eq 0) { return '' }
        return (($items | Sort-Object) -join '; ')
    }
    return [string]$Value
}
$script:ConvertAdValueToString = $script:ConvertAdValueDef

function Write-Status {
    param([string]$Message, [string]$Level = 'INFO')
    $stamp = (Get-Date).ToString('HH:mm:ss')
    if ($script:StatusBox -and -not $script:StatusBox.IsDisposed) {
        try {
            $script:StatusBox.AppendText("[$stamp] $Level  $Message`r`n")
            $script:StatusBox.SelectionStart = $script:StatusBox.TextLength
            $script:StatusBox.ScrollToCaret()
        } catch { }
    }
}

function Write-Audit {
    param([string]$Message)
    $line = ('{0}  {1}  {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $env:USERNAME, (Sanitize-LogValue $Message))
    try {
        Add-Content -Path $script:AuditLog -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch {
        if (-not $script:AuditLogFailureReported) {
            Write-Status "WARNING: Audit logging failed: $($_.Exception.Message)" 'WARN'
            $script:AuditLogFailureReported = $true
        }
    }
}

# ---------------------------------------------------------------------------
# Background comparison scriptblock
# ---------------------------------------------------------------------------
$script:CompareScript = {
    param($Pdc, $R1, $R2, $Type, $Filter, $SearchBase, $Dn, $Zone, $DiffOnly, $ConvertFuncDef, $UserProps, $CompProps, $GroupProps, $NonRestorable)

    $script:ConvertAdValueToString = $ConvertFuncDef
    $result = [pscustomobject]@{ Rows = @(); Error = $null }
    $rows = New-Object System.Collections.ArrayList

    function Escape-LdapFilterInternal {
        param([string]$Value)
        if ([string]::IsNullOrEmpty($Value)) { return $Value }
        # String overloads only — Char Replace('\00') throws on PS 5.1
        $Value = $Value.Replace('\', '\5c')
        $Value = $Value.Replace('*', '\2a')
        $Value = $Value.Replace('(', '\28')
        $Value = $Value.Replace(')', '\29')
        $Value = $Value.Replace([string][char]0, '\00')
        $Value = $Value.Replace('/', '\2f')
        return $Value
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $dcMap = [ordered]@{ 'PDC' = $Pdc; 'Replica1' = $R1; 'Replica2' = $R2 }

        function New-Row {
            param($Object,$Guid,$Dn,$Attr,$Restorable,$PdcVal,$R1Val,$R2Val,$Status)
            [pscustomobject]@{
                Object = $Object; ObjectGUID = $Guid; DN = $Dn; Attribute = $Attr
                Restorable = $Restorable; PDC = $PdcVal; Replica1 = $R1Val
                Replica2 = $R2Val; Status = $Status
            }
        }

        switch ($Type) {
            { $_ -in @('Users','Computers','Groups') } {
                switch ($Type) {
                    'Users'     { $props = $UserProps;  $catFilter = '(&(objectCategory=person)(objectClass=user))' }
                    'Computers' { $props = $CompProps;  $catFilter = '(objectCategory=computer)' }
                    'Groups'    { $props = $GroupProps; $catFilter = '(objectCategory=group)' }
                }

                $nameClause = ''
                if ($Filter) {
                    $raw = $Filter.Trim()
                    $escapedFilter = Escape-LdapFilterInternal $raw
                    # UPN (contains @): match UPN exactly or as substring; also try sAMAccountName left of @
                    if ($raw -match '@') {
                        $samPart = ($raw -split '@', 2)[0]
                        $escapedSam = Escape-LdapFilterInternal $samPart
                        $nameClause = "(|(userPrincipalName=$escapedFilter)(userPrincipalName=*$escapedFilter*)(sAMAccountName=$escapedSam)(sAMAccountName=*$escapedSam*))"
                    }
                    else {
                        # sAMAccountName / UPN / common name fields (substring)
                        $nameClause = "(|(sAMAccountName=$escapedFilter)(sAMAccountName=*$escapedFilter*)(userPrincipalName=$escapedFilter)(userPrincipalName=*$escapedFilter*)(cn=*$escapedFilter*)(displayName=*$escapedFilter*)(name=*$escapedFilter*))"
                    }
                }
                $ldap = "(&$catFilter$nameClause)"

                $tables = @{}
                foreach ($key in $dcMap.Keys) {
                    $srv = $dcMap[$key]
                    $t = @{}
                    $params = @{ Server = $srv; LDAPFilter = $ldap; Properties = $props; ErrorAction = 'Stop' }
                    if ($SearchBase) { $params['SearchBase'] = $SearchBase }
                    $objs = Get-ADObject @params
                    foreach ($o in $objs) { $t[[string]$o.ObjectGUID] = $o }
                    $tables[$key] = $t
                }

                $allGuids = New-Object System.Collections.Generic.HashSet[string]
                foreach ($key in $dcMap.Keys) { foreach ($g in $tables[$key].Keys) { [void]$allGuids.Add($g) } }

                foreach ($guid in $allGuids) {
                    $oP = $tables['PDC'][$guid]; $o1 = $tables['Replica1'][$guid]; $o2 = $tables['Replica2'][$guid]
                    $anyObj = if ($oP) { $oP } elseif ($o1) { $o1 } else { $o2 }
                    $name = [string]$anyObj.Name
                    $dn   = [string]$anyObj.DistinguishedName
                    $objMissing = (-not $oP) -or (-not $o1) -or (-not $o2)

                    foreach ($attr in $props) {
                        $pv = if ($oP) { & $script:ConvertAdValueToString $oP.$attr 0 } else { '<object missing>' }
                        $v1 = if ($o1) { & $script:ConvertAdValueToString $o1.$attr 0 } else { '<object missing>' }
                        $v2 = if ($o2) { & $script:ConvertAdValueToString $o2.$attr 0 } else { '<object missing>' }

                        $present = @()
                        if ($oP) { $present += $pv }
                        if ($o1) { $present += $v1 }
                        if ($o2) { $present += $v2 }
                        $distinct = $present | Select-Object -Unique

                        if ($objMissing) { $status = 'ObjectMissing' }
                        elseif ($distinct.Count -le 1) { $status = 'Match' }
                        else { $status = 'Different' }

                        if ($DiffOnly -and $status -eq 'Match') { continue }

                        $restorable = (-not $objMissing) -and ($attr -notin $NonRestorable)
                        [void]$rows.Add((New-Row $name $guid $dn $attr $restorable $pv $v1 $v2 $status))
                    }
                }
            }

            'DNS' {
                Import-Module DnsServer -ErrorAction Stop
                if (-not $Zone) { throw 'Select a DNS zone first.' }

                $tables = @{}
                foreach ($key in $dcMap.Keys) {
                    $srv = $dcMap[$key]
                    $t = @{}
                    $recs = Get-DnsServerResourceRecord -ComputerName $srv -ZoneName $Zone -ErrorAction Stop
                    foreach ($r in $recs) {
                        $data = ''
                        try { $data = ($r.RecordData.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ',' } catch { }
                        $k = '{0}|{1}' -f $r.HostName, $r.RecordType
                        $t[$k] = ("TTL={0}; {1}" -f $r.TimeToLive, $data)
                    }
                    $tables[$key] = $t
                }

                $allKeys = New-Object System.Collections.Generic.HashSet[string]
                foreach ($key in $dcMap.Keys) { foreach ($k in $tables[$key].Keys) { [void]$allKeys.Add($k) } }

                foreach ($k in $allKeys) {
                    $pv = if ($tables['PDC'].ContainsKey($k))      { $tables['PDC'][$k] }      else { '<missing>' }
                    $v1 = if ($tables['Replica1'].ContainsKey($k)) { $tables['Replica1'][$k] } else { '<missing>' }
                    $v2 = if ($tables['Replica2'].ContainsKey($k)) { $tables['Replica2'][$k] } else { '<missing>' }
                    $distinct = @($pv,$v1,$v2) | Select-Object -Unique
                    $status = if ($distinct.Count -le 1) { 'Match' } else { 'Different' }
                    if ($DiffOnly -and $status -eq 'Match') { continue }
                    [void]$rows.Add((New-Row $k '' '' 'Record' $false $pv $v1 $v2 $status))
                }
            }

            'GroupPolicy' {
                Import-Module GroupPolicy -ErrorAction Stop
                $tables = @{}
                foreach ($key in $dcMap.Keys) {
                    $srv = $dcMap[$key]
                    $t = @{}
                    $gpos = Get-GPO -All -Server $srv -ErrorAction Stop
                    foreach ($g in $gpos) {
                        $t[[string]$g.Id] = [pscustomobject]@{
                            Name       = $g.DisplayName
                            Status     = [string]$g.GpoStatus
                            UserVer    = $g.User.DSVersion
                            UserSysVer = $g.User.SysvolVersion
                            CompVer    = $g.Computer.DSVersion
                            CompSysVer = $g.Computer.SysvolVersion
                            Modified   = $g.ModificationTime
                            WmiFilter  = if ($g.WmiFilter) { $g.WmiFilter.Name } else { '' }
                        }
                    }
                    $tables[$key] = $t
                }

                $allIds = New-Object System.Collections.Generic.HashSet[string]
                foreach ($key in $dcMap.Keys) { foreach ($id in $tables[$key].Keys) { [void]$allIds.Add($id) } }

                $fields = @('Status','UserVer','UserSysVer','CompVer','CompSysVer','Modified','WmiFilter')
                foreach ($id in $allIds) {
                    $gP = $tables['PDC'][$id]; $g1 = $tables['Replica1'][$id]; $g2 = $tables['Replica2'][$id]
                    $any = if ($gP) { $gP } elseif ($g1) { $g1 } else { $g2 }
                    $name = $any.Name
                    $objMissing = (-not $gP) -or (-not $g1) -or (-not $g2)

                    foreach ($field in $fields) {
                        $pv = if ($gP) { & $script:ConvertAdValueToString $gP.$field 0 } else { '<object missing>' }
                        $v1 = if ($g1) { & $script:ConvertAdValueToString $g1.$field 0 } else { '<object missing>' }
                        $v2 = if ($g2) { & $script:ConvertAdValueToString $g2.$field 0 } else { '<object missing>' }
                        $present = @()
                        if ($gP) { $present += $pv }; if ($g1) { $present += $v1 }; if ($g2) { $present += $v2 }
                        $distinct = $present | Select-Object -Unique
                        if ($objMissing) { $status = 'ObjectMissing' }
                        elseif ($distinct.Count -le 1) { $status = 'Match' }
                        else { $status = 'Different' }
                        if ($DiffOnly -and $status -eq 'Match') { continue }
                        [void]$rows.Add((New-Row $name $id '' $field $false $pv $v1 $v2 $status))
                    }
                }
            }

            'Replication Metadata' {
                if (-not $Dn) { throw 'Enter a distinguished name (DN) to inspect metadata.' }
                $tables = @{}
                foreach ($key in $dcMap.Keys) {
                    $srv = $dcMap[$key]
                    $t = @{}
                    $meta = Get-ADReplicationAttributeMetadata -Server $srv -Object $Dn -ErrorAction Stop
                    foreach ($m in $meta) {
                        $t[$m.AttributeName] = ("v{0}; {1}; from {2}" -f $m.Version, `
                            (& $script:ConvertAdValueToString $m.LastOriginatingChangeTime 0), $m.LastOriginatingChangeDirectoryServerIdentity)
                    }
                    $tables[$key] = $t
                }
                $allAttrs = New-Object System.Collections.Generic.HashSet[string]
                foreach ($key in $dcMap.Keys) { foreach ($a in $tables[$key].Keys) { [void]$allAttrs.Add($a) } }
                foreach ($a in $allAttrs) {
                    $pv = if ($tables['PDC'].ContainsKey($a))      { $tables['PDC'][$a] }      else { '<missing>' }
                    $v1 = if ($tables['Replica1'].ContainsKey($a)) { $tables['Replica1'][$a] } else { '<missing>' }
                    $v2 = if ($tables['Replica2'].ContainsKey($a)) { $tables['Replica2'][$a] } else { '<missing>' }
                    $distinct = @($pv,$v1,$v2) | Select-Object -Unique
                    $status = if ($distinct.Count -le 1) { 'Match' } else { 'Different' }
                    if ($DiffOnly -and $status -eq 'Match') { continue }
                    [void]$rows.Add((New-Row $Dn '' $Dn $a $false $pv $v1 $v2 $status))
                }
            }
        }

        $result.Rows = $rows.ToArray()
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

# ---------------------------------------------------------------------------
# Replication timing helper
# ---------------------------------------------------------------------------
function Get-DcLastReplicationInfo {
    param([string]$Server)
    if ([string]::IsNullOrWhiteSpace($Server)) {
        return @{ Text = 'Last sync: —'; Detail = $null }
    }
    try {
        $meta = @(Get-ADReplicationPartnerMetadata -Target $Server -ErrorAction Stop)
        if ($meta.Count -eq 0) {
            return @{ Text = 'Last sync: no partners'; Detail = $null }
        }
        $latest = $meta |
            Where-Object { $_.LastReplicationSuccess } |
            Sort-Object LastReplicationSuccess -Descending |
            Select-Object -First 1
        if (-not $latest) {
            return @{ Text = 'Last sync: never'; Detail = $null }
        }
        $when = $latest.LastReplicationSuccess.ToLocalTime()
        $age = (Get-Date) - $when
        $ageText = if ($age.TotalMinutes -lt 60) {
            ('{0:N0}m ago' -f $age.TotalMinutes)
        } elseif ($age.TotalHours -lt 48) {
            ('{0:N1}h ago' -f $age.TotalHours)
        } else {
            ('{0:N1}d ago' -f $age.TotalDays)
        }
        $partner = $latest.Partner
        if ($partner -match 'CN=([^,]+)') { $partner = $Matches[1] }
        return @{
            Text   = ("Last sync: {0}  ({1})" -f $when.ToString('yyyy-MM-dd HH:mm'), $ageText)
            Detail = ("Partner: {0}" -f $partner)
        }
    }
    catch {
        return @{ Text = 'Last sync: unavailable'; Detail = $_.Exception.Message }
    }
}

function Update-ReplicationLabels {
    $pdcInfo = Get-DcLastReplicationInfo -Server $txtPdc.Text
    $lblPdcSync.Text = $pdcInfo.Text
    if ($pdcInfo.Detail) { $lblPdcSync.Text = "$($pdcInfo.Text)  ·  $($pdcInfo.Detail)" }

    $r1 = [string]$cmbR1.SelectedItem
    $r1Info = Get-DcLastReplicationInfo -Server $r1
    $lblR1Sync.Text = $r1Info.Text
    if ($r1Info.Detail) { $lblR1Sync.Text = "$($r1Info.Text)  ·  $($r1Info.Detail)" }

    $r2 = [string]$cmbR2.SelectedItem
    $r2Info = Get-DcLastReplicationInfo -Server $r2
    $lblR2Sync.Text = $r2Info.Text
    if ($r2Info.Detail) { $lblR2Sync.Text = "$($r2Info.Text)  ·  $($r2Info.Detail)" }
}

# ---------------------------------------------------------------------------
# Main form — TableLayout columns so buttons NEVER overlap DC fields
# ---------------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Active Directory Recovery'
$form.Size = New-Object System.Drawing.Size(1280, 860)
$form.MinimumSize = New-Object System.Drawing.Size(1180, 760)
$form.StartPosition = 'CenterScreen'
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::None
$form.BackColor = $script:Theme.BgApp
$form.Font = $script:Theme.FontUi
$form.ForeColor = $script:Theme.TextPrimary
$form.SuspendLayout()

function New-StackedField {
    param(
        [string]$Caption,
        [System.Windows.Forms.Control]$InputControl,
        [System.Windows.Forms.Label]$SyncLabel
    )
    $p = New-Object System.Windows.Forms.Panel
    $p.Dock = 'Fill'
    $p.Padding = New-Object System.Windows.Forms.Padding(8, 4, 8, 4)
    $p.BackColor = $script:Theme.BgPanel

    $cap = New-Object System.Windows.Forms.Label
    $cap.Text = $Caption
    $cap.Font = $script:Theme.FontUi
    $cap.ForeColor = $script:Theme.TextMuted
    $cap.Dock = 'Top'
    $cap.Height = 20
    $cap.BackColor = [System.Drawing.Color]::Transparent

    $InputControl.Dock = 'Top'
    $InputControl.Height = 24

    $SyncLabel.Dock = 'Fill'
    $SyncLabel.Font = $script:Theme.FontSync
    $SyncLabel.ForeColor = $script:Theme.Accent
    $SyncLabel.BackColor = [System.Drawing.Color]::Transparent
    $SyncLabel.Padding = New-Object System.Windows.Forms.Padding(0, 6, 0, 0)

    # Add in reverse dock order: Fill first, then Top controls (last Top is highest)
    $p.Controls.Add($SyncLabel)
    $p.Controls.Add($InputControl)
    $p.Controls.Add($cap)
    return $p
}

# --- Header ---
$pnlHeader = New-Object System.Windows.Forms.Panel
$pnlHeader.Height = 80
$pnlHeader.Dock = 'Top'
$pnlHeader.BackColor = $script:Theme.BgHeader
$pnlHeader.Padding = New-Object System.Windows.Forms.Padding(20, 12, 20, 10)

$hdrLayout = New-Object System.Windows.Forms.TableLayoutPanel
$hdrLayout.Dock = 'Fill'
$hdrLayout.ColumnCount = 2
$hdrLayout.RowCount = 2
$hdrLayout.BackColor = $script:Theme.BgHeader
[void]$hdrLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 70)))
[void]$hdrLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 30)))
[void]$hdrLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 30)))
[void]$hdrLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 24)))
$pnlHeader.Controls.Add($hdrLayout)

$lblBrand = New-Object System.Windows.Forms.Label
$lblBrand.Text = 'Active Directory Recovery'
$lblBrand.Font = $script:Theme.FontTitle
$lblBrand.ForeColor = $script:Theme.TextOnDark
$lblBrand.Dock = 'Fill'
$lblBrand.TextAlign = 'MiddleLeft'
$lblBrand.BackColor = [System.Drawing.Color]::Transparent
$hdrLayout.Controls.Add($lblBrand, 0, 0)

$lblDom = New-Object System.Windows.Forms.Label
$lblDom.Text = 'Domain not discovered'
$lblDom.Font = $script:Theme.FontUi
$lblDom.ForeColor = [System.Drawing.Color]::FromArgb(140, 190, 196)
$lblDom.Dock = 'Fill'
$lblDom.TextAlign = 'MiddleRight'
$lblDom.BackColor = [System.Drawing.Color]::Transparent
$hdrLayout.Controls.Add($lblDom, 1, 0)
$hdrLayout.SetRowSpan($lblDom, 2)

$lblTagline = New-Object System.Windows.Forms.Label
$lblTagline.Text = 'Compare delayed replicas and restore attributes to the PDC'
$lblTagline.Font = $script:Theme.FontSub
$lblTagline.ForeColor = [System.Drawing.Color]::FromArgb(160, 176, 190)
$lblTagline.Dock = 'Fill'
$lblTagline.TextAlign = 'MiddleLeft'
$lblTagline.BackColor = [System.Drawing.Color]::Transparent
$hdrLayout.Controls.Add($lblTagline, 0, 1)

# --- Main split: work area (grows) / activity log (draggable) ---
$splitMain = New-Object System.Windows.Forms.SplitContainer
$splitMain.Dock = 'Fill'
$splitMain.Orientation = 'Horizontal'
$splitMain.BackColor = $script:Theme.Border
$splitMain.SplitterWidth = 6
$splitMain.Panel1MinSize = 280
$splitMain.Panel2MinSize = 70
$splitMain.FixedPanel = 'None'

# Work panel (top of split)
$pnlWork = New-Object System.Windows.Forms.Panel
$pnlWork.Dock = 'Fill'
$pnlWork.BackColor = $script:Theme.BgApp
$pnlWork.Padding = New-Object System.Windows.Forms.Padding(12, 10, 12, 6)
$splitMain.Panel1.Controls.Add($pnlWork)

# Activity panel (bottom of split) — user can drag splitter
$pnlStatus = New-Object System.Windows.Forms.Panel
$pnlStatus.Dock = 'Fill'
$pnlStatus.BackColor = $script:Theme.BgStatus
$pnlStatus.Padding = New-Object System.Windows.Forms.Padding(14, 6, 14, 8)
$splitMain.Panel2.Controls.Add($pnlStatus)

$lblStatusTitle = New-Object System.Windows.Forms.Label
$lblStatusTitle.Text = 'ACTIVITY  (drag the bar above to resize)'
$lblStatusTitle.Font = $script:Theme.FontSection
$lblStatusTitle.ForeColor = [System.Drawing.Color]::FromArgb(140, 190, 196)
$lblStatusTitle.Dock = 'Top'
$lblStatusTitle.Height = 20
$lblStatusTitle.BackColor = [System.Drawing.Color]::Transparent
$pnlStatus.Controls.Add($lblStatusTitle)

$script:StatusBox = New-Object System.Windows.Forms.TextBox
$script:StatusBox.Multiline = $true
$script:StatusBox.ScrollBars = 'Both'
$script:StatusBox.WordWrap = $false
$script:StatusBox.ReadOnly = $true
$script:StatusBox.BorderStyle = 'None'
$script:StatusBox.BackColor = $script:Theme.BgStatus
$script:StatusBox.ForeColor = [System.Drawing.Color]::FromArgb(200, 214, 224)
$script:StatusBox.Font = $script:Theme.FontMono
$script:StatusBox.Dock = 'Fill'
$pnlStatus.Controls.Add($script:StatusBox)
$script:StatusBox.BringToFront()

# Form control order: Fill first, then Top header
$form.Controls.Add($splitMain)
$form.Controls.Add($pnlHeader)

# Work area uses Dock Top / Fill / Bottom so Results expands with the window
# Add Fill control first, then Bottom, then Tops (WinForms dock order)
$pnlResults = New-Object System.Windows.Forms.Panel
$pnlResults.Dock = 'Fill'
$pnlResults.BackColor = $script:Theme.BgPanel
$pnlResults.Padding = New-Object System.Windows.Forms.Padding(10, 6, 10, 8)
$pnlWork.Controls.Add($pnlResults)

$pnlActions = New-Object System.Windows.Forms.Panel
$pnlActions.Dock = 'Bottom'
$pnlActions.Height = 46
$pnlActions.BackColor = $script:Theme.BgApp
$pnlWork.Controls.Add($pnlActions)

$pnlQ = New-Object System.Windows.Forms.Panel
$pnlQ.Dock = 'Top'
$pnlQ.Height = 98
$pnlQ.BackColor = $script:Theme.BgPanel
$pnlQ.Padding = New-Object System.Windows.Forms.Padding(10, 6, 10, 6)
$pnlQ.Margin = New-Object System.Windows.Forms.Padding(0)
$pnlWork.Controls.Add($pnlQ)

$gapQ = New-Object System.Windows.Forms.Panel
$gapQ.Dock = 'Top'
$gapQ.Height = 10
$gapQ.BackColor = $script:Theme.BgApp
$pnlWork.Controls.Add($gapQ)

$pnlDc = New-Object System.Windows.Forms.Panel
$pnlDc.Dock = 'Top'
$pnlDc.Height = 138
$pnlDc.BackColor = $script:Theme.BgPanel
$pnlDc.Padding = New-Object System.Windows.Forms.Padding(10, 6, 10, 6)
$pnlWork.Controls.Add($pnlDc)

# ========== DOMAIN CONTROLLERS ==========
$bar1 = New-Object System.Windows.Forms.Panel
$bar1.Dock = 'Left'
$bar1.Width = 4
$bar1.BackColor = $script:Theme.Accent
$pnlDc.Controls.Add($bar1)

$dcInner = New-Object System.Windows.Forms.TableLayoutPanel
$dcInner.Dock = 'Fill'
$dcInner.ColumnCount = 1
$dcInner.RowCount = 2
$dcInner.BackColor = $script:Theme.BgPanel
[void]$dcInner.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$dcInner.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 22)))
[void]$dcInner.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$pnlDc.Controls.Add($dcInner)
$dcInner.BringToFront()

$lblDcSection = New-Object System.Windows.Forms.Label
$lblDcSection.Text = 'DOMAIN CONTROLLERS'
$lblDcSection.Font = $script:Theme.FontSection
$lblDcSection.ForeColor = $script:Theme.TextPrimary
$lblDcSection.Dock = 'Fill'
$lblDcSection.TextAlign = 'MiddleLeft'
$lblDcSection.BackColor = [System.Drawing.Color]::Transparent
$dcInner.Controls.Add($lblDcSection, 0, 0)

# 3 field columns + 1 button column (fixed) — buttons cannot cover fields
$dcCols = New-Object System.Windows.Forms.TableLayoutPanel
$dcCols.Dock = 'Fill'
$dcCols.ColumnCount = 4
$dcCols.RowCount = 1
$dcCols.BackColor = $script:Theme.BgPanel
[void]$dcCols.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 33.33)))
[void]$dcCols.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 33.33)))
[void]$dcCols.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 33.34)))
[void]$dcCols.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 150)))
[void]$dcCols.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$dcInner.Controls.Add($dcCols, 0, 1)

$txtPdc = New-ThemedTextBox -Location (New-Object System.Drawing.Point(0, 0)) -Size (New-Object System.Drawing.Size(100, 24)) -ReadOnly
$lblPdcSync = New-Object System.Windows.Forms.Label
$lblPdcSync.Text = 'Last sync: —'
$dcCols.Controls.Add((New-StackedField -Caption 'PDC Emulator' -InputControl $txtPdc -SyncLabel $lblPdcSync), 0, 0)

$cmbR1 = New-ThemedCombo -Location (New-Object System.Drawing.Point(0, 0)) -Size (New-Object System.Drawing.Size(100, 24))
$lblR1Sync = New-Object System.Windows.Forms.Label
$lblR1Sync.Text = 'Last sync: —'
$dcCols.Controls.Add((New-StackedField -Caption 'Delayed Replica 1' -InputControl $cmbR1 -SyncLabel $lblR1Sync), 1, 0)

$cmbR2 = New-ThemedCombo -Location (New-Object System.Drawing.Point(0, 0)) -Size (New-Object System.Drawing.Size(100, 24))
$lblR2Sync = New-Object System.Windows.Forms.Label
$lblR2Sync.Text = 'Last sync: —'
$dcCols.Controls.Add((New-StackedField -Caption 'Delayed Replica 2' -InputControl $cmbR2 -SyncLabel $lblR2Sync), 2, 0)

$pnlDcBtns = New-Object System.Windows.Forms.Panel
$pnlDcBtns.Dock = 'Fill'
$pnlDcBtns.Padding = New-Object System.Windows.Forms.Padding(8, 22, 4, 4)
$pnlDcBtns.BackColor = $script:Theme.BgPanel
$dcCols.Controls.Add($pnlDcBtns, 3, 0)

$btnDiscover = New-FlatButton -Text 'Discover DCs' -Location (New-Object System.Drawing.Point(8, 22)) `
    -Size (New-Object System.Drawing.Size(130, 32)) -BackColor $script:Theme.Accent -ForeColor ([System.Drawing.Color]::White)
$btnDiscover.Dock = 'Top'
$btnDiscover.Height = 32
$pnlDcBtns.Controls.Add($btnDiscover)

$spacerBtn = New-Object System.Windows.Forms.Panel
$spacerBtn.Dock = 'Top'
$spacerBtn.Height = 8
$spacerBtn.BackColor = $script:Theme.BgPanel
$pnlDcBtns.Controls.Add($spacerBtn)

$btnRefreshSync = New-FlatButton -Text 'Refresh Sync' -Location (New-Object System.Drawing.Point(8, 62)) `
    -Size (New-Object System.Drawing.Size(130, 28)) -Secondary
$btnRefreshSync.Dock = 'Top'
$btnRefreshSync.Height = 28
$pnlDcBtns.Controls.Add($btnRefreshSync)

# Dock Top order: last added appears at top — add Refresh, spacer, Discover so Discover is on top
$pnlDcBtns.Controls.Clear()
$pnlDcBtns.Controls.Add($btnRefreshSync)  # bottom
$pnlDcBtns.Controls.Add($spacerBtn)
$pnlDcBtns.Controls.Add($btnDiscover)     # top

# ========== COMPARISON TARGET ==========
$bar2 = New-Object System.Windows.Forms.Panel
$bar2.Dock = 'Left'
$bar2.Width = 4
$bar2.BackColor = $script:Theme.Accent
$pnlQ.Controls.Add($bar2)

$qInner = New-Object System.Windows.Forms.TableLayoutPanel
$qInner.Dock = 'Fill'
$qInner.ColumnCount = 1
$qInner.RowCount = 2
$qInner.BackColor = $script:Theme.BgPanel
[void]$qInner.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$qInner.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 22)))
[void]$qInner.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$pnlQ.Controls.Add($qInner)
$qInner.BringToFront()

$lblQSection = New-Object System.Windows.Forms.Label
$lblQSection.Text = 'COMPARISON TARGET'
$lblQSection.Font = $script:Theme.FontSection
$lblQSection.ForeColor = $script:Theme.TextPrimary
$lblQSection.Dock = 'Fill'
$lblQSection.TextAlign = 'MiddleLeft'
$lblQSection.BackColor = [System.Drawing.Color]::Transparent
$qInner.Controls.Add($lblQSection, 0, 0)

$qCols = New-Object System.Windows.Forms.TableLayoutPanel
$qCols.Dock = 'Fill'
$qCols.ColumnCount = 6
$qCols.RowCount = 2
$qCols.BackColor = $script:Theme.BgPanel
[void]$qCols.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 160))) # Target
[void]$qCols.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 25)))   # Filter/Zone/DN
[void]$qCols.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 35)))   # SearchBase / Load Zones
[void]$qCols.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 140))) # Diff checkbox
[void]$qCols.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 120))) # Compare
[void]$qCols.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 100))) # Cancel
[void]$qCols.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 20)))
[void]$qCols.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 30)))
$qInner.Controls.Add($qCols, 0, 1)

$lblType = New-Object System.Windows.Forms.Label
$lblType.Text = 'Target'
$lblType.Font = $script:Theme.FontUi
$lblType.ForeColor = $script:Theme.TextMuted
$lblType.Dock = 'Fill'
$lblType.TextAlign = 'BottomLeft'
$qCols.Controls.Add($lblType, 0, 0)

$cmbType = New-ThemedCombo -Location (New-Object System.Drawing.Point(0, 0)) -Size (New-Object System.Drawing.Size(150, 24))
$cmbType.Dock = 'Fill'
[void]$cmbType.Items.AddRange([string[]]@('Users','Computers','Groups','DNS','GroupPolicy','Replication Metadata'))
$cmbType.SelectedIndex = 0
$qCols.Controls.Add($cmbType, 0, 1)

# Filter column hosts Name filter OR Zone OR DN depending on target
$pnlFilterHost = New-Object System.Windows.Forms.Panel
$pnlFilterHost.Dock = 'Fill'
$pnlFilterHost.BackColor = $script:Theme.BgPanel
$qCols.Controls.Add($pnlFilterHost, 1, 0)
$qCols.SetRowSpan($pnlFilterHost, 2)

$lblFilter = New-Object System.Windows.Forms.Label
$lblFilter.Text = 'sAMAccountName / UPN'
$lblFilter.Font = $script:Theme.FontUi
$lblFilter.ForeColor = $script:Theme.TextMuted
$lblFilter.Location = New-Object System.Drawing.Point(4, 0)
$lblFilter.Size = New-Object System.Drawing.Size(200, 20)
$pnlFilterHost.Controls.Add($lblFilter)

$txtFilter = New-ThemedTextBox -Location (New-Object System.Drawing.Point(4, 22)) -Size (New-Object System.Drawing.Size(200, 24))
$txtFilter.Anchor = 'Top,Left,Right'
$pnlFilterHost.Controls.Add($txtFilter)

$lblZone = New-Object System.Windows.Forms.Label
$lblZone.Text = 'DNS Zone'
$lblZone.Font = $script:Theme.FontUi
$lblZone.ForeColor = $script:Theme.TextMuted
$lblZone.Location = New-Object System.Drawing.Point(4, 0)
$lblZone.Size = New-Object System.Drawing.Size(200, 20)
$lblZone.Visible = $false
$pnlFilterHost.Controls.Add($lblZone)

$cmbZone = New-ThemedCombo -Location (New-Object System.Drawing.Point(4, 22)) -Size (New-Object System.Drawing.Size(200, 24))
$cmbZone.Anchor = 'Top,Left,Right'
$cmbZone.Visible = $false
$pnlFilterHost.Controls.Add($cmbZone)

$lblDn = New-Object System.Windows.Forms.Label
$lblDn.Text = 'Object DN (metadata)'
$lblDn.Font = $script:Theme.FontUi
$lblDn.ForeColor = $script:Theme.TextMuted
$lblDn.Location = New-Object System.Drawing.Point(4, 0)
$lblDn.Size = New-Object System.Drawing.Size(200, 20)
$lblDn.Visible = $false
$pnlFilterHost.Controls.Add($lblDn)

$txtDn = New-ThemedTextBox -Location (New-Object System.Drawing.Point(4, 22)) -Size (New-Object System.Drawing.Size(200, 24))
$txtDn.Anchor = 'Top,Left,Right'
$txtDn.Visible = $false
$pnlFilterHost.Controls.Add($txtDn)

# SearchBase / Load Zones host
$pnlBaseHost = New-Object System.Windows.Forms.Panel
$pnlBaseHost.Dock = 'Fill'
$pnlBaseHost.BackColor = $script:Theme.BgPanel
$qCols.Controls.Add($pnlBaseHost, 2, 0)
$qCols.SetRowSpan($pnlBaseHost, 2)

$lblBase = New-Object System.Windows.Forms.Label
$lblBase.Text = 'SearchBase (optional)'
$lblBase.Font = $script:Theme.FontUi
$lblBase.ForeColor = $script:Theme.TextMuted
$lblBase.Location = New-Object System.Drawing.Point(4, 0)
$lblBase.Size = New-Object System.Drawing.Size(260, 20)
$pnlBaseHost.Controls.Add($lblBase)

$txtBase = New-ThemedTextBox -Location (New-Object System.Drawing.Point(4, 22)) -Size (New-Object System.Drawing.Size(260, 24))
$txtBase.Anchor = 'Top,Left,Right'
$pnlBaseHost.Controls.Add($txtBase)

$btnZones = New-FlatButton -Text 'Load Zones' -Location (New-Object System.Drawing.Point(4, 20)) `
    -Size (New-Object System.Drawing.Size(110, 28)) -Secondary
$btnZones.Visible = $false
$pnlBaseHost.Controls.Add($btnZones)

$chkDiff = New-Object System.Windows.Forms.CheckBox
$chkDiff.Text = 'Differences only'
$chkDiff.Dock = 'Fill'
$chkDiff.Checked = $true
$chkDiff.Font = $script:Theme.FontUi
$chkDiff.ForeColor = $script:Theme.TextPrimary
$chkDiff.BackColor = [System.Drawing.Color]::Transparent
$chkDiff.Padding = New-Object System.Windows.Forms.Padding(4, 18, 0, 0)
$qCols.Controls.Add($chkDiff, 3, 0)
$qCols.SetRowSpan($chkDiff, 2)

$btnCompare = New-FlatButton -Text 'Compare' -Location (New-Object System.Drawing.Point(0, 0)) `
    -Size (New-Object System.Drawing.Size(110, 32)) -BackColor $script:Theme.Accent -ForeColor ([System.Drawing.Color]::White)
$btnCompare.Enabled = $false
$btnCompare.Dock = 'Bottom'
$btnCompare.Height = 32
$qCols.Controls.Add($btnCompare, 4, 1)

$btnCancel = New-FlatButton -Text 'Cancel' -Location (New-Object System.Drawing.Point(0, 0)) `
    -Size (New-Object System.Drawing.Size(90, 32)) -Secondary
$btnCancel.Enabled = $false
$btnCancel.Dock = 'Bottom'
$btnCancel.Height = 32
$qCols.Controls.Add($btnCancel, 5, 1)

$pnlFilterHost.Add_Resize({
    $rw = [Math]::Max(80, $pnlFilterHost.ClientSize.Width - 8)
    $txtFilter.Width = $rw
    $cmbZone.Width = $rw
    $txtDn.Width = $rw
})
$pnlBaseHost.Add_Resize({
    $rw = [Math]::Max(80, $pnlBaseHost.ClientSize.Width - 8)
    $txtBase.Width = $rw
})

# ========== RESULTS ==========
$resInner = New-Object System.Windows.Forms.TableLayoutPanel
$resInner.Dock = 'Fill'
$resInner.ColumnCount = 1
$resInner.RowCount = 2
$resInner.BackColor = $script:Theme.BgPanel
[void]$resInner.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$resInner.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 26)))
[void]$resInner.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$pnlResults.Controls.Add($resInner)

$hdrResults = New-Object System.Windows.Forms.FlowLayoutPanel
$hdrResults.Dock = 'Fill'
$hdrResults.FlowDirection = 'LeftToRight'
$hdrResults.WrapContents = $false
$hdrResults.BackColor = $script:Theme.BgPanel
$resInner.Controls.Add($hdrResults, 0, 0)

$lblResults = New-Object System.Windows.Forms.Label
$lblResults.Text = 'RESULTS'
$lblResults.Font = $script:Theme.FontSection
$lblResults.ForeColor = $script:Theme.TextPrimary
$lblResults.AutoSize = $true
$lblResults.Margin = New-Object System.Windows.Forms.Padding(0, 4, 12, 0)
$hdrResults.Controls.Add($lblResults)

$lblCount = New-Object System.Windows.Forms.Label
$lblCount.Text = '0 rows'
$lblCount.Font = $script:Theme.FontUi
$lblCount.ForeColor = $script:Theme.TextMuted
$lblCount.AutoSize = $true
$lblCount.Margin = New-Object System.Windows.Forms.Padding(0, 5, 12, 0)
$hdrResults.Controls.Add($lblCount)

$btnCheckDiffs = New-FlatButton -Text 'Check Differences' -Location (New-Object System.Drawing.Point(0, 0)) `
    -Size (New-Object System.Drawing.Size(140, 26)) -Secondary
$btnCheckDiffs.Margin = New-Object System.Windows.Forms.Padding(8, 1, 6, 0)
$hdrResults.Controls.Add($btnCheckDiffs)

$btnClearChecks = New-FlatButton -Text 'Clear Checks' -Location (New-Object System.Drawing.Point(0, 0)) `
    -Size (New-Object System.Drawing.Size(110, 26)) -Secondary
$btnClearChecks.Margin = New-Object System.Windows.Forms.Padding(0, 1, 0, 0)
$hdrResults.Controls.Add($btnClearChecks)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = 'Fill'
Set-ModernGridStyle -Grid $grid
$resInner.Controls.Add($grid, 0, 1)

# Checkbox column for pick-and-choose restore
$colSelect = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$colSelect.HeaderText = 'Restore?'
$colSelect.Name = 'Select'
$colSelect.Width = 70
$colSelect.FillWeight = 7
$colSelect.MinimumWidth = 60
$colSelect.TrueValue = $true
$colSelect.FalseValue = $false
$colSelect.ThreeState = $false
$colSelect.ToolTipText = 'Check each change you want to restore to the PDC'
[void]$grid.Columns.Add($colSelect)

Add-GridColumns -Grid $grid -Columns @(
    (New-GridColumn -Header 'Object'     -Name 'Object'     -Width 160 -FillWeight 17),
    (New-GridColumn -Header 'Attribute'  -Name 'Attribute'  -Width 120 -FillWeight 13),
    (New-GridColumn -Header 'PDC'        -Name 'PDC'        -Width 200 -FillWeight 21),
    (New-GridColumn -Header 'Replica 1'  -Name 'Replica1'   -Width 200 -FillWeight 21),
    (New-GridColumn -Header 'Replica 2'  -Name 'Replica2'   -Width 200 -FillWeight 21),
    (New-GridColumn -Header 'Status'     -Name 'Status'     -Width 90  -FillWeight 9),
    (New-GridColumn -Header 'GUID'       -Name 'ObjectGUID' -Width 80  -FillWeight 1 -Hidden),
    (New-GridColumn -Header 'DN'         -Name 'DN'         -Width 80  -FillWeight 1 -Hidden),
    (New-GridColumn -Header 'Restorable' -Name 'Restorable' -Width 80  -FillWeight 1 -Hidden)
)

# Only the Select checkbox is editable
foreach ($c in $grid.Columns) {
    if ($c.Name -ne 'Select') { $c.ReadOnly = $true }
}

# ========== ACTIONS ==========

$btnRestore = New-FlatButton -Text 'Restore Checked  →  PDC' -Location (New-Object System.Drawing.Point(0, 8)) `
    -Size (New-Object System.Drawing.Size(220, 32)) -BackColor $script:Theme.Accent -ForeColor ([System.Drawing.Color]::White)
$btnRestore.Enabled = $false
$pnlActions.Controls.Add($btnRestore)

$btnDetails = New-FlatButton -Text 'View Details' -Location (New-Object System.Drawing.Point(232, 8)) `
    -Size (New-Object System.Drawing.Size(120, 32)) -Secondary
$btnDetails.Enabled = $false
$pnlActions.Controls.Add($btnDetails)

$btnExport = New-FlatButton -Text 'Export CSV' -Location (New-Object System.Drawing.Point(364, 8)) `
    -Size (New-Object System.Drawing.Size(110, 32)) -Secondary
$pnlActions.Controls.Add($btnExport)

$swDiff = New-Object System.Windows.Forms.Panel
$swDiff.Location = New-Object System.Drawing.Point(500, 16)
$swDiff.Size = New-Object System.Drawing.Size(12, 12)
$swDiff.BackColor = $script:Theme.DiffBg
$pnlActions.Controls.Add($swDiff)
$lblLeg1 = New-Object System.Windows.Forms.Label
$lblLeg1.Text = 'Different'
$lblLeg1.Location = New-Object System.Drawing.Point(516, 13)
$lblLeg1.AutoSize = $true
$lblLeg1.ForeColor = $script:Theme.TextMuted
$pnlActions.Controls.Add($lblLeg1)

$swMiss = New-Object System.Windows.Forms.Panel
$swMiss.Location = New-Object System.Drawing.Point(590, 16)
$swMiss.Size = New-Object System.Drawing.Size(12, 12)
$swMiss.BackColor = $script:Theme.MissingBg
$pnlActions.Controls.Add($swMiss)
$lblLeg2 = New-Object System.Windows.Forms.Label
$lblLeg2.Text = 'Missing object'
$lblLeg2.Location = New-Object System.Drawing.Point(606, 13)
$lblLeg2.AutoSize = $true
$lblLeg2.ForeColor = $script:Theme.TextMuted
$pnlActions.Controls.Add($lblLeg2)

$swMatch = New-Object System.Windows.Forms.Panel
$swMatch.Location = New-Object System.Drawing.Point(720, 16)
$swMatch.Size = New-Object System.Drawing.Size(12, 12)
$swMatch.BackColor = $script:Theme.MatchBg
$pnlActions.Controls.Add($swMatch)
$lblLeg3 = New-Object System.Windows.Forms.Label
$lblLeg3.Text = 'Match'
$lblLeg3.Location = New-Object System.Drawing.Point(736, 13)
$lblLeg3.AutoSize = $true
$lblLeg3.ForeColor = $script:Theme.TextMuted
$pnlActions.Controls.Add($lblLeg3)

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 300

function Update-SplitLayout {
    if ($form.IsDisposed -or $splitMain.IsDisposed) { return }
    try {
        # Keep ~18% for activity, rest for results/work — scales with window height
        $h = $splitMain.ClientSize.Height
        if ($h -lt 200) { return }
        $activity = [Math]::Max(80, [Math]::Min(220, [int]($h * 0.18)))
        $desired = $h - $activity - $splitMain.SplitterWidth
        if ($desired -lt $splitMain.Panel1MinSize) { $desired = $splitMain.Panel1MinSize }
        if ($desired -gt ($h - $splitMain.Panel2MinSize - $splitMain.SplitterWidth)) {
            $desired = $h - $splitMain.Panel2MinSize - $splitMain.SplitterWidth
        }
        # Only auto-adjust when user hasn't dragged far from the ratio (or on first show)
        if (-not $script:SplitUserAdjusted) {
            $splitMain.SplitterDistance = $desired
        }
    } catch { }
}

$script:SplitUserAdjusted = $false
$splitMain.Add_SplitterMoved({ $script:SplitUserAdjusted = $true })
$form.Add_Resize({
    # Re-apply proportional split only until the user drags the splitter once
    if (-not $script:SplitUserAdjusted) { Update-SplitLayout }
})

$form.ResumeLayout($true)

# ---------------------------------------------------------------------------
# Contextual visibility
# ---------------------------------------------------------------------------
function Update-ContextControls {
    $t = $cmbType.SelectedItem
    $isObj = $t -in @('Users','Computers','Groups')
    $isDns = ($t -eq 'DNS')
    $isMeta = ($t -eq 'Replication Metadata')

    $lblFilter.Visible = $isObj; $txtFilter.Visible = $isObj
    $lblBase.Visible = $isObj;   $txtBase.Visible = $isObj
    $lblZone.Visible = $isDns;   $cmbZone.Visible = $isDns; $btnZones.Visible = $isDns
    $lblDn.Visible = $isMeta;    $txtDn.Visible = $isMeta

    $btnRestore.Enabled = $false
    $btnRestore.Text = 'Restore Checked  →  PDC'
}
$cmbType.Add_SelectedIndexChanged({ Update-ContextControls })

$cmbR1.Add_SelectedIndexChanged({
    if ($txtPdc.Text) {
        $info = Get-DcLastReplicationInfo -Server ([string]$cmbR1.SelectedItem)
        $lblR1Sync.Text = $info.Text
        if ($info.Detail) { $lblR1Sync.Text = "$($info.Text)  ·  $($info.Detail)" }
    }
})
$cmbR2.Add_SelectedIndexChanged({
    if ($txtPdc.Text) {
        $info = Get-DcLastReplicationInfo -Server ([string]$cmbR2.SelectedItem)
        $lblR2Sync.Text = $info.Text
        if ($info.Detail) { $lblR2Sync.Text = "$($info.Text)  ·  $($info.Detail)" }
    }
})

# ---------------------------------------------------------------------------
# Discover DCs
# ---------------------------------------------------------------------------
$btnDiscover.Add_Click({
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Status 'Discovering domain controllers...'
        $domain = Get-ADDomain -ErrorAction Stop
        $pdc = $domain.PDCEmulator
        $txtPdc.Text = $pdc
        $lblDom.Text = "Domain: $($domain.DNSRoot)"

        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName | Sort-Object
        $cmbR1.Items.Clear(); $cmbR2.Items.Clear()
        foreach ($d in $dcs) { [void]$cmbR1.Items.Add($d); [void]$cmbR2.Items.Add($d) }

        $others = @($dcs | Where-Object { $_ -ne $pdc })
        if ($others.Count -ge 1) { $cmbR1.SelectedItem = $others[0] }
        if ($others.Count -ge 2) { $cmbR2.SelectedItem = $others[1] }
        elseif ($others.Count -ge 1) { $cmbR2.SelectedItem = $others[0] }

        $btnCompare.Enabled = $true
        Write-Status ("Found PDC '{0}' and {1} DC(s). Reading last replication times..." -f $pdc, $dcs.Count)
        Update-ReplicationLabels
        Write-Status 'Replication timestamps updated.'
    }
    catch {
        Write-Status $_.Exception.Message 'ERROR'
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,'Discovery failed','OK','Error') | Out-Null
    }
})

$btnRefreshSync.Add_Click({
    if (-not $txtPdc.Text) { Write-Status 'Discover DCs first.' 'WARN'; return }
    try {
        Write-Status 'Refreshing last replication times...'
        Update-ReplicationLabels
        Write-Status 'Replication timestamps updated.'
    } catch {
        Write-Status $_.Exception.Message 'ERROR'
    }
})

$btnZones.Add_Click({
    if (-not $txtPdc.Text) { Write-Status 'Discover DCs first.' 'WARN'; return }
    try {
        Import-Module DnsServer -ErrorAction Stop
        $cmbZone.Items.Clear()
        $zones = Get-DnsServerZone -ComputerName $txtPdc.Text -ErrorAction Stop |
                 Where-Object { -not $_.IsAutoCreated } | Select-Object -ExpandProperty ZoneName | Sort-Object
        foreach ($z in $zones) { [void]$cmbZone.Items.Add($z) }
        if ($cmbZone.Items.Count -gt 0) { $cmbZone.SelectedIndex = 0 }
        Write-Status ("Loaded {0} DNS zone(s)." -f $zones.Count)
    }
    catch { Write-Status $_.Exception.Message 'ERROR' }
})

# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------
function Start-Comparison {
    if (-not $cmbR1.SelectedItem -or -not $cmbR2.SelectedItem) {
        [System.Windows.Forms.MessageBox]::Show('Select both delayed replicas.','Missing input','OK','Warning') | Out-Null
        return
    }
    if ($cmbR1.SelectedItem -eq $cmbR2.SelectedItem) {
        [System.Windows.Forms.MessageBox]::Show('Replica 1 and Replica 2 must be different DCs.','Invalid selection','OK','Warning') | Out-Null
        return
    }
    if ($txtBase.Text -and -not (Test-DistinguishedName $txtBase.Text)) {
        [System.Windows.Forms.MessageBox]::Show(
            "SearchBase must be a valid Distinguished Name (e.g., OU=Users,DC=domain,DC=com)",
            'Invalid DN', 'OK', 'Warning') | Out-Null
        return
    }
    if ($cmbType.SelectedItem -eq 'Replication Metadata' -and $txtDn.Text -and -not (Test-DistinguishedName $txtDn.Text)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Object DN must be a valid Distinguished Name (e.g., CN=User,OU=Users,DC=domain,DC=com)",
            'Invalid DN', 'OK', 'Warning') | Out-Null
        return
    }

    $grid.Rows.Clear()
    $btnCompare.Enabled = $false
    $btnCancel.Enabled = $true
    $btnRestore.Enabled = $false
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    Write-Status ("Comparing {0}  |  PDC={1}  R1={2}  R2={3}" -f $cmbType.SelectedItem, $txtPdc.Text, $cmbR1.SelectedItem, $cmbR2.SelectedItem)

    $script:Runspace = [runspacefactory]::CreateRunspace()
    $script:Runspace.ApartmentState = 'STA'
    $script:Runspace.ThreadOptions = 'ReuseThread'
    $script:Runspace.Open()

    $script:PowerShell = [powershell]::Create()
    $script:PowerShell.Runspace = $script:Runspace
    [void]$script:PowerShell.AddScript($script:CompareScript)
    [void]$script:PowerShell.AddArgument($txtPdc.Text)
    [void]$script:PowerShell.AddArgument([string]$cmbR1.SelectedItem)
    [void]$script:PowerShell.AddArgument([string]$cmbR2.SelectedItem)
    [void]$script:PowerShell.AddArgument([string]$cmbType.SelectedItem)
    [void]$script:PowerShell.AddArgument($txtFilter.Text)
    [void]$script:PowerShell.AddArgument($txtBase.Text)
    [void]$script:PowerShell.AddArgument($txtDn.Text)
    [void]$script:PowerShell.AddArgument([string]$cmbZone.SelectedItem)
    [void]$script:PowerShell.AddArgument([bool]$chkDiff.Checked)
    [void]$script:PowerShell.AddArgument($script:ConvertAdValueDef)
    [void]$script:PowerShell.AddArgument($script:Config.Users)
    [void]$script:PowerShell.AddArgument($script:Config.Computers)
    [void]$script:PowerShell.AddArgument($script:Config.Groups)
    [void]$script:PowerShell.AddArgument($script:NonRestorable)

    $script:Handle = $script:PowerShell.BeginInvoke()
    $timer.Start()
}

$timer.Add_Tick({
    if ($null -eq $script:Handle) { $timer.Stop(); return }

    if ($form.IsDisposed) {
        $timer.Stop()
        if ($script:PowerShell) {
            try { $script:PowerShell.Stop() } catch {}
            try { $script:PowerShell.Dispose() } catch {}
        }
        if ($script:Runspace) {
            try { $script:Runspace.Close(); $script:Runspace.Dispose() } catch {}
        }
        return
    }

    if (-not $script:Handle.IsCompleted) { return }

    $timer.Stop()
    $result = $null
    try { $result = $script:PowerShell.EndInvoke($script:Handle) } catch { Write-Status $_.Exception.Message 'ERROR' }

    try { $script:PowerShell.Dispose() } catch {}
    try { $script:Runspace.Close(); $script:Runspace.Dispose() } catch {}
    $script:PowerShell = $null; $script:Runspace = $null; $script:Handle = $null

    if ($form.IsDisposed) { return }

    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    $btnCompare.Enabled = $true
    $btnCancel.Enabled = $false

    $payload = $result | Select-Object -First 1
    if ($payload -and $payload.Error) {
        Write-Status $payload.Error 'ERROR'
        [System.Windows.Forms.MessageBox]::Show($payload.Error,'Comparison failed','OK','Error') | Out-Null
        return
    }

    $rows = @()
    if ($payload) { $rows = @($payload.Rows) }

    $grid.SuspendLayout()
    foreach ($r in $rows) {
        $canRestore = [bool]$r.Restorable
        $idx = $grid.Rows.Add(@(
            $false,
            $r.Object, $r.Attribute, $r.PDC, $r.Replica1, $r.Replica2, $r.Status,
            $r.ObjectGUID, $r.DN, [string]$r.Restorable
        ))
        $row = $grid.Rows[$idx]
        # Non-restorable rows cannot be checked for restore
        $row.Cells['Select'].ReadOnly = (-not $canRestore)
        if (-not $canRestore) {
            $row.Cells['Select'].ToolTipText = 'Not restorable (system/computed attribute or missing object)'
        }
        switch ($r.Status) {
            'Different'     { $row.DefaultCellStyle.BackColor = $script:Theme.DiffBg }
            'ObjectMissing' { $row.DefaultCellStyle.BackColor = $script:Theme.MissingBg }
            'Match'         { $row.DefaultCellStyle.BackColor = $script:Theme.MatchBg }
        }
    }
    $grid.ResumeLayout()
    $lblCount.Text = "$($grid.Rows.Count) rows"
    Update-RestoreButtonState
    Write-Status ("Comparison complete. {0} row(s). Check the boxes for changes you want to restore." -f $grid.Rows.Count)
})

$btnCompare.Add_Click({ Start-Comparison })

$btnCancel.Add_Click({
    if ($script:PowerShell) {
        try { $script:PowerShell.Stop() } catch {}
        $timer.Stop()
        try { $script:PowerShell.Dispose() } catch {}
        try { $script:Runspace.Close(); $script:Runspace.Dispose() } catch {}
        $script:PowerShell = $null; $script:Runspace = $null; $script:Handle = $null
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
        $btnCompare.Enabled = $true; $btnCancel.Enabled = $false
        Write-Status 'Comparison cancelled.' 'WARN'
    }
})

$grid.Add_SelectionChanged({
    $btnDetails.Enabled = ($grid.SelectedRows.Count -eq 1)
    Update-RestoreButtonState
})

# Commit checkbox edits immediately and refresh restore button
$grid.Add_CurrentCellDirtyStateChanged({
    if ($grid.IsCurrentCellDirty -and $grid.CurrentCell -is [System.Windows.Forms.DataGridViewCheckBoxCell]) {
        [void]$grid.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit)
    }
})
$grid.Add_CellValueChanged({
    param($sender, $e)
    if ($e.RowIndex -lt 0) { return }
    if ($grid.Columns[$e.ColumnIndex].Name -eq 'Select') { Update-RestoreButtonState }
})

function Test-RowChecked {
    param($Row)
    $v = $Row.Cells['Select'].Value
    return ($v -eq $true -or $v -eq 'True' -or $v -eq 1)
}

function Get-CheckedRestoreTargets {
    $targets = New-Object System.Collections.ArrayList
    foreach ($row in $grid.Rows) {
        if ($row.IsNewRow) { continue }
        if (-not (Test-RowChecked $row)) { continue }
        if ([string]$row.Cells['Restorable'].Value -ne 'True') { continue }
        [void]$targets.Add([pscustomobject]@{
            Row       = $row
            Object    = [string]$row.Cells['Object'].Value
            Attribute = [string]$row.Cells['Attribute'].Value
            Guid      = [string]$row.Cells['ObjectGUID'].Value
            PdcVal    = [string]$row.Cells['PDC'].Value
            R1Val     = [string]$row.Cells['Replica1'].Value
            R2Val     = [string]$row.Cells['Replica2'].Value
        })
    }
    return $targets
}

function Update-RestoreButtonState {
    $btnRestore.Enabled = $false
    $btnRestore.Text = 'Restore Checked  →  PDC'
    $t = $cmbType.SelectedItem
    if ($t -notin @('Users','Computers','Groups')) { return }

    $n = 0
    foreach ($row in $grid.Rows) {
        if ($row.IsNewRow) { continue }
        if ((Test-RowChecked $row) -and ([string]$row.Cells['Restorable'].Value -eq 'True')) { $n++ }
    }
    if ($n -lt 1) { return }
    $btnRestore.Enabled = $true
    if ($n -eq 1) {
        $btnRestore.Text = 'Restore Checked  →  PDC'
    } else {
        $btnRestore.Text = ("Restore {0} Checked  →  PDC" -f $n)
    }
}

$btnCheckDiffs.Add_Click({
    if ($cmbType.SelectedItem -notin @('Users','Computers','Groups')) {
        Write-Status 'Restore checkboxes apply to Users / Computers / Groups only.' 'WARN'
        return
    }
    $n = 0
    foreach ($row in $grid.Rows) {
        if ($row.IsNewRow) { continue }
        $restorable = ([string]$row.Cells['Restorable'].Value -eq 'True')
        $isDiff = ([string]$row.Cells['Status'].Value -eq 'Different')
        if ($restorable -and $isDiff) {
            $row.Cells['Select'].Value = $true
            $n++
        } else {
            $row.Cells['Select'].Value = $false
        }
    }
    $grid.EndEdit()
    Update-RestoreButtonState
    Write-Status ("Checked {0} different restorable change(s). Review, then Restore Checked." -f $n)
})

$btnClearChecks.Add_Click({
    foreach ($row in $grid.Rows) {
        if ($row.IsNewRow) { continue }
        $row.Cells['Select'].Value = $false
    }
    $grid.EndEdit()
    Update-RestoreButtonState
    Write-Status 'Cleared all restore checkboxes.'
})

# ---------------------------------------------------------------------------
# Difference detail dialog (double-click or View Details)
# ---------------------------------------------------------------------------
function Get-ValueTokens {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    if ($Value -in @('<object missing>','<missing>')) { return @($Value) }
    # Multi-valued AD attrs are joined with '; ' in Convert-AdValueToString
    $parts = @($Value -split ';\s*' | Where-Object { $_ -ne '' } | ForEach-Object { $_.Trim() })
    if ($parts.Count -le 1) { return @($Value) }
    return ($parts | Sort-Object -Unique)
}

function Get-DiffSummaryText {
    param([string]$PdcVal, [string]$R1Val, [string]$R2Val, [string]$R1Name, [string]$R2Name, [string]$Status)

    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add("Status: $Status")
    [void]$lines.Add('')

    $samePR1 = ($PdcVal -eq $R1Val)
    $samePR2 = ($PdcVal -eq $R2Val)
    $sameR12 = ($R1Val -eq $R2Val)

    if ($Status -eq 'Match') {
        [void]$lines.Add('All three domain controllers report the same value for this attribute.')
    }
    elseif ($Status -eq 'ObjectMissing') {
        [void]$lines.Add('The object is missing on at least one domain controller (see values marked <object missing>).')
    }
    else {
        if (-not $samePR1) { [void]$lines.Add("PDC differs from Replica 1 ($R1Name).") }
        else { [void]$lines.Add("PDC matches Replica 1 ($R1Name).") }
        if (-not $samePR2) { [void]$lines.Add("PDC differs from Replica 2 ($R2Name).") }
        else { [void]$lines.Add("PDC matches Replica 2 ($R2Name).") }
        if ($sameR12) { [void]$lines.Add("Replica 1 and Replica 2 match each other (both differ from PDC, or all three match).") }
        else { [void]$lines.Add("Replica 1 and Replica 2 also differ from each other.") }
    }

    $pTokens = @(Get-ValueTokens $PdcVal)
    $r1Tokens = @(Get-ValueTokens $R1Val)
    $r2Tokens = @(Get-ValueTokens $R2Val)
    $isMulti = ($pTokens.Count -gt 1) -or ($r1Tokens.Count -gt 1) -or ($r2Tokens.Count -gt 1)

    if ($isMulti -and $Status -eq 'Different') {
        [void]$lines.Add('')
        [void]$lines.Add('--- Multi-value breakdown ---')

        $onlyPdcVsR1 = @($pTokens | Where-Object { $_ -notin $r1Tokens })
        $onlyR1VsPdc = @($r1Tokens | Where-Object { $_ -notin $pTokens })
        $onlyPdcVsR2 = @($pTokens | Where-Object { $_ -notin $r2Tokens })
        $onlyR2VsPdc = @($r2Tokens | Where-Object { $_ -notin $pTokens })

        if ($onlyPdcVsR1.Count -gt 0) {
            [void]$lines.Add(("On PDC but not Replica 1 ({0}):" -f $onlyPdcVsR1.Count))
            foreach ($x in ($onlyPdcVsR1 | Select-Object -First 40)) { [void]$lines.Add("  + $x") }
            if ($onlyPdcVsR1.Count -gt 40) { [void]$lines.Add(("  ... and {0} more" -f ($onlyPdcVsR1.Count - 40))) }
        }
        if ($onlyR1VsPdc.Count -gt 0) {
            [void]$lines.Add(("On Replica 1 but not PDC ({0}):" -f $onlyR1VsPdc.Count))
            foreach ($x in ($onlyR1VsPdc | Select-Object -First 40)) { [void]$lines.Add("  + $x") }
            if ($onlyR1VsPdc.Count -gt 40) { [void]$lines.Add(("  ... and {0} more" -f ($onlyR1VsPdc.Count - 40))) }
        }
        if ($onlyPdcVsR2.Count -gt 0) {
            [void]$lines.Add(("On PDC but not Replica 2 ({0}):" -f $onlyPdcVsR2.Count))
            foreach ($x in ($onlyPdcVsR2 | Select-Object -First 40)) { [void]$lines.Add("  + $x") }
            if ($onlyPdcVsR2.Count -gt 40) { [void]$lines.Add(("  ... and {0} more" -f ($onlyPdcVsR2.Count - 40))) }
        }
        if ($onlyR2VsPdc.Count -gt 0) {
            [void]$lines.Add(("On Replica 2 but not PDC ({0}):" -f $onlyR2VsPdc.Count))
            foreach ($x in ($onlyR2VsPdc | Select-Object -First 40)) { [void]$lines.Add("  + $x") }
            if ($onlyR2VsPdc.Count -gt 40) { [void]$lines.Add(("  ... and {0} more" -f ($onlyR2VsPdc.Count - 40))) }
        }
        if ($onlyPdcVsR1.Count -eq 0 -and $onlyR1VsPdc.Count -eq 0 -and $onlyPdcVsR2.Count -eq 0 -and $onlyR2VsPdc.Count -eq 0) {
            [void]$lines.Add('(Values differ as whole strings but token sets look identical — check whitespace/order.)')
        }
    }

    return ($lines -join "`r`n")
}

function Show-DifferenceDetail {
    param(
        [string]$ObjectName,
        [string]$Attribute,
        [string]$Guid,
        [string]$Dn,
        [string]$Status,
        [string]$PdcName,
        [string]$PdcVal,
        [string]$R1Name,
        [string]$R1Val,
        [string]$R2Name,
        [string]$R2Val,
        [string]$TargetType,
        [bool]$Restorable = $false,
        $SourceRow = $null
    )

    $script:DetailAction = $null  # 'check' | 'restore' | $null

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'Difference Details'
    $dlg.Size = New-Object System.Drawing.Size(980, 640)
    $dlg.MinimumSize = New-Object System.Drawing.Size(800, 520)
    $dlg.StartPosition = 'CenterParent'
    $dlg.BackColor = $script:Theme.BgApp
    $dlg.Font = $script:Theme.FontUi
    $dlg.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::None

    $hdr = New-Object System.Windows.Forms.Panel
    $hdr.Dock = 'Top'
    $hdr.Height = 72
    $hdr.BackColor = $script:Theme.BgHeader
    $dlg.Controls.Add($hdr)

    $ht = New-Object System.Windows.Forms.Label
    $ht.Text = 'Attribute difference details'
    $ht.Font = $script:Theme.FontTitle
    $ht.ForeColor = $script:Theme.TextOnDark
    $ht.Location = New-Object System.Drawing.Point(18, 12)
    $ht.AutoSize = $true
    $ht.BackColor = [System.Drawing.Color]::Transparent
    $hdr.Controls.Add($ht)

    $hs = New-Object System.Windows.Forms.Label
    $hs.Text = ("{0}  ·  {1}  ·  {2}" -f $ObjectName, $Attribute, $Status)
    $hs.Font = $script:Theme.FontSub
    $hs.ForeColor = [System.Drawing.Color]::FromArgb(160, 176, 190)
    $hs.Location = New-Object System.Drawing.Point(20, 44)
    $hs.AutoSize = $true
    $hs.BackColor = [System.Drawing.Color]::Transparent
    $hdr.Controls.Add($hs)

    $footer = New-Object System.Windows.Forms.Panel
    $footer.Dock = 'Bottom'
    $footer.Height = 48
    $footer.BackColor = $script:Theme.BgApp
    $dlg.Controls.Add($footer)

    $btnClose = New-FlatButton -Text 'Close' -Location (New-Object System.Drawing.Point(850, 8)) `
        -Size (New-Object System.Drawing.Size(100, 32)) -Secondary
    $btnClose.Anchor = 'Top,Right'
    $btnClose.DialogResult = 'Cancel'
    $footer.Controls.Add($btnClose)
    $dlg.CancelButton = $btnClose

    $btnMark = New-FlatButton -Text 'Check for Restore' -Location (New-Object System.Drawing.Point(14, 8)) `
        -Size (New-Object System.Drawing.Size(150, 32)) -Secondary
    $btnMark.Enabled = $Restorable
    if (-not $Restorable) { $btnMark.Text = 'Not Restorable' }
    $footer.Controls.Add($btnMark)

    $btnRestoreOne = New-FlatButton -Text 'Restore This Change…' -Location (New-Object System.Drawing.Point(176, 8)) `
        -Size (New-Object System.Drawing.Size(180, 32)) -BackColor $script:Theme.Accent -ForeColor ([System.Drawing.Color]::White)
    $btnRestoreOne.Enabled = $Restorable
    $footer.Controls.Add($btnRestoreOne)

    $btnMark.Add_Click({
        $script:DetailAction = 'check'
        $dlg.DialogResult = 'OK'
        $dlg.Close()
    })
    $btnRestoreOne.Add_Click({
        $script:DetailAction = 'restore'
        $dlg.DialogResult = 'OK'
        $dlg.Close()
    })

    $footer.Add_Resize({
        $btnClose.Left = $footer.ClientSize.Width - $btnClose.Width - 16
    })

    $body = New-Object System.Windows.Forms.Panel
    $body.Dock = 'Fill'
    $body.Padding = New-Object System.Windows.Forms.Padding(14)
    $body.BackColor = $script:Theme.BgApp
    $dlg.Controls.Add($body)
    $body.BringToFront()

    $meta = New-Object System.Windows.Forms.Label
    $meta.Dock = 'Top'
    $meta.Height = 56
    $meta.Font = $script:Theme.FontUi
    $meta.ForeColor = $script:Theme.TextPrimary
    $metaText = "Target type: $TargetType`r`nDN: $Dn"
    if ($Guid) { $metaText += "`r`nObjectGUID: $Guid" }
    $meta.Text = $metaText
    $body.Controls.Add($meta)

    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = 'Fill'
    $split.Orientation = 'Horizontal'
    $split.SplitterWidth = 6
    $split.Panel1MinSize = 160
    $split.Panel2MinSize = 100
    $body.Controls.Add($split)
    $split.BringToFront()

    # Three value columns
    $vals = New-Object System.Windows.Forms.TableLayoutPanel
    $vals.Dock = 'Fill'
    $vals.ColumnCount = 3
    $vals.RowCount = 2
    $vals.BackColor = $script:Theme.BgApp
    [void]$vals.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 33.33)))
    [void]$vals.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 33.33)))
    [void]$vals.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 33.34)))
    [void]$vals.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 28)))
    [void]$vals.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $split.Panel1.Controls.Add($vals)

    function New-DetailValuePane {
        param([string]$Title, [string]$Value, [System.Drawing.Color]$AccentBg)
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Text = $Title
        $lbl.Dock = 'Fill'
        $lbl.TextAlign = 'MiddleLeft'
        $lbl.Font = $script:Theme.FontSection
        $lbl.ForeColor = $script:Theme.TextPrimary
        $lbl.Padding = New-Object System.Windows.Forms.Padding(4, 0, 0, 0)

        $tb = New-Object System.Windows.Forms.TextBox
        $tb.Multiline = $true
        $tb.ScrollBars = 'Both'
        $tb.WordWrap = $true
        $tb.ReadOnly = $true
        $tb.Dock = 'Fill'
        $tb.Font = $script:Theme.FontMono
        $tb.BorderStyle = 'FixedSingle'
        $tb.BackColor = $AccentBg
        $tb.ForeColor = $script:Theme.TextPrimary
        $display = if ([string]::IsNullOrEmpty($Value)) { '(empty)' } else { $Value }
        # Show multi-values one per line for readability
        $tokens = @(Get-ValueTokens $Value)
        if ($tokens.Count -gt 1) {
            $tb.Text = ($tokens -join "`r`n")
        } else {
            $tb.Text = $display
        }
        return @{ Label = $lbl; Box = $tb }
    }

    $bgP = $script:Theme.BgPanel
    $bgR1 = $script:Theme.BgPanel
    $bgR2 = $script:Theme.BgPanel
    if ($Status -eq 'Different') {
        if ($PdcVal -ne $R1Val -or $PdcVal -ne $R2Val) { $bgP = $script:Theme.DiffBg }
        if ($R1Val -ne $PdcVal) { $bgR1 = $script:Theme.MissingBg }
        if ($R2Val -ne $PdcVal) { $bgR2 = $script:Theme.MissingBg }
        if ($R1Val -eq $R2Val -and $R1Val -ne $PdcVal) {
            $bgR1 = $script:Theme.MatchBg
            $bgR2 = $script:Theme.MatchBg
        }
    }
    elseif ($Status -eq 'ObjectMissing') {
        $bgP = $script:Theme.MissingBg
        $bgR1 = $script:Theme.MissingBg
        $bgR2 = $script:Theme.MissingBg
    }
    elseif ($Status -eq 'Match') {
        $bgP = $script:Theme.MatchBg; $bgR1 = $script:Theme.MatchBg; $bgR2 = $script:Theme.MatchBg
    }

    $pP = New-DetailValuePane -Title ("PDC  ($PdcName)") -Value $PdcVal -AccentBg $bgP
    $p1 = New-DetailValuePane -Title ("Replica 1  ($R1Name)") -Value $R1Val -AccentBg $bgR1
    $p2 = New-DetailValuePane -Title ("Replica 2  ($R2Name)") -Value $R2Val -AccentBg $bgR2

    $vals.Controls.Add($pP.Label, 0, 0)
    $vals.Controls.Add($p1.Label, 1, 0)
    $vals.Controls.Add($p2.Label, 2, 0)
    $vals.Controls.Add($pP.Box, 0, 1)
    $vals.Controls.Add($p1.Box, 1, 1)
    $vals.Controls.Add($p2.Box, 2, 1)

    $sumBox = New-Object System.Windows.Forms.TextBox
    $sumBox.Multiline = $true
    $sumBox.ScrollBars = 'Vertical'
    $sumBox.ReadOnly = $true
    $sumBox.Dock = 'Fill'
    $sumBox.Font = $script:Theme.FontUi
    $sumBox.BorderStyle = 'FixedSingle'
    $sumBox.BackColor = $script:Theme.BgPanel
    $sumBox.ForeColor = $script:Theme.TextPrimary
    $sumBox.Text = Get-DiffSummaryText -PdcVal $PdcVal -R1Val $R1Val -R2Val $R2Val `
        -R1Name $R1Name -R2Name $R2Name -Status $Status
    $split.Panel2.Controls.Add($sumBox)

    $dlg.Add_Shown({
        try {
            $split.SplitterDistance = [Math]::Max(180, [int]($split.ClientSize.Height * 0.55))
        } catch { }
    })

    [void]$dlg.ShowDialog($form)
    return $script:DetailAction
}

function Show-SelectedRowDetails {
    if ($grid.SelectedRows.Count -ne 1) {
        [System.Windows.Forms.MessageBox]::Show(
            'Select a single results row, then click View Details (or double-click the row).',
            'View Details', 'OK', 'Information') | Out-Null
        return
    }
    $row = $grid.SelectedRows[0]
    $restorable = ([string]$row.Cells['Restorable'].Value -eq 'True')
    $action = Show-DifferenceDetail `
        -ObjectName ([string]$row.Cells['Object'].Value) `
        -Attribute  ([string]$row.Cells['Attribute'].Value) `
        -Guid       ([string]$row.Cells['ObjectGUID'].Value) `
        -Dn         ([string]$row.Cells['DN'].Value) `
        -Status     ([string]$row.Cells['Status'].Value) `
        -PdcName    $txtPdc.Text `
        -PdcVal     ([string]$row.Cells['PDC'].Value) `
        -R1Name     ([string]$cmbR1.SelectedItem) `
        -R1Val      ([string]$row.Cells['Replica1'].Value) `
        -R2Name     ([string]$cmbR2.SelectedItem) `
        -R2Val      ([string]$row.Cells['Replica2'].Value) `
        -TargetType ([string]$cmbType.SelectedItem) `
        -Restorable $restorable `
        -SourceRow  $row

    if ($action -eq 'check') {
        if ($restorable) {
            $row.Cells['Select'].Value = $true
            $grid.EndEdit()
            Update-RestoreButtonState
            Write-Status ("Checked '{0}' on '{1}' for restore." -f $row.Cells['Attribute'].Value, $row.Cells['Object'].Value)
        }
    }
    elseif ($action -eq 'restore') {
        if (-not $restorable) { return }
        # Check only this row, then invoke the normal restore path for a single checked item
        foreach ($r in $grid.Rows) {
            if ($r.IsNewRow) { continue }
            $r.Cells['Select'].Value = $false
        }
        $row.Cells['Select'].Value = $true
        $grid.EndEdit()
        Update-RestoreButtonState
        $btnRestore.PerformClick()
    }
}

$btnDetails.Add_Click({ Show-SelectedRowDetails })
$grid.Add_CellDoubleClick({
    param($sender, $e)
    if ($e.RowIndex -lt 0) { return }
    if ($grid.Columns[$e.ColumnIndex].Name -eq 'Select') { return }
    if ($grid.SelectedRows.Count -ge 1) { Show-SelectedRowDetails }
})

# ---------------------------------------------------------------------------
# Restore dialogs
# ---------------------------------------------------------------------------
function Show-RestoreDialog {
    param($ObjectName,$Attribute,$Guid,$PdcVal,$R1Name,$R1Val,$R2Name,$R2Val)

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'Restore Attribute to PDC'
    $dlg.Size = New-Object System.Drawing.Size(660, 440)
    $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false
    $dlg.BackColor = $script:Theme.BgApp
    $dlg.Font = $script:Theme.FontUi

    $hdr = New-Object System.Windows.Forms.Panel
    $hdr.Dock = 'Top'; $hdr.Height = 56; $hdr.BackColor = $script:Theme.BgHeader
    $dlg.Controls.Add($hdr)
    $ht = New-Object System.Windows.Forms.Label
    $ht.Text = 'Restore to PDC'
    $ht.Font = $script:Theme.FontSection
    $ht.ForeColor = $script:Theme.TextOnDark
    $ht.Location = New-Object System.Drawing.Point(18, 18)
    $ht.AutoSize = $true
    $hdr.Controls.Add($ht)

    $card = New-Object System.Windows.Forms.Panel
    $card.Location = New-Object System.Drawing.Point(16, 68)
    $card.Size = New-Object System.Drawing.Size(612, 280)
    $card.BackColor = $script:Theme.BgPanel
    $dlg.Controls.Add($card)

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = "Object:  $ObjectName`r`nAttribute:  $Attribute`r`n`r`nChoose the source DC to copy the value FROM:"
    $lbl.Location = New-Object System.Drawing.Point(16, 12)
    $lbl.Size = New-Object System.Drawing.Size(580, 60)
    $lbl.ForeColor = $script:Theme.TextPrimary
    $card.Controls.Add($lbl)

    $rbR1 = New-Object System.Windows.Forms.RadioButton
    $rbR1.Text = "Replica 1  ($R1Name)"
    $rbR1.Location = New-Object System.Drawing.Point(20, 78); $rbR1.AutoSize = $true; $rbR1.Checked = $true
    $rbR1.ForeColor = $script:Theme.TextPrimary
    $card.Controls.Add($rbR1)

    $txtR1 = New-ThemedTextBox -Location (New-Object System.Drawing.Point(40, 100)) -Size (New-Object System.Drawing.Size(540, 44)) -ReadOnly
    $txtR1.Multiline = $true; $txtR1.ScrollBars = 'Vertical'; $txtR1.Text = $R1Val
    $card.Controls.Add($txtR1)

    $rbR2 = New-Object System.Windows.Forms.RadioButton
    $rbR2.Text = "Replica 2  ($R2Name)"
    $rbR2.Location = New-Object System.Drawing.Point(20, 152); $rbR2.AutoSize = $true
    $rbR2.ForeColor = $script:Theme.TextPrimary
    $card.Controls.Add($rbR2)

    $txtR2 = New-ThemedTextBox -Location (New-Object System.Drawing.Point(40, 174)) -Size (New-Object System.Drawing.Size(540, 44)) -ReadOnly
    $txtR2.Multiline = $true; $txtR2.ScrollBars = 'Vertical'; $txtR2.Text = $R2Val
    $card.Controls.Add($txtR2)

    $lblCur = New-ThemedLabel -Text 'Current value on PDC (will be overwritten)' -Location (New-Object System.Drawing.Point(20, 226)) -Muted
    $card.Controls.Add($lblCur)
    $txtCur = New-ThemedTextBox -Location (New-Object System.Drawing.Point(20, 246)) -Size (New-Object System.Drawing.Size(560, 24)) -ReadOnly
    $txtCur.Text = $PdcVal
    $txtCur.BackColor = $script:Theme.MissingBg
    $card.Controls.Add($txtCur)

    $btnOk = New-FlatButton -Text 'Restore to PDC' -Location (New-Object System.Drawing.Point(360, 360)) `
        -Size (New-Object System.Drawing.Size(140, 32)) -BackColor $script:Theme.Accent -ForeColor ([System.Drawing.Color]::White)
    $btnOk.DialogResult = 'OK'
    $dlg.Controls.Add($btnOk); $dlg.AcceptButton = $btnOk

    $btnNo = New-FlatButton -Text 'Cancel' -Location (New-Object System.Drawing.Point(510, 360)) `
        -Size (New-Object System.Drawing.Size(100, 32)) -Secondary
    $btnNo.DialogResult = 'Cancel'
    $dlg.Controls.Add($btnNo); $dlg.CancelButton = $btnNo

    $res = $dlg.ShowDialog($form)
    if ($res -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    if ($rbR1.Checked) { return $R1Name } else { return $R2Name }
}

function Show-BulkRestoreDialog {
    param($Items,$R1Name,$R2Name)

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = ("Bulk Restore {0} Attribute(s)" -f $Items.Count)
    $dlg.Size = New-Object System.Drawing.Size(780, 580)
    $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false
    $dlg.BackColor = $script:Theme.BgApp
    $dlg.Font = $script:Theme.FontUi

    $hdr = New-Object System.Windows.Forms.Panel
    $hdr.Dock = 'Top'; $hdr.Height = 56; $hdr.BackColor = $script:Theme.BgHeader
    $dlg.Controls.Add($hdr)
    $ht = New-Object System.Windows.Forms.Label
    $ht.Text = ("Bulk Restore  ·  {0} attributes" -f $Items.Count)
    $ht.Font = $script:Theme.FontSection
    $ht.ForeColor = $script:Theme.TextOnDark
    $ht.Location = New-Object System.Drawing.Point(18, 18)
    $ht.AutoSize = $true
    $hdr.Controls.Add($ht)

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = 'Choose one source DC. Each selected attribute will be copied FROM that DC TO the PDC.'
    $lbl.Location = New-Object System.Drawing.Point(20, 68)
    $lbl.Size = New-Object System.Drawing.Size(720, 24)
    $lbl.ForeColor = $script:Theme.TextMuted
    $dlg.Controls.Add($lbl)

    $rbR1 = New-Object System.Windows.Forms.RadioButton
    $rbR1.Text = "Source: Replica 1  ($R1Name)"
    $rbR1.Location = New-Object System.Drawing.Point(24, 98); $rbR1.AutoSize = $true; $rbR1.Checked = $true
    $dlg.Controls.Add($rbR1)

    $rbR2 = New-Object System.Windows.Forms.RadioButton
    $rbR2.Text = "Source: Replica 2  ($R2Name)"
    $rbR2.Location = New-Object System.Drawing.Point(320, 98); $rbR2.AutoSize = $true
    $dlg.Controls.Add($rbR2)

    $pg = New-Object System.Windows.Forms.DataGridView
    $pg.Location = New-Object System.Drawing.Point(20, 130)
    $pg.Size = New-Object System.Drawing.Size(720, 340)
    Set-ModernGridStyle -Grid $pg
    $pg.MultiSelect = $false
    Add-GridColumns -Grid $pg -Columns @(
        (New-GridColumn -Header 'Object' -Name 'Object' -Width 180),
        (New-GridColumn -Header 'Attribute' -Name 'Attribute' -Width 130),
        (New-GridColumn -Header 'New value (from source)' -Name 'NewVal' -Width 200),
        (New-GridColumn -Header 'Current PDC value' -Name 'CurVal' -Width 185)
    )
    $dlg.Controls.Add($pg)

    $previewRefresh = {
        $pg.Rows.Clear()
        foreach ($it in $Items) {
            $newVal = if ($rbR1.Checked) { $it.R1Val } else { $it.R2Val }
            [void]$pg.Rows.Add(@($it.Object, $it.Attribute, $newVal, $it.PdcVal))
        }
    }
    $rbR1.Add_CheckedChanged($previewRefresh)
    $rbR2.Add_CheckedChanged($previewRefresh)
    & $previewRefresh

    $btnOk = New-FlatButton -Text 'Restore All to PDC' -Location (New-Object System.Drawing.Point(470, 488)) `
        -Size (New-Object System.Drawing.Size(160, 32)) -BackColor $script:Theme.Accent -ForeColor ([System.Drawing.Color]::White)
    $btnOk.DialogResult = 'OK'
    $dlg.Controls.Add($btnOk); $dlg.AcceptButton = $btnOk

    $btnNo = New-FlatButton -Text 'Cancel' -Location (New-Object System.Drawing.Point(640, 488)) `
        -Size (New-Object System.Drawing.Size(100, 32)) -Secondary
    $btnNo.DialogResult = 'Cancel'
    $dlg.Controls.Add($btnNo); $dlg.CancelButton = $btnNo

    $res = $dlg.ShowDialog($form)
    if ($res -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    if ($rbR1.Checked) { return $R1Name } else { return $R2Name }
}

function Invoke-AttributeRestore {
    param($Guid,$Attr,$SourceDc,$Pdc)
    try {
        $src = Get-ADObject -Server $SourceDc -Identity $Guid -Properties $Attr -ErrorAction Stop
        $raw = $src.$Attr

        $isEmpty = ($null -eq $raw) -or `
                   ($raw -is [string] -and $raw -eq '') -or `
                   (($raw -is [System.Collections.IEnumerable]) -and -not ($raw -is [string]) -and (@($raw).Count -eq 0))

        if ($isEmpty) {
            Set-ADObject -Server $Pdc -Identity $Guid -Clear $Attr -Confirm:$false -ErrorAction Stop
            return @{ Ok = $true; Action = 'Cleared'; Error = $null }
        }
        else {
            $valForSet = $raw
            if (($raw -is [System.Collections.IEnumerable]) -and -not ($raw -is [string]) -and -not ($raw -is [byte[]])) {
                $valForSet = @($raw)
            }
            Set-ADObject -Server $Pdc -Identity $Guid -Replace @{ $Attr = $valForSet } -Confirm:$false -ErrorAction Stop
            return @{ Ok = $true; Action = 'Replaced'; Error = $null }
        }
    }
    catch {
        return @{ Ok = $false; Action = $null; Error = $_.Exception.Message }
    }
}

$btnRestore.Add_Click({
    $r1Name = [string]$cmbR1.SelectedItem
    $r2Name = [string]$cmbR2.SelectedItem
    $pdc    = $txtPdc.Text

    if ($cmbType.SelectedItem -notin @('Users','Computers','Groups')) {
        Write-Status 'Restore is only available for Users, Computers, and Groups.' 'WARN'
        return
    }

    $targets = Get-CheckedRestoreTargets
    if ($targets.Count -lt 1) {
        Write-Status 'No changes checked. Tick the boxes next to the attributes you want to restore, or click Check Differences.' 'WARN'
        [System.Windows.Forms.MessageBox]::Show(
            "Check the box on each change you want to restore, then click Restore Checked.`r`n`r`nTip: use Check Differences to select all restorable differences, then uncheck any you want to skip.",
            'Nothing checked', 'OK', 'Information') | Out-Null
        return
    }

    try { Import-Module ActiveDirectory -ErrorAction Stop }
    catch {
        Write-Status $_.Exception.Message 'ERROR'
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,'Restore failed','OK','Error') | Out-Null
        return
    }

    if ($targets.Count -eq 1) {
        $t = $targets[0]
        $sourceDc = Show-RestoreDialog -ObjectName $t.Object -Attribute $t.Attribute -Guid $t.Guid `
                        -PdcVal $t.PdcVal -R1Name $r1Name -R1Val $t.R1Val -R2Name $r2Name -R2Val $t.R2Val
        if (-not $sourceDc) { Write-Status 'Restore cancelled.' 'WARN'; return }

        $res = Invoke-AttributeRestore -Guid $t.Guid -Attr $t.Attribute -SourceDc $sourceDc -Pdc $pdc
        if ($res.Ok) {
            Write-Status ("{0} '{1}' on '{2}' at PDC from '{3}'." -f $res.Action, $t.Attribute, $t.Object, $sourceDc)
            Write-Audit ("RESTORE obj='$($t.Object)' guid='$($t.Guid)' attr='$($t.Attribute)' action='$($res.Action)' source='$sourceDc' target-PDC='$pdc' oldPDCval='$($t.PdcVal)'")
            $t.Row.Cells['PDC'].Value = if ($sourceDc -eq $r1Name) { $t.R1Val } else { $t.R2Val }
            $t.Row.Cells['Select'].Value = $false
            Update-RestoreButtonState
            [System.Windows.Forms.MessageBox]::Show(
                "Attribute '$($t.Attribute)' restored to the PDC from '$sourceDc'.`r`n`r`nAllow replication to converge, then re-run Compare to verify.",
                'Restore complete','OK','Information') | Out-Null
        } else {
            Write-Status $res.Error 'ERROR'
            [System.Windows.Forms.MessageBox]::Show($res.Error,'Restore failed','OK','Error') | Out-Null
        }
        return
    }

    $sourceDc = Show-BulkRestoreDialog -Items $targets -R1Name $r1Name -R2Name $r2Name
    if (-not $sourceDc) { Write-Status 'Bulk restore cancelled.' 'WARN'; return }

    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    $ok = 0; $fail = 0
    $errs = New-Object System.Collections.ArrayList
    foreach ($t in $targets) {
        $res = Invoke-AttributeRestore -Guid $t.Guid -Attr $t.Attribute -SourceDc $sourceDc -Pdc $pdc
        if ($res.Ok) {
            $ok++
            Write-Status ("{0} '{1}' on '{2}' from '{3}'." -f $res.Action, $t.Attribute, $t.Object, $sourceDc)
            Write-Audit ("BULK-RESTORE obj='$($t.Object)' guid='$($t.Guid)' attr='$($t.Attribute)' action='$($res.Action)' source='$sourceDc' target-PDC='$pdc' oldPDCval='$($t.PdcVal)'")
            $t.Row.Cells['PDC'].Value = if ($sourceDc -eq $r1Name) { $t.R1Val } else { $t.R2Val }
            $t.Row.Cells['Select'].Value = $false
        } else {
            $fail++
            Write-Status ("FAILED '{0}' on '{1}': {2}" -f $t.Attribute, $t.Object, $res.Error) 'ERROR'
            [void]$errs.Add(("{0} / {1}: {2}" -f $t.Object, $t.Attribute, $res.Error))
        }
    }
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    Update-RestoreButtonState

    $summary = ("Bulk restore complete.`r`n`r`nSucceeded: {0}`r`nFailed: {1}`r`nSource: {2}`r`n`r`nAllow replication to converge, then re-run Compare to verify." -f $ok, $fail, $sourceDc)
    if ($errs.Count -gt 0) {
        $shown = $errs | Select-Object -First 10
        $summary += ("`r`n`r`nErrors:`r`n{0}" -f ($shown -join "`r`n"))
        if ($errs.Count -gt 10) { $summary += ("`r`n...and {0} more (see status log)." -f ($errs.Count - 10)) }
    }
    $icon = if ($fail -gt 0) { 'Warning' } else { 'Information' }
    [System.Windows.Forms.MessageBox]::Show($summary,'Bulk restore result','OK',$icon) | Out-Null
})

$btnExport.Add_Click({
    if ($grid.Rows.Count -eq 0) { Write-Status 'Nothing to export.' 'WARN'; return }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = 'CSV files (*.csv)|*.csv'
    $sfd.FileName = ('AD-Delta-{0}-{1}.csv' -f $cmbType.SelectedItem, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    if ($sfd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
    $out = foreach ($r in $grid.Rows) {
        [pscustomobject]@{
            Object    = $r.Cells['Object'].Value
            Attribute = $r.Cells['Attribute'].Value
            PDC       = $r.Cells['PDC'].Value
            Replica1  = $r.Cells['Replica1'].Value
            Replica2  = $r.Cells['Replica2'].Value
            Status    = $r.Cells['Status'].Value
            DN        = $r.Cells['DN'].Value
        }
    }
    try {
        $out | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
        Write-Status ("Exported {0} row(s) to {1}" -f $grid.Rows.Count, $sfd.FileName)
    } catch { Write-Status $_.Exception.Message 'ERROR' }
})

# ---------------------------------------------------------------------------
# Init & show
# ---------------------------------------------------------------------------
$form.Add_Shown({
    Update-ContextControls
    $script:SplitUserAdjusted = $false
    Update-SplitLayout
    Write-Status 'Ready. Click Discover DCs to begin.'
    Write-Status ("Audit log: {0}" -f $script:AuditLog)
    Write-Status 'Tip: Check boxes for the changes you want, or use Check Differences then uncheck any to skip.'
    Write-Status 'Tip: Double-click a row for details (Check for Restore / Restore This Change).'
    Write-Status 'Tip: Drag the bar above ACTIVITY to resize the results grid.'
})

$form.Add_FormClosing({
    if ($script:Handle) {
        Write-Status 'Stopping background operation...' 'WARN'
        try {
            if ($script:PowerShell) { $script:PowerShell.Stop() }
        } catch {}
    }
    $timer.Stop()
})

[void]$form.ShowDialog()

if ($script:PowerShell) { try { $script:PowerShell.Dispose() } catch {} }
if ($script:Runspace)   { try { $script:Runspace.Close(); $script:Runspace.Dispose() } catch {} }
