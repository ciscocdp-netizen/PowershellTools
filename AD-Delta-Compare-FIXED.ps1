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
    Version: 1.3
    - Renamed to Active Directory Recovery
    - Fixed clipped header / overlapping panels / button placement
    - Shows last successful inbound replication time per DC
    - Fixed DataGridView.Columns.AddRange Object[] cast (PS 5.1)
    - Modern flat UI theme
#>

# ---------------------------------------------------------------------------
# Assemblies
# ---------------------------------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false)

# ---------------------------------------------------------------------------
# Theme (modern flat — teal accent on cool slate, light shell)
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
    FontUiBold  = New-Object System.Drawing.Font('Segoe UI Semibold', 9.0, [System.Drawing.FontStyle]::Bold)
    FontTitle   = New-Object System.Drawing.Font('Segoe UI Semibold', 16.0, [System.Drawing.FontStyle]::Bold)
    FontSub     = New-Object System.Drawing.Font('Segoe UI', 9.0)
    FontMono    = New-Object System.Drawing.Font('Consolas', 8.5)
    FontSection = New-Object System.Drawing.Font('Segoe UI Semibold', 9.5, [System.Drawing.FontStyle]::Bold)
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
    param([string]$Header, [string]$Name, [int]$Width, [switch]$Hidden)
    $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $col.HeaderText = $Header
    $col.Name = $Name
    $col.Width = $Width
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
    $Grid.ColumnHeadersHeight = 36
    $Grid.ColumnHeadersHeightSizeMode = 'DisableResizing'
    $Grid.DefaultCellStyle.BackColor = $script:Theme.BgPanel
    $Grid.DefaultCellStyle.ForeColor = $script:Theme.TextPrimary
    $Grid.DefaultCellStyle.Font = $script:Theme.FontUi
    $Grid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(200, 230, 232)
    $Grid.DefaultCellStyle.SelectionForeColor = $script:Theme.TextPrimary
    $Grid.AlternatingRowsDefaultCellStyle.BackColor = $script:Theme.GridAlt
    $Grid.RowTemplate.Height = 28
    $Grid.AllowUserToAddRows = $false
    $Grid.AllowUserToDeleteRows = $false
    $Grid.AllowUserToResizeRows = $false
    $Grid.ReadOnly = $true
    $Grid.SelectionMode = 'FullRowSelect'
    $Grid.MultiSelect = $true
    $Grid.AutoSizeColumnsMode = 'None'
    $Grid.RowHeadersVisible = $false
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
    $Value = $Value.Replace('\', '\5c')
    $Value = $Value.Replace('*', '\2a')
    $Value = $Value.Replace('(', '\28')
    $Value = $Value.Replace(')', '\29')
    $Value = $Value.Replace([char]0x00, '\00')
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
        $Value = $Value.Replace('\', '\5c')
        $Value = $Value.Replace('*', '\2a')
        $Value = $Value.Replace('(', '\28')
        $Value = $Value.Replace(')', '\29')
        $Value = $Value.Replace([char]0x00, '\00')
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
                    $escapedFilter = Escape-LdapFilterInternal $Filter
                    $nameClause = "(|(sAMAccountName=*$escapedFilter*)(cn=*$escapedFilter*)(displayName=*$escapedFilter*)(name=*$escapedFilter*))"
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
# Main form — TableLayout (no overlapping dock panels)
# ---------------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Active Directory Recovery'
$form.Size = New-Object System.Drawing.Size(1280, 900)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(1080, 760)
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
$form.BackColor = $script:Theme.BgApp
$form.Font = $script:Theme.FontUi
$form.ForeColor = $script:Theme.TextPrimary

$root = New-Object System.Windows.Forms.TableLayoutPanel
$root.Dock = 'Fill'
$root.ColumnCount = 1
$root.RowCount = 3
$root.BackColor = $script:Theme.BgApp
[void]$root.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 88)))
[void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 120)))
$form.Controls.Add($root)

# --- Header (row 0) ---
$pnlHeader = New-Object System.Windows.Forms.Panel
$pnlHeader.Dock = 'Fill'
$pnlHeader.BackColor = $script:Theme.BgHeader
$pnlHeader.Padding = New-Object System.Windows.Forms.Padding(20, 14, 20, 10)
$root.Controls.Add($pnlHeader, 0, 0)

$lblBrand = New-Object System.Windows.Forms.Label
$lblBrand.Text = 'Active Directory Recovery'
$lblBrand.Font = $script:Theme.FontTitle
$lblBrand.ForeColor = $script:Theme.TextOnDark
$lblBrand.Location = New-Object System.Drawing.Point(20, 12)
$lblBrand.AutoSize = $true
$lblBrand.BackColor = [System.Drawing.Color]::Transparent
$pnlHeader.Controls.Add($lblBrand)

$lblTagline = New-Object System.Windows.Forms.Label
$lblTagline.Text = 'Compare delayed replicas and restore attributes to the PDC'
$lblTagline.Font = $script:Theme.FontSub
$lblTagline.ForeColor = [System.Drawing.Color]::FromArgb(160, 176, 190)
$lblTagline.Location = New-Object System.Drawing.Point(22, 48)
$lblTagline.AutoSize = $true
$lblTagline.BackColor = [System.Drawing.Color]::Transparent
$pnlHeader.Controls.Add($lblTagline)

$lblDom = New-Object System.Windows.Forms.Label
$lblDom.Text = 'Domain not discovered'
$lblDom.Font = $script:Theme.FontUi
$lblDom.ForeColor = [System.Drawing.Color]::FromArgb(140, 190, 196)
$lblDom.AutoSize = $false
$lblDom.TextAlign = 'MiddleRight'
$lblDom.Anchor = 'Top,Right'
$lblDom.Size = New-Object System.Drawing.Size(360, 40)
$lblDom.Location = New-Object System.Drawing.Point(($pnlHeader.Width - 380), 24)
$lblDom.BackColor = [System.Drawing.Color]::Transparent
$pnlHeader.Controls.Add($lblDom)
$pnlHeader.Add_Resize({
    $lblDom.Left = [Math]::Max(400, $pnlHeader.ClientSize.Width - $lblDom.Width - 20)
})

# --- Body (row 1) ---
$pnlBody = New-Object System.Windows.Forms.Panel
$pnlBody.Dock = 'Fill'
$pnlBody.BackColor = $script:Theme.BgApp
$pnlBody.Padding = New-Object System.Windows.Forms.Padding(16, 12, 16, 8)
$root.Controls.Add($pnlBody, 0, 1)

$bodyLayout = New-Object System.Windows.Forms.TableLayoutPanel
$bodyLayout.Dock = 'Fill'
$bodyLayout.ColumnCount = 1
$bodyLayout.RowCount = 4
$bodyLayout.BackColor = $script:Theme.BgApp
[void]$bodyLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$bodyLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 150)))  # DCs
[void]$bodyLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 100)))  # Query
[void]$bodyLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) # Results
[void]$bodyLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 52)))  # Actions
$pnlBody.Controls.Add($bodyLayout)

# --- Domain Controllers card ---
$pnlDc = New-Object System.Windows.Forms.Panel
$pnlDc.Dock = 'Fill'
$pnlDc.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 10)
$pnlDc.BackColor = $script:Theme.BgPanel
$bodyLayout.Controls.Add($pnlDc, 0, 0)

$accentBar = New-Object System.Windows.Forms.Panel
$accentBar.Dock = 'Left'
$accentBar.Width = 4
$accentBar.BackColor = $script:Theme.Accent
$pnlDc.Controls.Add($accentBar)

$lblDcSection = New-ThemedLabel -Text 'DOMAIN CONTROLLERS' -Location (New-Object System.Drawing.Point(18, 10)) -Section
$pnlDc.Controls.Add($lblDcSection)

# Column layout: 3 DC fields + Discover button
$colW = 300
$colGap = 20
$col1 = 18
$col2 = $col1 + $colW + $colGap
$col3 = $col2 + $colW + $colGap
$colBtn = $col3 + $colW + $colGap

$lblPdc = New-ThemedLabel -Text 'PDC Emulator' -Location (New-Object System.Drawing.Point($col1, 36)) -Muted
$pnlDc.Controls.Add($lblPdc)
$txtPdc = New-ThemedTextBox -Location (New-Object System.Drawing.Point($col1, 54)) -Size (New-Object System.Drawing.Size($colW, 24)) -ReadOnly
$pnlDc.Controls.Add($txtPdc)
$lblPdcSync = New-Object System.Windows.Forms.Label
$lblPdcSync.Text = 'Last sync: —'
$lblPdcSync.Font = New-Object System.Drawing.Font('Segoe UI', 8.0)
$lblPdcSync.ForeColor = $script:Theme.Accent
$lblPdcSync.Location = New-Object System.Drawing.Point($col1, 84)
$lblPdcSync.Size = New-Object System.Drawing.Size($colW, 36)
$lblPdcSync.BackColor = [System.Drawing.Color]::Transparent
$pnlDc.Controls.Add($lblPdcSync)

$lblR1 = New-ThemedLabel -Text 'Delayed Replica 1' -Location (New-Object System.Drawing.Point($col2, 36)) -Muted
$pnlDc.Controls.Add($lblR1)
$cmbR1 = New-ThemedCombo -Location (New-Object System.Drawing.Point($col2, 54)) -Size (New-Object System.Drawing.Size($colW, 24))
$pnlDc.Controls.Add($cmbR1)
$lblR1Sync = New-Object System.Windows.Forms.Label
$lblR1Sync.Text = 'Last sync: —'
$lblR1Sync.Font = New-Object System.Drawing.Font('Segoe UI', 8.0)
$lblR1Sync.ForeColor = $script:Theme.Accent
$lblR1Sync.Location = New-Object System.Drawing.Point($col2, 84)
$lblR1Sync.Size = New-Object System.Drawing.Size($colW, 36)
$lblR1Sync.BackColor = [System.Drawing.Color]::Transparent
$pnlDc.Controls.Add($lblR1Sync)

$lblR2 = New-ThemedLabel -Text 'Delayed Replica 2' -Location (New-Object System.Drawing.Point($col3, 36)) -Muted
$pnlDc.Controls.Add($lblR2)
$cmbR2 = New-ThemedCombo -Location (New-Object System.Drawing.Point($col3, 54)) -Size (New-Object System.Drawing.Size($colW, 24))
$pnlDc.Controls.Add($cmbR2)
$lblR2Sync = New-Object System.Windows.Forms.Label
$lblR2Sync.Text = 'Last sync: —'
$lblR2Sync.Font = New-Object System.Drawing.Font('Segoe UI', 8.0)
$lblR2Sync.ForeColor = $script:Theme.Accent
$lblR2Sync.Location = New-Object System.Drawing.Point($col3, 84)
$lblR2Sync.Size = New-Object System.Drawing.Size($colW, 36)
$lblR2Sync.BackColor = [System.Drawing.Color]::Transparent
$pnlDc.Controls.Add($lblR2Sync)

$btnDiscover = New-FlatButton -Text 'Discover DCs' -Location (New-Object System.Drawing.Point($colBtn, 50)) `
    -Size (New-Object System.Drawing.Size(130, 32)) -BackColor $script:Theme.Accent -ForeColor ([System.Drawing.Color]::White)
$btnDiscover.Anchor = 'Top,Right'
$pnlDc.Controls.Add($btnDiscover)

$btnRefreshSync = New-FlatButton -Text 'Refresh Sync' -Location (New-Object System.Drawing.Point($colBtn, 88)) `
    -Size (New-Object System.Drawing.Size(130, 28)) -Secondary
$btnRefreshSync.Anchor = 'Top,Right'
$pnlDc.Controls.Add($btnRefreshSync)

# Keep Discover/Refresh pinned to the right edge of the DC card
$pnlDc.Add_Resize({
    $rightPad = 16
    $btnW = 130
    $x = [Math]::Max($col3 + $colW + 16, $pnlDc.ClientSize.Width - $btnW - $rightPad)
    $btnDiscover.Left = $x
    $btnRefreshSync.Left = $x
})

# --- Comparison Target card ---
$pnlQ = New-Object System.Windows.Forms.Panel
$pnlQ.Dock = 'Fill'
$pnlQ.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 10)
$pnlQ.BackColor = $script:Theme.BgPanel
$bodyLayout.Controls.Add($pnlQ, 0, 1)

$accentBar2 = New-Object System.Windows.Forms.Panel
$accentBar2.Dock = 'Left'
$accentBar2.Width = 4
$accentBar2.BackColor = $script:Theme.Accent
$pnlQ.Controls.Add($accentBar2)

$lblQSection = New-ThemedLabel -Text 'COMPARISON TARGET' -Location (New-Object System.Drawing.Point(18, 8)) -Section
$pnlQ.Controls.Add($lblQSection)

$lblType = New-ThemedLabel -Text 'Target' -Location (New-Object System.Drawing.Point(18, 32)) -Muted
$pnlQ.Controls.Add($lblType)
$cmbType = New-ThemedCombo -Location (New-Object System.Drawing.Point(18, 50)) -Size (New-Object System.Drawing.Size(160, 24))
[void]$cmbType.Items.AddRange([string[]]@('Users','Computers','Groups','DNS','GroupPolicy','Replication Metadata'))
$cmbType.SelectedIndex = 0
$pnlQ.Controls.Add($cmbType)

$lblFilter = New-ThemedLabel -Text 'Name filter' -Location (New-Object System.Drawing.Point(198, 32)) -Muted
$pnlQ.Controls.Add($lblFilter)
$txtFilter = New-ThemedTextBox -Location (New-Object System.Drawing.Point(198, 50)) -Size (New-Object System.Drawing.Size(170, 24))
$pnlQ.Controls.Add($txtFilter)

$lblBase = New-ThemedLabel -Text 'SearchBase (optional)' -Location (New-Object System.Drawing.Point(388, 32)) -Muted
$pnlQ.Controls.Add($lblBase)
$txtBase = New-ThemedTextBox -Location (New-Object System.Drawing.Point(388, 50)) -Size (New-Object System.Drawing.Size(260, 24))
$pnlQ.Controls.Add($txtBase)

$lblZone = New-ThemedLabel -Text 'DNS Zone' -Location (New-Object System.Drawing.Point(198, 32)) -Muted
$pnlQ.Controls.Add($lblZone)
$cmbZone = New-ThemedCombo -Location (New-Object System.Drawing.Point(198, 50)) -Size (New-Object System.Drawing.Size(200, 24))
$pnlQ.Controls.Add($cmbZone)
$btnZones = New-FlatButton -Text 'Load Zones' -Location (New-Object System.Drawing.Point(410, 46)) `
    -Size (New-Object System.Drawing.Size(110, 30)) -Secondary
$pnlQ.Controls.Add($btnZones)

$lblDn = New-ThemedLabel -Text 'Object DN (metadata)' -Location (New-Object System.Drawing.Point(198, 32)) -Muted
$pnlQ.Controls.Add($lblDn)
$txtDn = New-ThemedTextBox -Location (New-Object System.Drawing.Point(198, 50)) -Size (New-Object System.Drawing.Size(320, 24))
$pnlQ.Controls.Add($txtDn)

$chkDiff = New-Object System.Windows.Forms.CheckBox
$chkDiff.Text = 'Differences only'
$chkDiff.Location = New-Object System.Drawing.Point(670, 52)
$chkDiff.AutoSize = $true
$chkDiff.Checked = $true
$chkDiff.Font = $script:Theme.FontUi
$chkDiff.ForeColor = $script:Theme.TextPrimary
$chkDiff.BackColor = [System.Drawing.Color]::Transparent
$pnlQ.Controls.Add($chkDiff)

$btnCompare = New-FlatButton -Text 'Compare' -Location (New-Object System.Drawing.Point(0, 46)) `
    -Size (New-Object System.Drawing.Size(110, 32)) -BackColor $script:Theme.Accent -ForeColor ([System.Drawing.Color]::White)
$btnCompare.Enabled = $false
$btnCompare.Anchor = 'Top,Right'
$pnlQ.Controls.Add($btnCompare)

$btnCancel = New-FlatButton -Text 'Cancel' -Location (New-Object System.Drawing.Point(0, 46)) `
    -Size (New-Object System.Drawing.Size(90, 32)) -Secondary
$btnCancel.Enabled = $false
$btnCancel.Anchor = 'Top,Right'
$pnlQ.Controls.Add($btnCancel)

$pnlQ.Add_Resize({
    $rightPad = 16
    $btnCancel.Left = $pnlQ.ClientSize.Width - $btnCancel.Width - $rightPad
    $btnCompare.Left = $btnCancel.Left - $btnCompare.Width - 8
    $chkDiff.Left = [Math]::Min(670, $btnCompare.Left - 160)
})

# --- Results card ---
$pnlResults = New-Object System.Windows.Forms.Panel
$pnlResults.Dock = 'Fill'
$pnlResults.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 8)
$pnlResults.BackColor = $script:Theme.BgPanel
$pnlResults.Padding = New-Object System.Windows.Forms.Padding(12, 8, 12, 12)
$bodyLayout.Controls.Add($pnlResults, 0, 2)

$lblResults = New-ThemedLabel -Text 'RESULTS' -Location (New-Object System.Drawing.Point(6, 4)) -Section
$pnlResults.Controls.Add($lblResults)

$lblCount = New-Object System.Windows.Forms.Label
$lblCount.Text = '0 rows'
$lblCount.Font = $script:Theme.FontUi
$lblCount.ForeColor = $script:Theme.TextMuted
$lblCount.Location = New-Object System.Drawing.Point(100, 6)
$lblCount.AutoSize = $true
$lblCount.BackColor = [System.Drawing.Color]::Transparent
$pnlResults.Controls.Add($lblCount)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = 'Fill'
$grid.Margin = New-Object System.Windows.Forms.Padding(0, 28, 0, 0)
Set-ModernGridStyle -Grid $grid
# Dock Fill fills whole panel; use a nested layout so header label stays visible
$resultsInner = New-Object System.Windows.Forms.TableLayoutPanel
$resultsInner.Dock = 'Fill'
$resultsInner.ColumnCount = 1
$resultsInner.RowCount = 2
$resultsInner.BackColor = $script:Theme.BgPanel
[void]$resultsInner.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$resultsInner.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 28)))
[void]$resultsInner.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$pnlResults.Controls.Clear()
$pnlResults.Controls.Add($resultsInner)

$hdrResults = New-Object System.Windows.Forms.Panel
$hdrResults.Dock = 'Fill'
$hdrResults.BackColor = $script:Theme.BgPanel
$resultsInner.Controls.Add($hdrResults, 0, 0)
$lblResults.Location = New-Object System.Drawing.Point(4, 4)
$lblCount.Location = New-Object System.Drawing.Point(90, 6)
$hdrResults.Controls.Add($lblResults)
$hdrResults.Controls.Add($lblCount)

$resultsInner.Controls.Add($grid, 0, 1)

Add-GridColumns -Grid $grid -Columns @(
    (New-GridColumn -Header 'Object'    -Name 'Object'     -Width 200),
    (New-GridColumn -Header 'Attribute' -Name 'Attribute'  -Width 150),
    (New-GridColumn -Header 'PDC'       -Name 'PDC'        -Width 250),
    (New-GridColumn -Header 'Replica 1' -Name 'Replica1'   -Width 250),
    (New-GridColumn -Header 'Replica 2' -Name 'Replica2'   -Width 250),
    (New-GridColumn -Header 'Status'    -Name 'Status'     -Width 110),
    (New-GridColumn -Header 'GUID'      -Name 'ObjectGUID' -Width 80 -Hidden),
    (New-GridColumn -Header 'DN'        -Name 'DN'         -Width 80 -Hidden),
    (New-GridColumn -Header 'Restorable'-Name 'Restorable' -Width 80 -Hidden)
)

# --- Action bar ---
$pnlActions = New-Object System.Windows.Forms.Panel
$pnlActions.Dock = 'Fill'
$pnlActions.BackColor = $script:Theme.BgApp
$bodyLayout.Controls.Add($pnlActions, 0, 3)

$btnRestore = New-FlatButton -Text 'Restore Selected  →  PDC' -Location (New-Object System.Drawing.Point(0, 8)) `
    -Size (New-Object System.Drawing.Size(220, 34)) -BackColor $script:Theme.Accent -ForeColor ([System.Drawing.Color]::White)
$btnRestore.Enabled = $false
$pnlActions.Controls.Add($btnRestore)

$btnExport = New-FlatButton -Text 'Export CSV' -Location (New-Object System.Drawing.Point(232, 8)) `
    -Size (New-Object System.Drawing.Size(120, 34)) -Secondary
$pnlActions.Controls.Add($btnExport)

$swDiff = New-Object System.Windows.Forms.Panel
$swDiff.Location = New-Object System.Drawing.Point(380, 18)
$swDiff.Size = New-Object System.Drawing.Size(12, 12)
$swDiff.BackColor = $script:Theme.DiffBg
$pnlActions.Controls.Add($swDiff)
$lblLeg1 = New-Object System.Windows.Forms.Label
$lblLeg1.Text = 'Different'
$lblLeg1.Location = New-Object System.Drawing.Point(396, 15)
$lblLeg1.AutoSize = $true
$lblLeg1.ForeColor = $script:Theme.TextMuted
$pnlActions.Controls.Add($lblLeg1)

$swMiss = New-Object System.Windows.Forms.Panel
$swMiss.Location = New-Object System.Drawing.Point(470, 18)
$swMiss.Size = New-Object System.Drawing.Size(12, 12)
$swMiss.BackColor = $script:Theme.MissingBg
$pnlActions.Controls.Add($swMiss)
$lblLeg2 = New-Object System.Windows.Forms.Label
$lblLeg2.Text = 'Missing object'
$lblLeg2.Location = New-Object System.Drawing.Point(486, 15)
$lblLeg2.AutoSize = $true
$lblLeg2.ForeColor = $script:Theme.TextMuted
$pnlActions.Controls.Add($lblLeg2)

$swMatch = New-Object System.Windows.Forms.Panel
$swMatch.Location = New-Object System.Drawing.Point(600, 18)
$swMatch.Size = New-Object System.Drawing.Size(12, 12)
$swMatch.BackColor = $script:Theme.MatchBg
$pnlActions.Controls.Add($swMatch)
$lblLeg3 = New-Object System.Windows.Forms.Label
$lblLeg3.Text = 'Match'
$lblLeg3.Location = New-Object System.Drawing.Point(616, 15)
$lblLeg3.AutoSize = $true
$lblLeg3.ForeColor = $script:Theme.TextMuted
$pnlActions.Controls.Add($lblLeg3)

# --- Status log (row 2) ---
$pnlStatus = New-Object System.Windows.Forms.Panel
$pnlStatus.Dock = 'Fill'
$pnlStatus.BackColor = $script:Theme.BgStatus
$pnlStatus.Padding = New-Object System.Windows.Forms.Padding(16, 8, 16, 10)
$root.Controls.Add($pnlStatus, 0, 2)

$lblStatusTitle = New-Object System.Windows.Forms.Label
$lblStatusTitle.Text = 'ACTIVITY'
$lblStatusTitle.Font = $script:Theme.FontSection
$lblStatusTitle.ForeColor = [System.Drawing.Color]::FromArgb(140, 190, 196)
$lblStatusTitle.Dock = 'Top'
$lblStatusTitle.Height = 22
$lblStatusTitle.BackColor = [System.Drawing.Color]::Transparent
$pnlStatus.Controls.Add($lblStatusTitle)

$script:StatusBox = New-Object System.Windows.Forms.TextBox
$script:StatusBox.Dock = 'Fill'
$script:StatusBox.Multiline = $true
$script:StatusBox.ScrollBars = 'Vertical'
$script:StatusBox.ReadOnly = $true
$script:StatusBox.BorderStyle = 'None'
$script:StatusBox.BackColor = $script:Theme.BgStatus
$script:StatusBox.ForeColor = [System.Drawing.Color]::FromArgb(200, 214, 224)
$script:StatusBox.Font = $script:Theme.FontMono
$pnlStatus.Controls.Add($script:StatusBox)
$script:StatusBox.BringToFront()

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 300

# ---------------------------------------------------------------------------
# Contextual visibility
# ---------------------------------------------------------------------------
function Update-ContextControls {
    $t = $cmbType.SelectedItem
    $isObj = $t -in @('Users','Computers','Groups')
    $lblFilter.Visible = $isObj; $txtFilter.Visible = $isObj
    $lblBase.Visible = $isObj;   $txtBase.Visible = $isObj
    $lblZone.Visible = ($t -eq 'DNS'); $cmbZone.Visible = ($t -eq 'DNS'); $btnZones.Visible = ($t -eq 'DNS')
    $lblDn.Visible = ($t -eq 'Replication Metadata'); $txtDn.Visible = ($t -eq 'Replication Metadata')
    $btnRestore.Enabled = $false
    $btnRestore.Text = 'Restore Selected  →  PDC'
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
        $idx = $grid.Rows.Add(@($r.Object,$r.Attribute,$r.PDC,$r.Replica1,$r.Replica2,$r.Status,$r.ObjectGUID,$r.DN,[string]$r.Restorable))
        $row = $grid.Rows[$idx]
        switch ($r.Status) {
            'Different'     { $row.DefaultCellStyle.BackColor = $script:Theme.DiffBg }
            'ObjectMissing' { $row.DefaultCellStyle.BackColor = $script:Theme.MissingBg }
            'Match'         { $row.DefaultCellStyle.BackColor = $script:Theme.MatchBg }
        }
    }
    $grid.ResumeLayout()
    $lblCount.Text = "$($grid.Rows.Count) rows"
    Write-Status ("Comparison complete. {0} row(s)." -f $grid.Rows.Count)
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
    $btnRestore.Enabled = $false
    $btnRestore.Text = 'Restore Selected  →  PDC'
    $t = $cmbType.SelectedItem
    if ($t -notin @('Users','Computers','Groups')) { return }
    if ($grid.SelectedRows.Count -lt 1) { return }

    $restCount = 0
    foreach ($r in $grid.SelectedRows) {
        if ([string]$r.Cells['Restorable'].Value -eq 'True') { $restCount++ }
    }
    if ($restCount -lt 1) { return }

    $btnRestore.Enabled = $true
    if ($restCount -eq 1) {
        $btnRestore.Text = 'Restore Selected  →  PDC'
    } else {
        $btnRestore.Text = ("Restore {0} Selected  →  PDC" -f $restCount)
    }
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
    if ($grid.SelectedRows.Count -lt 1) { return }
    $r1Name = [string]$cmbR1.SelectedItem
    $r2Name = [string]$cmbR2.SelectedItem
    $pdc    = $txtPdc.Text

    $targets = New-Object System.Collections.ArrayList
    foreach ($row in $grid.SelectedRows) {
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
    if ($targets.Count -lt 1) { Write-Status 'No restorable rows selected.' 'WARN'; return }

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
        } else {
            $fail++
            Write-Status ("FAILED '{0}' on '{1}': {2}" -f $t.Attribute, $t.Object, $res.Error) 'ERROR'
            [void]$errs.Add(("{0} / {1}: {2}" -f $t.Object, $t.Attribute, $res.Error))
        }
    }
    $form.Cursor = [System.Windows.Forms.Cursors]::Default

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
    # Force right-edge button placement after first layout pass
    $pnlDc.PerformLayout()
    $pnlQ.PerformLayout()
    Write-Status 'Ready. Click Discover DCs to begin.'
    Write-Status ("Audit log: {0}" -f $script:AuditLog)
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
