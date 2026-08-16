<#
.SYNOPSIS
    AD Delta Compare & Restore - GUI tool to compare a PDC Emulator against two
    delayed-replication domain controllers and restore attributes back to the PDC.

.DESCRIPTION
    Windows PowerShell 5.1 compatible. Uses Windows Forms.

    - Discovers the PDC Emulator and all DCs in the domain.
    - Performs a 3-way, attribute-level comparison (PDC + Replica1 + Replica2)
      for Users, Computers, Groups, DNS, Group Policy, and Replication Metadata.
    - Restores individual attributes on existing directory objects FROM either
      delayed replica TO the PDC Emulator (Set-ADObject -Replace / -Clear).
    - Every restore is preceded by a before/after confirmation dialog.

    Restore is enabled for directory objects only (Users / Computers / Groups).
    DNS, Group Policy, and Replication Metadata targets are compare-only.

    Objects are keyed by objectGUID (stable across replicas). Comparison uses
    LDAP attribute names via Get-ADObject so the exact same names can be written
    back with Set-ADObject -Replace, avoiding property-name translation issues.

.REQUIREMENTS
    - Windows PowerShell 5.1 (run STA: powershell.exe is STA by default).
    - RSAT modules: ActiveDirectory (required), DnsServer (DNS tab),
      GroupPolicy (Group Policy tab).
    - Rights to read the target partitions and to write to the PDC for restore.

.USAGE
    powershell -ExecutionPolicy Bypass -STA -File .\AD-Delta-Compare-FIXED.ps1

.NOTES
    Version: 1.1 (Fixed for Windows Server 2016)
    - Fixed LDAP injection vulnerability
    - Replaced Invoke-Expression with proper scoping
    - Added proper runspace cleanup
    - Added SearchBase DN validation
    - Improved error handling
    - Added DPI scaling support
    - Added audit log error reporting
#>

# ---------------------------------------------------------------------------
# Assemblies
# ---------------------------------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ---------------------------------------------------------------------------
# Global configuration
# ---------------------------------------------------------------------------
$script:Config = [ordered]@{
    # LDAP attribute names fetched & compared per object type.
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

# Attributes that must never be written back (computed / back-links / system).
$script:NonRestorable = @(
    'whenChanged','distinguishedName','memberOf','objectGUID','objectSid',
    'canonicalName','whenCreated','uSNChanged','uSNCreated'
)

$script:AuditLog = Join-Path -Path $env:TEMP -ChildPath 'AD-Delta-Restore-Audit.log'
$script:AuditLogFailureReported = $false

# Async plumbing
$script:Runspace   = $null
$script:PowerShell = $null
$script:Handle     = $null

# ---------------------------------------------------------------------------
# Helper: Escape LDAP special characters (FIX #1)
# ---------------------------------------------------------------------------
function Escape-LdapFilter {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    
    $Value = $Value.Replace('\', '\5c')  # Backslash must be first
    $Value = $Value.Replace('*', '\2a')
    $Value = $Value.Replace('(', '\28')
    $Value = $Value.Replace(')', '\29')
    $Value = $Value.Replace([char]0x00, '\00')  # NUL
    $Value = $Value.Replace('/', '\2f')
    return $Value
}

# ---------------------------------------------------------------------------
# Helper: Validate DN format
# ---------------------------------------------------------------------------
function Test-DistinguishedName {
    param([string]$DN)
    if ([string]::IsNullOrWhiteSpace($DN)) { return $false }
    # Basic DN validation: must contain = and typically starts with CN=, OU=, DC=
    return $DN -match '^(CN|OU|DC)=.+' -and $DN -match '='
}

# ---------------------------------------------------------------------------
# Helper: Sanitize log output to prevent injection
# ---------------------------------------------------------------------------
function Sanitize-LogValue {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    # Remove control characters and limit length
    $Value = $Value -replace '[\r\n\t]', ' '
    $Value = $Value -replace '[^\x20-\x7E]', '?'  # Replace non-printable
    if ($Value.Length -gt 200) { $Value = $Value.Substring(0, 197) + '...' }
    return $Value
}

# ---------------------------------------------------------------------------
# Shared value-normalization function (FIX #2 - proper scoping)
# ---------------------------------------------------------------------------
$script:ConvertAdValueDef = {
    param($Value, [int]$Depth = 0)
    
    # Prevent infinite recursion (FIX #13)
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

# Create the function in current scope for local use
$script:ConvertAdValueToString = $script:ConvertAdValueDef

# ---------------------------------------------------------------------------
# Logging helpers (UI status + audit file)
# ---------------------------------------------------------------------------
function Write-Status {
    param([string]$Message, [string]$Level = 'INFO')
    $stamp = (Get-Date).ToString('HH:mm:ss')
    if ($script:StatusBox -and -not $script:StatusBox.IsDisposed) {
        try {
            $script:StatusBox.AppendText("[$stamp] $Level  $Message`r`n")
        } catch {
            # Form may be disposed, silently ignore
        }
    }
}

function Write-Audit {
    param([string]$Message)
    $line = ('{0}  {1}  {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $env:USERNAME, (Sanitize-LogValue $Message))
    try { 
        Add-Content -Path $script:AuditLog -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch {
        # FIX #10: Report audit failure once
        if (-not $script:AuditLogFailureReported) {
            Write-Status "WARNING: Audit logging failed: $($_.Exception.Message)" 'WARN'
            $script:AuditLogFailureReported = $true
        }
    }
}

# ---------------------------------------------------------------------------
# Background comparison scriptblock (runs in a separate runspace)
# ---------------------------------------------------------------------------
$script:CompareScript = {
    param($Pdc, $R1, $R2, $Type, $Filter, $SearchBase, $Dn, $Zone, $DiffOnly, $ConvertFuncDef, $UserProps, $CompProps, $GroupProps, $NonRestorable)

    # FIX #2: Use proper script block instead of Invoke-Expression
    $script:ConvertAdValueToString = $ConvertFuncDef

    $result = [pscustomobject]@{ Rows = @(); Error = $null }
    $rows = New-Object System.Collections.ArrayList

    # Helper to escape LDAP filter (replicated in runspace)
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
                    # FIX #1: Escape LDAP special characters
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
# GUI
# ---------------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = 'AD Delta Compare & Restore  -  PDC vs Delayed Replicas'
$form.Size = New-Object System.Drawing.Size(1280, 820)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(1040, 640)
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi  # FIX #8: DPI scaling

# --- Top: DC selection ---
$grpDc = New-Object System.Windows.Forms.GroupBox
$grpDc.Text = 'Domain Controllers'
$grpDc.Location = New-Object System.Drawing.Point(10, 10)
$grpDc.Size = New-Object System.Drawing.Size(1250, 90)
$grpDc.Anchor = 'Top,Left,Right'
$form.Controls.Add($grpDc)

$lblPdc = New-Object System.Windows.Forms.Label
$lblPdc.Text = 'PDC Emulator (reference):'
$lblPdc.Location = New-Object System.Drawing.Point(12, 25); $lblPdc.AutoSize = $true
$grpDc.Controls.Add($lblPdc)

$txtPdc = New-Object System.Windows.Forms.TextBox
$txtPdc.Location = New-Object System.Drawing.Point(160, 22)
$txtPdc.Size = New-Object System.Drawing.Size(280, 22)
$txtPdc.ReadOnly = $true
$txtPdc.BackColor = [System.Drawing.Color]::FromArgb(235,235,235)
$grpDc.Controls.Add($txtPdc)

$lblR1 = New-Object System.Windows.Forms.Label
$lblR1.Text = 'Delayed Replica 1:'
$lblR1.Location = New-Object System.Drawing.Point(460, 25); $lblR1.AutoSize = $true
$grpDc.Controls.Add($lblR1)

$cmbR1 = New-Object System.Windows.Forms.ComboBox
$cmbR1.Location = New-Object System.Drawing.Point(575, 22)
$cmbR1.Size = New-Object System.Drawing.Size(280, 22)
$cmbR1.DropDownStyle = 'DropDownList'
$grpDc.Controls.Add($cmbR1)

$lblR2 = New-Object System.Windows.Forms.Label
$lblR2.Text = 'Delayed Replica 2:'
$lblR2.Location = New-Object System.Drawing.Point(460, 55); $lblR2.AutoSize = $true
$grpDc.Controls.Add($lblR2)

$cmbR2 = New-Object System.Windows.Forms.ComboBox
$cmbR2.Location = New-Object System.Drawing.Point(575, 52)
$cmbR2.Size = New-Object System.Drawing.Size(280, 22)
$cmbR2.DropDownStyle = 'DropDownList'
$grpDc.Controls.Add($cmbR2)

$btnDiscover = New-Object System.Windows.Forms.Button
$btnDiscover.Text = 'Discover DCs'
$btnDiscover.Location = New-Object System.Drawing.Point(880, 20)
$btnDiscover.Size = New-Object System.Drawing.Size(140, 28)
$grpDc.Controls.Add($btnDiscover)

$lblDom = New-Object System.Windows.Forms.Label
$lblDom.Text = 'Domain: (not discovered)'
$lblDom.Location = New-Object System.Drawing.Point(880, 55); $lblDom.AutoSize = $true
$grpDc.Controls.Add($lblDom)

# --- Query controls ---
$grpQ = New-Object System.Windows.Forms.GroupBox
$grpQ.Text = 'Comparison Target'
$grpQ.Location = New-Object System.Drawing.Point(10, 105)
$grpQ.Size = New-Object System.Drawing.Size(1250, 90)
$grpQ.Anchor = 'Top,Left,Right'
$form.Controls.Add($grpQ)

$lblType = New-Object System.Windows.Forms.Label
$lblType.Text = 'Target:'
$lblType.Location = New-Object System.Drawing.Point(12, 25); $lblType.AutoSize = $true
$grpQ.Controls.Add($lblType)

$cmbType = New-Object System.Windows.Forms.ComboBox
$cmbType.Location = New-Object System.Drawing.Point(70, 22)
$cmbType.Size = New-Object System.Drawing.Size(180, 22)
$cmbType.DropDownStyle = 'DropDownList'
[void]$cmbType.Items.AddRange(@('Users','Computers','Groups','DNS','GroupPolicy','Replication Metadata'))
$cmbType.SelectedIndex = 0
$grpQ.Controls.Add($cmbType)

$lblFilter = New-Object System.Windows.Forms.Label
$lblFilter.Text = 'Name filter:'
$lblFilter.Location = New-Object System.Drawing.Point(270, 25); $lblFilter.AutoSize = $true
$grpQ.Controls.Add($lblFilter)

$txtFilter = New-Object System.Windows.Forms.TextBox
$txtFilter.Location = New-Object System.Drawing.Point(350, 22)
$txtFilter.Size = New-Object System.Drawing.Size(200, 22)
$grpQ.Controls.Add($txtFilter)

$lblBase = New-Object System.Windows.Forms.Label
$lblBase.Text = 'SearchBase (OU DN, optional):'
$lblBase.Location = New-Object System.Drawing.Point(12, 55); $lblBase.AutoSize = $true
$grpQ.Controls.Add($lblBase)

$txtBase = New-Object System.Windows.Forms.TextBox
$txtBase.Location = New-Object System.Drawing.Point(190, 52)
$txtBase.Size = New-Object System.Drawing.Size(360, 22)
$grpQ.Controls.Add($txtBase)

$lblZone = New-Object System.Windows.Forms.Label
$lblZone.Text = 'DNS Zone:'
$lblZone.Location = New-Object System.Drawing.Point(570, 25); $lblZone.AutoSize = $true
$grpQ.Controls.Add($lblZone)

$cmbZone = New-Object System.Windows.Forms.ComboBox
$cmbZone.Location = New-Object System.Drawing.Point(640, 22)
$cmbZone.Size = New-Object System.Drawing.Size(240, 22)
$cmbZone.DropDownStyle = 'DropDownList'
$grpQ.Controls.Add($cmbZone)

$btnZones = New-Object System.Windows.Forms.Button
$btnZones.Text = 'Load Zones'
$btnZones.Location = New-Object System.Drawing.Point(885, 20)
$btnZones.Size = New-Object System.Drawing.Size(90, 26)
$grpQ.Controls.Add($btnZones)

$lblDn = New-Object System.Windows.Forms.Label
$lblDn.Text = 'Object DN (metadata):'
$lblDn.Location = New-Object System.Drawing.Point(570, 55); $lblDn.AutoSize = $true
$grpQ.Controls.Add($lblDn)

$txtDn = New-Object System.Windows.Forms.TextBox
$txtDn.Location = New-Object System.Drawing.Point(700, 52)
$txtDn.Size = New-Object System.Drawing.Size(280, 22)
$grpQ.Controls.Add($txtDn)

$chkDiff = New-Object System.Windows.Forms.CheckBox
$chkDiff.Text = 'Differences only'
$chkDiff.Location = New-Object System.Drawing.Point(1000, 24)
$chkDiff.AutoSize = $true
$chkDiff.Checked = $true
$grpQ.Controls.Add($chkDiff)

$btnCompare = New-Object System.Windows.Forms.Button
$btnCompare.Text = 'Compare'
$btnCompare.Location = New-Object System.Drawing.Point(1000, 50)
$btnCompare.Size = New-Object System.Drawing.Size(110, 30)
$btnCompare.Enabled = $false
$grpQ.Controls.Add($btnCompare)

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = 'Cancel'
$btnCancel.Location = New-Object System.Drawing.Point(1120, 50)
$btnCancel.Size = New-Object System.Drawing.Size(90, 30)
$btnCancel.Enabled = $false
$grpQ.Controls.Add($btnCancel)

# --- Results grid ---
$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location = New-Object System.Drawing.Point(10, 205)
$grid.Size = New-Object System.Drawing.Size(1250, 430)
$grid.Anchor = 'Top,Bottom,Left,Right'
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.ReadOnly = $true
$grid.SelectionMode = 'FullRowSelect'
$grid.MultiSelect = $true
$grid.AutoSizeColumnsMode = 'None'
$grid.RowHeadersVisible = $false
$form.Controls.Add($grid)

$colObject = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colObject.HeaderText = 'Object'; $colObject.Name = 'Object'; $colObject.Width = 200
$colAttr = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colAttr.HeaderText = 'Attribute'; $colAttr.Name = 'Attribute'; $colAttr.Width = 150
$colPdc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colPdc.HeaderText = 'PDC'; $colPdc.Name = 'PDC'; $colPdc.Width = 250
$colR1 = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colR1.HeaderText = 'Replica 1'; $colR1.Name = 'Replica1'; $colR1.Width = 250
$colR2 = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colR2.HeaderText = 'Replica 2'; $colR2.Name = 'Replica2'; $colR2.Width = 250
$colStatus = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colStatus.HeaderText = 'Status'; $colStatus.Name = 'Status'; $colStatus.Width = 110
$colGuid = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colGuid.HeaderText = 'GUID'; $colGuid.Name = 'ObjectGUID'; $colGuid.Visible = $false
$colDn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDn.HeaderText = 'DN'; $colDn.Name = 'DN'; $colDn.Visible = $false
$colRest = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colRest.HeaderText = 'Restorable'; $colRest.Name = 'Restorable'; $colRest.Visible = $false
[void]$grid.Columns.AddRange(@($colObject,$colAttr,$colPdc,$colR1,$colR2,$colStatus,$colGuid,$colDn,$colRest))

# --- Bottom actions + status ---
$btnRestore = New-Object System.Windows.Forms.Button
$btnRestore.Text = 'Restore Selected -> PDC'
$btnRestore.Location = New-Object System.Drawing.Point(10, 645)
$btnRestore.Size = New-Object System.Drawing.Size(200, 30)
$btnRestore.Anchor = 'Bottom,Left'
$btnRestore.Enabled = $false
$form.Controls.Add($btnRestore)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text = 'Export CSV'
$btnExport.Location = New-Object System.Drawing.Point(220, 645)
$btnExport.Size = New-Object System.Drawing.Size(110, 30)
$btnExport.Anchor = 'Bottom,Left'
$form.Controls.Add($btnExport)

$lblCount = New-Object System.Windows.Forms.Label
$lblCount.Text = 'Rows: 0'
$lblCount.Location = New-Object System.Drawing.Point(345, 652); $lblCount.AutoSize = $true
$lblCount.Anchor = 'Bottom,Left'
$form.Controls.Add($lblCount)

$script:StatusBox = New-Object System.Windows.Forms.TextBox
$script:StatusBox.Location = New-Object System.Drawing.Point(10, 685)
$script:StatusBox.Size = New-Object System.Drawing.Size(1250, 90)
$script:StatusBox.Multiline = $true
$script:StatusBox.ScrollBars = 'Vertical'
$script:StatusBox.ReadOnly = $true
$script:StatusBox.Anchor = 'Bottom,Left,Right'
$script:StatusBox.BackColor = [System.Drawing.Color]::FromArgb(245,245,245)
$form.Controls.Add($script:StatusBox)

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 300

# ---------------------------------------------------------------------------
# Contextual visibility of query controls
# ---------------------------------------------------------------------------
function Update-ContextControls {
    $t = $cmbType.SelectedItem
    $isObj = $t -in @('Users','Computers','Groups')
    $lblFilter.Visible = $isObj; $txtFilter.Visible = $isObj
    $lblBase.Visible = $isObj;   $txtBase.Visible = $isObj
    $lblZone.Visible = ($t -eq 'DNS'); $cmbZone.Visible = ($t -eq 'DNS'); $btnZones.Visible = ($t -eq 'DNS')
    $lblDn.Visible = ($t -eq 'Replication Metadata'); $txtDn.Visible = ($t -eq 'Replication Metadata')
    $btnRestore.Enabled = $false
}
$cmbType.Add_SelectedIndexChanged({ Update-ContextControls })

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
        Write-Status ("Found PDC '{0}' and {1} DC(s)." -f $pdc, $dcs.Count)
    }
    catch {
        Write-Status $_.Exception.Message 'ERROR'
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,'Discovery failed','OK','Error') | Out-Null
    }
})

# ---------------------------------------------------------------------------
# Load DNS zones (from PDC)
# ---------------------------------------------------------------------------
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
# Run comparison (async runspace)
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

    # FIX #6: Validate SearchBase DN format
    if ($txtBase.Text -and -not (Test-DistinguishedName $txtBase.Text)) {
        [System.Windows.Forms.MessageBox]::Show(
            "SearchBase must be a valid Distinguished Name (e.g., OU=Users,DC=domain,DC=com)",
            'Invalid DN', 'OK', 'Warning') | Out-Null
        return
    }

    # FIX #6: Validate DN for metadata
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

# FIX #3: Improved timer handler with proper disposal checks
$timer.Add_Tick({
    if ($null -eq $script:Handle) { $timer.Stop(); return }
    
    # Check if form is disposed (user closed window)
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

    # Check again before updating UI
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
            'Different'     { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,224,224) }
            'ObjectMissing' { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,244,204) }
            'Match'         { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(224,255,224) }
        }
    }
    $grid.ResumeLayout()
    $lblCount.Text = "Rows: $($grid.Rows.Count)"
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

# ---------------------------------------------------------------------------
# Enable Restore only on a valid, restorable directory-object row
# ---------------------------------------------------------------------------
$grid.Add_SelectionChanged({
    $btnRestore.Enabled = $false
    $btnRestore.Text = 'Restore Selected -> PDC'
    $t = $cmbType.SelectedItem
    if ($t -notin @('Users','Computers','Groups')) { return }
    if ($grid.SelectedRows.Count -lt 1) { return }

    # Count how many of the selected rows are actually restorable.
    $restCount = 0
    foreach ($r in $grid.SelectedRows) {
        if ([string]$r.Cells['Restorable'].Value -eq 'True') { $restCount++ }
    }
    if ($restCount -lt 1) { return }

    $btnRestore.Enabled = $true
    if ($restCount -eq 1) {
        $btnRestore.Text = 'Restore Selected -> PDC'
    } else {
        $btnRestore.Text = ("Restore {0} Selected -> PDC" -f $restCount)
    }
})

# ---------------------------------------------------------------------------
# Restore dialog (choose source replica) + write to PDC
# ---------------------------------------------------------------------------
function Show-RestoreDialog {
    param($ObjectName,$Attribute,$Guid,$PdcVal,$R1Name,$R1Val,$R2Name,$R2Val)

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'Restore Attribute to PDC'
    $dlg.Size = New-Object System.Drawing.Size(640, 420)
    $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = "Object:  $ObjectName`r`nAttribute:  $Attribute`r`n`r`nChoose the source DC to copy the value FROM (it will be written to the PDC):"
    $lbl.Location = New-Object System.Drawing.Point(15, 15)
    $lbl.Size = New-Object System.Drawing.Size(600, 70)
    $dlg.Controls.Add($lbl)

    $rbR1 = New-Object System.Windows.Forms.RadioButton
    $rbR1.Text = "Replica 1  ($R1Name)"
    $rbR1.Location = New-Object System.Drawing.Point(20, 90); $rbR1.AutoSize = $true; $rbR1.Checked = $true
    $dlg.Controls.Add($rbR1)

    $txtR1 = New-Object System.Windows.Forms.TextBox
    $txtR1.Text = $R1Val; $txtR1.ReadOnly = $true; $txtR1.Multiline = $true; $txtR1.ScrollBars = 'Vertical'
    $txtR1.Location = New-Object System.Drawing.Point(40, 112); $txtR1.Size = New-Object System.Drawing.Size(560, 50)
    $dlg.Controls.Add($txtR1)

    $rbR2 = New-Object System.Windows.Forms.RadioButton
    $rbR2.Text = "Replica 2  ($R2Name)"
    $rbR2.Location = New-Object System.Drawing.Point(20, 172); $rbR2.AutoSize = $true
    $dlg.Controls.Add($rbR2)

    $txtR2 = New-Object System.Windows.Forms.TextBox
    $txtR2.Text = $R2Val; $txtR2.ReadOnly = $true; $txtR2.Multiline = $true; $txtR2.ScrollBars = 'Vertical'
    $txtR2.Location = New-Object System.Drawing.Point(40, 194); $txtR2.Size = New-Object System.Drawing.Size(560, 50)
    $dlg.Controls.Add($txtR2)

    $lblCur = New-Object System.Windows.Forms.Label
    $lblCur.Text = 'Current value on PDC (will be overwritten):'
    $lblCur.Location = New-Object System.Drawing.Point(20, 252); $lblCur.AutoSize = $true
    $dlg.Controls.Add($lblCur)

    $txtCur = New-Object System.Windows.Forms.TextBox
    $txtCur.Text = $PdcVal; $txtCur.ReadOnly = $true; $txtCur.Multiline = $true; $txtCur.ScrollBars = 'Vertical'
    $txtCur.Location = New-Object System.Drawing.Point(20, 274); $txtCur.Size = New-Object System.Drawing.Size(580, 50)
    $txtCur.BackColor = [System.Drawing.Color]::FromArgb(255,244,204)
    $dlg.Controls.Add($txtCur)

    $btnOk = New-Object System.Windows.Forms.Button
    $btnOk.Text = 'Restore to PDC'; $btnOk.Location = New-Object System.Drawing.Point(360, 335)
    $btnOk.Size = New-Object System.Drawing.Size(130, 30); $btnOk.DialogResult = 'OK'
    $dlg.Controls.Add($btnOk); $dlg.AcceptButton = $btnOk

    $btnNo = New-Object System.Windows.Forms.Button
    $btnNo.Text = 'Cancel'; $btnNo.Location = New-Object System.Drawing.Point(500, 335)
    $btnNo.Size = New-Object System.Drawing.Size(100, 30); $btnNo.DialogResult = 'Cancel'
    $dlg.Controls.Add($btnNo); $dlg.CancelButton = $btnNo

    $res = $dlg.ShowDialog($form)
    if ($res -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    if ($rbR1.Checked) { return $R1Name } else { return $R2Name }
}

# ---------------------------------------------------------------------------
# Bulk restore dialog: choose ONE source replica for ALL selected rows,
# preview every affected object/attribute, then confirm.
# Returns the chosen source DC hostname (matching $R1Name or $R2Name), or $null.
# ---------------------------------------------------------------------------
function Show-BulkRestoreDialog {
    param($Items,$R1Name,$R2Name)

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = ("Bulk Restore {0} Attribute(s) to PDC" -f $Items.Count)
    $dlg.Size = New-Object System.Drawing.Size(760, 560)
    $dlg.StartPosition = 'CenterParent'
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = ("You are about to restore {0} attribute(s) across the selected objects.`r`nChoose the single source DC to copy each value FROM. Each row's value from that DC will be written to the PDC." -f $Items.Count)
    $lbl.Location = New-Object System.Drawing.Point(15, 12)
    $lbl.Size = New-Object System.Drawing.Size(720, 45)
    $dlg.Controls.Add($lbl)

    $rbR1 = New-Object System.Windows.Forms.RadioButton
    $rbR1.Text = "Source: Replica 1  ($R1Name)"
    $rbR1.Location = New-Object System.Drawing.Point(20, 62); $rbR1.AutoSize = $true; $rbR1.Checked = $true
    $dlg.Controls.Add($rbR1)

    $rbR2 = New-Object System.Windows.Forms.RadioButton
    $rbR2.Text = "Source: Replica 2  ($R2Name)"
    $rbR2.Location = New-Object System.Drawing.Point(300, 62); $rbR2.AutoSize = $true
    $dlg.Controls.Add($rbR2)

    # Preview grid of what will change.
    $pg = New-Object System.Windows.Forms.DataGridView
    $pg.Location = New-Object System.Drawing.Point(15, 92)
    $pg.Size = New-Object System.Drawing.Size(715, 360)
    $pg.AllowUserToAddRows = $false; $pg.AllowUserToDeleteRows = $false
    $pg.ReadOnly = $true; $pg.RowHeadersVisible = $false
    $pg.SelectionMode = 'FullRowSelect'; $pg.MultiSelect = $false
    $pg.AutoSizeColumnsMode = 'None'
    $cO = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $cO.HeaderText = 'Object'; $cO.Width = 180
    $cA = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $cA.HeaderText = 'Attribute'; $cA.Width = 130
    $cN = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $cN.HeaderText = 'New value (from source)'; $cN.Width = 200
    $cC = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $cC.HeaderText = 'Current PDC value'; $cC.Width = 185
    [void]$pg.Columns.AddRange(@($cO,$cA,$cN,$cC))
    $dlg.Controls.Add($pg)

    # FIX #11: Use local variable instead of script scope
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

    $btnOk = New-Object System.Windows.Forms.Button
    $btnOk.Text = 'Restore All to PDC'; $btnOk.Location = New-Object System.Drawing.Point(460, 470)
    $btnOk.Size = New-Object System.Drawing.Size(150, 30); $btnOk.DialogResult = 'OK'
    $dlg.Controls.Add($btnOk); $dlg.AcceptButton = $btnOk

    $btnNo = New-Object System.Windows.Forms.Button
    $btnNo.Text = 'Cancel'; $btnNo.Location = New-Object System.Drawing.Point(620, 470)
    $btnNo.Size = New-Object System.Drawing.Size(110, 30); $btnNo.DialogResult = 'Cancel'
    $dlg.Controls.Add($btnNo); $dlg.CancelButton = $btnNo

    $res = $dlg.ShowDialog($form)
    if ($res -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    if ($rbR1.Checked) { return $R1Name } else { return $R2Name }
}

# ---------------------------------------------------------------------------
# Shared write helper: restore one attribute on one object FROM $SourceDc TO the PDC.
# Reads the raw value fresh from the source DC (never trusts grid strings).
# Returns a hashtable: @{ Ok=$bool; Action='Replaced'|'Cleared'; Error=<msg> }
# ---------------------------------------------------------------------------
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

    # Collect only the restorable rows from the current selection.
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

    # -------- Single-row restore: keep the detailed per-attribute dialog --------
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

    # -------- Bulk restore: one source DC for all, preview + confirm, then loop --------
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

# ---------------------------------------------------------------------------
# Export CSV
# ---------------------------------------------------------------------------
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
    Write-Status 'Ready. Click "Discover DCs" to begin.'
    Write-Status ("Audit log: {0}" -f $script:AuditLog)
})

# FIX #12: Improved form cleanup
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

# FIX #12: Cleanup on close
if ($script:PowerShell) { try { $script:PowerShell.Dispose() } catch {} }
if ($script:Runspace)   { try { $script:Runspace.Close(); $script:Runspace.Dispose() } catch {} }
