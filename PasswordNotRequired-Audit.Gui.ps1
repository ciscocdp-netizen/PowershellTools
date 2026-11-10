# Dot-sourced by PasswordNotRequired-Audit.ps1 after helpers, -SelfTest, STA, and module load.
# Do not run this file directly.

# =============================================================================================
# AD helpers
# =============================================================================================

function Invoke-UiDoEvents {
    if ($script:WinFormsLoaded) {
        try { [System.Windows.Forms.Application]::DoEvents() } catch { }
    }
}

function Find-DomainControllerHost {
    param([string]$Domain, [string]$Server, [switch]$Writable)
    if ($Server) { return $Server }
    if (-not $Domain) { $Domain = $env:USERDNSDOMAIN }
    if (-not $Domain) { throw 'Domain name is empty; pick a DC or run from a domain-joined computer.' }

    $discover = {
        param([bool]$NeedWritable)
        $p = @{ DomainName = $Domain; Discover = $true; ErrorAction = 'Stop' }
        if ($NeedWritable) { $p.Writable = $true }
        Get-DcHostName (Get-ADDomainController @p)
    }
    try {
        return & $discover ([bool]$Writable)
    }
    catch {
        if ($Writable) {
            try { return & $discover $false } catch { throw "Could not discover a DC for ${Domain}: $($_.Exception.Message)" }
        }
        throw "Could not discover a DC for ${Domain}: $($_.Exception.Message)"
    }
}

$script:DomainCache = @{}
function Get-DomainContext {
    param([string]$Domain, [string]$Server)
    if (-not $Domain) { $Domain = $env:USERDNSDOMAIN }
    $key = "$Domain|$Server"
    if (-not $script:DomainCache.ContainsKey($key)) {
        $target = Find-DomainControllerHost -Domain $Domain -Server $Server -Writable
        $dom = Get-ADDomain -Server $target
        $dcs = @(Get-ADDomainController -Filter * -Server $target | ForEach-Object { Get-DcHostName $_ } | Where-Object { $_ } | Select-Object -Unique)
        $script:DomainCache[$key] = [pscustomobject]@{
            Server  = $target
            NetBIOS = $dom.NetBIOSName
            PDC     = $dom.PDCEmulator
            DCs     = $dcs
            DeadDCs = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList @([StringComparer]::OrdinalIgnoreCase)
        }
    }
    $script:DomainCache[$key]
}

function Test-BlankPassword {
    param([string]$Sam, [string]$NetBIOS, [string]$Dc)

    if ($Sam -match '\$$') { return 'Skipped (computer account)' }

    if (-not $script:LdapTypesLoaded) {
        Add-Type -AssemblyName System.DirectoryServices.Protocols
        $script:LdapTypesLoaded = $true
    }

    $id   = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Dc, 389)
    $cred = New-Object System.Net.NetworkCredential($Sam, '', $NetBIOS)
    $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($id, $cred, [System.DirectoryServices.Protocols.AuthType]::Negotiate)
    $conn.Timeout = [TimeSpan]::FromSeconds(20)
    $conn.SessionOptions.Signing = $true
    $conn.SessionOptions.Sealing = $true
    $conn.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
    try {
        $conn.Bind()
        # Confirm we really authenticated as the target (guards against falling back to the caller's creds).
        $req  = New-Object System.DirectoryServices.Protocols.ExtendedRequest('1.3.6.1.4.1.4203.1.11.3')
        $resp = $conn.SendRequest($req)
        $who  = [Text.Encoding]::UTF8.GetString($resp.ResponseValue).Trim([char]0).Trim()
        if ($who -ilike "*\$Sam") { return 'BLANK PASSWORD CONFIRMED' }
        return "Inconclusive (bound as '$who')"
    }
    catch {
        $code = $null
        $ex = $_.Exception
        if ($ex.PSObject.Properties['ErrorCode']) { $code = $ex.ErrorCode }
        elseif ($ex.InnerException -and $ex.InnerException.PSObject.Properties['ErrorCode']) { $code = $ex.InnerException.ErrorCode }
        $blob = "$($ex.Message) $($ex.InnerException.Message)"
        if ($code -eq 49 -or $blob -match 'invalidCredentials|logon failure|52e|0x52e|data 52e') { return 'Not blank' }
        return "Inconclusive: $($ex.Message)"
    }
    finally {
        if ($conn) { try { $conn.Dispose() } catch { } }
    }
}

function Get-ObjectMetadata {
    # PowerShell equivalent of: repadmin /showobjmeta <DC> "<DN>"
    param([string]$DistinguishedName, [string]$Server, [string]$Label, [switch]$IncludeLinkedValues)

    $params = @{ Object = $DistinguishedName; Server = $Server; ErrorAction = 'Stop' }
    if ($IncludeLinkedValues) { $params.ShowAllLinkedValues = $true }

    @(
        Get-ADReplicationAttributeMetadata @params |
            Select-Object @{ n = 'Object'; e = { $Label } },
                AttributeName,
                Version,
                LastOriginatingChangeTime,
                @{ n = 'OriginatingDC'; e = { Get-DsaName $_.LastOriginatingChangeDirectoryServerIdentity } },
                @{ n = 'OriginatingUSN'; e = { $_.LastOriginatingChangeUsn } },
                @{ n = 'LocalUSN'; e = { $_.LocalChangeUsn } },
                IsLinkValue,
                @{ n = 'LinkState'; e = {
                        if (-not $_.IsLinkValue) { '' }
                        elseif ($_.LastOriginatingDeleteTime -and $_.LastOriginatingDeleteTime.Year -gt 1601) { 'ABSENT' }
                        else { 'PRESENT' }
                    }
                },
                @{ n = 'AttributeValue'; e = {
                        $v = [string]$_.AttributeValue
                        if ($v.Length -gt 300) { $v.Substring(0, 300) + '...' } else { $v }
                    }
                },
                FirstOriginatingCreateTime,
                LastOriginatingDeleteTime |
            Sort-Object IsLinkValue, AttributeName
    )
}

function Get-AdObjectWithProperties {
    # Get-ADObject validates the entire -Properties list up front. One unknown
    # name (badPwdTime vs badPasswordTime) aborts the lookup. Drop the named
    # parameter from the error and retry so one schema mismatch cannot fail the account.
    param($Identity, [string]$Server, [string[]]$Properties)

    $props = New-Object 'System.Collections.Generic.List[string]'
    foreach ($p in @($Properties)) {
        if ($p -and -not ($props -contains $p)) { $props.Add($p) }
    }

    $guard = $props.Count + 2
    while ($guard-- -gt 0) {
        try {
            $splat = @{ Identity = $Identity; Server = $Server; ErrorAction = 'Stop' }
            if ($props.Count) { $splat.Properties = [string[]]$props.ToArray() }
            return Get-ADObject @splat
        }
        catch {
            $bad = Get-UnknownAdPropertyName $_
            if (-not $bad) { throw }
            $removed = $false
            for ($i = $props.Count - 1; $i -ge 0; $i--) {
                if ($props[$i] -ieq $bad) {
                    $props.RemoveAt($i)
                    $removed = $true
                }
            }
            if (-not $removed) { throw }
            Write-Log "  AD property '$bad' is not available via Get-ADObject - skipped" 'Warn'
        }
    }
    throw "Could not read $Identity via $Server after dropping unknown properties."
}

function Get-PnrAdObject {
    param($Identity, [string]$Server)

    $o = Get-AdObjectWithProperties -Identity $Identity -Server $Server -Properties $script:PnrLdapProperties
    $uac = 0
    try { $uac = [int]$o.userAccountControl } catch { $uac = 0 }

    $cannotChange = $null
    try {
        if ($o.objectClass -contains 'user' -or $o.ObjectClass -eq 'user') {
            $cannotChange = [bool](Get-ADUser -Identity $o.ObjectGUID -Server $Server -Properties CannotChangePassword).CannotChangePassword
        }
    }
    catch { $cannotChange = $null }

    $protected = $null
    try { $protected = [bool]$o.ProtectedFromAccidentalDeletion } catch { }

    $classes = @($o.objectClass)
    $isComputer = ($classes -contains 'computer') -or ($o.ObjectClass -eq 'computer')

    [pscustomobject]@{
        SamAccountName                   = $o.sAMAccountName
        DisplayName                      = $o.displayName
        Enabled                          = -not ($uac -band $script:AccountDisableBit)
        Description                      = $o.description
        info                             = $o.info
        userAccountControl               = $uac
        PasswordLastSet                  = ConvertFrom-FileTime $o.pwdLastSet
        pwdLastSet                       = $o.pwdLastSet
        PasswordNeverExpires             = [bool]($uac -band 0x10000)
        CannotChangePassword             = $cannotChange
        lastLogonTimestamp               = $o.lastLogonTimestamp
        lastLogon                        = $o.lastLogon
        logonCount                       = $o.logonCount
        badPwdTime                       = (Get-AdPropertyValue $o @('badPasswordTime', 'LastBadPasswordAttempt', 'badPwdTime'))
        BadLogonCount                    = (Get-AdPropertyValue $o @('badPwdCount', 'BadLogonCount'))
        LockedOut                        = [bool](ConvertFrom-FileTime $o.lockoutTime)
        AccountExpirationDate            = ConvertFrom-FileTime $o.accountExpires
        whenCreated                      = $o.whenCreated
        whenChanged                      = $o.whenChanged
        MemberOf                         = $o.memberOf
        adminCount                       = $o.adminCount
        primaryGroupID                   = $o.primaryGroupID
        ServicePrincipalName             = $o.servicePrincipalName
        TrustedForDelegation             = [bool]($uac -band 0x80000)
        TrustedToAuthForDelegation       = [bool]($uac -band 0x1000000)
        DoesNotRequirePreAuth            = [bool]($uac -band 0x400000)
        AllowReversiblePasswordEncryption = [bool]($uac -band 0x80)
        UseDESKeyOnly                    = [bool]($uac -band 0x200000)
        'msDS-SupportedEncryptionTypes'  = $o.'msDS-SupportedEncryptionTypes'
        LogonWorkstations                = $o.userWorkstations
        ScriptPath                       = $o.scriptPath
        HomeDirectory                    = $o.homeDirectory
        Manager                          = $o.manager
        SIDHistory                       = $o.sIDHistory
        ProtectedFromAccidentalDeletion  = $protected
        SID                              = $o.objectSid
        ObjectGUID                       = $o.ObjectGUID
        DistinguishedName                = $o.DistinguishedName
        ObjectClass                      = if ($isComputer) { 'computer' } else { 'user' }
        'msDS-ResultantPSO'              = $o.'msDS-ResultantPSO'
        tokenGroups                      = $null
        IsComputer                       = $isComputer
    }
}

function Invoke-PnrAccountAudit {
    param([string]$DistinguishedName, [string]$Guid, [string]$Server, [int]$StaleDays, [bool]$AllDcLastLogon, [bool]$TestBlank)

    $ctx = Get-DomainContext -Domain (Get-DomainFromDN -DN $DistinguishedName) -Server $Server
    $identity = $DistinguishedName
    if ($Guid) {
        $g = [guid]::Empty
        if ([guid]::TryParse($Guid, [ref]$g) -and $g -ne [guid]::Empty) { $identity = $g }
    }

    $u = Get-PnrAdObject -Identity $identity -Server $ctx.Server
    $sam = $u.SamAccountName

    # ---- repadmin /showobjmeta equivalent ----------------------------------------------------
    $meta = @()
    try {
        $meta = @(Get-ObjectMetadata -DistinguishedName $u.DistinguishedName -Server $ctx.Server -Label $sam -IncludeLinkedValues)
    }
    catch {
        Write-Log "  replication metadata unavailable: $($_.Exception.Message)" 'Warn'
    }

    $m = @{}
    foreach ($e in $meta) { if (-not $e.IsLinkValue) { $m[$e.AttributeName] = $e } }

    $latest = $meta | Where-Object { -not $_.IsLinkValue -and $_.LastOriginatingChangeTime } | Sort-Object LastOriginatingChangeTime -Descending | Select-Object -First 1
    $lastChangedAttrs = $null
    if ($latest) {
        $lastChangedAttrs = ($meta | Where-Object {
                -not $_.IsLinkValue -and $_.LastOriginatingChangeTime -and
                [math]::Abs(($_.LastOriginatingChangeTime - $latest.LastOriginatingChangeTime).TotalSeconds) -lt 2
            } | ForEach-Object { $_.AttributeName }) -join ', '
    }

    # ---- True last logon (lastLogon is per-DC, not replicated) -------------------------------
    $lastLogon = $null; $lastLogonDc = $null; $logonCount = 0; $badPwdTime = $null
    $unreachable = New-Object System.Collections.Generic.List[string]
    if ($AllDcLastLogon) { $dcList = @($ctx.DCs) } else { $dcList = @($ctx.Server) }

    foreach ($dc in $dcList) {
        Invoke-UiDoEvents
        if ($ctx.DeadDCs.Contains($dc)) { $unreachable.Add($dc); continue }
        try {
            $o  = Get-AdObjectWithProperties -Identity $u.ObjectGUID -Server $dc -Properties @('lastLogon', 'logonCount', 'badPasswordTime')
            $ll = ConvertFrom-FileTime $o.lastLogon
            if ($ll -and (-not $lastLogon -or $ll -gt $lastLogon)) { $lastLogon = $ll; $lastLogonDc = $dc }
            if ($o.logonCount -gt $logonCount) { $logonCount = [int]$o.logonCount }
            $bp = ConvertFrom-FileTime (Get-AdPropertyValue $o @('badPasswordTime', 'LastBadPasswordAttempt', 'badPwdTime'))
            if ($bp -and (-not $badPwdTime -or $bp -gt $badPwdTime)) { $badPwdTime = $bp }
        }
        catch {
            $null = $ctx.DeadDCs.Add($dc)
            $unreachable.Add($dc)
            Write-Log "  DC $dc unreachable - skipped for the rest of this run" 'Warn'
        }
    }

    $lastLogonTimestamp = ConvertFrom-FileTime $u.lastLogonTimestamp
    $effectiveLastLogon = @($lastLogon, $lastLogonTimestamp) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
    $daysSinceLogon     = Get-DaysSince $effectiveLastLogon

    # ---- Password state ----------------------------------------------------------------------
    $pwdLastSetRaw = Get-PwdLastSetRaw $u.pwdLastSet
    $pwdAgeDays    = Get-DaysSince $u.PasswordLastSet
    $pwdSetCount   = $null
    if ($m.ContainsKey('ntPwdHistory')) { $pwdSetCount = $m['ntPwdHistory'].Version }
    $pwdWritten = $null; $pwdWrittenDc = $null
    if ($m.ContainsKey('unicodePwd')) {
        $pwdWritten   = $m['unicodePwd'].LastOriginatingChangeTime
        $pwdWrittenDc = $m['unicodePwd'].OriginatingDC
    }

    # ---- Groups ------------------------------------------------------------------------------
    $allGroups  = New-Object System.Collections.Generic.List[string]
    $privGroups = New-Object System.Collections.Generic.List[string]
    try {
        $tgObj = Get-ADObject -Identity $u.ObjectGUID -Server $ctx.Server -Properties tokenGroups
        $u.tokenGroups = $tgObj.tokenGroups
    }
    catch {
        Write-Log "  tokenGroups not available for ${sam}: $($_.Exception.Message)" 'Warn'
    }
    if ($u.tokenGroups) {
        foreach ($sid in @($u.tokenGroups)) {
            $sidValue = $null
            try { $sidValue = $sid.Value } catch { $sidValue = [string]$sid }
            try { $name = $sid.Translate([System.Security.Principal.NTAccount]).Value } catch { $name = $sidValue }
            $allGroups.Add($name)
            if (Test-PrivilegedSid $sidValue) { $privGroups.Add($name) }
        }
    }
    $sidString = if ($u.SID -and $u.SID.PSObject.Properties['Value']) { [string]$u.SID.Value } else { [string]$u.SID }
    $primarySid = Get-PrimaryGroupSid -ObjectSid $sidString -PrimaryGroupId ([int]$u.primaryGroupID)
    if (Test-PrivilegedSid $primarySid) {
        try { $pgName = ([System.Security.Principal.SecurityIdentifier]$primarySid).Translate([System.Security.Principal.NTAccount]).Value }
        catch { $pgName = $primarySid }
        if ($privGroups -notcontains $pgName) { $privGroups.Add($pgName) }
        if ($allGroups -notcontains $pgName) { $allGroups.Add($pgName) }
    }
    $directGroups = (@($u.MemberOf) | ForEach-Object { Get-RdnValue $_ }) -join '; '

    # ---- Classification & associated server --------------------------------------------------
    $category = Get-PnrAccountCategory -Sam $sam -IsComputer:$u.IsComputer

    $assocServer = Get-PnrAssociatedServerName $sam
    $assocServerInAD = $null; $assocServerDns = $null
    if ($assocServer) {
        try {
            $assocServerInAD = [bool](Get-ADComputer -Filter "Name -eq '$($assocServer -replace "'", "''")'" -Server $ctx.Server -ErrorAction SilentlyContinue)
        }
        catch { $assocServerInAD = $false }
        try {
            $assocServerDns = [bool](Resolve-DnsName -Name $assocServer -ErrorAction SilentlyContinue)
        }
        catch { $assocServerDns = $false }
    }

    # ---- Optional blank password test --------------------------------------------------------
    $blankTest = 'Not tested'
    if ($TestBlank) {
        if ($u.IsComputer) { $blankTest = 'Skipped (computer account)' }
        elseif ($u.Enabled) { $blankTest = Test-BlankPassword -Sam $sam -NetBIOS $ctx.NetBIOS -Dc $ctx.Server }
        else { $blankTest = 'Skipped (account disabled)' }
    }

    # ---- Risk flags --------------------------------------------------------------------------
    $flags = New-Object System.Collections.Generic.List[string]
    if ($blankTest -eq 'BLANK PASSWORD CONFIRMED')                 { $flags.Add('BLANK_PASSWORD') }
    if ($u.Enabled)                                                { $flags.Add('ENABLED') } else { $flags.Add('DISABLED') }
    if ($privGroups.Count -gt 0)                                   { $flags.Add('PRIVILEGED_GROUP') }
    if ($u.adminCount -eq 1)                                       { $flags.Add('ADMINCOUNT=1') }
    if ($u.ServicePrincipalName)                                   { $flags.Add('HAS_SPN(kerberoastable)') }
    if ($u.TrustedForDelegation -or $u.TrustedToAuthForDelegation) { $flags.Add('DELEGATION') }
    if ($u.DoesNotRequirePreAuth)                                  { $flags.Add('NO_PREAUTH(asrep-roastable)') }
    if ($u.AllowReversiblePasswordEncryption)                      { $flags.Add('REVERSIBLE_ENCRYPTION') }
    if ($u.UseDESKeyOnly)                                          { $flags.Add('DES_ONLY') }
    if ($pwdLastSetRaw -eq 0)                                      { $flags.Add('PWDLASTSET=0') }
    if ($pwdAgeDays -gt 365)                                       { $flags.Add('PASSWORD>1YR') }
    if (-not $effectiveLastLogon)                                  { $flags.Add('NEVER_LOGGED_ON') }
    elseif ($daysSinceLogon -gt $StaleDays)                        { $flags.Add("STALE>$($StaleDays)d") }
    if ($assocServer -and -not $assocServerInAD)                   { $flags.Add('SERVER_GONE_FROM_AD') }

    # ---- Recommendation ----------------------------------------------------------------------
    if ($blankTest -eq 'BLANK PASSWORD CONFIRMED') {
        $rec = 'URGENT: password is blank. Disable now, or reset to a strong password AND clear the flag (clearing the flag alone does NOT remove a blank password).'
    }
    elseif ($sam -match '^MSOL_') {
        $rec = 'Confirm this is the CURRENT AD DS connector account on the Entra Connect server (Synchronization Service Manager > Connectors > AD connector > Properties > Connect to AD forest). If current: clear the flag (no password change, no outage). If not current: disable, then delete after a hold period.'
    }
    elseif ($assocServer -and -not $assocServerInAD) {
        $rec = "Server '$assocServer' no longer exists in AD. Disable, move to a quarantine OU, delete after hold period."
    }
    elseif (-not $u.Enabled) {
        $rec = 'Already disabled. Clearing the flag has zero impact; consider deleting if no longer required. If AD rejects the clear, the password is probably blank - reset it first.'
    }
    elseif (-not $effectiveLastLogon -or $daysSinceLogon -gt $StaleDays) {
        $rec = "No logon in $StaleDays+ days. Clear the flag and disable; delete after hold period if nothing breaks."
    }
    else {
        $rec = 'Active account. Clearing the flag does not change its current password; confirm owner and that the password is not blank before/after.'
    }
    if ($privGroups.Count -gt 0) { $rec += ' NOTE: member of privileged group(s) - prioritise.' }

    # ---- Summary row -------------------------------------------------------------------------
    $uacMeta = $null
    if ($m.ContainsKey('userAccountControl')) { $uacMeta = $m['userAccountControl'] }

    $record = [pscustomobject][ordered]@{
        SamAccountName             = $sam
        DisplayName                = $u.DisplayName
        Enabled                    = $u.Enabled
        Category                   = $category
        RiskFlags                  = $flags -join ', '
        Recommendation             = $rec
        Description                = $u.Description
        Info                       = $u.info
        UserAccountControl         = $u.userAccountControl
        UacFlags                   = ConvertTo-UacText $u.userAccountControl
        UacLastChanged             = if ($uacMeta) { $uacMeta.LastOriginatingChangeTime } else { $null }
        UacChangedOnDC             = if ($uacMeta) { $uacMeta.OriginatingDC } else { $null }
        UacVersion                 = if ($uacMeta) { $uacMeta.Version } else { $null }
        BlankPasswordTest          = $blankTest
        PasswordLastSet            = $u.PasswordLastSet
        PwdLastSetRaw              = $pwdLastSetRaw
        PasswordAgeDays            = $pwdAgeDays
        PasswordSetCount_Approx    = $pwdSetCount
        PasswordWrittenOn          = $pwdWritten
        PasswordWrittenByDC        = $pwdWrittenDc
        PasswordNeverExpires       = $u.PasswordNeverExpires
        CannotChangePassword       = $u.CannotChangePassword
        FineGrainedPSO             = ($u.'msDS-ResultantPSO' | ForEach-Object { Get-RdnValue $_ })
        LastLogon_AllDCs           = $lastLogon
        LastLogonDC                = $lastLogonDc
        LastLogonTimestamp         = $lastLogonTimestamp
        EffectiveLastLogon         = $effectiveLastLogon
        DaysSinceLastLogon         = $daysSinceLogon
        LogonCount_MaxDC           = $logonCount
        LastBadPasswordTime        = $badPwdTime
        BadLogonCount              = $u.BadLogonCount
        LockedOut                  = $u.LockedOut
        AccountExpires             = $u.AccountExpirationDate
        Created                    = $u.whenCreated
        Modified                   = $u.whenChanged
        LastChangedAttributes      = $lastChangedAttrs
        LastChangedOnDC            = if ($latest) { $latest.OriginatingDC } else { $null }
        DirectGroups               = $directGroups
        AllGroups_Nested           = $allGroups -join '; '
        PrivilegedGroups           = $privGroups -join '; '
        AdminCount                 = $u.adminCount
        PrimaryGroupID             = $u.primaryGroupID
        SPNs                       = @($u.ServicePrincipalName) -join '; '
        TrustedForDelegation       = $u.TrustedForDelegation
        TrustedToAuthForDelegation = $u.TrustedToAuthForDelegation
        DoesNotRequirePreAuth      = $u.DoesNotRequirePreAuth
        ReversibleEncryption       = $u.AllowReversiblePasswordEncryption
        UseDESKeyOnly              = $u.UseDESKeyOnly
        SupportedEncryptionTypes   = $u.'msDS-SupportedEncryptionTypes'
        LogonWorkstations          = $u.LogonWorkstations
        ScriptPath                 = $u.ScriptPath
        HomeDirectory              = $u.HomeDirectory
        Manager                    = $u.Manager
        AssociatedServer           = $assocServer
        AssociatedServerInAD       = $assocServerInAD
        AssociatedServerInDNS      = $assocServerDns
        SIDHistory                 = @($u.SIDHistory) -join '; '
        ProtectedFromDeletion      = $u.ProtectedFromAccidentalDeletion
        ObjectSID                  = $sidString
        ObjectGUID                 = $u.ObjectGUID
        DistinguishedName          = $u.DistinguishedName
        QueriedDC                  = $ctx.Server
        DCsUnreachable             = $unreachable -join '; '
    }

    $rollbackRow = [pscustomobject][ordered]@{
        SamAccountName    = $sam
        ObjectGUID        = $u.ObjectGUID
        DistinguishedName = $u.DistinguishedName
        Server            = $ctx.Server
        OriginalUAC       = $u.userAccountControl
        OriginalUacFlags  = ConvertTo-UacText $u.userAccountControl
        RestoreCommand    = "Set-ADObject -Identity '$($u.ObjectGUID)' -Replace @{userAccountControl=$($u.userAccountControl)} -Server '$($ctx.Server)'"
        CapturedAt        = Get-Date
    }

    # ---- Per-object evidence text ------------------------------------------------------------
    $detail = New-Object System.Text.StringBuilder
    $null = $detail.AppendLine(('=' * 100))
    $null = $detail.AppendLine("PASSWD_NOTREQD evidence : $sam")
    $null = $detail.AppendLine("Collected               : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME")
    $null = $detail.AppendLine(('=' * 100))
    $null = $detail.AppendLine(($record | Format-List | Out-String -Width 300))
    $null = $detail.AppendLine("--- Replication metadata (repadmin /showobjmeta $($ctx.Server) `"$($u.DistinguishedName)`") ---")
    $null = $detail.AppendLine(($meta | Where-Object { -not $_.IsLinkValue } |
            Format-Table AttributeName, Version, LastOriginatingChangeTime, OriginatingDC, OriginatingUSN, LocalUSN -AutoSize |
            Out-String -Width 300))
    $links = @($meta | Where-Object { $_.IsLinkValue })
    if ($links.Count) {
        $null = $detail.AppendLine('--- Linked value metadata ---')
        $null = $detail.AppendLine(($links |
                Format-Table AttributeName, LinkState, AttributeValue, Version, FirstOriginatingCreateTime, LastOriginatingChangeTime, OriginatingDC -AutoSize |
                Out-String -Width 400))
    }

    [pscustomobject]@{
        Record   = $record
        Meta     = $meta
        Rollback = $rollbackRow
        Detail   = $detail.ToString()
    }
}

function Resolve-AdTarget {
    # Accepts a DN, sAMAccountName (optionally DOMAIN\sam) or GUID; returns the DN and the DC used.
    param([string]$Identity, [string]$Server)

    $Identity = $Identity.Trim().Trim('"')
    if (-not $Identity) { throw 'Enter a distinguished name, sAMAccountName or GUID.' }

    $guid = [guid]::Empty
    $isGuid = [guid]::TryParse($Identity, [ref]$guid)
    $isDn   = $Identity -match '^(CN|OU|DC)=' -and $Identity -match 'DC='

    if ($isDn) { $domain = Get-DomainFromDN -DN $Identity } else { $domain = $env:USERDNSDOMAIN }
    $ctx = Get-DomainContext -Domain $domain -Server $Server

    if ($isGuid) {
        $obj = Get-ADObject -Identity $guid -Server $ctx.Server
    }
    elseif ($isDn) {
        $obj = Get-ADObject -Identity $Identity -Server $ctx.Server
    }
    else {
        $sam = ($Identity -split '\\')[-1] -replace "'", "''"
        $obj = Get-ADObject -Filter "sAMAccountName -eq '$sam'" -Server $ctx.Server
        if (-not $obj) { throw "No object with sAMAccountName '$Identity' found via $($ctx.Server)." }
        $obj = @($obj)[0]
    }

    [pscustomobject]@{ DistinguishedName = $obj.DistinguishedName; ObjectGUID = $obj.ObjectGUID; Server = $ctx.Server }
}

# =============================================================================================
# UI helpers
# =============================================================================================
function New-Size    { param([int]$W, [int]$H) New-Object System.Drawing.Size($W, $H) }
function New-Padding { param([int]$L, [int]$T, [int]$R, [int]$B) New-Object System.Windows.Forms.Padding($L, $T, $R, $B) }

function New-Label {
    param([string]$Text)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.AutoSize = $true
    $l.Anchor = 'Left'
    $l.Margin = New-Padding 3 7 3 3
    $l
}

function New-Button {
    param([string]$Text, [int]$Width = 120)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.Size = New-Size $Width 28
    $b.Margin = New-Padding 3 3 3 3
    $b
}

function New-TextBox {
    $t = New-Object System.Windows.Forms.TextBox
    $t.Anchor = 'Left,Right'
    $t.Margin = New-Padding 3 4 3 3
    $t
}

function New-DcCombo {
    $c = New-Object System.Windows.Forms.ComboBox
    $c.DropDownStyle = 'DropDown'
    $c.Anchor = 'Left,Right'
    $c.Margin = New-Padding 3 4 3 3
    [void]$c.Items.Add($script:AutoDcText)
    $c.SelectedIndex = 0
    $c
}

function New-Grid {
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = 'Fill'
    $g.ReadOnly = $true
    $g.AllowUserToAddRows = $false
    $g.AllowUserToDeleteRows = $false
    $g.SelectionMode = 'FullRowSelect'
    $g.MultiSelect = $true
    $g.RowHeadersVisible = $false
    $g.AutoSizeColumnsMode = 'None'
    $g.ColumnHeadersHeightSizeMode = 'AutoSize'
    $g.BackgroundColor = [System.Drawing.SystemColors]::Window
    $g.BorderStyle = 'FixedSingle'
    $g.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(247, 248, 250)
    $g
}

function New-RootTable {
    param([int]$Rows)
    $t = New-Object System.Windows.Forms.TableLayoutPanel
    $t.Dock = 'Fill'
    $t.ColumnCount = 1
    $t.RowCount = $Rows
    $t.Padding = New-Padding 6 6 6 6
    [void]$t.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
    for ($r = 0; $r -lt $Rows - 1; $r++) { [void]$t.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('AutoSize'))) }
    [void]$t.RowStyles.Add((New-Object System.Windows.Forms.RowStyle('Percent', 100)))
    $t
}

function New-FormTable {
    # 4 columns: label | stretching input | button | button
    $t = New-Object System.Windows.Forms.TableLayoutPanel
    $t.Dock = 'Fill'
    $t.AutoSize = $true
    $t.AutoSizeMode = 'GrowAndShrink'
    $t.ColumnCount = 4
    [void]$t.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
    [void]$t.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
    [void]$t.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
    [void]$t.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
    $t
}

function New-Flow {
    $f = New-Object System.Windows.Forms.FlowLayoutPanel
    $f.Dock = 'Fill'
    $f.AutoSize = $true
    $f.AutoSizeMode = 'GrowAndShrink'
    $f.WrapContents = $true
    $f
}

function New-Group {
    param([string]$Text, $Content)
    $g = New-Object System.Windows.Forms.GroupBox
    $g.Text = $Text
    $g.Dock = 'Fill'
    $g.AutoSize = $true
    $g.AutoSizeMode = 'GrowAndShrink'
    $g.Padding = New-Padding 8 6 8 6
    $g.Controls.Add($Content)
    $g
}

function Show-Error {
    param([string]$Message, [string]$Title = 'Error')
    try {
        [void][System.Windows.Forms.MessageBox]::Show($form, $Message, $Title, 'OK', 'Error')
    }
    catch {
        [void][System.Windows.Forms.MessageBox]::Show($Message, $Title, 'OK', 'Error')
    }
}

function Confirm-Action {
    param([string]$Message, [string]$Title = 'Confirm', [string]$Icon = 'Warning')
    [System.Windows.Forms.MessageBox]::Show($form, $Message, $Title, 'YesNo', $Icon, 'Button2') -eq 'Yes'
}

function Get-DcChoice {
    param($Combo)
    $t = $Combo.Text.Trim()
    if (-not $t -or $t -eq $script:AutoDcText) { return '' }
    $t
}

function Write-Log {
    param([string]$Message, [ValidateSet('Info', 'Warn', 'Error', 'Success')][string]$Level = 'Info')
    $box = $script:TxtLog
    if (-not $box) { return }
    try { if ($box.IsDisposed) { return } } catch { return }
    switch ($Level) {
        'Warn'    { $color = [System.Drawing.Color]::DarkOrange }
        'Error'   { $color = [System.Drawing.Color]::Firebrick }
        'Success' { $color = [System.Drawing.Color]::ForestGreen }
        default   { $color = [System.Drawing.SystemColors]::WindowText }
    }
    try {
        $box.SelectionStart = $box.TextLength
        $box.SelectionLength = 0
        $box.SelectionColor = $color
        $box.AppendText(('[{0:HH:mm:ss}] {1}{2}' -f (Get-Date), $Message, [Environment]::NewLine))
        $box.ScrollToCaret()
    }
    catch { }
    Invoke-UiDoEvents
}

function Show-TextWindow {
    param([string]$Title, [string]$Text, [string]$DefaultFileName = 'evidence.txt')

    $w = New-Object System.Windows.Forms.Form
    $w.Text = $Title
    $w.Size = New-Size 1100 750
    $w.StartPosition = 'CenterParent'
    $w.Font = $form.Font

    $box = New-Object System.Windows.Forms.TextBox
    $box.Multiline = $true
    $box.ReadOnly = $true
    $box.WordWrap = $false
    $box.ScrollBars = 'Both'
    $box.Dock = 'Fill'
    $box.Font = New-Object System.Drawing.Font('Consolas', 9)
    $box.BackColor = [System.Drawing.SystemColors]::Window
    $box.Text = $Text

    $bar = New-Flow
    $bar.Dock = 'Bottom'
    $bar.FlowDirection = 'RightToLeft'
    $btnClose = New-Button 'Close' 90
    $btnSave  = New-Button 'Save as...' 110
    $btnCopy  = New-Button 'Copy to clipboard' 140
    $bar.Controls.AddRange(@($btnClose, $btnSave, $btnCopy))

    $btnClose.Add_Click({ $w.Close() })
    $btnCopy.Add_Click({
            if ($box.Text) { [System.Windows.Forms.Clipboard]::SetText($box.Text) }
        })
    $btnSave.Add_Click({
            $dlg = New-Object System.Windows.Forms.SaveFileDialog
            $dlg.Filter = 'Text files (*.txt)|*.txt|All files (*.*)|*.*'
            $dlg.FileName = $DefaultFileName
            if ($dlg.ShowDialog($w) -eq 'OK') {
                $box.Text | Out-File -FilePath $dlg.FileName -Encoding UTF8
                Write-Log "Saved: $($dlg.FileName)" 'Success'
            }
        })

    $w.Controls.Add($box)
    $w.Controls.Add($bar)
    [void]$w.ShowDialog($form)
    $w.Dispose()
}

function Select-OpenFile {
    param([string]$Title, [string]$Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*', [string]$InitialPath)
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title = $Title
    $dlg.Filter = $Filter
    $dlg.CheckFileExists = $true
    if ($InitialPath -and (Test-Path -LiteralPath $InitialPath)) {
        $item = Get-Item -LiteralPath $InitialPath
        if ($item.PSIsContainer) { $dlg.InitialDirectory = $item.FullName } else { $dlg.InitialDirectory = $item.DirectoryName; $dlg.FileName = $item.Name }
    }
    elseif ($PSScriptRoot) {
        $dlg.InitialDirectory = $PSScriptRoot
    }
    if ($dlg.ShowDialog($form) -eq 'OK') { return $dlg.FileName }
    $null
}

function Select-SaveFile {
    param([string]$Title, [string]$DefaultName, [string]$InitialDirectory, [string]$Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*')
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Title = $Title
    $dlg.Filter = $Filter
    $dlg.FileName = $DefaultName
    $dlg.OverwritePrompt = $true
    if ($InitialDirectory -and (Test-Path -LiteralPath $InitialDirectory)) { $dlg.InitialDirectory = $InitialDirectory }
    if ($dlg.ShowDialog($form) -eq 'OK') { return $dlg.FileName }
    $null
}

function Select-Folder {
    param([string]$Description, [string]$InitialPath)
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = $Description
    $dlg.ShowNewFolderButton = $true
    if ($InitialPath -and (Test-Path -LiteralPath $InitialPath)) { $dlg.SelectedPath = $InitialPath }
    if ($dlg.ShowDialog($form) -eq 'OK') { return $dlg.SelectedPath }
    $null
}

# =============================================================================================
# State
# =============================================================================================
$script:Cancel        = $false
$script:Busy          = $false
$script:ResultsTable  = $null
$script:EvidenceByKey = @{}
$script:LastRunFolder = $null
$script:MetaResults   = @()
$script:FixTable      = $null

# =============================================================================================
# Main form
# =============================================================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "Semperis PASSWD_NOTREQD Investigator v$($script:PnrVersion)"
$form.Size = New-Size 1320 880
$form.MinimumSize = New-Size 1000 650
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$script:Form = $form

$split = New-Object System.Windows.Forms.SplitContainer
$split.Dock = 'Fill'
$split.Orientation = 'Horizontal'
$split.FixedPanel = 'Panel2'

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$tabs.Padding = New-Object System.Drawing.Point(14, 5)

$tabAudit = New-Object System.Windows.Forms.TabPage; $tabAudit.Text = '1. Bulk audit'
$tabMeta  = New-Object System.Windows.Forms.TabPage; $tabMeta.Text  = '2. Object metadata (repadmin /showobjmeta)'
$tabFix   = New-Object System.Windows.Forms.TabPage; $tabFix.Text   = '3. Remediate / rollback'
$tabs.TabPages.AddRange(@($tabAudit, $tabMeta, $tabFix))
$split.Panel1.Controls.Add($tabs)

$txtLog = New-Object System.Windows.Forms.RichTextBox
$txtLog.Dock = 'Fill'
$txtLog.ReadOnly = $true
$txtLog.BackColor = [System.Drawing.SystemColors]::Window
$txtLog.Font = New-Object System.Drawing.Font('Consolas', 9)
$txtLog.BorderStyle = 'None'
$script:TxtLog = $txtLog
$grpLog = New-Object System.Windows.Forms.GroupBox
$grpLog.Text = 'Activity log'
$grpLog.Dock = 'Fill'
$grpLog.Controls.Add($txtLog)
$split.Panel2.Controls.Add($grpLog)

$status = New-Object System.Windows.Forms.StatusStrip
$lblStatus = New-Object System.Windows.Forms.ToolStripStatusLabel
$lblStatus.Spring = $true
$lblStatus.TextAlign = 'MiddleLeft'
$lblStatus.Text = 'Ready'
$lblWho = New-Object System.Windows.Forms.ToolStripStatusLabel
$lblWho.Text = "Running as $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME"
[void]$status.Items.Add($lblStatus)
[void]$status.Items.Add($lblWho)

$form.Controls.Add($split)
$form.Controls.Add($status)

# =============================================================================================
# Tab 1 - Bulk audit
# =============================================================================================
$auditRoot = New-RootTable -Rows 4
$tabAudit.Controls.Add($auditRoot)

$optTable = New-FormTable

$txtCsv = New-TextBox
$btnCsv = New-Button 'Browse...' 100
$lblCsvInfo = New-Label 'No file selected'
$lblCsvInfo.ForeColor = [System.Drawing.Color]::DimGray
$optTable.Controls.Add((New-Label 'Semperis CSV export:'), 0, 0)
$optTable.Controls.Add($txtCsv, 1, 0)
$optTable.Controls.Add($btnCsv, 2, 0)
$optTable.Controls.Add($lblCsvInfo, 3, 0)

$txtOut = New-TextBox
$btnOut = New-Button 'Browse...' 100
$btnOpenOut = New-Button 'Open last report' 130
$btnOpenOut.Enabled = $false
$optTable.Controls.Add((New-Label 'Output folder:'), 0, 1)
$optTable.Controls.Add($txtOut, 1, 1)
$optTable.Controls.Add($btnOut, 2, 1)
$optTable.Controls.Add($btnOpenOut, 3, 1)

$cboDc = New-DcCombo
$btnLoadDcs = New-Button 'Load DCs' 100
$optTable.Controls.Add((New-Label 'Domain controller:'), 0, 2)
$optTable.Controls.Add($cboDc, 1, 2)
$optTable.Controls.Add($btnLoadDcs, 2, 2)

$optFlow = New-Flow
$optFlow.Margin = New-Padding 0 0 0 0
$nudStale = New-Object System.Windows.Forms.NumericUpDown
$nudStale.Minimum = 1
$nudStale.Maximum = 3650
$nudStale.Value = [Math]::Max(1, [Math]::Min(3650, $StaleDays))
$nudStale.Width = 70
$nudStale.Margin = New-Padding 3 4 12 3
$chkAllDcs = New-Object System.Windows.Forms.CheckBox
$chkAllDcs.Text = 'Query every DC for true lastLogon (slower, accurate)'
$chkAllDcs.AutoSize = $true
$chkAllDcs.Checked = $true
$chkAllDcs.Margin = New-Padding 3 6 12 3
$chkBlank = New-Object System.Windows.Forms.CheckBox
$chkBlank.Text = 'Test for blank password (enabled accounts only)'
$chkBlank.AutoSize = $true
$chkBlank.Margin = New-Padding 3 6 3 3
$optFlow.Controls.AddRange(@($nudStale, $chkAllDcs, $chkBlank))
$optTable.Controls.Add((New-Label 'Stale after (days):'), 0, 3)
$optTable.Controls.Add($optFlow, 1, 3)
$optTable.SetColumnSpan($optFlow, 3)

$auditRoot.Controls.Add((New-Group 'Inputs' $optTable), 0, 0)

$auditBar = New-Flow
$btnRun = New-Button 'Run audit' 110
$btnRun.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$btnCancel = New-Button 'Cancel' 90
$btnCancel.Enabled = $false
$btnEvidence = New-Button 'View evidence' 120
$btnShowMeta = New-Button 'Show replication metadata' 190
$btnToFix = New-Button 'Send to remediation' 160
$lblFilter = New-Label '   Filter:'
$txtFilter = New-Object System.Windows.Forms.TextBox
$txtFilter.Width = 220
$txtFilter.Margin = New-Padding 3 6 3 3
$auditBar.Controls.AddRange(@($btnRun, $btnCancel, $btnEvidence, $btnShowMeta, $btnToFix, $lblFilter, $txtFilter))
$auditRoot.Controls.Add($auditBar, 0, 1)

$progressPanel = New-Object System.Windows.Forms.TableLayoutPanel
$progressPanel.Dock = 'Fill'
$progressPanel.AutoSize = $true
$progressPanel.ColumnCount = 2
[void]$progressPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
[void]$progressPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('AutoSize')))
$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Dock = 'Fill'
$progress.Height = 18
$lblProgress = New-Label ''
$progressPanel.Controls.Add($progress, 0, 0)
$progressPanel.Controls.Add($lblProgress, 1, 0)
$auditRoot.Controls.Add($progressPanel, 0, 2)

$gridResults = New-Grid
$auditRoot.Controls.Add($gridResults, 0, 3)

# =============================================================================================
# Tab 2 - Object metadata
# =============================================================================================
$metaRoot = New-RootTable -Rows 4
$tabMeta.Controls.Add($metaRoot)

$metaTable = New-FormTable
$txtMetaObj = New-TextBox
$btnMetaPick = New-Button 'Pick from CSV...' 130
$metaTable.Controls.Add((New-Label 'Object (DN, sAMAccountName or GUID):'), 0, 0)
$metaTable.Controls.Add($txtMetaObj, 1, 0)
$metaTable.Controls.Add($btnMetaPick, 2, 0)

$cboMetaDc = New-DcCombo
$btnMetaLoadDcs = New-Button 'Load DCs' 100
$metaTable.Controls.Add((New-Label 'Domain controller:'), 0, 1)
$metaTable.Controls.Add($cboMetaDc, 1, 1)
$metaTable.Controls.Add($btnMetaLoadDcs, 2, 1)

$chkMetaLinks = New-Object System.Windows.Forms.CheckBox
$chkMetaLinks.Text = 'Include linked-value metadata (member / memberOf history, PRESENT/ABSENT)'
$chkMetaLinks.AutoSize = $true
$chkMetaLinks.Checked = $true
$chkMetaLinks.Margin = New-Padding 3 6 3 3
$metaTable.Controls.Add($chkMetaLinks, 1, 2)
$metaTable.SetColumnSpan($chkMetaLinks, 3)
$metaRoot.Controls.Add((New-Group 'Target' $metaTable), 0, 0)

$metaBar = New-Flow
$btnMetaRun = New-Button 'Show metadata' 130
$btnMetaRun.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$btnMetaExport = New-Button 'Export CSV...' 120
$btnMetaText = New-Button 'View as text' 110
$btnMetaCopy = New-Button 'Copy repadmin command' 170
$metaBar.Controls.AddRange(@($btnMetaRun, $btnMetaExport, $btnMetaText, $btnMetaCopy))
$metaRoot.Controls.Add($metaBar, 0, 1)

$lblMetaInfo = New-Label 'Enter an object and click Show metadata.'
$lblMetaInfo.ForeColor = [System.Drawing.Color]::DimGray
$metaRoot.Controls.Add($lblMetaInfo, 0, 2)

$gridMeta = New-Grid
$metaRoot.Controls.Add($gridMeta, 0, 3)

# =============================================================================================
# Tab 3 - Remediate / rollback
# =============================================================================================
$fixRoot = New-RootTable -Rows 4
$tabFix.Controls.Add($fixRoot)

$fixWarn = New-Label ('Changes Active Directory. Ticked accounts get PASSWD_NOTREQD cleared via Set-ADAccountControl -PasswordNotRequired $false. ' +
    'The current userAccountControl is appended to the rollback file BEFORE each change. Clearing the flag does NOT change an existing (possibly blank) password. ' +
    'If AD rejects the clear, the password is usually blank or too weak - reset it first.')
$fixWarn.AutoSize = $true
$fixWarn.MaximumSize = New-Size 1200 0
$fixWarn.ForeColor = [System.Drawing.Color]::FromArgb(150, 40, 20)
$fixWarn.Margin = New-Padding 3 3 3 6
$fixRoot.Controls.Add($fixWarn, 0, 0)

$fixTableLayout = New-FormTable
$fixSourceFlow = New-Flow
$fixSourceFlow.Margin = New-Padding 0 0 0 0
$btnFixLoadCsv = New-Button 'Load Summary.csv...' 150
$btnFixUseResults = New-Button 'Use audit results' 140
$btnFixAll = New-Button 'Select all' 90
$btnFixNone = New-Button 'Select none' 95
$btnFixDisabled = New-Button 'Select disabled only' 150
$fixSourceFlow.Controls.AddRange(@($btnFixLoadCsv, $btnFixUseResults, $btnFixAll, $btnFixNone, $btnFixDisabled))
$fixTableLayout.Controls.Add((New-Label 'Accounts:'), 0, 0)
$fixTableLayout.Controls.Add($fixSourceFlow, 1, 0)
$fixTableLayout.SetColumnSpan($fixSourceFlow, 3)

$txtRollback = New-TextBox
$btnRollbackBrowse = New-Button 'Browse...' 100
$fixTableLayout.Controls.Add((New-Label 'Rollback file:'), 0, 1)
$fixTableLayout.Controls.Add($txtRollback, 1, 1)
$fixTableLayout.Controls.Add($btnRollbackBrowse, 2, 1)

$fixActionFlow = New-Flow
$fixActionFlow.Margin = New-Padding 0 0 0 0
$chkAlsoDisable = New-Object System.Windows.Forms.CheckBox
$chkAlsoDisable.Text = 'Also disable the account'
$chkAlsoDisable.AutoSize = $true
$chkAlsoDisable.Margin = New-Padding 3 8 16 3
$btnFixPreview = New-Button 'Preview changes' 130
$btnFixApply = New-Button 'Clear PASSWD_NOTREQD on selected' 250
$btnFixApply.ForeColor = [System.Drawing.Color]::FromArgb(160, 20, 20)
$btnFixApply.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$btnFixRestore = New-Button 'Restore from rollback CSV...' 200
$fixActionFlow.Controls.AddRange(@($chkAlsoDisable, $btnFixPreview, $btnFixApply, $btnFixRestore))
$fixTableLayout.Controls.Add((New-Label 'Action:'), 0, 2)
$fixTableLayout.Controls.Add($fixActionFlow, 1, 2)
$fixTableLayout.SetColumnSpan($fixActionFlow, 3)

$fixRoot.Controls.Add((New-Group 'Remediation' $fixTableLayout), 0, 1)

$lblFixInfo = New-Label 'Load accounts to begin. Tick the Select box for each account to change.'
$lblFixInfo.ForeColor = [System.Drawing.Color]::DimGray
$fixRoot.Controls.Add($lblFixInfo, 0, 2)

$gridFix = New-Grid
$gridFix.ReadOnly = $false
$gridFix.SelectionMode = 'CellSelect'
$fixRoot.Controls.Add($gridFix, 0, 3)

$script:BusyControls = @(
    $btnRun, $btnCsv, $btnOut, $btnLoadDcs, $btnEvidence, $btnShowMeta, $btnToFix,
    $btnMetaRun, $btnMetaLoadDcs, $btnMetaExport, $btnMetaPick,
    $btnFixLoadCsv, $btnFixUseResults, $btnFixApply, $btnFixRestore, $btnFixPreview
)

function Set-Busy {
    param([bool]$IsBusy, [string]$Message = 'Ready')
    $script:Busy = $IsBusy
    if ($form -and -not $form.IsDisposed) {
        foreach ($c in $script:BusyControls) { try { $c.Enabled = -not $IsBusy } catch { } }
        try { $btnCancel.Enabled = $IsBusy } catch { }
        try { $form.Cursor = $(if ($IsBusy) { 'AppStarting' } else { 'Default' }) } catch { }
        try { $lblStatus.Text = $Message } catch { }
    }
    Invoke-UiDoEvents
}

# =============================================================================================
# Shared behaviour
# =============================================================================================
function New-PnrResultsTable {
    param($Sample)
    $dt = New-Object System.Data.DataTable
    foreach ($p in $Sample.PSObject.Properties) { [void]$dt.Columns.Add($p.Name, [string]) }
    $dt
}

function Add-PnrResultRow {
    param($Record)
    if (-not $script:ResultsTable) {
        $script:ResultsTable = New-PnrResultsTable $Record
        $gridResults.DataSource = $script:ResultsTable
    }
    $dr = $script:ResultsTable.NewRow()
    foreach ($p in $Record.PSObject.Properties) {
        if ($script:ResultsTable.Columns.Contains($p.Name)) { $dr[$p.Name] = Format-Cell $p.Value }
    }
    $script:ResultsTable.Rows.Add($dr)
}

function Set-PnrResultRow {
    param([int]$Index, $Record)
    if (-not $script:ResultsTable -or $Index -lt 0 -or $Index -ge $script:ResultsTable.Rows.Count) {
        Add-PnrResultRow $Record
        return
    }
    $dr = $script:ResultsTable.Rows[$Index]
    foreach ($p in $Record.PSObject.Properties) {
        if ($script:ResultsTable.Columns.Contains($p.Name)) { $dr[$p.Name] = Format-Cell $p.Value }
    }
}

function Show-PnrCsvPreview {
    param([object[]]$Rows, [string]$SourcePath, [switch]$Quiet)
    $script:EvidenceByKey = @{}
    $script:ResultsTable = $null
    $gridResults.DataSource = $null
    if (-not $Quiet) { $txtFilter.Text = '' }
    foreach ($row in $Rows) {
        $stub = New-PnrStubRecord $row
        Add-PnrResultRow $stub
        if (-not $Quiet) {
            Write-Log ("  {0}: {1} | {2}" -f $stub.SamAccountName, $stub.RiskFlags, $stub.Category)
        }
    }
    if ($gridResults.Columns.Count) {
        $gridResults.AutoResizeColumns('DisplayedCells')
        foreach ($wide in 'Recommendation', 'Category', 'DistinguishedName', 'Description') {
            $col = $gridResults.Columns[$wide]
            if ($col) { $col.Width = [Math]::Min($col.Width, 360) }
        }
        if ($gridResults.Columns['SamAccountName']) { $gridResults.Columns['SamAccountName'].Frozen = $true }
    }
    if ($SourcePath -and -not $Quiet) {
        Write-Log "CSV loaded: $SourcePath — $($Rows.Count) account(s). Click Run audit for live AD metadata." 'Success'
    }
}

function Update-CsvInfo {
    $path = $txtCsv.Text.Trim().Trim('"')
    if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $lblCsvInfo.Text = 'No file selected'
        $lblCsvInfo.ForeColor = [System.Drawing.Color]::DimGray
        return
    }
    try {
        $rows = @(Import-PnrCsv -Path $path)
        $domains = @($rows | ForEach-Object { Get-DomainFromDN $_.DistinguishedName } | Where-Object { $_ } | Sort-Object -Unique)
        $enabled = @($rows | ForEach-Object { New-PnrStubRecord $_ } | Where-Object { $_.Enabled -eq $true }).Count
        $lblCsvInfo.Text = "$($rows.Count) object(s), $($domains.Count) domain(s), $enabled enabled"
        $lblCsvInfo.ForeColor = [System.Drawing.Color]::ForestGreen
        if (-not $txtOut.Text) { $txtOut.Text = Split-Path -Path $path -Parent }
        Show-PnrCsvPreview -Rows $rows -SourcePath $path
    }
    catch {
        $lblCsvInfo.Text = $_.Exception.Message
        $lblCsvInfo.ForeColor = [System.Drawing.Color]::Firebrick
    }
}

function Update-DcLists {
    Set-Busy $true 'Discovering domain controllers...'
    try {
        $domains = @()
        $csv = $txtCsv.Text.Trim().Trim('"')
        if ($csv -and (Test-Path -LiteralPath $csv -PathType Leaf)) {
            try {
                $domains = @(Import-PnrCsv -Path $csv | ForEach-Object { Get-DomainFromDN $_.DistinguishedName } | Where-Object { $_ } | Sort-Object -Unique)
            }
            catch { }
        }
        if (-not $domains) { $domains = @($env:USERDNSDOMAIN | Where-Object { $_ }) }

        $found = New-Object System.Collections.Generic.List[string]
        foreach ($d in $domains) {
            try {
                $seed = Find-DomainControllerHost -Domain $d
                Get-ADDomainController -Filter * -Server $seed | Sort-Object HostName | ForEach-Object {
                    $h = Get-DcHostName $_
                    if ($h) { $found.Add($h) }
                }
                Write-Log "Found DCs for $d" 'Success'
            }
            catch { Write-Log "Could not enumerate DCs for ${d}: $($_.Exception.Message)" 'Warn' }
        }

        foreach ($combo in @($cboDc, $cboMetaDc)) {
            $current = $combo.Text
            $combo.Items.Clear()
            [void]$combo.Items.Add($script:AutoDcText)
            foreach ($h in ($found | Select-Object -Unique)) { [void]$combo.Items.Add($h) }
            $combo.Text = $current
            if (-not $combo.Text) { $combo.SelectedIndex = 0 }
        }
        Write-Log "$($found.Count) domain controller(s) added to the lists."
    }
    finally { Set-Busy $false }
}

function Invoke-MetaLookup {
    if ($script:Busy) { return }
    Set-Busy $true 'Reading replication metadata...'
    try {
        $target = Resolve-AdTarget -Identity $txtMetaObj.Text -Server (Get-DcChoice $cboMetaDc)
        Write-Log "repadmin /showobjmeta $($target.Server) `"$($target.DistinguishedName)`""
        $label = Get-RdnValue $target.DistinguishedName
        $script:MetaResults = Get-ObjectMetadata -DistinguishedName $target.DistinguishedName -Server $target.Server -Label $label -IncludeLinkedValues:$chkMetaLinks.Checked
        $script:MetaTarget = $target
        $gridMeta.DataSource = ConvertTo-DataTable $script:MetaResults
        $gridMeta.AutoResizeColumns('DisplayedCells')
        $attrCount = @($script:MetaResults | Where-Object { -not $_.IsLinkValue }).Count
        $linkCount = @($script:MetaResults | Where-Object { $_.IsLinkValue }).Count
        $lblMetaInfo.Text = "$($target.DistinguishedName)   |   DC: $($target.Server)   |   $attrCount attribute(s), $linkCount linked value(s)"
        $lblMetaInfo.ForeColor = [System.Drawing.SystemColors]::ControlText
        Write-Log "Metadata loaded: $attrCount attribute(s), $linkCount linked value(s)." 'Success'
    }
    catch {
        Write-Log "Metadata lookup failed: $($_.Exception.Message)" 'Error'
        Show-Error $_.Exception.Message 'Metadata lookup failed'
    }
    finally { Set-Busy $false }
}

function Get-SelectedResult {
    if (-not $gridResults.CurrentRow -or -not $gridResults.CurrentRow.DataBoundItem) {
        Show-Error 'Select an account in the results grid first.' 'Nothing selected'
        return $null
    }
    $gridResults.CurrentRow.DataBoundItem
}

function Import-FixRows {
    param([object[]]$Items, [string]$SourceLabel)

    $dt = New-Object System.Data.DataTable
    [void]$dt.Columns.Add('Select', [bool])
    $cols = 'SamAccountName', 'Enabled', 'RiskFlags', 'Recommendation', 'UserAccountControl', 'UacFlags', 'EffectiveLastLogon', 'ObjectGUID', 'DistinguishedName', 'QueriedDC', 'Result'
    foreach ($c in $cols) { [void]$dt.Columns.Add($c, [string]) }

    foreach ($item in $Items) {
        $r = $dt.NewRow()
        $r['Select'] = $false
        foreach ($c in $cols) { if ($c -ne 'Result') { $r[$c] = Get-Val $item $c } }
        $dt.Rows.Add($r)
    }

    $script:FixTable = $dt
    $gridFix.DataSource = $dt
    foreach ($col in $gridFix.Columns) { $col.ReadOnly = ($col.Name -ne 'Select') }
    $gridFix.Columns['Select'].Width = 55
    $gridFix.AutoResizeColumns('DisplayedCells')
    $gridFix.Columns['Select'].Frozen = $true
    $gridFix.Columns['Recommendation'].Width = 360
    $lblFixInfo.Text = "$($dt.Rows.Count) account(s) loaded from $SourceLabel."
    Write-Log "Remediation list loaded: $($dt.Rows.Count) account(s) from $SourceLabel."

    if (-not $txtRollback.Text) {
        if ($script:LastRunFolder) { $folder = $script:LastRunFolder } else { $folder = [Environment]::GetFolderPath('MyDocuments') }
        $txtRollback.Text = Join-Path $folder ('Rollback_Remediation_{0:yyyyMMdd_HHmmss}.csv' -f (Get-Date))
    }
}

function Get-FixSelection {
    if (-not $script:FixTable) { Show-Error 'Load accounts first.' 'Nothing loaded'; return @() }
    $gridFix.EndEdit()
    @($script:FixTable.Rows | Where-Object { $_['Select'] -is [bool] -and $_['Select'] })
}

function Save-Evidence {
    param([string]$Key, [string]$Text)
    if ($Key) { $script:EvidenceByKey[$Key] = $Text }
}

function Get-Evidence {
    param($Item)
    $guid = Get-Val $Item 'ObjectGUID'
    $sam  = Get-Val $Item 'SamAccountName'
    if ($guid -and $script:EvidenceByKey.ContainsKey($guid)) { return $script:EvidenceByKey[$guid] }
    if ($sam -and $script:EvidenceByKey.ContainsKey($sam)) { return $script:EvidenceByKey[$sam] }
    return $null
}

# =============================================================================================
# Events - Tab 1
# =============================================================================================
$btnCsv.Add_Click({
        $path = Select-OpenFile -Title 'Select the Semperis "Password Not Required" CSV export' -InitialPath $txtCsv.Text
        if ($path) { $txtCsv.Text = $path; Update-CsvInfo; Write-Log "Input: $path" }
    })
$txtCsv.Add_Leave({ Update-CsvInfo })

$btnOut.Add_Click({
        $path = Select-Folder -Description 'Select where the audit report folder should be created' -InitialPath $txtOut.Text
        if ($path) { $txtOut.Text = $path }
    })

$btnOpenOut.Add_Click({ if ($script:LastRunFolder) { Invoke-Item -LiteralPath $script:LastRunFolder } })
$btnLoadDcs.Add_Click({ Update-DcLists })
$btnMetaLoadDcs.Add_Click({ Update-DcLists })

$chkBlank.Add_Click({
        if ($chkBlank.Checked) {
            $ok = Confirm-Action ("For each ENABLED account this makes one Kerberos/NTLM bind attempt with an empty password.`r`n`r`n" +
                "A failed attempt logs event 4625/4771 and increments badPwdCount by 1 on the PDC. " +
                "Tell your SOC/monitoring team before running it.`r`n`r`nEnable the blank-password test?") 'Blank password test'
            if (-not $ok) { $chkBlank.Checked = $false }
        }
    })

$btnCancel.Add_Click({ $script:Cancel = $true; Write-Log 'Cancel requested - stopping after the current account...' 'Warn' })

$btnRun.Add_Click({
        $csv = $txtCsv.Text.Trim().Trim('"')
        if (-not $csv -or -not (Test-Path -LiteralPath $csv -PathType Leaf)) { Show-Error 'Select the Semperis CSV export first.' 'Missing input'; return }
        $outRoot = $txtOut.Text.Trim().Trim('"')
        if (-not $outRoot) { Show-Error 'Select an output folder first.' 'Missing output folder'; return }

        try { $rows = @(Import-PnrCsv -Path $csv) }
        catch { Show-Error "Could not read the CSV:`r`n$($_.Exception.Message)"; return }

        $runFolder = Join-Path $outRoot ('PNR-Audit_{0:yyyyMMdd_HHmmss}' -f (Get-Date))
        $detailFolder = Join-Path $runFolder 'Objects'
        try { $null = New-Item -Path $detailFolder -ItemType Directory -Force }
        catch { Show-Error "Could not create the output folder:`r`n$($_.Exception.Message)"; return }

        $script:Cancel = $false
        $script:DomainCache = @{}
        $script:EvidenceByKey = @{}
        $txtFilter.Text = ''
        Show-PnrCsvPreview -Rows $rows -Quiet

        $summary  = New-Object System.Collections.Generic.List[object]
        $allMeta  = New-Object System.Collections.Generic.List[object]
        $rollback = New-Object System.Collections.Generic.List[object]
        $errors   = New-Object System.Collections.Generic.List[object]

        $dc        = Get-DcChoice $cboDc
        $stale     = [int]$nudStale.Value
        $allDcs    = $chkAllDcs.Checked
        $testBlank = $chkBlank.Checked

        $progress.Minimum = 0
        $progress.Maximum = [Math]::Max(1, $rows.Count)
        $progress.Value = 0
        Set-Busy $true 'Auditing...'
        Write-Log "Audit started: $($rows.Count) object(s). Output: $runFolder"
        if ($dc) { Write-Log "Using DC: $dc" } else { Write-Log 'Using auto-discovered writable DC per domain' }

        try {
            $i = 0
            $seen = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList @([StringComparer]::OrdinalIgnoreCase)
            foreach ($row in $rows) {
                if ($script:Cancel) { Write-Log 'Audit cancelled by user.' 'Warn'; break }
                $i++
                $gridIndex = $i - 1
                $dn = $row.DistinguishedName
                $guid = $row.ObjectGuid
                $dedupe = if ($guid) { $guid } else { $dn }
                if (-not $seen.Add($dedupe)) {
                    Write-Log "[$i/$($rows.Count)] duplicate skipped: $dn" 'Warn'
                    $progress.Value = $i
                    continue
                }
                $lblProgress.Text = "$i / $($rows.Count)"
                $lblStatus.Text = "Auditing $dn"
                Write-Log "[$i/$($rows.Count)] $dn"

                try {
                    $res = Invoke-PnrAccountAudit -DistinguishedName $dn -Guid $guid -Server $dc -StaleDays $stale -AllDcLastLogon $allDcs -TestBlank $testBlank
                    $rec = $res.Record
                    foreach ($e in $res.Meta) { $allMeta.Add($e) }
                    $rollback.Add($res.Rollback)
                    Save-Evidence -Key ([string]$rec.ObjectGUID) -Text $res.Detail
                    Save-Evidence -Key $rec.SamAccountName -Text $res.Detail
                    $safeName = $rec.SamAccountName -replace '[\\/:*?"<>|]', '_'
                    $res.Detail | Out-File -FilePath (Join-Path $detailFolder "$safeName.txt") -Encoding UTF8
                    if ($rec.RiskFlags -match 'BLANK_PASSWORD|PRIVILEGED_GROUP') { $lvl = 'Error' }
                    elseif ($rec.Enabled) { $lvl = 'Warn' }
                    else { $lvl = 'Info' }
                    Write-Log "  $($rec.SamAccountName): $($rec.RiskFlags)" $lvl
                }
                catch {
                    Write-Log "  could not be read: $($_.Exception.Message)" 'Error'
                    $errors.Add([pscustomobject]@{ DistinguishedName = $dn; ObjectGuid = $guid; SamAccountName = $row.SamAccountName; Error = $_.Exception.Message })
                    $rec = New-PnrStubRecord $row -LookupError $_.Exception.Message
                    $evidence = @("PASSWD_NOTREQD spreadsheet values : $($rec.SamAccountName)", "AD lookup failed: $($_.Exception.Message)", ($rec | Format-List | Out-String -Width 300)) -join [Environment]::NewLine
                    Save-Evidence -Key ([string]$rec.ObjectGUID) -Text $evidence
                    Save-Evidence -Key $rec.SamAccountName -Text $evidence
                    $safeName = $rec.SamAccountName -replace '[\\/:*?"<>|]', '_'
                    if (-not $safeName) { $safeName = 'unknown' }
                    $evidence | Out-File -FilePath (Join-Path $detailFolder "$safeName.txt") -Encoding UTF8
                }

                $summary.Add($rec)
                Set-PnrResultRow -Index $gridIndex -Record $rec
                $progress.Value = $i
            }

            if ($summary.Count) {
                $summary  | Export-Csv -Path (Join-Path $runFolder 'Summary.csv')             -NoTypeInformation -Encoding UTF8
            }
            if ($allMeta.Count) {
                $allMeta  | Export-Csv -Path (Join-Path $runFolder 'ReplicationMetadata.csv') -NoTypeInformation -Encoding UTF8
            }
            if ($rollback.Count) {
                $rollback | Export-Csv -Path (Join-Path $runFolder 'Rollback.csv')            -NoTypeInformation -Encoding UTF8
            }
            if ($errors.Count) { $errors | Export-Csv -Path (Join-Path $runFolder 'Errors.csv') -NoTypeInformation -Encoding UTF8 }

            $script:LastRunFolder = $runFolder
            $btnOpenOut.Enabled = $true
            if ($gridResults.Columns.Count) {
                $gridResults.AutoResizeColumns('DisplayedCells')
                foreach ($wide in 'Recommendation', 'AllGroups_Nested', 'DirectGroups', 'Description') {
                    $col = $gridResults.Columns[$wide]
                    if ($col) { $col.Width = [Math]::Min($col.Width, 360) }
                }
                if ($gridResults.Columns['SamAccountName']) { $gridResults.Columns['SamAccountName'].Frozen = $true }
            }

            Write-Log "Audit complete: $($summary.Count) account(s), $($errors.Count) error(s). Report: $runFolder" 'Success'
            $msg = "Audited $($summary.Count) of $($rows.Count) account(s)."
            if ($errors.Count) { $msg += "`r`n$($errors.Count) object(s) could not be read - see Errors.csv." }
            $msg += "`r`n`r`nReport folder:`r`n$runFolder`r`n`r`nOpen it now?"
            if ([System.Windows.Forms.MessageBox]::Show($form, $msg, 'Audit complete', 'YesNo', 'Information') -eq 'Yes') {
                Invoke-Item -LiteralPath $runFolder
            }
        }
        catch {
            Write-Log "Audit failed: $($_.Exception.Message)" 'Error'
            Show-Error $_.Exception.Message 'Audit failed'
        }
        finally {
            $lblProgress.Text = ''
            Set-Busy $false
        }
    })

$gridResults.Add_CellFormatting({
        param($s, $e)
        if ($e.RowIndex -lt 0) { return }
        try {
            $drv = $s.Rows[$e.RowIndex].DataBoundItem
            if (-not $drv) { return }
            $flags = [string](Get-Val $drv 'RiskFlags')
            if ($flags -match 'BLANK_PASSWORD|PRIVILEGED_GROUP') { $e.CellStyle.BackColor = [System.Drawing.Color]::MistyRose }
            elseif ($flags -match '(^|, )ENABLED') { $e.CellStyle.BackColor = [System.Drawing.Color]::LemonChiffon }
            elseif ($flags -match 'DISABLED') { $e.CellStyle.ForeColor = [System.Drawing.Color]::DimGray }
        }
        catch { }
    })

$txtFilter.Add_TextChanged({
        if (-not $script:ResultsTable) { return }
        $script:ResultsTable.DefaultView.RowFilter = Get-FilterExpression $txtFilter.Text
    })

$showEvidence = {
    $item = Get-SelectedResult
    if (-not $item) { return }
    $sam = Get-Val $item 'SamAccountName'
    $text = Get-Evidence $item
    if ($text) {
        Show-TextWindow -Title "Evidence - $sam" -Text $text -DefaultFileName "$sam.txt"
    }
    else {
        Show-Error "No in-memory evidence for $sam. Open the Objects folder from the last report." 'Evidence not loaded'
    }
}
$btnEvidence.Add_Click($showEvidence)
$gridResults.Add_CellDoubleClick({ param($s, $e) if ($e.RowIndex -ge 0) { & $showEvidence } })

$btnShowMeta.Add_Click({
        $item = Get-SelectedResult
        if (-not $item) { return }
        $txtMetaObj.Text = Get-Val $item 'DistinguishedName'
        $cboMetaDc.Text = Get-Val $item 'QueriedDC'
        $tabs.SelectedTab = $tabMeta
        Invoke-MetaLookup
    })

$btnToFix.Add_Click({
        if (-not $script:ResultsTable -or -not $script:ResultsTable.Rows.Count) { Show-Error 'Run an audit first.' 'No results'; return }
        Import-FixRows -Items @($script:ResultsTable.Rows) -SourceLabel 'the current audit'
        $tabs.SelectedTab = $tabFix
    })

# =============================================================================================
# Events - Tab 2
# =============================================================================================
$btnMetaRun.Add_Click({ Invoke-MetaLookup })
$txtMetaObj.Add_KeyDown({
        param($s, $e)
        if ($e.KeyCode -eq 'Enter') { $e.SuppressKeyPress = $true; Invoke-MetaLookup }
    })

$btnMetaPick.Add_Click({
        $path = Select-OpenFile -Title 'Pick an object from a Semperis CSV or Summary.csv' -InitialPath $txtCsv.Text
        if (-not $path) { return }
        try {
            $rows = @(Import-PnrCsv -Path $path)
            $picker = New-Object System.Windows.Forms.Form
            $picker.Text = 'Select an object'
            $picker.Size = New-Size 900 500
            $picker.StartPosition = 'CenterParent'
            $picker.Font = $form.Font
            $list = New-Object System.Windows.Forms.ListBox
            $list.Dock = 'Fill'
            $list.IntegralHeight = $false
            foreach ($r in $rows) { [void]$list.Items.Add($r.DistinguishedName) }
            $ok = New-Button 'Select' 100
            $ok.Dock = 'Bottom'
            $ok.DialogResult = 'OK'
            $picker.AcceptButton = $ok
            $list.Add_DoubleClick({ $picker.DialogResult = 'OK'; $picker.Close() })
            $picker.Controls.Add($list)
            $picker.Controls.Add($ok)
            if ($picker.ShowDialog($form) -eq 'OK' -and $list.SelectedItem) {
                $txtMetaObj.Text = [string]$list.SelectedItem
                $picker.Dispose()
                Invoke-MetaLookup
            }
            else { $picker.Dispose() }
        }
        catch { Show-Error $_.Exception.Message }
    })

$btnMetaExport.Add_Click({
        if (-not $script:MetaResults) { Show-Error 'Load metadata first.' 'Nothing to export'; return }
        $name = (Get-RdnValue $script:MetaTarget.DistinguishedName) -replace '[\\/:*?"<>|,\s()]+', '_'
        $path = Select-SaveFile -Title 'Export replication metadata' -DefaultName "ObjMeta_$name.csv" -InitialDirectory $txtOut.Text
        if ($path) {
            $script:MetaResults | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
            Write-Log "Exported: $path" 'Success'
        }
    })

$btnMetaText.Add_Click({
        if (-not $script:MetaResults) { Show-Error 'Load metadata first.' 'Nothing to show'; return }
        $sb = New-Object System.Text.StringBuilder
        $null = $sb.AppendLine("repadmin /showobjmeta $($script:MetaTarget.Server) `"$($script:MetaTarget.DistinguishedName)`"")
        $null = $sb.AppendLine("Collected $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by $env:USERDOMAIN\$env:USERNAME")
        $null = $sb.AppendLine('')
        $null = $sb.AppendLine(($script:MetaResults | Where-Object { -not $_.IsLinkValue } |
                Format-Table LocalUSN, OriginatingDC, OriginatingUSN, LastOriginatingChangeTime, Version, AttributeName -AutoSize | Out-String -Width 300))
        $links = @($script:MetaResults | Where-Object { $_.IsLinkValue })
        if ($links.Count) {
            $null = $sb.AppendLine('Linked values:')
            $null = $sb.AppendLine(($links |
                    Format-Table AttributeName, LinkState, AttributeValue, FirstOriginatingCreateTime, LastOriginatingChangeTime, Version, OriginatingDC -AutoSize | Out-String -Width 400))
        }
        $name = (Get-RdnValue $script:MetaTarget.DistinguishedName) -replace '[\\/:*?"<>|,\s()]+', '_'
        Show-TextWindow -Title "showobjmeta - $($script:MetaTarget.DistinguishedName)" -Text $sb.ToString() -DefaultFileName "ObjMeta_$name.txt"
    })

$btnMetaCopy.Add_Click({
        $dn = $txtMetaObj.Text.Trim().Trim('"')
        if ($script:MetaTarget) { $dn = $script:MetaTarget.DistinguishedName; $dcName = $script:MetaTarget.Server }
        else { $dcName = Get-DcChoice $cboMetaDc; if (-not $dcName) { $dcName = '<DC>' } }
        $cmd = "repadmin /showobjmeta $dcName `"$dn`""
        [System.Windows.Forms.Clipboard]::SetText($cmd)
        Write-Log "Copied: $cmd"
    })

# =============================================================================================
# Events - Tab 3
# =============================================================================================
$gridFix.Add_CurrentCellDirtyStateChanged({
        if ($gridFix.IsCurrentCellDirty) { $gridFix.CommitEdit('CurrentCellChange') }
    })

$gridFix.Add_CellFormatting({
        param($s, $e)
        if ($e.RowIndex -lt 0) { return }
        try {
            $drv = $s.Rows[$e.RowIndex].DataBoundItem
            if (-not $drv) { return }
            $result = [string](Get-Val $drv 'Result')
            if ($result -like 'OK*' -or $result -like 'PARTIAL*') { $e.CellStyle.BackColor = [System.Drawing.Color]::Honeydew }
            elseif ($result -like 'FAILED*') { $e.CellStyle.BackColor = [System.Drawing.Color]::MistyRose }
            elseif ((Get-Val $drv 'RiskFlags') -match 'BLANK_PASSWORD|PRIVILEGED_GROUP') { $e.CellStyle.ForeColor = [System.Drawing.Color]::Firebrick }
        }
        catch { }
    })

$btnFixLoadCsv.Add_Click({
        $initial = $script:LastRunFolder
        if (-not $initial) { $initial = $txtOut.Text }
        $path = Select-OpenFile -Title 'Select a Summary.csv produced by a previous audit' -InitialPath $initial
        if (-not $path) { return }
        try {
            $rows = @(Import-Csv -LiteralPath $path)
            if (-not $rows.Count -or -not (Get-RowField $rows[0] 'ObjectGuid')) {
                Show-Error 'This does not look like an audit Summary.csv (no ObjectGUID column).' 'Invalid file'
                return
            }
            if (-not $txtRollback.Text) {
                $txtRollback.Text = Join-Path (Split-Path $path -Parent) ('Rollback_Remediation_{0:yyyyMMdd_HHmmss}.csv' -f (Get-Date))
            }
            Import-FixRows -Items $rows -SourceLabel (Split-Path $path -Leaf)
        }
        catch { Show-Error $_.Exception.Message }
    })

$btnFixUseResults.Add_Click({
        if (-not $script:ResultsTable -or -not $script:ResultsTable.Rows.Count) { Show-Error 'Run an audit on tab 1 first, or load a Summary.csv.' 'No results'; return }
        Import-FixRows -Items @($script:ResultsTable.Rows) -SourceLabel 'the current audit'
    })

$btnFixAll.Add_Click({ if ($script:FixTable) { foreach ($r in $script:FixTable.Rows) { $r['Select'] = $true } } })
$btnFixNone.Add_Click({ if ($script:FixTable) { foreach ($r in $script:FixTable.Rows) { $r['Select'] = $false } } })
$btnFixDisabled.Add_Click({ if ($script:FixTable) { foreach ($r in $script:FixTable.Rows) { $r['Select'] = ([string]$r['Enabled'] -ieq 'False') } } })

$btnRollbackBrowse.Add_Click({
        $dir = $null
        if ($txtRollback.Text) { $dir = Split-Path $txtRollback.Text -Parent }
        $name = 'Rollback_Remediation_{0:yyyyMMdd_HHmmss}.csv' -f (Get-Date)
        $path = Select-SaveFile -Title 'Where should the rollback file be written?' -DefaultName $name -InitialDirectory $dir
        if ($path) { $txtRollback.Text = $path }
    })

$btnFixPreview.Add_Click({
        $sel = Get-FixSelection
        if (-not $sel.Count) { Show-Error 'Tick at least one account in the Select column.' 'Nothing selected'; return }
        $sb = New-Object System.Text.StringBuilder
        $null = $sb.AppendLine("Planned changes ($($sel.Count) account(s)) - nothing has been changed yet.")
        $null = $sb.AppendLine("Rollback file: $($txtRollback.Text)")
        $null = $sb.AppendLine('')
        foreach ($r in $sel) {
            $uac = 0
            [void][int]::TryParse([string]$r['UserAccountControl'], [ref]$uac)
            $new = Clear-PasswdNotReqdBit -UserAccountControl $uac -AlsoDisable:$chkAlsoDisable.Checked
            $server = [string]$r['QueriedDC']
            $null = $sb.AppendLine("$($r['SamAccountName'])  [$($r['RiskFlags'])]")
            $null = $sb.AppendLine("  DN     : $($r['DistinguishedName'])")
            $null = $sb.AppendLine("  Before : $uac  ($(ConvertTo-UacText $uac))")
            $null = $sb.AppendLine("  After  : $new  ($(ConvertTo-UacText $new))")
            $null = $sb.AppendLine("  Cmd    : Set-ADAccountControl -Identity '$($r['ObjectGUID'])' -PasswordNotRequired `$false -Server '$server'")
            if ($chkAlsoDisable.Checked) { $null = $sb.AppendLine("           Disable-ADAccount -Identity '$($r['ObjectGUID'])' -Server '$server'") }
            $null = $sb.AppendLine('')
        }
        $null = $sb.AppendLine('Note: "Before" is the value captured at audit time; the live value is re-read and recorded in the rollback file immediately before each change.')
        $null = $sb.AppendLine('If AD rejects the clear, the password is usually blank or too weak - reset it, then clear the flag. Disabling still works.')
        Show-TextWindow -Title 'Remediation preview' -Text $sb.ToString() -DefaultFileName 'RemediationPlan.txt'
    })

$btnFixApply.Add_Click({
        $sel = Get-FixSelection
        if (-not $sel.Count) { Show-Error 'Tick at least one account in the Select column.' 'Nothing selected'; return }
        $rbPath = $txtRollback.Text.Trim().Trim('"')
        if (-not $rbPath) { Show-Error 'Choose a rollback file location first.' 'Missing rollback file'; return }
        $rbParent = Split-Path $rbPath -Parent
        if ($rbParent) {
            try { $null = New-Item -Path $rbParent -ItemType Directory -Force }
            catch { Show-Error "Rollback folder is not writable:`r`n$($_.Exception.Message)"; return }
        }

        $risky = @($sel | Where-Object { $_['RiskFlags'] -match 'PRIVILEGED_GROUP|BLANK_PASSWORD|(^|, )ENABLED' })
        $action = 'clear PASSWD_NOTREQD'
        if ($chkAlsoDisable.Checked) { $action += ' AND DISABLE' }
        $msg = "You are about to $action on $($sel.Count) account(s)."
        if ($risky.Count) { $msg += "`r`n`r`n$($risky.Count) of them are ENABLED, privileged or have a blank password:`r`n  " + (($risky | Select-Object -First 15 | ForEach-Object { $_['SamAccountName'] }) -join "`r`n  ") }
        $msg += "`r`n`r`nOriginal values will be saved to:`r`n$rbPath`r`n`r`nContinue?"
        if (-not (Confirm-Action $msg 'Confirm AD change')) { return }

        $script:Cancel = $false
        Set-Busy $true 'Applying changes...'
        $ok = 0; $failed = 0; $skipped = 0; $partial = 0
        try {
            foreach ($r in $sel) {
                if ($script:Cancel) { Write-Log 'Remediation cancelled by user.' 'Warn'; break }
                $sam = [string]$r['SamAccountName']
                try {
                    $guid = [guid][string]$r['ObjectGUID']
                    $server = [string]$r['QueriedDC']
                    if (-not $server) { $server = (Get-DomainContext -Domain (Get-DomainFromDN ([string]$r['DistinguishedName'])) -Server '').Server }

                    $u = Get-ADObject -Identity $guid -Server $server -Properties userAccountControl, sAMAccountName
                    $before = [int]$u.userAccountControl
                    if (-not ($before -band $script:PasswdNotReqdBit) -and -not $chkAlsoDisable.Checked) {
                        $r['Result'] = 'Skipped - flag already cleared'
                        Write-Log "$sam : flag already cleared, skipped." 'Warn'
                        $skipped++
                        continue
                    }

                    [pscustomobject][ordered]@{
                        SamAccountName    = $u.sAMAccountName
                        ObjectGUID        = $u.ObjectGUID
                        DistinguishedName = $u.DistinguishedName
                        Server            = $server
                        OriginalUAC       = $before
                        OriginalUacFlags  = ConvertTo-UacText $before
                        RestoreCommand    = "Set-ADObject -Identity '$($u.ObjectGUID)' -Replace @{userAccountControl=$before} -Server '$server'"
                        CapturedAt        = Get-Date
                        ChangedBy         = "$env:USERDOMAIN\$env:USERNAME"
                    } | Export-Csv -Path $rbPath -Append -NoTypeInformation -Encoding UTF8

                    $disableOk = $null
                    $flagOk = $null
                    $flagErr = $null
                    if ($chkAlsoDisable.Checked -and -not ($before -band $script:AccountDisableBit)) {
                        try { Disable-ADAccount -Identity $guid -Server $server; $disableOk = $true }
                        catch { $disableOk = $false; $flagErr = $_.Exception.Message }
                    }
                    if ($before -band $script:PasswdNotReqdBit) {
                        try {
                            Set-ADAccountControl -Identity $guid -PasswordNotRequired $false -Server $server
                            $flagOk = $true
                        }
                        catch {
                            $flagErr = Get-AdChangeErrorMessage $_
                            if ($flagErr -match 'blank|password does not meet') {
                                $flagOk = $false
                            }
                            else {
                                # Computers / objects that Set-ADAccountControl will not take.
                                try {
                                    $live = [int](Get-ADObject -Identity $guid -Server $server -Properties userAccountControl).userAccountControl
                                    Set-ADObject -Identity $guid -Replace @{ userAccountControl = ($live -band (-bnot $script:PasswdNotReqdBit)) } -Server $server
                                    $flagOk = $true
                                }
                                catch {
                                    $flagOk = $false
                                    $flagErr = Get-AdChangeErrorMessage $_
                                }
                            }
                        }
                    }

                    $after = [int](Get-ADObject -Identity $guid -Server $server -Properties userAccountControl).userAccountControl
                    $r['UserAccountControl'] = [string]$after
                    $r['UacFlags'] = ConvertTo-UacText $after
                    $r['Enabled'] = [string](-not ($after -band $script:AccountDisableBit))

                    if ($flagOk -eq $false -and $disableOk -eq $true) {
                        $r['Result'] = "PARTIAL $before -> $after ($flagErr)"
                        $r['Select'] = $false
                        Write-Log "$sam : disabled, but PASSWD_NOTREQD remains. $flagErr" 'Warn'
                        $partial++
                    }
                    elseif ($flagOk -eq $true -and $disableOk -eq $false) {
                        $r['Result'] = "PARTIAL $before -> $after (flag cleared; disable failed: $flagErr)"
                        $r['Select'] = $false
                        Write-Log "$sam : PASSWD_NOTREQD cleared, but disable failed. $flagErr" 'Warn'
                        $partial++
                    }
                    elseif ($flagOk -eq $false) {
                        $r['Result'] = "FAILED: $flagErr"
                        Write-Log "$sam : FAILED - $flagErr" 'Error'
                        $failed++
                    }
                    elseif ($disableOk -eq $false) {
                        $r['Result'] = "FAILED: $flagErr"
                        Write-Log "$sam : FAILED - $flagErr" 'Error'
                        $failed++
                    }
                    else {
                        $r['Result'] = "OK $before -> $after"
                        $r['Select'] = $false
                        Write-Log "$sam : userAccountControl $before -> $after ($(ConvertTo-UacText $after))" 'Success'
                        $ok++
                    }
                }
                catch {
                    $r['Result'] = "FAILED: $($_.Exception.Message)"
                    Write-Log "$sam : FAILED - $($_.Exception.Message)" 'Error'
                    $failed++
                }
            }
        }
        finally { Set-Busy $false }

        $summaryMsg = "Changed: $ok   Partial: $partial   Skipped: $skipped   Failed: $failed`r`n`r`nRollback file:`r`n$rbPath"
        Write-Log ($summaryMsg -replace "`r`n", ' ') 'Success'
        [void][System.Windows.Forms.MessageBox]::Show($form, $summaryMsg, 'Remediation complete', 'OK', 'Information')
    })

$btnFixRestore.Add_Click({
        $initial = $txtRollback.Text
        if (-not $initial) { $initial = $script:LastRunFolder }
        $path = Select-OpenFile -Title 'Select a rollback CSV (Rollback.csv or Rollback_Remediation_*.csv)' -InitialPath $initial
        if (-not $path) { return }
        try { $rows = @(Import-Csv -LiteralPath $path) }
        catch { Show-Error $_.Exception.Message; return }
        $hasUac = $false; $hasGuid = $false
        foreach ($n in $rows[0].PSObject.Properties.Name) {
            $h = Get-NormalizedHeaderName $n
            if ($h -ieq 'OriginalUAC') { $hasUac = $true }
            if (($h -replace '\s', '') -in @('ObjectGUID', 'ObjectGuid') -or $h -ieq 'Object guid') { $hasGuid = $true }
        }
        if (-not $rows.Count -or -not $hasUac -or -not $hasGuid) {
            Show-Error 'The file must contain ObjectGUID and OriginalUAC columns.' 'Invalid rollback file'
            return
        }

        # A remediation rollback file can contain the same account twice; the earliest entry is the true original.
        $rows = @($rows | Group-Object ObjectGUID | ForEach-Object { $_.Group | Select-Object -First 1 })
        $preview = ($rows | Select-Object -First 15 | ForEach-Object { "  $($_.SamAccountName) -> $($_.OriginalUAC) ($($_.OriginalUacFlags))" }) -join "`r`n"
        if ($rows.Count -gt 15) { $preview += "`r`n  ... and $($rows.Count - 15) more" }
        if (-not (Confirm-Action "Restore the original userAccountControl on $($rows.Count) account(s)?`r`n`r`n$preview" 'Confirm rollback')) { return }

        Set-Busy $true 'Restoring...'
        $ok = 0; $failed = 0
        try {
            foreach ($r in $rows) {
                try {
                    $server = $r.Server
                    if (-not $server -and $r.RestoreCommand -match "-Server '([^']+)'") { $server = $Matches[1] }
                    if (-not $server) { $server = (Get-DomainContext -Domain (Get-DomainFromDN $r.DistinguishedName) -Server '').Server }
                    Set-ADObject -Identity ([guid]$r.ObjectGUID) -Replace @{ userAccountControl = [int]$r.OriginalUAC } -Server $server
                    Write-Log "$($r.SamAccountName): restored userAccountControl=$($r.OriginalUAC)" 'Success'
                    $ok++
                }
                catch {
                    Write-Log "$($r.SamAccountName): restore FAILED - $($_.Exception.Message)" 'Error'
                    $failed++
                }
            }
        }
        finally { Set-Busy $false }
        [void][System.Windows.Forms.MessageBox]::Show($form, "Restored: $ok   Failed: $failed", 'Rollback complete', 'OK', 'Information')
    })

# =============================================================================================
# Startup
# =============================================================================================
if ($CsvPath)      { $txtCsv.Text = $CsvPath }
if ($OutputFolder) { $txtOut.Text = $OutputFolder }
if ($Server)       { $cboDc.Text = $Server; $cboMetaDc.Text = $Server }
if (-not $txtOut.Text -and -not $CsvPath) { $txtOut.Text = [Environment]::GetFolderPath('MyDocuments') }
Update-CsvInfo

$form.Add_Shown({
        $split.SplitterDistance = [Math]::Max(300, $split.Height - 190)
        Write-Log "Ready (v$($script:PnrVersion)). Tab 1: pick the Semperis CSV and an output folder, then click Run audit."
        $form.Activate()
    })

$form.Add_FormClosing({
        param($s, $e)
        if ($script:Busy) {
            if (Confirm-Action 'An operation is still running. Stop it and close?' 'Close') { $script:Cancel = $true }
            else { $e.Cancel = $true }
        }
    })

[void]$form.ShowDialog()
$form.Dispose()
