# ═══════════════════════════════════════════════════════════════════════════════
# DHCP Manager - Critical Fixes Patch
# Apply these changes to your existing DHCP-Manager.ps1 script
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
# STEP 1: Add to GLOBAL STATE section (after $Global:StatusTimer = $null)
# ───────────────────────────────────────────────────────────────────────────────

$Global:ActionLog = [System.Collections.Generic.List[string]]::new()

# ───────────────────────────────────────────────────────────────────────────────
# STEP 2: Add LOGGING FUNCTIONS (before UTILITY FUNCTIONS section)
# ───────────────────────────────────────────────────────────────────────────────

function Write-ActionLog {
    param(
        [string]$Message,
        [string]$Level = 'INFO' # INFO, WARN, ERROR, SUCCESS
    )
    $timestamp = Get-Date -Format 'HH:mm:ss.fff'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    try {
        $Global:ActionLog.Add($logEntry)
        
        # Keep only last 1000 entries
        if ($Global:ActionLog.Count -gt 1000) {
            $Global:ActionLog.RemoveAt(0)
        }
    } catch {}
    
    # Output to console for debugging
    $color = switch ($Level) {
        'SUCCESS' { 'Green' }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        default   { 'Cyan' }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Update-LogDisplay {
    if ($null -eq $TxtLog) { return }
    
    try {
        $TxtLog.Dispatcher.Invoke([action]{
            $TxtLog.Text = ($Global:ActionLog | Select-Object -Last 500) -join "`r`n"
            if ($null -ne $LogScrollViewer) {
                $LogScrollViewer.ScrollToEnd()
            }
        }, [System.Windows.Threading.DispatcherPriority]::Background)
    } catch {
        # Silent fail for log display updates
    }
}

# ───────────────────────────────────────────────────────────────────────────────
# STEP 3: REPLACE Set-Status function
# ───────────────────────────────────────────────────────────────────────────────

function Set-Status {
    param([string]$Message, [string]$Color = '#9AA3B2')
    Write-ActionLog "Status: $Message" "INFO"
    try {
        $TxtStatus.Dispatcher.Invoke([action]{
            $TxtStatus.Text = $Message
            $TxtStatus.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($Color)
        }, [System.Windows.Threading.DispatcherPriority]::Normal)
    } catch {
        Write-ActionLog "Error updating status: $_" "ERROR"
    }
}

# ───────────────────────────────────────────────────────────────────────────────
# STEP 4: REPLACE Get-SelectedScope function
# ───────────────────────────────────────────────────────────────────────────────

function Get-SelectedScopeId {
    # First check if a scope is selected in the Scopes grid
    if ($GridScopes.SelectedItem) {
        $scopeId = $GridScopes.SelectedItem.ScopeId.ToString()
        Write-ActionLog "Scope selected from grid: $scopeId" "INFO"
        return $scopeId
    }
    
    # Then check global selected scope
    if ($Global:SelectedScope) {
        Write-ActionLog "Using global selected scope: $Global:SelectedScope" "INFO"
        return $Global:SelectedScope
    }
    
    Write-ActionLog "No scope selected" "WARN"
    return $null
}

# ───────────────────────────────────────────────────────────────────────────────
# STEP 5: UPDATE Build-NavTree function - Add logging and error handling
# ───────────────────────────────────────────────────────────────────────────────

function Build-NavTree {
    Write-ActionLog "Building navigation tree..." "INFO"
    
    if (-not $Global:DHCPServer) {
        Write-ActionLog "Cannot build nav tree: No DHCP server connected" "WARN"
        return
    }
    
    try {
        $NavTree.Items.Clear()
        
        # ... (keep existing tree building code, but add logging after key operations)
        
        Write-ActionLog "Fetching scopes from $Global:DHCPServer..." "INFO"
        $scopes = Get-DhcpServerv4Scope -ComputerName $Global:DHCPServer -ErrorAction Stop
        Write-ActionLog "Found $($scopes.Count) scopes" "SUCCESS"
        
        # ... (rest of existing code)
        
        Write-ActionLog "Navigation tree built successfully with $($scopes.Count) scopes" "SUCCESS"
        
    } catch {
        Write-ActionLog "Error building navigation tree: $_" "ERROR"
        Set-Status "Error building navigation tree: $_" '#F44336'
    }
}

# ───────────────────────────────────────────────────────────────────────────────
# STEP 6: UPDATE Load-Scopes function - Add logging
# ───────────────────────────────────────────────────────────────────────────────

function Load-Scopes {
    Write-ActionLog "Loading scopes from $Global:DHCPServer..." "INFO"
    Set-Status 'Loading scopes...'
    
    try {
        $scopes = Get-DhcpServerv4Scope -ComputerName $Global:DHCPServer -ErrorAction Stop
        Write-ActionLog "Retrieved $($scopes.Count) scopes" "SUCCESS"
        
        # ... (keep existing code for stats and items)
        
        $GridScopes.ItemsSource = [System.Collections.ObjectModel.ObservableCollection[object]]($items)
        Set-Status "Loaded $($scopes.Count) scopes." '#4CAF50'
        Set-LastRefresh
        Write-ActionLog "Scopes loaded successfully" "SUCCESS"
        
    } catch {
        Write-ActionLog "Error loading scopes: $_" "ERROR"
        Set-Status "Error loading scopes: $_" '#F44336'
    }
    
    Update-LogDisplay
}

# ───────────────────────────────────────────────────────────────────────────────
# STEP 7: UPDATE Load-Leases function - Add validation and logging
# ───────────────────────────────────────────────────────────────────────────────

function Load-Leases {
    param([string]$ScopeId)
    
    if (-not $ScopeId) {
        Write-ActionLog "Cannot load leases: No scope ID provided" "ERROR"
        Set-Status "Error: No scope selected" '#F44336'
        return
    }
    
    Write-ActionLog "Loading leases for scope $ScopeId..." "INFO"
    Set-Status "Loading leases for $ScopeId..."
    
    try {
        $leases = Get-DhcpServerv4Lease -ComputerName $Global:DHCPServer -ScopeId $ScopeId -ErrorAction Stop
        Write-ActionLog "Retrieved $($leases.Count) leases" "SUCCESS"
        
        # ... (keep existing items creation code)
        
        $GridLeases.ItemsSource = [System.Collections.ObjectModel.ObservableCollection[object]]($items)
        Set-Status "Loaded $($leases.Count) leases for scope $ScopeId." '#4CAF50'
        Set-LastRefresh
        Write-ActionLog "Leases loaded successfully" "SUCCESS"
        
    } catch {
        Write-ActionLog "Error loading leases: $_" "ERROR"
        Set-Status "Error loading leases: $_" '#F44336'
    }
    
    Update-LogDisplay
}

# ───────────────────────────────────────────────────────────────────────────────
# STEP 8: ADD Log Button Handler (add near other button handlers)
# ───────────────────────────────────────────────────────────────────────────────

$BtnViewLog.add_Click({
    Write-ActionLog "Opening action log view..." "INFO"
    Show-Tab $TabLog
    $TxtBreadcrumb.Text = "Action Log"
    Update-LogDisplay
})

$BtnLogClear.add_Click({
    Write-ActionLog "Clearing action log..." "INFO"
    $Global:ActionLog.Clear()
    Write-ActionLog "Action log cleared" "SUCCESS"
    Update-LogDisplay
})

$BtnLogExport.add_Click({
    try {
        $dlg = New-Object System.Windows.Forms.SaveFileDialog
        $dlg.Filter   = 'Log files (*.log)|*.log|Text files (*.txt)|*.txt|All files (*.*)|*.*'
        $dlg.FileName  = "DHCP-Manager-Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        if ($dlg.ShowDialog() -eq 'OK') {
            $Global:ActionLog | Out-File -FilePath $dlg.FileName -Encoding UTF8
            Write-ActionLog "Log exported to $($dlg.FileName)" "SUCCESS"
            Set-Status "Log exported successfully" '#4CAF50'
        }
    } catch {
        Write-ActionLog "Error exporting log: $_" "ERROR"
        Show-MessageBox "Error exporting log:`n$_" 'Export Error' 'OK' 'Error'
    }
    Update-LogDisplay
})

# ───────────────────────────────────────────────────────────────────────────────
# STEP 9: UPDATE Handle-NavSelect to add logging
# ───────────────────────────────────────────────────────────────────────────────

function Handle-NavSelect {
    param([string]$Tag)
    Write-ActionLog "Handling navigation selection: $Tag" "INFO"
    
    try {
        if ($Tag -match '^Scope:([^:]+)$') {
            $scopeId = $Matches[1]
            $Global:SelectedScope = $scopeId
            Write-ActionLog "Selected scope: $scopeId" "SUCCESS"
            $TxtBreadcrumb.Text = "$Global:DHCPServer > IPv4 > $scopeId"
            Show-Tab $TabLeases
            Load-Leases $scopeId
        }
        elseif ($Tag -match '^Scope:([^:]+):Leases$') {
            $scopeId = $Matches[1]
            $Global:SelectedScope = $scopeId
            Write-ActionLog "Viewing leases for scope: $scopeId" "INFO"
            $TxtBreadcrumb.Text = "$Global:DHCPServer > IPv4 > $scopeId > Leases"
            Show-Tab $TabLeases
            Load-Leases $scopeId
        }
        # ... (add similar logging for other conditions)
    } catch {
        Write-ActionLog "Error handling navigation selection: $_" "ERROR"
        Set-Status "Navigation error: $_" '#F44336'
    }
}

# ───────────────────────────────────────────────────────────────────────────────
# STEP 10: Apply same pattern to ALL Load-* functions
# ───────────────────────────────────────────────────────────────────────────────
# For each Load-* function:
# 1. Add Write-ActionLog at start
# 2. Wrap in try-catch
# 3. Log success/error
# 4. Call Update-LogDisplay at end

Write-Host @"

═══════════════════════════════════════════════════════════════════════════════
PATCH FILE LOADED
═══════════════════════════════════════════════════════════════════════════════

To apply this patch to your DHCP-Manager.ps1:

1. Copy the functions above and replace the corresponding functions in your script
2. Add the $Global:ActionLog variable to the GLOBAL STATE section
3. Add logging calls to ALL other data loading functions following the pattern
4. Test thoroughly after applying changes

Key Improvements:
✓ Real-time action logging with timestamps
✓ Better error handling and visibility
✓ Scope selection tracking
✓ Thread-safe UI updates
✓ Console debugging output

═══════════════════════════════════════════════════════════════════════════════
"@ -ForegroundColor Green
