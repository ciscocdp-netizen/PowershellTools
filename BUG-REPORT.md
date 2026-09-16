# AD Delta Compare & Restore - Bug Report & Analysis
## Windows Server 2016 Compatibility Review

**Review Date:** 2026-08-16  
**Target Platform:** Windows Server 2016 with PowerShell 5.1  
**Script:** AD-Delta-Compare.ps1

---

## Executive Summary

The script is **mostly compatible** with Windows Server 2016, but has **several critical bugs** and potential issues that will cause runtime failures. Below is a detailed analysis with severity ratings.

---

## Critical Issues (Must Fix)

### 1. **LDAP Filter Injection Vulnerability**
**Severity:** CRITICAL  
**Location:** Lines 147-150 (CompareScript, Users/Computers/Groups section)

```powershell
if ($Filter) {
    $f = $Filter
    $nameClause = "(|(sAMAccountName=*$f*)(cn=*$f*)(displayName=*$f*)(name=*$f*))"
}
```

**Problem:** User input from `$txtFilter` is directly concatenated into LDAP filter without escaping special characters. LDAP special characters include: `*`, `(`, `)`, `\`, `/`, and `NUL`.

**Impact:** 
- Script will crash if user types `(`, `)`, `*` in the filter box
- Potential LDAP injection attack vector
- Invalid LDAP syntax errors

**Example Failure:**
```
User types: John (Admin)
Generated filter: (|(sAMAccountName=*John (Admin)*)...)
Result: Invalid LDAP filter syntax error
```

**Fix Required:** Escape LDAP special characters before building filter.

---

### 2. **Invoke-Expression Security Risk**
**Severity:** CRITICAL (Security)  
**Location:** Line 117

```powershell
Invoke-Expression $NormText
```

**Problem:** Using `Invoke-Expression` on a script-scoped variable that defines a function. While `$NormText` is not user-controlled in current implementation, this is a dangerous pattern.

**Impact:**
- Code injection risk if script is modified
- Makes code harder to audit for security
- PowerShell best practices strongly discourage `Invoke-Expression`

**Recommended Fix:** Use script blocks or dot-sourcing instead.

---

### 3. **Race Condition in Timer Event Handler**
**Severity:** HIGH  
**Location:** Lines 616-655 (Timer.Add_Tick event)

**Problem:** The timer checks completion status every 300ms but doesn't properly handle concurrent access to shared variables. If the form is closed while comparison is running, resources may not be cleaned up properly.

**Specific Issues:**
- `$script:Handle`, `$script:PowerShell`, `$script:Runspace` accessed without synchronization
- Form controls accessed from timer thread without invoke check
- No protection against form disposal during timer tick

**Impact:**
- Potential `ObjectDisposedException` if form closed during comparison
- Resource leaks (runspace not disposed)
- UI thread exceptions

---

### 4. **Missing Error Handling for Module Imports**
**Severity:** HIGH  
**Location:** Multiple locations (lines 577, 596, 866)

**Problem:** Module imports outside the background runspace don't check if modules are available before calling their cmdlets.

```powershell
$btnZones.Add_Click({
    if (-not $txtPdc.Text) { Write-Status 'Discover DCs first.' 'WARN'; return }
    try {
        Import-Module DnsServer -ErrorAction Stop  # Good
        # ... uses DNS cmdlets
```

**Issue:** If DnsServer module is not installed (not part of base Windows Server 2016), error is caught but subsequent clicks might fail.

---

### 5. **DataGridView Column Index vs Name Inconsistency**
**Severity:** MEDIUM  
**Location:** Lines 734-750 (grid selection handler)

```powershell
if ([string]$r.Cells['Restorable'].Value -eq 'True') { $restCount++ }
```

**Problem:** Accessing cells by string name instead of index. While this works, it's slower and can fail if column names change.

**Better approach:** Use column index or store reference to column.

---

## High-Priority Issues

### 6. **Insufficient Validation of SearchBase DN**
**Severity:** MEDIUM  
**Location:** Line 154

```powershell
if ($SearchBase) { $params['SearchBase'] = $SearchBase }
```

**Problem:** No validation that `$SearchBase` is a valid DN format before passing to `Get-ADObject`.

**Impact:** Cryptic error messages if user enters invalid DN.

**Fix:** Add DN format validation.

---

### 7. **Grid Color Coding May Fail on High Contrast Themes**
**Severity:** LOW (Accessibility)  
**Location:** Lines 644-649

```powershell
switch ($r.Status) {
    'Different'     { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,224,224) }
    'ObjectMissing' { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,244,204) }
    'Match'         { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(224,255,224) }
}
```

**Problem:** Hard-coded colors don't respect Windows high-contrast accessibility settings.

---

### 8. **Form Scaling Issues on High-DPI Displays**
**Severity:** MEDIUM  
**Location:** Lines 307-508 (all absolute positioning)

**Problem:** Uses absolute pixel positioning with `AutoScaleMode` not set. On high-DPI displays (150%, 200% scaling), layout will be incorrect.

**Fix:** Add after EnableVisualStyles():
```powershell
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
```

---

### 9. **Audit Log Encoding Issue**
**Severity:** LOW  
**Location:** Line 106

```powershell
try { Add-Content -Path $script:AuditLog -Value $line -Encoding UTF8 } catch { }
```

**Problem:** On Windows Server 2016 with PowerShell 5.1, `-Encoding UTF8` creates UTF-8 with BOM, which may cause issues with some log parsers.

**Note:** This is expected behavior in PS 5.1, but worth documenting.

---

### 10. **Silent Failure in Write-Audit**
**Severity:** MEDIUM  
**Location:** Line 106

```powershell
try { Add-Content -Path $script:AuditLog -Value $line -Encoding UTF8 } catch { }
```

**Problem:** Silently catches ALL exceptions, including permission errors. User never knows if audit logging is failing.

**Fix:** Log to Write-Status on first failure.

---

## Windows Server 2016 Specific Compatibility

### ✅ Compatible Features:
- PowerShell 5.1 syntax (ordered hashtables, `[pscustomobject]@{}`)
- Windows Forms (`System.Windows.Forms`, `System.Drawing`)
- ActiveDirectory module (included in RSAT)
- Runspace API and threading model
- All operators and cmdlets used

### ⚠️ Potential Issues:

#### DnsServer Module
- **Not installed by default** on Windows Server 2016
- Requires "DNS Server Tools" RSAT feature
- Script handles this with try/catch, but should warn user upfront

#### GroupPolicy Module
- **Not installed by default** on Windows Server 2016
- Requires "Group Policy Management Tools" RSAT feature
- Script handles this with try/catch

#### Recommended Pre-check:
Add to script start:
```powershell
$requiredModules = @('ActiveDirectory', 'DnsServer', 'GroupPolicy')
$missing = $requiredModules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
if ($missing) {
    [System.Windows.Forms.MessageBox]::Show(
        "Missing required modules: $($missing -join ', ')`r`n`r`nInstall RSAT features first.",
        'Missing Dependencies', 'OK', 'Warning')
}
```

---

## Logic Bugs

### 11. **$script:BulkPreviewRefresh Scope Pollution**
**Severity:** LOW  
**Location:** Lines 829-835

```powershell
$script:BulkPreviewRefresh = {
    $pg.Rows.Clear()
    foreach ($it in $Items) {
        $newVal = if ($rbR1.Checked) { $it.R1Val } else { $it.R2Val }
        [void]$pg.Rows.Add(@($it.Object, $it.Attribute, $newVal, $it.PdcVal))
    }
}
```

**Problem:** Defines a script-scope variable inside a function. This pollutes the script scope and could cause issues if function is called multiple times concurrently.

**Fix:** Use local variable or function scope.

---

### 12. **Incomplete Runspace Cleanup on Form Close**
**Severity:** MEDIUM  
**Location:** Lines 977-979

```powershell
if ($script:PowerShell) { try { $script:PowerShell.Dispose() } catch {} }
if ($script:Runspace)   { try { $script:Runspace.Dispose() } catch {} }
```

**Problem:** Only cleans up if `$script:PowerShell` and `$script:Runspace` still exist. If comparison is in progress, need to stop it first.

**Fix:** Check if `$script:Handle` exists and call `Stop()`.

---

### 13. **Convert-AdValueToString Recursion Risk**
**Severity:** LOW  
**Location:** Lines 76-88

```powershell
function Convert-AdValueToString {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [byte[]]) { return ([System.BitConverter]::ToString($Value)) }
    if ($Value -is [datetime]) { return ($Value.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")) }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = @()
        foreach ($v in $Value) { $items += (Convert-AdValueToString $v) }  # RECURSION
        if ($items.Count -eq 0) { return '' }
        return (($items | Sort-Object) -join '; ')
    }
    return [string]$Value
}
```

**Problem:** Recursive function with no depth limit. If AD returns deeply nested structures (unlikely but possible), could cause stack overflow.

**Fix:** Add depth parameter and limit to 5-10 levels.

---

## Performance Issues

### 14. **Inefficient Grid Population**
**Severity:** LOW  
**Location:** Lines 641-650

```powershell
$grid.SuspendLayout()
foreach ($r in $rows) {
    $idx = $grid.Rows.Add(@($r.Object,$r.Attribute,$r.PDC,$r.Replica1,$r.Replica2,$r.Status,$r.ObjectGUID,$r.DN,[string]$r.Restorable))
    $row = $grid.Rows[$idx]
    switch ($r.Status) {
        # ... color coding
    }
}
$grid.ResumeLayout()
```

**Problem:** Calling `$grid.Rows.Add()` in a loop is slow for large datasets (1000+ rows). Each call triggers internal grid updates.

**Better approach:** Use `DataGridView.DataSource` with a DataTable or BindingList.

---

### 15. **Hashtable Lookup in Tight Loop**
**Severity:** LOW  
**Location:** Lines 164-193

Multiple nested loops with hashtable lookups. For large AD environments (10,000+ objects), this could be slow.

**Note:** Acceptable for most environments, but could optimize with parallel processing.

---

## Security Best Practices

### 16. **Credentials Not Handled**
**Severity:** INFO  
**Location:** N/A

**Observation:** Script assumes current user credentials have rights to:
- Read from all DCs
- Write to PDC

**Recommendation:** Add optional `-Credential` parameter for alternate credentials.

---

### 17. **No Change Rollback Mechanism**
**Severity:** MEDIUM  
**Location:** Restore functionality

**Problem:** Once attributes are restored to PDC, there's no built-in rollback. Audit log helps, but manual rollback is tedious.

**Recommendation:** Add "Export restore script" feature that generates a reverse script.

---

## Code Quality Issues

### 18. **Inconsistent Error Handling**
- Some functions use try/catch with MessageBox
- Some use try/catch with Write-Status
- Some silently suppress errors with `catch { }`

**Recommendation:** Standardize error handling pattern.

---

### 19. **No Input Sanitization for Audit Log**
**Severity:** LOW  
**Location:** Lines 868-870

User-controlled values (object names, attribute values) written to audit log without sanitization. Could be used for log injection.

**Fix:** Sanitize newlines and special characters.

---

## Testing Recommendations

### Unit Tests Needed:
1. ✅ LDAP filter with special characters: `(`, `)`, `*`, `\`, `/`
2. ✅ SearchBase with invalid DN format
3. ✅ Missing RSAT modules
4. ✅ Permission denied on PDC write
5. ✅ Form close during active comparison
6. ✅ Empty/null attribute values in restore
7. ✅ Large dataset (10,000+ objects)
8. ✅ High-DPI display scaling
9. ✅ Network disconnection during comparison

---

## Summary of Required Fixes

| Priority | Issue | Fix Complexity |
|----------|-------|----------------|
| CRITICAL | LDAP injection | Easy |
| CRITICAL | Invoke-Expression | Medium |
| HIGH | Timer race condition | Medium |
| HIGH | Form disposal handling | Easy |
| MEDIUM | SearchBase validation | Easy |
| MEDIUM | Audit log failures | Easy |
| MEDIUM | DPI scaling | Easy |
| LOW | BulkPreviewRefresh scope | Easy |

---

## Recommended Testing Environment

- ✅ Windows Server 2016 (Build 14393) or later
- ✅ PowerShell 5.1.14393 or later
- ✅ Domain-joined system
- ✅ ActiveDirectory module installed
- ⚠️ DnsServer module (optional, for DNS comparison)
- ⚠️ GroupPolicy module (optional, for GPO comparison)
- ✅ User with read access to domain
- ✅ User with write access to PDC (for restore operations)

---

## Overall Assessment

**Grade: B- (Functional but needs fixes)**

The script demonstrates good understanding of:
- ✅ AD replication concepts
- ✅ Windows Forms GUI development
- ✅ Async operations with runspaces
- ✅ LDAP filtering basics

However, it has production-blocking bugs that must be fixed before deployment in a critical environment.

**Recommendation:** Fix critical issues (#1, #2, #3) before using in production.
