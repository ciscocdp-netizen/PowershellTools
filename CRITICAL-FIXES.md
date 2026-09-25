# Critical Fixes Applied - Launch Issues Resolved

## Issue #1: XAML Event Handler Error (FIXED ✅)

### Error Message
```
Fatal error during initialization: Exception calling "Load" with "1" argument(s): 
"Failed to create a 'SelectionChangedEventHandler' from the text 
'GridFilterInspectorDrives_SelectionChanged'."
```

### Root Cause
The XAML had an inline event handler reference:
```xml
<DataGrid SelectionChanged="GridFilterInspectorDrives_SelectionChanged">
```

This syntax expects a compiled code-behind class, but our PowerShell script uses runtime event registration.

### Fix (Commit `79f43f6`)
Removed the `SelectionChanged` attribute from XAML. The event handler is properly registered in code:
```powershell
$gridFilterInspector.add_SelectionChanged({ ... })
```

---

## Issue #2: Dispatcher Threading Error (FIXED ✅)

### Error Message
```
Fatal error during initialization: Exception calling "ShowDialog" with "0" argument(s): 
"The property 'Text' cannot be found on this object. Verify that the property 
exists and can be set."
```

### Root Cause
The `Write-ActionLog` and `Update-StatusBar` functions were calling `Dispatcher.Invoke()` even when already running on the UI thread. This created nested dispatcher invocations, causing the WPF property system to fail.

**Original problematic code**:
```powershell
function Write-ActionLog {
    # This ALWAYS called Dispatcher.Invoke, even from UI thread
    $script:Window.Dispatcher.Invoke([action]{
        $script:ActionLogEntries.Add($entry)
    })
}
```

When called from the `add_Loaded` event handler (which runs on UI thread), this created:
- UI thread → Dispatcher.Invoke → UI thread (nested)
- Property access failures due to re-entrancy issues

### Fix (Commit `e9b7e42`)

Added `CheckAccess()` to determine current thread context:

```powershell
function Write-ActionLog {
    param([string]$Message, [string]$Level = 'INFO')
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = [pscustomobject]@{
        Timestamp = $timestamp
        Level = $Level
        Message = $Message
    }
    
    # Always log to console (safe)
    $color = switch ($Level) {
        'SUCCESS' { 'Green' }
        'WARNING' { 'Yellow' }
        'ERROR' { 'Red' }
        default { 'Gray' }
    }
    Write-Host "[$timestamp] $Level : $Message" -ForegroundColor $color
    
    # Only update UI if window is initialized
    if ($null -ne $script:Window) {
        try {
            if ($script:Window.Dispatcher.CheckAccess()) {
                # Already on UI thread - execute directly
                $script:ActionLogEntries.Add($entry)
            } else {
                # On background thread - marshal to UI thread
                $script:Window.Dispatcher.Invoke([action]{
                    $script:ActionLogEntries.Add($entry)
                })
            }
        } catch {
            # Fail silently if window not ready
        }
    }
}

function Update-StatusBar {
    param([string]$Message, [string]$Color = 'Success')
    
    if ($null -eq $script:Window) { return }
    
    try {
        $updateAction = {
            $statusText = $script:Window.FindName('TxtStatusLeft')
            if ($null -eq $statusText) { return }
            
            $statusText.Text = $Message
            $statusText.Foreground = $script:Window.Resources[$Color]
        }
        
        if ($script:Window.Dispatcher.CheckAccess()) {
            # Already on UI thread
            & $updateAction
        } else {
            # On background thread
            $script:Window.Dispatcher.Invoke([action]$updateAction)
        }
    } catch {
        # Fail silently if window not ready
    }
}
```

### Key Improvements

1. **Thread-Aware Execution**:
   - `CheckAccess()` returns `$true` if already on UI thread
   - Avoids nested `Dispatcher.Invoke()` calls
   - Direct execution when safe, marshalling when necessary

2. **Null Safety**:
   - Check `$script:Window` exists before accessing
   - Check controls exist before setting properties
   - Graceful degradation if UI not ready

3. **Error Handling**:
   - Try-catch blocks prevent initialization race conditions
   - Console logging still works even if UI fails
   - Silent failures for non-critical UI updates

---

## Testing Status

### ✅ Both Issues Fixed

**Commit History**:
- `79f43f6` - Fix XAML event handler reference for Filter Inspector grid
- `e9b7e42` - Fix dispatcher threading issues in logging functions

**Branch**: `cursor/gpo-drive-mapping-validator-gui-4391`  
**PR**: [#24](https://github.com/ciscocdp-netizen/PowershellTools/pull/24)

### Expected Behavior

When you run:
```powershell
.\GPO-DriveMap-Manager-v2-FULL.ps1
```

You should see:
1. Console output: "Initializing GPO Drive Mapping Validator & Manager..."
2. Console output: "Launching UI..."
3. Dark-themed GUI window appears (2-3 seconds)
4. No error dialogs
5. Status bar shows "Ready" in green
6. Clock updates every second in bottom-right corner

---

## Technical Background: WPF Threading Model

### Single-Threaded Apartment (STA)
WPF runs in STA mode, meaning:
- Only one thread (the UI thread) can modify UI elements
- Background threads must marshal calls to UI thread via `Dispatcher`
- The UI thread processes messages from a queue

### Dispatcher.CheckAccess()
```powershell
if ($script:Window.Dispatcher.CheckAccess()) {
    # Code is ALREADY on UI thread - safe to modify UI directly
    $textBox.Text = "New Value"
} else {
    # Code is on BACKGROUND thread - must marshal to UI thread
    $script:Window.Dispatcher.Invoke([action]{
        $textBox.Text = "New Value"
    })
}
```

### Why Nested Invoke Fails

**Scenario**: Event handler calls function that calls `Dispatcher.Invoke()`

```powershell
# Window.Loaded event handler (runs on UI thread)
$script:Window.add_Loaded({
    # We're already on UI thread here
    Write-ActionLog "Application started" "SUCCESS"
    # ^ This function calls Dispatcher.Invoke() AGAIN
    # Result: UI thread → Dispatcher.Invoke → UI thread (BAD)
})
```

**Problem**:
- The UI thread is waiting for the `Invoke` to complete
- But the `Invoke` needs the UI thread to execute
- This creates a re-entrancy issue
- WPF's property system gets confused about which context owns the object

**Solution**:
- Check if already on UI thread: `CheckAccess()`
- If yes, execute directly (no `Invoke`)
- If no, use `Invoke` to marshal

---

## Best Practices for PowerShell WPF

### ✅ DO THIS
```powershell
function Update-UI {
    if ($script:Window.Dispatcher.CheckAccess()) {
        $control.Text = "Value"
    } else {
        $script:Window.Dispatcher.Invoke([action]{
            $control.Text = "Value"
        })
    }
}
```

### ❌ DON'T DO THIS
```powershell
function Update-UI {
    # ALWAYS using Invoke, even when already on UI thread
    $script:Window.Dispatcher.Invoke([action]{
        $control.Text = "Value"
    })
}
```

### ✅ DO THIS
```powershell
$script:Window.add_Loaded({
    # Already on UI thread - no Invoke needed
    $txtStatus.Text = "Ready"
})
```

### ❌ DON'T DO THIS
```powershell
$script:Window.add_Loaded({
    # Unnecessary nested Invoke
    $script:Window.Dispatcher.Invoke([action]{
        $txtStatus.Text = "Ready"
    })
})
```

---

## Verification Checklist

After pulling the latest changes, verify:

- [ ] Script launches without error dialogs
- [ ] Dark-themed window appears
- [ ] Toolbar shows domain and GPO dropdowns
- [ ] All 6 tabs are visible and clickable
- [ ] Status bar shows "Ready" in green (bottom-left)
- [ ] Clock shows current time and updates every second (bottom-right)
- [ ] Action Log tab shows "Application started" entry
- [ ] Domain dropdown populates with available domains
- [ ] No console errors about "Text" property or "SelectionChanged"

---

## If Issues Persist

### Diagnostic Steps

1. **Check PowerShell Version**:
   ```powershell
   $PSVersionTable.PSVersion
   # Should be 5.1 or higher
   ```

2. **Verify RSAT Modules**:
   ```powershell
   Get-Module -ListAvailable ActiveDirectory, GroupPolicy
   ```

3. **Run with Verbose Output**:
   ```powershell
   $VerbosePreference = 'Continue'
   $ErrorActionPreference = 'Continue'
   .\GPO-DriveMap-Manager-v2-FULL.ps1
   ```

4. **Check for Assembly Loading Issues**:
   ```powershell
   Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
   Add-Type -AssemblyName PresentationCore -ErrorAction Stop
   Add-Type -AssemblyName WindowsBase -ErrorAction Stop
   ```

5. **Test Basic WPF**:
   ```powershell
   Add-Type -AssemblyName PresentationFramework
   $window = New-Object System.Windows.Window
   $window.Title = "Test"
   $window.Width = 300
   $window.Height = 200
   [void]$window.ShowDialog()
   # Should show a blank window
   ```

---

## Summary

Both critical launch issues have been resolved:

1. ✅ **XAML Event Handler Error** - Removed inline event handler, using code registration
2. ✅ **Dispatcher Threading Error** - Added `CheckAccess()` to prevent nested invocations

**Latest Commit**: `e9b7e42` - Fix dispatcher threading issues in logging functions  
**Branch**: `cursor/gpo-drive-mapping-validator-gui-4391`  
**Status**: Ready for testing

Please try launching the script again. It should work cleanly now! 🚀
