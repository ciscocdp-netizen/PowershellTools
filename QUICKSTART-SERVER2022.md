# Quick Start for Windows Server 2022

## ⚡ TL;DR - Get Started in 30 Seconds

Since you're on **Windows Server 2022**, the GUI may not work. Use the CLI instead:

### Option 1: Interactive Menu (Easiest)
```powershell
.\Start-GPOValidator-CLI.ps1
```

### Option 2: Direct Command (Fastest)
```powershell
.\Test-GpoDriveMapTargeting.ps1 -GpoName "Your GPO Name" -TargetUsers alice, bob
```

---

## 📋 For Your Specific Situation

You tried to run:
```powershell
.\GPO_MappedDriveValidation.ps1
```

But it hung because the GUI requires desktop components not available on your server.

### ✅ What To Do Instead:

**Step 1: Use the interactive CLI launcher**
```powershell
cd "C:\Users\Anthony.Blake.ark\Documents"
.\Start-GPOValidator-CLI.ps1
```

This will show you a menu:
```
═══ Main Menu ═══

  [1] Quick Validation (specific users)
  [2] Validate Entire OU
  [3] Show Help / CLI Usage
  [4] Open Documentation Folder
  [5] Try GUI (if supported)
  [Q] Quit
```

Choose option 1 or 2, and follow the prompts!

---

## 🎯 Real Examples for Your Environment

### Example 1: Test a GPO Against Specific Users

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Corporate Drives" `
    -TargetUsers john.smith, jane.doe, bob.jones
```

### Example 2: Test Against Your Finance Department

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Corporate Drives" `
    -TargetOU "OU=Finance,OU=Users,DC=yourdomain,DC=com" `
    -ExportCsvPath "C:\Validation\Finance-Drives-Report.csv"
```

### Example 3: Debug Why a User Isn't Getting a Drive

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Corporate Drives" `
    -TargetUsers problem.user `
    -ShowFilterTrace
```

This shows you EXACTLY why each filter matched or didn't match.

---

## 📊 Example Output

When you run a validation, you'll see:

```
=================== SUMMARY: Who receives which drive ===================

john.smith:
  H:  \\fileserver\home\john.smith   (Home Drive)
  S:  \\fileserver\shared   (Shared Drive)
  F:  \\fileserver\finance   (Finance Drive)

jane.doe:
  H:  \\fileserver\home\jane.doe   (Home Drive)
  S:  \\fileserver\shared   (Shared Drive)

=================== DRIVE-LETTER CONFLICTS ===================
None detected.

Validation complete.
```

---

## 🔍 Before You Start

### Check What You Have:

```powershell
# Check if you have the right modules
Get-Module -ListAvailable ActiveDirectory, GroupPolicy

# If missing, install RSAT (as Administrator):
Install-WindowsFeature RSAT-AD-PowerShell, RSAT-GP
```

### Test If GUI Would Work (Optional):

```powershell
.\Test-WPF-Compatibility.ps1
```

This will tell you if the GUI can work on your server. **Spoiler: probably not on Server 2022 Core.**

---

## 💡 Common Tasks

### Validate Before Adding a New Drive

```powershell
# 1. Check current state
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Corporate Drives" `
    -TargetUsers alice `
    -ExportCsvPath "C:\Before.csv"

# 2. Add your new drive in GPMC (don't apply yet!)

# 3. Validate again
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Corporate Drives" `
    -TargetUsers alice `
    -ExportCsvPath "C:\After.csv"

# 4. Compare results, fix conflicts, then deploy!
```

### Troubleshoot User Complaint

```powershell
# User says "I'm not getting the F: drive"
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "Corporate Drives" `
    -TargetUsers complaining.user `
    -ShowFilterTrace
```

The trace will show you exactly which filter is blocking them.

### Validate Entire Department Before Rollout

```powershell
.\Test-GpoDriveMapTargeting.ps1 `
    -GpoName "New Finance Drives" `
    -TargetOU "OU=Finance,OU=Users,DC=corp,DC=com" `
    -ExportCsvPath "C:\Validation\Finance-Rollout-$(Get-Date -Format 'yyyyMMdd').csv"
```

---

## 📚 Documentation

All in your Documents folder:

- **TROUBLESHOOTING-SERVER.md** - Why GUI hangs and what to do
- **EXAMPLES.md** - 13 practical examples
- **GPO-DRIVEMAP-VALIDATOR-USERGUIDE.md** - Full guide
- **README.md** - Quick overview

---

## 🆘 If Something Goes Wrong

### Error: "Module not found"

```powershell
# Install RSAT
Install-WindowsFeature RSAT-AD-PowerShell, RSAT-GP
```

### Error: "GPO not found"

- Check the exact GPO name (case-sensitive)
- Or use `-DrivesXmlPath` to point directly to the XML file

### Script Still Hanging?

```powershell
# Press Ctrl+C to stop
# Then use the CLI version:
.\Start-GPOValidator-CLI.ps1
```

---

## 🎯 Your Next Steps

1. **Open PowerShell as Administrator** on your Server 2022 machine

2. **Navigate to your folder:**
   ```powershell
   cd "C:\Users\Anthony.Blake.ark\Documents"
   ```

3. **Run the interactive launcher:**
   ```powershell
   .\Start-GPOValidator-CLI.ps1
   ```

4. **Follow the prompts!**

Or jump straight to validation:

```powershell
.\Test-GpoDriveMapTargeting.ps1 -GpoName "YOUR-GPO-NAME-HERE" -TargetUsers user1, user2
```

---

## 💬 Quick Reference

```powershell
# === Most Common Commands ===

# Interactive (easiest)
.\Start-GPOValidator-CLI.ps1

# Quick test
.\Test-GpoDriveMapTargeting.ps1 -GpoName "GPO Name" -TargetUsers alice,bob

# Full department
.\Test-GpoDriveMapTargeting.ps1 -GpoName "GPO Name" -TargetOU "OU=Dept,DC=domain,DC=com"

# Debug mode
.\Test-GpoDriveMapTargeting.ps1 -GpoName "GPO Name" -TargetUsers alice -ShowFilterTrace

# With export
.\Test-GpoDriveMapTargeting.ps1 -GpoName "GPO Name" -TargetUsers alice -ExportCsvPath "C:\report.csv"
```

---

**🎉 The CLI version has ALL the same features as the GUI - just without the buttons and pretty colors!**

**All validation capabilities work perfectly on Server 2022. 🚀**
