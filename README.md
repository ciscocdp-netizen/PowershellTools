# PowershellTools

Admin-focused Windows PowerShell utilities.

## Conditional Access What If

`CA-WhatIf-PolicyChecker.ps1` is an Entra ID Conditional Access simulator that follows the same model as the Microsoft Entra **What If** tool.

- Primary engine: Microsoft Graph `POST /identity/conditionalAccess/evaluate`
- Fallback: local include/exclude and condition evaluator
- Windows 7 Aero-styled WinForms UI
- Combined enforced result (block wins; report-only is not treated as enforced)

```powershell
# GUI
.\CA-WhatIf-PolicyChecker.ps1

# Local engine self-test (no Graph, no UI)
.\CA-WhatIf-PolicyChecker.ps1 -SelfTest
```
