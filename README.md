# PowershellTools

## Entra ID Security Baseline

`Invoke-EntraSecurityBaseline.ps1` runs a Maester-style Entra ID assessment (authentication methods, Conditional Access, legacy-auth WhatIf, directory recommendations) against Microsoft Graph and writes a self-contained interactive HTML report.

```powershell
.\Invoke-EntraSecurityBaseline.ps1 -DemoMode
.\Invoke-EntraSecurityBaseline.ps1 -TenantId contoso.onmicrosoft.com
.\Invoke-EntraSecurityBaseline.ps1 -DeviceCode
.\Invoke-EntraSecurityBaseline.ps1 -SelfTest
```

Keep `EntraSecurityBaseline.ReportTemplate.html` next to the script. `-DemoMode` builds the report from bundled sample data (no Graph sign-in). `-SelfTest` validates helpers and demo report generation. The report is not opened automatically; pass `-Launch` if you want that.

### CrowdStrike Falcon

Falcon often quarantines unsigned PowerShell that looks like a dropper (character-code string building, a large inline JavaScript payload, write-then-execute). This revision keeps JavaScript in the HTML template, uses built-in `ConvertTo-Json`, and does not launch the report unless you pass `-Launch`.

If it is still blocked:

```powershell
Unblock-File .\Invoke-EntraSecurityBaseline.ps1
Unblock-File .\EntraSecurityBaseline.ReportTemplate.html
pwsh -NoProfile -File .\Invoke-EntraSecurityBaseline.ps1 -DemoMode
```

Ask your Falcon admin to allowlist this script folder or file hash (Prevention policy: IOA / ML exclusions). Do not run it with `-EncodedCommand` or `-ExecutionPolicy Bypass`; those flags are blocked more often than `RemoteSigned`. Prefer PowerShell 7.
