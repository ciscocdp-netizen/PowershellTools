# PowershellTools

## Entra ID Security Baseline

`Invoke-EntraSecurityBaseline.ps1` runs a Maester-style Entra ID assessment (authentication methods, Conditional Access, legacy-auth WhatIf, directory recommendations) against Microsoft Graph and writes a self-contained interactive HTML report.

```powershell
.\Invoke-EntraSecurityBaseline.ps1 -DemoMode
.\Invoke-EntraSecurityBaseline.ps1 -TenantId contoso.onmicrosoft.com
.\Invoke-EntraSecurityBaseline.ps1 -DeviceCode
.\Invoke-EntraSecurityBaseline.ps1 -SelfTest
```

`-DemoMode` builds the report from bundled sample data (no Graph sign-in). `-SelfTest` validates JSON encoding, StrictMode helpers, and demo report generation.
