# PowershellTools

PowerShell utilities for Windows / Entra ID administration.

## Get-EntraSmsVoiceAuthUsers.ps1

Finds **enabled** Entra ID users who have **SMS** and/or **voice** phone authentication methods, then exports a CSV.

### What it reports

- Users with registered phone MFA methods (`mobilePhone`, `officePhone`, `alternateMobilePhone`)
- Users whose preferred MFA method is `sms` or `voice*`
- **EmailAddress** and **EmployeeID** for each user
- Save File dialog to choose where the report is written

### Usage

```powershell
.\Get-EntraSmsVoiceAuthUsers.ps1
.\Get-EntraSmsVoiceAuthUsers.ps1 -OutputCsv .\SmsVoiceUsers.csv
.\Get-EntraSmsVoiceAuthUsers.ps1 -DeviceCode -TenantId contoso.onmicrosoft.com
.\Get-EntraSmsVoiceAuthUsers.ps1 -SelfTest
```

Sign-in defaults to **device code** (console-safe). That avoids the common
`A window handle must be configured` WAM/browser failure in PowerShell.
### Requirements

- `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser` (recommended)
- Graph permissions: `AuditLog.Read.All`, `User.Read.All` (admin consent)
- Entra role with access to the auth method registration report (e.g. Reports Reader)
