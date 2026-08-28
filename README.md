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
# Interactive browser / account-picker login (default)
.\Get-EntraSmsVoiceAuthUsers.ps1

.\Get-EntraSmsVoiceAuthUsers.ps1 -OutputCsv .\SmsVoiceUsers.csv
.\Get-EntraSmsVoiceAuthUsers.ps1 -TenantId contoso.onmicrosoft.com

# Device code only if interactive login is blocked
.\Get-EntraSmsVoiceAuthUsers.ps1 -DeviceCode

.\Get-EntraSmsVoiceAuthUsers.ps1 -SelfTest
```

Sign-in defaults to **interactive login**. The script relaunches in STA and shows a
small parent window so Windows WAM can attach a window handle. If Graph interactive
auth fails, it tries Azure PowerShell browser login, then device code.

### Requirements

- `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser` (recommended)
- Optional fallback: `Install-Module Az.Accounts -Scope CurrentUser`
- Graph permissions: `AuditLog.Read.All`, `User.Read.All` (admin consent)
- Entra role with access to the auth method registration report (e.g. Reports Reader)
