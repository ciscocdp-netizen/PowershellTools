# PowershellTools

## AD Report Tool

Interactive WinForms GUI for querying Active Directory (Users, Groups, Computers, OUs), with optional **Entra ID** enrichment for users.

```powershell
.\scripts\AD-Report-Tool.ps1
```

**Requirements**
- Windows PowerShell 5.1+
- ActiveDirectory RSAT module
- For Entra: install **one** of these (browser sign-in):
  ```powershell
  Install-Module Microsoft.Graph -Scope CurrentUser
  # or
  Install-Module Az.Accounts -Scope CurrentUser
  ```

### Entra ID (simplified)

1. Select **Users**
2. Click **Sign in to Entra ID** → complete browser sign-in (Graph permissions are requested automatically)
3. Check what to pull (Roles / Devices / Auth methods / Last failed sign-in)
4. Run an AD query with **Enrich Users after AD query**, or click **Enrich Current Results**

**Advanced sign-in options** (optional): tenant override or custom App (client) ID if your org blocks Microsoft first-party apps.

Enrichment matches users by `UserPrincipalName` / email. Failed sign-in logs need Entra ID P1/P2.
