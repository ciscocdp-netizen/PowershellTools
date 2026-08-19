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
2. Click **Sign in to Entra ID** once → browser sign-in (Graph permissions requested automatically)
3. That session is wired into all Graph pulls (roles, devices, auth methods, failed sign-ins)
4. Check what to pull, then run an AD query with **Enrich Users after AD query**, or click **Enrich Current Results**

If you already signed in with `Connect-MgGraph` / `Connect-AzAccount` in the same PowerShell session, the tool reuses that session.

**Advanced sign-in options** (optional): tenant override or custom App (client) ID if your org blocks Microsoft first-party apps.

Enrichment matches users by `UserPrincipalName` / email. Failed sign-in logs need Entra ID P1/P2.
