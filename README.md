# PowershellTools

## AD Report Tool

Interactive WinForms GUI for querying Active Directory (Users, Groups, Computers, OUs), with optional **Entra ID (Microsoft Graph)** enrichment for users.

```powershell
.\scripts\AD-Report-Tool.ps1
```

**Requirements**
- Windows PowerShell 5.1+
- ActiveDirectory RSAT module and read access to AD
- For Entra enrichment: network access to `login.microsoftonline.com` and `graph.microsoft.com`, plus Graph permissions (admin consent may be required):
  - `User.Read.All`
  - `Directory.Read.All`
  - `AuditLog.Read.All` (failed sign-ins; needs Entra ID P1/P2)
  - `UserAuthenticationMethod.Read.All`
  - `Device.Read.All`
  - `RoleManagement.Read.Directory`

### Entra ID enrichment (Users)

1. Select **Users**
2. In **Entra ID Enrichment**, choose data to pull:
   - Assigned roles
   - Devices (registered / owned)
   - Authentication methods
   - Last failed sign-in (error code, time, app, location, IP)
3. Enter your **Tenant** domain (e.g. `contoso.onmicrosoft.com`) or Directory (tenant) ID GUID — required to avoid AADSTS50059
4. Click **Connect Graph** and complete device-code sign-in in the browser
5. Either check **Enrich Users with Entra ID after query** and **Run Query**, or run a query first and click **Enrich Current Results**
6. Entra columns also appear under **Columns** and can be exported to CSV

Matching uses `UserPrincipalName` / `EmailAddress` against Entra.
