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
3. Enter your **Tenant** domain (e.g. `contoso.onmicrosoft.com`) or Directory (tenant) ID GUID
4. **App ID** defaults to Microsoft Graph PowerShell (`14d82eec-204b-4c2f-b113-9d477e6ee18c`)
   - If you get **AADSTS700016** (app not found in directory): click **Consent** as an admin, **or** register your own public-client app in the tenant and paste its Application (client) ID into **App ID**
5. Click **Connect Graph** and complete device-code sign-in in the browser
6. Either check **Enrich Users with Entra ID after query** and **Run Query**, or run a query first and click **Enrich Current Results**
7. Entra columns also appear under **Columns** and can be exported to CSV

#### Own app registration (locked-down tenants)

1. Entra admin center → **App registrations** → New registration (this org only)
2. **Authentication** → Allow public client flows = **Yes**
3. **API permissions** → Microsoft Graph (delegated) — the scopes listed above → **Grant admin consent**
4. Copy **Application (client) ID** into the tool’s **App ID** box

Matching uses `UserPrincipalName` / `EmailAddress` against Entra.
