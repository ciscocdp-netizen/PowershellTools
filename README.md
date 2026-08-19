# PowershellTools

## AD Report Tool

Interactive WinForms GUI for querying Active Directory (Users, Groups, Computers, OUs), with optional **Entra ID (Microsoft Graph)** enrichment for users.

```powershell
.\scripts\AD-Report-Tool.ps1
```

**Requirements**
- Windows PowerShell 5.1+
- ActiveDirectory RSAT module and read access to AD
- For Entra enrichment: network access to `login.microsoftonline.com` and `graph.microsoft.com`

### Entra ID enrichment (Users)

1. Select **Users**
2. Enter **Tenant** (domain or Directory ID GUID)
3. Choose **App**:
   - **Azure PowerShell** (try first — usually already in the tenant)
   - **Azure CLI**
   - **Custom App Registration** (required if Microsoft apps are blocked — see below)
   - Avoid **Microsoft Graph PowerShell** if you see **AADSTS700016** (admin consent cannot install it)
4. Click **Connect Graph** and complete device-code sign-in
5. Enable enrich options / **Enrich Current Results**

#### AADSTS700016 — register your own app

Admin consent for `14d82eec-…` (Graph PowerShell) will **fail** if that app is not in your directory. Create your own:

1. Entra admin center → **App registrations** → New registration (this org only)
2. **Authentication** → Allow public client flows = **Yes**
3. **API permissions** → Microsoft Graph (delegated) → Grant admin consent:
   - `User.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`
   - `UserAuthenticationMethod.Read.All`, `Device.Read.All`, `RoleManagement.Read.Directory`
4. Copy **Application (client) ID** → tool **App** = Custom → paste into **App ID** → Connect

Use the tool’s **Setup** button for the same walkthrough (opens App registrations).

Matching uses `UserPrincipalName` / `EmailAddress` against Entra. Sign-in logs need Entra ID P1/P2.
