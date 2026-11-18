# PowershellTools

Windows administration scripts for Active Directory, DHCP, and Microsoft 365 / Entra ID.

## Tools

| Script | Purpose |
| --- | --- |
| `Revoke-M365Sessions.ps1` | Interactively revoke Microsoft 365 / Entra ID sign-in sessions from a CSV of UPNs |
| `AD-ObjectManager-Modern.ps1` | WinForms tool to disable, enable, or delete AD users and computers in bulk |
| `DHCP-Manager-Production-Complete.ps1` | DHCP Manager starter template (see `START-HERE.md`) |

### Revoke Microsoft 365 sign-in sessions

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Revoke-M365Sessions.ps1
```

The script auto-relaunches in STA mode so the file picker works from a normal console, installs `Microsoft.Graph.Authentication` if needed, and supports a dry run before any sessions are revoked. Sign-in opens https://microsoft.com/devicelogin in your browser and prints a code in the console (Windows WAM cannot show a login prompt from ISE, VS Code, or Cursor). That login happens once; later Graph calls reuse the same session, and WAM is disabled so token refresh does not open extra Microsoft prompts. On a live run it can re-read each user from Graph and confirm `signInSessionsValidFromDateTime` moved forward.

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Revoke-M365Sessions.ps1 -SelfTest
```
