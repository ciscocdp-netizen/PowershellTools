# PowershellTools

Windows administration tools written in PowerShell.

| Tool | Entry point | What it does |
|------|-------------|--------------|
| AD Object Manager | `AD-ObjectManager-Modern.ps1` | Browse and manage Active Directory objects, including disabling and re-enabling computers. |
| DHCP Manager | `DHCP-Manager-Production.ps1` | Manage DHCP scopes and reservations. See `START-HERE.md` and `INDEX.md` for the full package. |
| M365 Mailbox Copy | `M365-Mailbox-Copy/M365-Mailbox-Copy-Tool.ps1` | Copy mail and calendar items between Microsoft 365 mailboxes over Microsoft Graph. |

Most of these are WinForms or WPF tools written for Windows PowerShell 5.1. Read the
tool's own README or script header before running it: several require permissions to
be granted beforehand.
