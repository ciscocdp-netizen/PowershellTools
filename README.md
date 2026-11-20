# PowershellTools

Windows administration scripts for Microsoft Entra ID, Active Directory, DHCP, and related tasks.

## Entra Conditional Access device exemption

`Set-EntraDeviceCAExemption.ps1` is an interactive tool (Windows PowerShell 5.1 and PowerShell 7+) that sets, updates, or clears `extensionAttribute1` on Windows Entra devices. Use that attribute in a Conditional Access **Filter for devices** rule.

```powershell
.\Set-EntraDeviceCAExemption.ps1
```

Requirements: `Microsoft.Graph.Authentication`, delegated `Device.ReadWrite.All`, and an Entra role that can write device objects (Cloud Device Administrator, Intune Administrator, or Global Administrator).

CSV bulk updates accept `DeviceId`, `ObjectId`, or `DisplayName`, plus optional `Value` and `Action` (`Set` or `Clear`). Headers such as `Device ID`, `Name`, and `Operation` are accepted. Comma, semicolon, and tab delimited files are detected automatically.

Helper tests (no Graph sign-in required):

```powershell
pwsh -NoProfile -File ./Tests/Set-EntraDeviceCAExemption.Tests.ps1
```
