# Domain DHCP Server Scan (v2.4)

Built by **Anthony Blake**

## What it does

Click **🔍 Scan Domain** in the toolbar to:

1. Discover **authorized DHCP servers** in Active Directory  
2. **Ping** each server (1.5s timeout)  
3. Show **Up / Down** status with latency  
4. Optionally fill **Server A** or **Server B** from the results  

## Discovery methods

1. **Preferred:** `Get-DhcpServerInDC` (DhcpServer module)  
2. **Fallback:** ADSI query of `CN=NetServices,CN=Services,<Configuration NC>`  

## How to use

1. Click **Scan Domain**  
2. Wait for the scan dialog to list servers and ping results  
3. Select a server → **Use as Server A** or **Use as Server B**  
4. Or **double-click** a row to fill the main connection box  
5. **Export** results to CSV if needed  

## Requirements

- Domain-joined machine (or network path to a DC)  
- Rights to read AD DHCP authorization data  
- ICMP allowed to target DHCP servers for ping status  
- `DhcpServer` RSAT module recommended  

## Notes

- Ping = reachability only (not proof the DHCP service is healthy)  
- Unauthorized / rogue DHCP servers are **not** listed by AD discovery  
- Down status can mean firewall blocking ICMP even if DHCP is up  
