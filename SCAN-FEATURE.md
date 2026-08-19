# Domain DHCP Server Scan (v2.4)

Built by **Anthony Blake**

## What it does

Click **Scan Domain** in the toolbar to:

1. Discover DHCP servers from Active Directory authorization data
2. Verify **Authorized** status for each server (Yes/No + detail)
3. **Ping** each server (1.5s timeout) for **Online** Up/Down
4. Optionally fill **Server A** or **Server B** from the results

## Result columns

| Column | Meaning |
|--------|---------|
| DNS Name | Server hostname from AD |
| IP Address | From AD or DNS resolution |
| Online | ICMP ping Up/Down |
| Authorized | Yes/No — present in AD DHCP authorization list |
| Latency | Ping round-trip |
| Authorization Detail | How authorization was determined |
| Source | Discovery method |

## Discovery / authorization methods

1. Preferred: `Get-DhcpServerInDC` (DhcpServer module) -> Authorized = Yes
2. Also: ADSI query of `CN=NetServices,CN=Services,<Configuration NC>`

Each result is explicitly checked against the AD authorized set (DNS and IP match).

## How to use

1. Click **Scan Domain**
2. Review **Online** and **Authorized** for each server
3. Select a server -> **Use as Server A** or **Use as Server B**
4. Or double-click a row to fill the main connection box
5. Export results to CSV if needed

## Notes

- Online = reachability only (ICMP); firewall may block ping while DHCP still works
- Authorized = listed in AD DHCP authorization — not a service health check
- Rogue/unauthorized DHCP servers are not returned by AD discovery alone
