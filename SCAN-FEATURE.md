# Domain DHCP Server Scan (v2.4.5)

Built by **Anthony Blake**

## What it does

Click **Scan Domain** in the toolbar to:

1. Discover DHCP servers from Active Directory authorization data across one or more DNS domains
2. Verify **Authorized** status for each server (Yes/No + detail)
3. **Ping** each server (1.5s timeout) for **Online** Up/Down
4. Optionally fill **Server A** or **Server B** from the results

## Multi-domain scanning

The scan dialog includes a **Domains to scan** list:

- Your **current domain** is added automatically
- Type another DNS domain (child, trusted, or forest peer) and click **Add Domain**
- **Remove** drops a domain from this scan (optional confirm for current domain)
- Enable **Remember extra domains for next launch** to persist extras under  
  `%LOCALAPPDATA%\DHCPManager\scan-domains.txt`

Each listed domain is queried via LDAP `CN=NetServices` on that domain. The current forest authorization list from `Get-DhcpServerInDC` is still included when available.

## Result columns

| Column | Meaning |
|--------|---------|
| Domain | DNS domain the authorization record came from |
| DNS Name | Server hostname from AD |
| IP Address | From AD or DNS resolution |
| Online | ICMP ping Up/Down |
| Authorized | Yes/No — present in AD DHCP authorization list |
| Latency | Ping round-trip |
| Authorization Detail | How authorization was determined |
| Source | Discovery method |

## Discovery / authorization methods

1. Preferred (current forest): `Get-DhcpServerInDC` (DhcpServer module)
2. Per domain: ADSI query of `CN=NetServices,CN=Services,<Configuration NC>` via `LDAP://<domain>/RootDSE`

Each result is checked against the combined AD authorized set (DNS and IP match).

## How to use

1. Click **Scan Domain**
2. Add any extra domains needed, then **Scan Now**
3. Review **Domain**, **Online**, and **Authorized** for each server
4. Select a server → **Use as Server A** or **Use as Server B**
5. Or double-click a row to fill the main connection box
6. Export results to CSV if needed

## Notes

- Online = reachability only (ICMP); firewall may block ping while DHCP still works
- Authorized = listed in AD DHCP authorization — not a service health check
- Extra domains require DNS resolution and LDAP access (trust / credentials)
- Rogue/unauthorized DHCP servers are not returned by AD discovery alone
