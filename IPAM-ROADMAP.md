# SolarWinds-like IPAM Roadmap (DHCP Manager)

**Author:** Anthony Blake  
**Current:** v2.7.0 (Dashboard Phase 1)

Goal: make this tool **feel and work** more like SolarWinds IPAM DHCP Management & Monitoring for **Microsoft DHCP**, while remaining a portable PowerShell + WPF script.

## Already strong (management)

- Scope / lease / reservation / exclusion / option / filter / policy management
- Multi-select lease ops, compare, migrate, events watch, BAD_ADDRESS troubleshoot
- Domain Scan for authorized estate inventory

## Phase 1 — shipped (v2.7.0)

- Monitoring **Dashboard** (KPIs, Active Alerts, Top 10 util, health, estate snapshot)
- Scopes dynamic filter
- Reuse Statistics poll as the monitoring data plane

## Phase 2 — next (recommended)

1. **Local trend history** — snapshot util to `%LOCALAPPDATA%\DHCPManager\` on each refresh; sparkline / last-N table; simple free-IP burn estimate
2. **Outbound alerts** — Windows Event Log + optional email/Teams webhook when Critical scopes appear
3. **Estate util rollup** — after Domain Scan, optionally poll Up+Authorized servers for Critical scope counts (multi-server Top risks)
4. **Health tab polish** — promote failover + unauthorized DHCP log IDs into a first-class Health view

## Phase 3 — always-on monitoring

- `-Monitor` / scheduled-task headless mode: scan → stats → alert → log without GUI
- Retention/cleanup for history files

## Intentionally out of scope (needs a different product)

- Multi-vendor DHCP/DNS (Cisco/ISC/Infoblox) as a full DDI platform
- Orion-style web console, RBAC, APE pollers
- True subnet maps / UDT switch-port correlation
- Packet-level rogue DHCP capture as a network agent

## Design north star

Keep SolarWinds-like **workflows** (summary → alert → drill-down → remediate) on Microsoft DHCP, not a pixel-perfect Orion clone.
