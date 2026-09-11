# IPAM-style Monitoring Dashboard (v2.7.0)

Footer: **Created by Anthony Blake**

## What this is

A **SolarWinds IPAM–inspired** monitoring summary for Microsoft DHCP — capacity KPIs, active alerts, Top 10 utilization, failover/conflict health, and an estate snapshot from Domain Scan — inside the existing PowerShell WPF console.

This is **Phase 1** of bringing DHCP Manager closer to SolarWinds DHCP Management & Monitoring. It does **not** replace SolarWinds IPAM (no multi-vendor DNS/IPAM DB, no Orion web console, no historical polling engine).

## How to use

1. Connect to a DHCP server → Dashboard opens automatically
2. Click **Refresh Monitoring** (polls the same engine as Statistics)
3. Review **Critical / Warning** KPIs and **Active alerts**
4. Double-click an alert or Top 10 row for scope details
5. **Scan Estate** to fill the multi-server snapshot
6. Use management tabs for CRUD; **Troubleshoot** for BAD_ADDRESS

## Widgets

| Widget | SolarWinds analogue |
|--------|---------------------|
| KPI strip (Scopes / Leases / Available / Util / Critical / Warnings) | IPAM Summary capacity cards |
| Active alerts | Active Alerts / scope utilization alerts |
| Top 10 scopes by utilization | Top 10 DHCP scopes by utilization |
| Server health (failover + conflict detection) | DHCP server status strip |
| Estate snapshot | DHCP servers inventory (from Scan Domain) |

## Also in v2.7.0

- **Scopes filter** — type-ahead filter on the Scopes tab (IPAM-style dynamic filter)
- Window title: **DHCP Manager v2.7 — Monitoring & Management**

## Roadmap (later phases)

See `IPAM-ROADMAP.md` for history/trends, outbound alerts, always-on monitor mode, and what stays out of scope for a single PS1.
