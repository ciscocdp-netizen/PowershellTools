# Multi-Server Compare Feature (v2.1)

## What it does

Connect a second DHCP server (Server B) and compare it against the primary server (Server A) for:

- **Scopes** — network ID, name, range, mask, state
- **Options** — server-level and scope-level option values
- **Leases** — matched primarily by MAC, then IP
- **Reservations** — matched primarily by MAC, then IP

## How to use

1. Connect **Server A** from the top toolbar (primary connection).
2. Open the **🔀 Compare** tab (or click **Compare** in the toolbar).
3. Enter **Server B** hostname/IP and click **Connect B**.
4. Choose what to compare: Scopes / Options / Leases / Reservations.
5. Click **▶️ Run Compare**.
6. Optionally filter: All / Only on A / Only on B / Matching / Different.
7. Click **💾 Export Results** to save a CSV.

## Result statuses

| Status | Meaning |
|--------|---------|
| Only on A | Present on primary, missing on compare server |
| Only on B | Present on compare server, missing on primary |
| Matching | Same key and same compared values |
| Different | Same key exists on both, but values differ |

## Notes

- Server B must be a different host than Server A.
- Primary Server A must be connected before connecting Server B.
- Options compare includes server options plus all scope options.
- Lease/reservation comparison keys off MAC when available (more stable across failover pairs).
