# Multi-Server Compare Feature (v2.5.5)

Footer: **Created by Anthony Blake**

## What it does

Connect a second DHCP server (Server B) and compare it against the primary server (Server A) for:

- **Scopes** — network ID, name, range, mask, state, lease duration
- **Options** — server-level and scope-level option values (keyed by Option ID + Vendor/User class + Policy)
- **Leases** — matched by normalized MAC (fallback: IP+scope)
- **Reservations** — matched by normalized MAC (fallback: IP+scope)

## Accuracy notes (v2.5.11)

- **Numeric Scope ID / IP sort:** Results sort like the DHCP MMC (`10.15.96.0` then `10.15.100.0`), not as text (`10.15.100.0` before `10.15.96.0`)
- **MAC normalization:** `aa-bb-cc-…`, `AA:BB:CC:…`, and `AABBCC…` are treated as the same client
- **IP normalization:** Scope IDs / ranges / option IPs compared via parsed IPv4 text
- **Names/hostnames:** case-insensitive
- **Options:** VendorClass, UserClass, and PolicyName are part of the match key (avoids collapsing different class options)
- **Option values:** multi-value options compared order-independently after trim/IP normalize
- **Lease AddressState:** Active vs ActiveReservation (and similar active variants) do **not** force a “Different” status on failover pairs

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
| Different | Same key exists on both, but compared values differ |

## Notes

- Server B must be a different host than Server A.
- Primary Server A must be connected before connecting Server B.
- Lease/reservation comparison keys off normalized MAC when available (stable across failover pairs).
