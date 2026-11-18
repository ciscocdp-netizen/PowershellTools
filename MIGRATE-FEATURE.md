# Scope Migration (v2.3)

Built by **Anthony Blake**

Migrate scopes from **Server A (source)** to **Server B (destination)**.

## What can be migrated

| Component | Behavior |
|-----------|----------|
| **Scope** | Creates the IPv4 scope on B (name, range, mask, lease duration, description) |
| **Scope Options** | Copies scope-level option values (003 router, 006 DNS, etc.) |
| **Reservations** | Copies reserved clients (IP + MAC/client ID) |
| **Exclusions** | Copies exclusion ranges |
| **Active Leases → Reservations** | Optional — turns live leases on A into reservations on B |
| **Activate on B** | Optionally activates the destination scope after success |
| **Deactivate on A** | Optionally deactivates the source scope after a clean migration |

## How to use

1. Connect **Server A** in the top toolbar (source).
2. Open **Compare** → connect **Server B** (destination).
3. Open **🚚 Migrate**.
4. Click **Load Source Scopes**.
5. Check the scopes to move (or Select All).
6. Choose what to include and conflict behavior:
   - **Merge into existing** — keep scope on B, still copy options/reservations/exclusions
   - **Skip scope** — leave that scope untouched on B
   - **Fail** — stop that scope if it already exists on B
7. Click **🧪 Dry Run** to preview every planned step.
8. Click **🚚 Migrate** to execute (confirmation required).
9. Export the plan/results CSV if needed.

## Safety notes

- Always **Dry Run** first in production.
- Prefer migrating **reservations** over raw leases when possible.
- If you use **Leases → Reservations**, review for duplicates before cutover.
- Deactivate source only after clients can reach the destination DHCP server.
- This migrates **scope-level** configuration; server-level options/policies/filters are not moved by this tab.

## Typical cutover flow

1. Compare A vs B (scopes/options/reservations)
2. Dry-run migration
3. Migrate with Activate on B enabled
4. Update helpers/relays/firewall as needed
5. Deactivate A (optional checkbox) once B is serving leases
6. Watch **Events** on A and B during cutover
