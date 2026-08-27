# DHCP Events + Live Watch (v2.5.0)

Footer: **Created by Anthony Blake**

## What you can do

1. **Detect Logs** — list `DhcpSrvLog*` files with **filename**, **last modified**, and size; pick which file to ingest
2. **Ingest** DHCP audit logs (Local / Server A / Server B / Custom path)
3. **Filter** ingested events by search text, Event ID, IP, MAC, hostname, and server
4. **Live Watch** Local / Server A / Server B / Custom file

## Detect Logs

1. Choose **Ingest Source**
2. Click **Detect Logs**
3. Review the list (sorted newest first)
4. Select a row → **Use Selected** (or double-click)
5. Click **Ingest Log**

## Filtering ingested events

Use the **Filter ingested events** bar:

| Control | Behavior |
|--------|----------|
| Search | Matches any field |
| Event ID | All, Assign/Renew/Release/Conflict/NACK/Decline/DNS/Auth |
| IP / MAC / Host | Contains match (MAC ignores separators) |
| Server | Distinct servers from loaded data |
| Apply Filter | Rebuilds the grid from the full ingested set |
| Clear Filters | Resets all criteria |
| Showing X of Y | Visible vs total ingested |

Export uses the **filtered** view. Live events still honor the current filter.

## Ingest performance

- Progress bar + ETA; Pause / Cancel
- Keeps newest 5,000 events in memory

## Live watch custom file

- Check **Custom file**, set **Watch file** (Browse or **Use ingest path**), then **Start Watch**

## Requirements for remote watch/ingest

- Administrative share access (`admin$` or `C$`)
- DHCP audit logging enabled
- DHCP management rights on the account
