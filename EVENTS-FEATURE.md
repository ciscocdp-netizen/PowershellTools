# DHCP Events + Live Watch (v2.2)

Author stamp in footer: **Anthony Blake**

## What you can do

1. **Ingest DHCP audit logs** from:
   - Local server (`%SystemRoot%\System32\dhcp\DhcpSrvLog*`)
   - Server A (primary connection) via `\\server\admin$\System32\dhcp` (falls back to `C$`)
   - Server B (compare connection) the same way
   - Custom file/folder path (Browse)

2. **Watch DHCP events in real time** on Local, Server A, and/or Server B simultaneously.
   - Polls audit logs every 2 seconds
   - Survives log rotation (resets offset if file shrinks)
   - Tags each event with the source server

## How to use

1. Open **📡 Events** (toolbar or tab).
2. Choose source → **Detect** or **Browse** → **Ingest Log** for history.
3. Check **Local** / **Server A** / **Server B** → **Start Watch**.
4. New Assign / Renew / Release / NACK / etc. rows appear at the top of the grid.
5. **Export** to CSV when needed. **Stop** when finished.

## Requirements for remote watch/ingest

- Administrative share access (`admin$` or `C$`) to the remote DHCP server
- DHCP audit logging enabled on the server
- Same account rights you already use for DHCP management

## Event IDs (common)

| ID | Meaning |
|----|---------|
| 10 | Assign |
| 11 | Renew |
| 12 | Release |
| 13 | Conflict |
| 15 | NACK |
| 16 | Decline |
| 30–32 | DNS updates |
