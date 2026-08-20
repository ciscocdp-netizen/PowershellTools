# DHCP Events + Live Watch (v2.4.9)

Footer: **Created by Anthony Blake**

## What you can do

1. **Ingest DHCP audit logs** from:
   - Local server (`%SystemRoot%\System32\dhcp\DhcpSrvLog*`)
   - Server A (primary connection) via `\\server\admin$\System32\dhcp` (falls back to `C$`)
   - Server B (compare connection) the same way
   - Custom file/folder path (Browse)

2. **Watch DHCP events in real time** on Local, Server A, Server B, and/or a **Custom file**.
   - Polls audit logs every 2 seconds
   - Survives log rotation (resets offset if file shrinks)
   - Tags each event with the source server

## Ingest performance + progress

- Parsing no longer updates the grid on every line (was very slow on large logs)
- Bottom status bar shows a **progress bar + ETA**; Events tab mirrors percent
- **Pause** / **Resume** (Events button or status bar) and **Cancel** (status bar)
- Keeps the newest 5,000 events if the file contains more

## Live watch custom file

- Check **Custom file**, set **Watch file** (Browse or **Use ingest path**), then **Start Watch**
- Can be combined with Local / Server A / Server B
- Polls the chosen `DhcpSrvLog*` file every 2 seconds from the end (new events only)

## How to use

1. Open **📡 Events** (toolbar or tab).
2. Choose source → **Detect** or **Browse** → **Ingest Log** for history.
3. Watch progress / ETA; use **Pause** or **Cancel** if needed.
4. For live watch: check **Local** / **Server A** / **Server B** and/or **Custom file** (set Watch file) → **Start Watch**.
5. New Assign / Renew / Release / NACK / etc. rows appear at the top of the grid.
6. **Export** to CSV when needed. **Stop** when finished.

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
