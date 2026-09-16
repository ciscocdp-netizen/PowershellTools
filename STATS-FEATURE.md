# Scope Statistics + High Utilization (v2.5.2)

Footer: **Created by Anthony Blake**

## What you can do

1. **Refresh All Scopes** — load server totals **and** utilization for every DHCP scope
2. **Flag high utilization** — default **≥ 90%** (changeable: 70 / 80 / 85 / 90 / 95)
3. **Alert banner** — lists Critical scopes so they stand out immediately
4. **Filter** — All scopes / Warning + Critical / Critical only
5. **Scope Details** — double-click a row (or **Scope Details** / Enter) for full stats, exclusions, reservation sample, and guidance
6. **Export** — CSV of the visible grid

## Status levels

| Level | Meaning |
|-------|---------|
| Critical | Utilization ≥ flag threshold (default 90%) |
| Warning | Within 10 points below the threshold (e.g. 80–89% when flag is 90%) |
| OK | Below the warning band |

## Detail popup includes

- Utilization (in use / free / total / reserved / pending)
- Scope config (name, range, mask, lease duration, description)
- Capacity guidance for Critical / Warning / OK
- Exclusion ranges
- Sample reservations
- Copy Details

## Tips

- Sort is highest utilization first after each refresh
- Changing the flag threshold re-levels the current results without re-querying the server
- Use Pause / Cancel on the shared progress bar for large servers
