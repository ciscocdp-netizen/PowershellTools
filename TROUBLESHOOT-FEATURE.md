# BAD_ADDRESS Troubleshooting (v2.6.0)

Footer: **Created by Anthony Blake**

## What you can do

1. Open **🛠️ Troubleshoot** (toolbar, nav tree, or tab)
2. Pick a scope (or **Use selected scope**)
3. Choose a probe sample size (**3 / 4 / 5**)
4. **Run Diagnostics** — walks the BAD_ADDRESS root-cause checklist
5. Review findings, BAD_ADDRESS leases, and ping/ARP probes
6. Fix the cause outside the tool as needed
7. Check **I reviewed the findings…**, then **Clear BAD_ADDRESS leases**
8. **Export Report** — CSV of findings, leases, and probes

## Diagnostic checklist

| Step | Check | What it does |
|------|--------|----------------|
| 1 | ConflictDetectionAttempts | Reads `Get-DhcpServerSetting` |
| 2 | BAD_ADDRESS inventory | Lists Bad/Declined / `BAD_ADDRESS` leases |
| 3 | Sequential vs random | Classifies IP pattern (Sequential / Clustered / Random) |
| 4 | Ping / ARP sample | Probes 3–5 BAD IPs from this host |
| 5 | MAC comparison | Same MAC across IPs → proxy ARP / middlebox clue |
| 6 | Device ownership | Whether sampled IPs look live |
| 7 | DHCP failover health | `Get-DhcpServerv4Failover` (+ stats when available) |
| 8 | Other DHCP on VLAN | AD-authorized servers + guidance for on-VLAN capture |
| 9 | Gateway / proxy ARP | Router option 003 ping/ARP + checklist |
| 10 | Clear readiness | Unlock clear only after review confirmation |

## Clear gating (safety)

Clear stays **disabled** until:

1. Diagnostics have been run for the current scope
2. There is at least one BAD_ADDRESS lease
3. You check the confirmation box
4. You accept the Yes/No confirm dialog

If you change scopes, re-run diagnostics before clearing.

## Tips

- ARP is most accurate when this console is on the **same VLAN** as the scope
- Rogue DHCP cannot be fully proven in-app — use a DHCP Offer capture on-VLAN
- Clearing without fixing the cause will usually refill BAD_ADDRESS quickly
- Use Pause / Cancel on the shared progress bar during long runs
