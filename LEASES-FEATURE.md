# Multi-select Leases (v2.5.3)

Footer: **Created by Anthony Blake**

## What you can do

On the **Leases** tab:

1. **Multi-select** leases with **Ctrl+click** or **Shift+click**
2. **Select All** / **Clear Selection**
3. **Release** one or many selected leases
4. **Convert to Reservation** one or many selected leases

## Selection

- Grid uses **Extended** selection (full rows)
- Status text shows how many are selected vs how many are in the grid

## Bulk Release

- Confirms with a summary of selected IPs/hostnames
- Progress bar with Pause / Cancel
- Per-lease success/failure summary at the end

## Bulk Convert to Reservation

- Confirms before changing anything
- Skips leases that:
  - Have no MAC / Client ID
  - Already look like a reservation (`AddressState` contains `Reservation`)
  - Already have a matching reservation on the server
- Progress bar with Pause / Cancel
- Summary: converted / skipped / failed

## Tip

Select a scope first (nav tree or Scopes tab), then open **Leases** and refresh.
