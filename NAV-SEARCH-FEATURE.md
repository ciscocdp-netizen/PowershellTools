# Navigation Scope Search (v2.5.6)

Footer: **Created by Anthony Blake**

## What you can do

In the left **DHCP Navigation** pane:

1. Type a **scope name**, **Scope ID**, or part of the description
2. The tree filters live to matching scopes
3. Press **Enter** or click **Find next match** to jump to the next match
4. Press **Esc** or click **✕** to clear the search

## Layout

- Search box + clear (**✕**) on one row (clear is docked so it never gets clipped)
- **Find next match** on its own full-width row
- Status text wraps under the controls
- Navigation pane default width is 280px (resizable via the splitter)

## Matching

- Case-insensitive contains match
- Searches scope **name**, **Scope ID**, and **description**
- Scopes header shows `Scopes (matches/total)` while filtering

## Tips

- Partial IP works (example: `10.20.`)
- Partial name works (example: `voice`)
- **Find next match** cycles through matches when more than one remains
- Selecting a match still opens that scope’s Leases view (same as clicking the tree)
