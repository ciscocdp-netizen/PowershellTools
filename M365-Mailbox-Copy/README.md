# Microsoft 365 Mailbox Copy Tool

A WinForms tool that copies mail and calendar items from one Microsoft 365 mailbox
into another over Microsoft Graph, using interactive (delegated) sign-in. Items are
copied, never moved: the source mailbox is left untouched.

| File | Purpose |
|------|---------|
| `M365-Mailbox-Copy-Tool.ps1` | The tool. Run it, sign in, fill in the two mailboxes, copy. |
| `tests/Invoke-AllTests.ps1` | Runs every suite below; exits non-zero on failure. |
| `tests/Invoke-FolderStructureTests.ps1` | Folder comparison and replication tests against a mocked Graph. |
| `tests/Invoke-ProgressTests.ps1` | Live status, progress and ETA tests against a virtual clock. |
| `tests/Invoke-CopyEmailsTests.ps1` | End-to-end `Copy-Emails` tests against a fake mailbox. |
| `tests/GraphMocks.ps1` | In-memory stand-in for the Graph mail-folder endpoints. |
| `tests/MessageMocks.ps1` | In-memory stand-in for the Graph message endpoints. |
| `tests/WinFormsShim.ps1` | Lets the tool's WinForms-typed functions load off Windows. |
| `tests/ToolLoader.ps1` | Loads the tool's functions without running its bootstrap or GUI. |

## Requirements

- Windows PowerShell 5.1 (the tool is a WinForms app and is written for 5.1).
- The `Microsoft.Graph.Mail`, `Microsoft.Graph.Calendar` and
  `Microsoft.Graph.Authentication` modules. The script installs them into the
  current user's scope on first run if they are missing.
- Delegated scopes, consented at sign-in: `Mail.ReadWrite`, `Mail.ReadWrite.Shared`,
  `Calendars.ReadWrite`, `Calendars.ReadWrite.Shared`.
- **FullAccess on both mailboxes**, granted to the account you sign in with.

## Running it

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\M365-Mailbox-Copy-Tool.ps1
```

1. Grant your account FullAccess on the source and target mailboxes (Exchange Admin
   Center, or `Add-MailboxPermission`). The tool cannot do this for you: Exchange
   Online PowerShell could not authenticate from a PowerShell 5.1 WinForms thread
   under MFA/Conditional Access, so it was dropped in v1.6.
2. Sign in (step 1 in the UI), tick the pre-flight checklist, enter the source and
   target addresses, choose mail and/or calendar, then start the copy.
3. Remove the FullAccess permissions when you are done. The completion dialog
   reminds you.

Permission changes can take a few minutes to take effect across Exchange Online. If
the copy reports `ErrorAccessDenied`, wait and retry before investigating anything
else.

## What gets copied

**Mail.** The folder hierarchy is mirrored first, then messages are copied folder by
folder. Original sent/received times, read state, importance, categories, recipients
and file attachments are preserved; times and the "not a draft" state are stamped
through MAPI extended properties, because Graph ignores `sentDateTime` /
`receivedDateTime` on create and always creates in the draft state. Duplicates are
detected per folder on subject + received time + sender, so a re-run resumes rather
than doubling up.

**Calendar.** Subject, body, start/end, all-day flag, location, recurrence, reminder,
free/busy, sensitivity and categories. Attendees are written as MAPI attendee strings
rather than the Graph `attendees` collection, because posting that collection makes
Exchange email an invitation to every attendee. Teams meetings keep the original join
URL instead of having a new meeting provisioned. Occurrences of a recurring series are
skipped; the series master is copied once.

## Folder replication

Both hierarchies are enumerated up front and compared, then **only the folders the
target is missing are created** — before any mail moves, so the structure matches the
source even for folders that hold no mail. Nothing in the target is renamed, moved or
deleted:

- Folders that already exist are reused exactly as they are.
- Folders that exist only in the target are listed in the log and left alone.
- Folders are compared by canonical path, where a well-known root (Inbox, Sent Items,
  Drafts, ...) is represented by its well-known name rather than its display name. A
  Dutch target mailbox therefore matches `Inbox\Clients` to `Postvak IN\Clients`
  instead of growing a second "Inbox".
- A display name that collides with an existing folder anyway (Graph answers 409
  `ErrorFolderExists`) is adopted rather than reported as a failure, and the log says
  it was reused rather than created.

The comparison is also re-run during verification at the end of the copy, which lists
anything still missing.

If a folder cannot be created or found, its messages are **skipped and reported**, and
so is its whole subtree. They are deliberately not posted to `/users/{id}/messages`,
which would silently file them as drafts in the target mailbox.

v1.15 fixed six defects here; see the changelog in the script header. In short: empty
folders were dropped, a name containing an apostrophe broke the OData lookup and got
its mail written to the parent folder (children were re-parented one level up), a
backslash in a name was expanded into a nested path, well-known folders were matched
by display name, failed folder listings silently dropped whole subtrees while the run
still reported success, and unresolvable folders had their mail drafted.

## Progress and ETA

Two lines above the progress bar are updated in place while the copy runs:

```
Copying email  -  folder 12/48 'Inbox\Projects\2024' - message 1,204/3,867  -  14,312 / 61,904  (23%)
Elapsed 21m 14s   |   remaining ~1h 09m 02s   |   done by 15:47   |   11.2 items/s   |   copied 13,900, skipped 400, failed 12
```

- The phase line names what the run is doing (scanning the source, scanning the
  target, comparing structures, creating missing folders, copying email, copying
  calendar, verifying), which folder it is on and that folder's position in the run,
  and the item counter inside it. Graph paging shows up here too, so a folder with
  tens of thousands of messages no longer floods the log with page counters.
- The ETA line shows elapsed time, estimated time remaining, the wall-clock time the
  copy is expected to finish, throughput, and the running copied / skipped / failed
  totals. The estimate uses throughput over a trailing two-minute window rather than
  the average since the start, so it reacts when Graph starts throttling instead of
  smoothing it away.
- The progress bar is a marquee while a phase's size is unknown, and a percentage once
  a total exists. If a folder returns a different number of messages than its
  `TotalItemCount` claimed, the overall total is corrected mid-run so the percentage
  and the estimate stay honest.
- Repaints are throttled to four per second: the copy runs on the UI thread, so
  painting every item would slow the copy down measurably.

The status log keeps folder-level events: what was created or reused, how many
messages the destination already held, per-batch results, per-folder totals, and any
failure detail.

## Known limitations

- Hidden folders are not enumerated (`GET /mailFolders` omits them unless
  `includeHiddenFolders=true` is requested).
- Duplicate detection keys on subject + received minute + sender, so two genuinely
  distinct messages that agree on all three (a double delivery, or two automated
  notices in the same minute) are treated as one and only the first is copied.
- The online archive is a separate mailbox and is not touched.
- Search folders are not copied.
- The copy runs on the UI thread. It pumps the message loop so progress paints and
  Cancel responds, but the window will feel sluggish on very large mailboxes.
- Throttling is handled with exponential back-off; a very large mailbox can still
  take a long time.

## Tests

The folder logic and the progress engine have regression tests that run without a
tenant. They load the function definitions out of `M365-Mailbox-Copy-Tool.ps1` itself
with the PowerShell parser (so they cannot drift from the shipped code, and the GUI
never starts) and drive them against a fake mailbox store and a virtual clock.

```powershell
# Windows PowerShell 5.1 or PowerShell 7, any OS
pwsh -File .\tests\Invoke-AllTests.ps1
```

161 assertions across three suites.

The **folder** suite covers empty folders, apostrophes in nested and top-level names,
backslashes in names, a localized target mailbox, repeated names under different
parents, a folder listing that fails partway through, name lookups that return nothing
or error out, a target that already matches the source (which must issue no writes and
no lookups at all), a partially populated target (only the absent folders may be
created), folders that exist only in the target, and a display name that collides with
a well-known folder in the target.

The **progress** suite covers duration formatting, the phase/detail/position status
line, the marquee and percentage states of the bar, the estimate itself — including
that it follows recent throughput rather than the average since the start — repaint
throttling, mid-run total corrections, and that every progress call is inert when
there is no UI.

The **copy** suite runs the real `Copy-Emails` end to end against fake message
endpoints: a full copy (every message must land in its own folder and nothing may be
posted to the mailbox root, which Graph would file as drafts), a second run that must
copy and create nothing, a partially populated target, a folder that cannot be created
(its mail is skipped, not drafted, and its subtree is not created), a folder whose
`TotalItemCount` disagrees with its message list, a message Graph rejects, and
cancelling mid-copy.

All three suites exit non-zero on failure, so they work as a build check.

Coverage was checked by mutation: re-introducing any of fourteen defects makes the
suites fail, including dropping the OData escaping, matching well-known folders by
display name, treating a failed lookup as "not found", creating every source folder
instead of only the missing ones, looking the target folder up by display-name path,
posting mail with no target folder to `/users/{id}/messages`, swallowing a failed
folder listing, skipping the mid-run total correction, estimating from the average
rate instead of the recent one, and removing the repaint throttle.
