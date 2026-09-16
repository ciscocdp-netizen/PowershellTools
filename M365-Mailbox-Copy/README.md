# Microsoft 365 Mailbox Copy Tool

A WinForms tool that copies mail and calendar items from one Microsoft 365 mailbox
into another over Microsoft Graph, using interactive (delegated) sign-in. Items are
copied, never moved: the source mailbox is left untouched.

| File | Purpose |
|------|---------|
| `M365-Mailbox-Copy-Tool.ps1` | The tool. Run it, sign in, fill in the two mailboxes, copy. |
| `tests/Invoke-FolderStructureTests.ps1` | Folder-replication regression tests against a mocked Graph. |
| `tests/GraphMocks.ps1` | In-memory stand-in for the Graph mail-folder endpoints. |
| `tests/WinFormsShim.ps1` | Lets the tool's WinForms-typed functions load off Windows. |

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

The target hierarchy is built before any mail is copied, so it matches the source even
for folders that hold no mail. Path segments are resolved one at a time, with results
cached, and each source well-known folder (Inbox, Sent Items, Drafts, ...) is resolved
through the *target's* well-known folder rather than by display name, so a mailbox in
another display language does not end up with a second "Inbox".

If a folder cannot be created or found, its messages are **skipped and reported**. They
are deliberately not posted to `/users/{id}/messages`, which would silently file them
as drafts in the target mailbox.

v1.15 fixed six defects here; see the changelog in the script header. In short: empty
folders were dropped, a name containing an apostrophe broke the OData lookup and got
its mail written to the parent folder (children were re-parented one level up), a
backslash in a name was expanded into a nested path, well-known folders were matched
by display name, failed folder listings silently dropped whole subtrees while the run
still reported success, and unresolvable folders had their mail drafted.

## Known limitations

- Hidden folders are not enumerated (`GET /mailFolders` omits them unless
  `includeHiddenFolders=true` is requested).
- The online archive is a separate mailbox and is not touched.
- Search folders are not copied.
- The copy runs on the UI thread. It pumps the message loop so progress paints and
  Cancel responds, but the window will feel sluggish on very large mailboxes.
- Throttling is handled with exponential back-off; a very large mailbox can still
  take a long time.

## Tests

The folder-replication logic has regression tests that run without a tenant. They load
the function definitions out of `M365-Mailbox-Copy-Tool.ps1` itself with the PowerShell
parser (so they cannot drift from the shipped code, and the GUI never starts) and drive
them against a fake mailbox store.

```powershell
# Windows PowerShell 5.1 or PowerShell 7, any OS
pwsh -File .\tests\Invoke-FolderStructureTests.ps1
```

43 assertions across nine cases: empty folders, apostrophes in nested and top-level
names, backslashes in names, a localized target mailbox, repeated names under
different parents, a folder listing that fails partway through, and name lookups that
return nothing or error out. The script exits non-zero on failure, so it works as a
build check.

Coverage was checked by mutation: re-introducing any of the original defects (dropping
the OData escaping, skipping empty folders, matching well-known folders by display
name, treating a failed lookup as "not found") makes the suite fail.
