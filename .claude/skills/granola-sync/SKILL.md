---
name: granola-sync
description: Show the command to run the Granola → Google Docs sync. NOTE — the sync cannot run inside Claude Code due to network sandbox restrictions. This skill tells you the right command to run in a regular Terminal window instead.
allowed-tools: Bash(python3 *)
argument-hint: "[--days N] [--dry-run] [--check]"
---

The Granola sync script cannot run inside Claude Code — the Bash sandbox
blocks access to the internal Salesforce network endpoints the script needs.

**Run it directly in a Terminal window instead:**

```
python3 ~/granola_sync.py
```

## Common commands

| What you want | Command |
|---|---|
| Sync last 30 days (default) | `python3 ~/granola_sync.py` |
| Preview without writing | `python3 ~/granola_sync.py --dry-run` |
| Sync further back | `python3 ~/granola_sync.py --days 90` |
| Check prerequisites | `python3 ~/granola_sync.py --check` |

## Notes

- The script auto-refreshes its auth token if expired — no manual re-auth needed
- A cron job runs the sync automatically at 8am, 12pm, 4pm, and 8pm
- See the README in the repo for full setup instructions
