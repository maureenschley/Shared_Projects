---
name: granola-sync
description: Run the Granola → Google Docs sync to pull the latest meeting notes into Drive. Accepts optional flags like --days N, --dry-run, or --check.
allowed-tools: Bash(python3 *)
argument-hint: "[--days N] [--dry-run] [--check]"
---

Run the Granola → Google Docs sync script.

## Steps

1. Run the sync script, passing through any arguments the user provided:
   ```
   python3 ~/granola_sync.py <args>
   ```
   Common invocations:
   - No args → sync the last 30 days: `python3 ~/granola_sync.py`
   - Preview without writing: `python3 ~/granola_sync.py --dry-run`
   - Sync further back: `python3 ~/granola_sync.py --days 90`
   - Check prerequisites: `python3 ~/granola_sync.py --check`

2. Show the full output from the script to the user.

3. Summarize what happened in plain language:
   - How many meetings were synced (created as new docs)
   - How many were skipped (already exist)
   - Any errors or warnings
   - If `--dry-run` was used, clarify that nothing was written

## Notes

- The script runs silently on success with a summary line; errors are printed to stderr
- If the script exits non-zero, show the error output and suggest running `python3 ~/granola_sync.py --check` to diagnose
- Do not modify the script or Drive contents — this skill is run-only
