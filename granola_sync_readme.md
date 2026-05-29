# Granola → Google Docs Sync

Automatically syncs your [Granola](https://granola.ai) meeting notes to Google Drive as formatted Google Docs. Each meeting becomes its own doc with two tabs:

- **Notes** — the Granola AI-generated summary with formatted headings
- **Transcript** — the verbatim, speaker-labeled transcript

Runs on a schedule so your Drive folder stays current without any manual steps. Deduplicates on every run — re-running never creates duplicate docs.

---

## Prerequisites

Before running, you need:

1. **macOS** — the script reads auth tokens from the macOS keychain
2. **Python 3.9+** — check with `python3 --version`
3. **Claude Code** with the **Google Workspace MCP plugin** installed and working — this provides the CA cert and the MCP adaptor token automatically
4. **A Granola account** — you'll authorize it on first run via a browser flow

---

## Setup

### 1. Download the script

```bash
curl -o ~/granola_sync.py https://raw.githubusercontent.com/<your-username>/<your-repo>/main/granola_sync.py
```

Or clone the repo and copy the file to your home directory.

### 2. Verify prerequisites

```bash
python3 ~/granola_sync.py --check
```

This checks every requirement and prints a ✓ / ✗ for each:

```
Checking prerequisites…

  ✓  Python 3.12.4
  ✓  CA cert  (/Users/you/.claude/certs/salesforce-ca-bundle.pem)
  ✓  Salesforce MCP adaptor token (keychain)
  ✗  Granola OAuth token
       No Granola token found. Run:  python3 granola_sync.py --reauth
  ✓  MCP gateway reachable

One or more checks failed. Fix the issues above, then re-run --check.
```

Fix anything flagged before moving on.

### 3. Authorize Granola

```bash
python3 ~/granola_sync.py --reauth
```

This opens a browser window to authorize the script with your Granola account. You only need to do this once — the token is stored at `~/.granola_sync_tokens.json` and refreshed automatically.

### 4. Preview before syncing

```bash
python3 ~/granola_sync.py --dry-run
```

Lists what would be created without writing anything to Drive.

### 5. Run your first sync

```bash
python3 ~/granola_sync.py
```

Syncs the last 30 days of meetings by default.

---

## Scheduling (recommended)

Run automatically 4x per day using cron:

```bash
crontab -e
```

Add this line (adjust the python3 path if needed — find yours with `which python3`):

```
0 8,12,16,20 * * * python3 /Users/YOUR_USERNAME/granola_sync.py >> /Users/YOUR_USERNAME/Library/Logs/granola_sync.log 2>&1
```

Create the log directory first if it doesn't exist:

```bash
mkdir -p ~/Library/Logs
```

Watch the log after the first scheduled run:

```bash
tail -f ~/Library/Logs/granola_sync.log
```

---

## Usage

```
python3 granola_sync.py [options]

Options:
  --days N            How many days back to sync (default: 30)
  --folder-name NAME  Drive folder name, created if missing (default: "Granola Meeting Notes")
  --dry-run           Preview what would be created without writing anything
  --reauth            Force re-authorization with Granola (opens browser)
  --check             Verify all prerequisites and print status
  --test MEETING_ID   Create a single test doc for one meeting UUID to verify output
```

---

## Troubleshooting

**Keychain entry not found**

If `--check` reports the MCP adaptor token is missing, your keychain account name may differ slightly. Find it with:

```bash
security find-generic-password -s mcp-adaptor.salesforce.com
```

Then set the env var before running:

```bash
export GRANOLA_SYNC_ADAPTOR_ACCOUNT="your-account-name-here"
python3 ~/granola_sync.py --check
```

**CA cert not found**

The cert ships with Claude Code. If it's in a different location on your machine:

```bash
export GRANOLA_SYNC_CA_CERT="/path/to/your/salesforce-ca-bundle.pem"
python3 ~/granola_sync.py --check
```

**Granola token expired**

```bash
python3 ~/granola_sync.py --reauth
```

**Want to sync further back than 30 days?**

```bash
python3 ~/granola_sync.py --days 90
```

---

## How it works

- **Granola API** — fetches meeting summaries and transcripts via Granola's MCP endpoint, authorized with OAuth2 PKCE
- **Google Workspace** — creates and updates Docs via the Salesforce MCP gateway (same infrastructure Claude Code uses)
- **Deduplication** — each doc embeds the Granola meeting ID in its content; subsequent runs skip meetings that already have a doc
- **No external dependencies** — pure Python standard library, nothing to `pip install`
