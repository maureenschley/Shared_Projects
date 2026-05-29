#!/usr/bin/env python3
"""
Granola → Google Docs sync script.

Architecture:
- Granola: direct HTTP MCP at https://mcp.granola.ai/mcp
  Auth: OAuth2 PKCE via mcp-auth.granola.ai; tokens stored in ~/.granola_sync_tokens.json
  First run opens a browser to authorize; subsequent runs use the stored refresh token.
- Google Workspace: Salesforce MCP gateway (SSE handshake → message endpoint)
  Auth: Salesforce MCP adaptor token from macOS keychain
- Deduplication: granola_id matched via "Granola Meeting ID:" header line (new docs)
  or legacy "<!-- granola_id: ... -->" HTML comment (pre-two-tab docs)

Usage:
    python3 granola_sync.py [--dry-run] [--days N] [--folder-name NAME]
    python3 granola_sync.py --reauth   # force re-authentication with Granola
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

GRANOLA_MCP_URL = "https://mcp.granola.ai/mcp"
GRANOLA_AUTH_SERVER = "https://mcp-auth.granola.ai"
GRANOLA_TOKEN_FILE = Path.home() / ".granola_sync_tokens.json"
OAUTH_REDIRECT_PORT = 8765
OAUTH_REDIRECT_URI = f"http://localhost:{OAUTH_REDIRECT_PORT}/callback"

GW_BASE = "https://dx-mcp-gateway.sfproxy.devx-preprod.aws-esvc1-useast2.aws.sfdc.cl"
GW_PROFILE = "sdb"

# Both of these can be overridden via environment variables if your machine's paths
# or keychain entry name differ from the defaults.
CA_CERT = os.environ.get(
    "GRANOLA_SYNC_CA_CERT",
    str(Path.home() / ".claude/certs/salesforce-ca-bundle.pem"),
)

ADAPTOR_SERVICE = "mcp-adaptor.salesforce.com"
ADAPTOR_ACCOUNT = os.environ.get(
    "GRANOLA_SYNC_ADAPTOR_ACCOUNT",
    "quantumk-token.prod.matrix-agent-service.dx-mcp-adaptor",
)
GRANOLA_ID_RE = re.compile(
    r"(?:<!--\s*granola_id:\s*|Granola Meeting ID:\s*)([0-9a-f-]{36})"
)

# ---------------------------------------------------------------------------
# Granola OAuth (mcp-auth.granola.ai) — PKCE auth_code flow
# ---------------------------------------------------------------------------

def _ssl_ctx() -> ssl.SSLContext:
    return ssl.create_default_context(cafile="/etc/ssl/cert.pem")


def _load_granola_tokens() -> dict:
    if GRANOLA_TOKEN_FILE.exists():
        with open(GRANOLA_TOKEN_FILE) as f:
            return json.load(f)
    return {}


def _save_granola_tokens(tokens: dict):
    GRANOLA_TOKEN_FILE.write_text(json.dumps(tokens, indent=2))
    GRANOLA_TOKEN_FILE.chmod(0o600)


def _register_oauth_client() -> str:
    """Dynamic client registration; returns client_id."""
    tokens = _load_granola_tokens()
    if tokens.get("client_id"):
        return tokens["client_id"]

    body = json.dumps({
        "client_name": "granola-sync",
        "redirect_uris": [OAUTH_REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "none",
        "response_types": ["code"],
        "scope": "openid email profile offline_access",
    }).encode()
    req = urllib.request.Request(
        f"{GRANOLA_AUTH_SERVER}/oauth2/register",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, context=_ssl_ctx()) as resp:
        result = json.loads(resp.read().decode())

    client_id = result["client_id"]
    tokens["client_id"] = client_id
    _save_granola_tokens(tokens)
    return client_id


def _pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def _run_auth_code_flow(client_id: str) -> dict:
    """Open browser, run local server to catch callback, exchange code for tokens."""
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(16)
    auth_code: list[str] = []
    server_error: list[str] = []

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            if params.get("state", [None])[0] != state:
                server_error.append("state mismatch")
            elif "error" in params:
                server_error.append(params["error"][0])
            else:
                auth_code.append(params["code"][0])
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h2>Authorized! You can close this tab.</h2>")

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("localhost", OAUTH_REDIRECT_PORT), CallbackHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    auth_url = (
        f"{GRANOLA_AUTH_SERVER}/oauth2/authorize"
        f"?response_type=code"
        f"&client_id={urllib.parse.quote(client_id)}"
        f"&redirect_uri={urllib.parse.quote(OAUTH_REDIRECT_URI)}"
        f"&scope={urllib.parse.quote('openid email profile offline_access')}"
        f"&state={state}"
        f"&code_challenge={challenge}"
        f"&code_challenge_method=S256"
    )
    print(f"\nOpening browser to authorize Granola access...")
    print(f"If the browser doesn't open, visit:\n  {auth_url}\n")
    webbrowser.open(auth_url)

    timeout = 120
    start = time.time()
    while not auth_code and not server_error and time.time() - start < timeout:
        time.sleep(0.5)
    server.shutdown()

    if server_error:
        raise RuntimeError(f"OAuth error: {server_error[0]}")
    if not auth_code:
        raise RuntimeError("OAuth timed out waiting for authorization")

    # Exchange code for tokens
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "code": auth_code[0],
        "redirect_uri": OAUTH_REDIRECT_URI,
        "client_id": client_id,
        "code_verifier": verifier,
    }).encode()
    req = urllib.request.Request(
        f"{GRANOLA_AUTH_SERVER}/oauth2/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, context=_ssl_ctx()) as resp:
        tokens = json.loads(resp.read().decode())

    tokens["obtained_at"] = int(time.time())
    tokens["client_id"] = client_id
    return tokens


def _refresh_granola_oauth(tokens: dict) -> dict:
    client_id = tokens["client_id"]
    body = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "refresh_token": tokens["refresh_token"],
        "client_id": client_id,
    }).encode()
    req = urllib.request.Request(
        f"{GRANOLA_AUTH_SERVER}/oauth2/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, context=_ssl_ctx()) as resp:
        new_tokens = json.loads(resp.read().decode())

    new_tokens["obtained_at"] = int(time.time())
    new_tokens["client_id"] = client_id
    return new_tokens


def get_granola_token(force_reauth: bool = False) -> str:
    """Return a valid Granola MCP access token, refreshing or re-authing as needed."""
    client_id = _register_oauth_client()
    tokens = _load_granola_tokens()

    if force_reauth or not tokens.get("access_token"):
        tokens = _run_auth_code_flow(client_id)
        _save_granola_tokens(tokens)
        return tokens["access_token"]

    # Refresh if within 60s of expiry
    obtained = tokens.get("obtained_at", 0)
    expires_in = tokens.get("expires_in", 0)
    if expires_in and time.time() >= obtained + expires_in - 60:
        try:
            tokens = _refresh_granola_oauth(tokens)
            _save_granola_tokens(tokens)
        except Exception as e:
            print(f"Token refresh failed ({e}), re-authorizing...")
            tokens = _run_auth_code_flow(client_id)
            _save_granola_tokens(tokens)

    return tokens["access_token"]


def _read_adaptor_blob() -> tuple[str, dict]:
    """Return (raw_keychain_string, parsed_blob_dict) from the keychain."""
    result = subprocess.run(
        ["security", "find-generic-password", "-s", ADAPTOR_SERVICE,
         "-a", ADAPTOR_ACCOUNT, "-w"],
        capture_output=True, text=True, check=True
    )
    raw = result.stdout.strip()
    decoded = base64.b64decode(raw + "==").decode("utf-8", errors="replace")
    return raw, json.loads(decoded)


def _refresh_adaptor_token(blob: dict) -> str:
    """Use the refresh_token in the keychain blob to get a fresh access_token.

    Updates the keychain entry in-place and returns the new access_token.
    """
    issuer = blob.get("issuer", "")
    token_url = f"{issuer}/protocol/openid-connect/token"
    refresh_token = blob.get("refresh_token", "")
    if not refresh_token:
        raise RuntimeError("No refresh_token in keychain blob — run Claude Code to re-authenticate.")

    ctx = ssl.create_default_context(cafile=CA_CERT) if Path(CA_CERT).exists() else ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ctx),
    )

    body = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "client_id": "dx-mcp-adaptor",
        "refresh_token": refresh_token,
    }).encode()
    req = urllib.request.Request(
        token_url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with opener.open(req, timeout=15) as resp:
        new_tokens = json.loads(resp.read().decode())

    access_token = new_tokens["access_token"]
    blob["access_token"] = access_token
    if "refresh_token" in new_tokens:
        blob["refresh_token"] = new_tokens["refresh_token"]
    blob["last_refreshed"] = datetime.now(timezone.utc).isoformat()

    # Write back to keychain
    new_raw = base64.b64encode(json.dumps(blob).encode()).decode()
    subprocess.run(
        ["security", "add-generic-password", "-U",
         "-s", ADAPTOR_SERVICE, "-a", ADAPTOR_ACCOUNT, "-w", new_raw],
        capture_output=True, check=True
    )
    return access_token


def get_adaptor_token() -> str:
    """Read the Salesforce MCP gateway token from the keychain, refreshing if expired."""
    _, blob = _read_adaptor_blob()
    access_token = blob.get("access_token", "")

    # Check expiry — refresh proactively if within 5 minutes of expiry or already expired
    expires_at_str = blob.get("expires_at", "")
    if expires_at_str and access_token:
        try:
            # Parse the ISO timestamp (handles both Z and ±HH:MM offsets)
            expires_at = datetime.fromisoformat(expires_at_str)
            now = datetime.now(timezone.utc)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if now >= expires_at - timedelta(minutes=5):
                print("  ↻ MCP adaptor token expired — refreshing…")
                access_token = _refresh_adaptor_token(blob)
                print("  ✓ Token refreshed.")
        except Exception as e:
            print(f"  ⚠ Could not check token expiry: {e}", file=sys.stderr)

    return access_token


# ---------------------------------------------------------------------------
# MCP response parsing
# ---------------------------------------------------------------------------

def _parse_mcp_response(body: str) -> dict:
    """Parse a JSON-RPC response that may be SSE-wrapped (event:/data: lines)."""
    if not body.strip():
        return {}
    # Extract all data: lines (SSE format)
    data_lines = [l[5:].strip() for l in body.splitlines() if l.startswith("data:")]
    if data_lines:
        body = "\n".join(data_lines)
    if not body.strip():
        return {}
    return json.loads(body)


# ---------------------------------------------------------------------------
# Granola MCP client (stateless HTTP)
# ---------------------------------------------------------------------------

def _granola_call(token: str, method: str, params: dict, retries: int = 4) -> dict:
    """Single JSON-RPC call to the Granola MCP endpoint with rate-limit retry."""
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }).encode()
    req = urllib.request.Request(
        GRANOLA_MCP_URL,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    for attempt in range(retries):
        with urllib.request.urlopen(req, context=_ssl_ctx()) as resp:
            body = resp.read().decode()
        result = _parse_mcp_response(body)
        # Granola returns rate-limit errors as tool content, not HTTP 429
        content = result.get("result", {}).get("content", [])
        text = next((c.get("text", "") for c in content if c.get("type") == "text"), "")
        if "rate limit" in text.lower():
            wait = 2 ** attempt * 3  # 3, 6, 12, 24s
            print(f"           ↳ Rate limited, waiting {wait}s...")
            time.sleep(wait)
            continue
        return result
    return result


def granola_list_meetings(token: str, days: int = 30) -> list[dict]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    result = _granola_call(token, "tools/call", {
        "name": "list_meetings",
        "arguments": {
            "time_range": "custom",
            "custom_start": start.date().isoformat(),
            "custom_end": end.date().isoformat(),
        }
    })
    content = result.get("result", {}).get("content", [{}])
    text = next((c["text"] for c in content if c.get("type") == "text"), "")
    return _parse_meeting_list(text)


def granola_get_transcript(token: str, meeting_id: str) -> str:
    """Fetch verbatim transcript for a single meeting. Returns empty string if unavailable."""
    result = _granola_call(token, "tools/call", {
        "name": "get_meeting_transcript",
        "arguments": {"meeting_id": meeting_id}
    })
    content = result.get("result", {}).get("content", [{}])
    text = next((c["text"] for c in content if c.get("type") == "text"), "")
    if not text:
        return ""
    try:
        data = json.loads(text)
        return data.get("transcript", "").strip()
    except json.JSONDecodeError:
        return text.strip()


def granola_get_meetings_batch(token: str, meeting_ids: list[str]) -> dict[str, dict]:
    """Fetch up to 10 meetings in one call. Returns {meeting_id: meeting_detail}."""
    result = _granola_call(token, "tools/call", {
        "name": "get_meetings",
        "arguments": {"meeting_ids": meeting_ids[:10]}
    })
    content = result.get("result", {}).get("content", [{}])
    text = next((c["text"] for c in content if c.get("type") == "text"), "")
    return {m["id"]: m for m in _parse_meeting_detail(text)}


def _parse_meeting_list(xml_text: str) -> list[dict]:
    """Extract id, title, date from the meetings XML blob."""
    meetings = []
    for m in re.finditer(
        r'<meeting id="([^"]+)"[^>]*title="([^"]+)"[^>]*date="([^"]+)"',
        xml_text
    ):
        meetings.append({"id": m.group(1), "title": m.group(2), "date": m.group(3)})
    return meetings


def _parse_meeting_detail(xml_text: str) -> list[dict]:
    """Extract full meeting detail including participants and summary."""
    meetings = []
    for m in re.finditer(
        r'<meeting id="([^"]+)"[^>]*title="([^"]+)"[^>]*date="([^"]+)".*?'
        r'<known_participants>(.*?)</known_participants>.*?'
        r'<summary>(.*?)</summary>',
        xml_text, re.DOTALL
    ):
        participants_raw = m.group(4).strip()
        participants = [p.strip() for p in participants_raw.split("\n") if p.strip()]
        meetings.append({
            "id": m.group(1),
            "title": m.group(2),
            "date": m.group(3),
            "participants": participants,
            "summary": m.group(5).strip(),
        })
    return meetings


# ---------------------------------------------------------------------------
# Heading-style helper
# ---------------------------------------------------------------------------

_HEADING_PREFIXES = [
    ("### ", "HEADING_3", 4),
    ("## ",  "HEADING_2", 3),
    ("# ",   "HEADING_1", 2),
]


def _build_heading_ops(
    content: str,
    tab_id: str = "",
    start_offset: int = 0,
) -> tuple[list[dict], list[dict]]:
    """Parse *content* and return (style_ops, delete_ops) for every heading line.

    style_ops  — update_paragraph_style requests, forward order.
    delete_ops — delete_text requests that strip the '# ' prefix, in *reverse*
                 order so later deletions don't shift earlier indices.

    Call batch_update_doc(style_ops) first, then batch_update_doc(delete_ops).

    start_offset controls where the content begins in the document (0-based gap
    index).  Use 0 for Tab 1 content created via create_doc (content starts at
    gap 0).  Use 1 for content inserted via insert_text at index 1 (content
    starts at gap 1, after the tab's initial newline).
    """
    style_ops: list[dict] = []
    delete_ops: list[dict] = []
    pos = start_offset  # 0-based gap index of the start of the first line

    for line in content.split("\n"):
        end_of_line = pos + len(line)

        for prefix, style, pfx_len in _HEADING_PREFIXES:
            if line.startswith(prefix):
                base: dict = {}
                if tab_id:
                    base["tab_id"] = tab_id

                style_ops.append({
                    "type": "update_paragraph_style",
                    "start_index": pos,
                    "end_index": end_of_line,
                    "named_style_type": style,
                    **base,
                })
                delete_ops.append({
                    "type": "delete_text",
                    "start_index": pos,
                    "end_index": pos + pfx_len,
                    **base,
                })
                break

        pos = end_of_line + 1  # +1 accounts for the \n character

    return style_ops, list(reversed(delete_ops))


# ---------------------------------------------------------------------------
# Google Workspace MCP client (SSE gateway)
# ---------------------------------------------------------------------------

class GWorkspaceClient:
    """Talks to the Salesforce MCP gateway via Streamable HTTP (/mcp endpoint)."""

    def __init__(self, token: str):
        self._token = token
        self._mcp_url = f"{GW_BASE}/v1/profile/{GW_PROFILE}/mcp"
        self._session_id: str | None = None
        self._req_id = 1
        self._ctx = ssl.create_default_context(cafile=CA_CERT)
        # Build a proxy-free opener so Claude Code's localhost proxy doesn't
        # intercept direct calls to the Salesforce MCP gateway.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=self._ctx),
        )
        self._initialize()

    def _headers(self) -> dict:
        h = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._session_id:
            h["Mcp-Session-Id"] = self._session_id
        return h

    def _initialize(self):
        """Send MCP initialize to get a session ID."""
        payload = json.dumps({
            "jsonrpc": "2.0", "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "granola-sync", "version": "1.0"},
            },
        }).encode()
        req = urllib.request.Request(self._mcp_url, data=payload, headers=self._headers())
        with self._opener.open(req, timeout=15) as resp:
            self._session_id = resp.headers.get("Mcp-Session-Id", "")
            resp.read()  # consume body

    def _send(self, method: str, params: dict) -> dict:
        req_id = self._req_id
        self._req_id += 1
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        }).encode()
        req = urllib.request.Request(self._mcp_url, data=payload, headers=self._headers())
        with self._opener.open(req, timeout=30) as resp:
            body = resp.read().decode()
        if not body.strip():
            return {}
        return _parse_mcp_response(body)

    def call_tool(self, tool_name: str, arguments: dict) -> str:
        result = self._send("tools/call", {"name": tool_name, "arguments": arguments})
        content = result.get("result", {}).get("content", [{}])
        return next((c["text"] for c in content if c.get("type") == "text"), "")

    def search_docs(self, query: str) -> list[dict]:
        text = self.call_tool("search_docs", {"query": query, "page_size": 5})
        return _parse_doc_list(text)

    def create_doc(self, title: str, content: str) -> str:
        text = self.call_tool("create_doc", {"title": title, "content": content})
        m = re.search(r"ID[:\s]+([A-Za-z0-9_-]{25,})", text)
        return m.group(1) if m else ""

    def get_doc_content(self, doc_id: str) -> str:
        return self.call_tool("get_doc_as_markdown", {"document_id": doc_id})

    def ensure_folder(self, folder_name: str) -> str:
        """Find or create a Drive folder; return its ID."""
        results = self.call_tool("search_drive_files", {
            "query": folder_name,
            "file_type": "folder",
        })
        ids = re.findall(r"ID[:\s]+([A-Za-z0-9_-]{25,})", results)
        if ids:
            return ids[0]
        text = self.call_tool("create_drive_folder", {"folder_name": folder_name})
        m = re.search(r"ID[:\s]+([A-Za-z0-9_-]{25,})", text)
        return m.group(1) if m else ""

    def move_to_folder(self, file_id: str, folder_id: str):
        self.call_tool("update_drive_file", {
            "file_id": file_id,
            "add_parents": folder_id,
            "remove_parents": "root",
        })

    def inspect_doc(self, doc_id: str, tab_id: str = "") -> dict:
        args: dict = {"document_id": doc_id, "detailed": True}
        if tab_id:
            args["tab_id"] = tab_id
        text = self.call_tool("inspect_doc_structure", args)
        try:
            # API response has preamble + JSON block + "Link:" footer; extract the JSON
            m = re.search(r"\{[\s\S]*\}", text)
            if m:
                return json.loads(m.group())
        except Exception:
            pass
        return {}

    def append_transcript(self, doc_id: str, transcript: str):
        """Append a transcript section to the end of an existing doc."""
        structure = self.inspect_doc(doc_id)
        end_index = structure.get("total_length", 1) - 1
        text_to_append = f"\n\n---\n\n## Transcript\n\n{transcript}\n"
        self.call_tool("modify_doc_text", {
            "document_id": doc_id,
            "start_index": end_index,
            "text": text_to_append,
        })

    def create_doc_with_tabs(self, title: str, notes_content: str,
                              transcript_content: str) -> str:
        """Create a Google Doc with two tabs: 'Notes' and 'Transcript'.

        Tab 1 ("Notes")      — receives notes_content at doc creation time.
        Tab 2 ("Transcript") — inserted then populated with transcript_content.

        Returns doc_id, or '' on failure.
        """
        # a) Create doc — content goes into the default (first) tab
        doc_id = self.create_doc(title, notes_content)
        if not doc_id:
            return ""

        # b) Tab 1 is always "t.0" in Google Docs
        tab1_id = "t.0"

        # c) Insert Transcript tab
        result_text = self.call_tool("batch_update_doc", {
            "document_id": doc_id,
            "operations": [{
                "type": "insert_doc_tab",
                "title": "Transcript",
                "index": 1,
            }],
        })

        # d-rename) Rename Tab 1 → "Notes" via batch_update_doc
        self.call_tool("batch_update_doc", {
            "document_id": doc_id,
            "operations": [{
                "type": "update_doc_tab",
                "tab_id": tab1_id,
                "title": "Notes",
            }],
        })
        # d) Extract newly created Transcript tab ID from the result message
        tab2_match = re.search(r"tab_id:\s*([\w.]+)", result_text or "")
        tab2_id_from_result = tab2_match.group(1) if tab2_match else ""

        # e) Resolve Transcript tab ID — use result text first, fall back to inspect
        tab2_id = tab2_id_from_result
        if not tab2_id:
            structure2 = self.inspect_doc(doc_id)
            for tab in structure2.get("tabs", []):
                if tab.get("tab_id") != tab1_id:
                    tab2_id = tab.get("tab_id", "")
                    break

        # f) Write transcript content to Tab 2
        tab2_text = transcript_content if transcript_content else "_No transcript available._\n"
        if tab2_id:
            self.call_tool("batch_update_doc", {
                "document_id": doc_id,
                "operations": [{
                    "type": "insert_text",
                    "index": 1,
                    "text": tab2_text,
                    "tab_id": tab2_id,
                }],
            })

        # g) Apply heading styles to both tabs (style first, then strip # prefixes).
        # Both tabs have content starting at index 1 (after the section break at 0).
        self._apply_heading_styles(doc_id, notes_content, tab1_id, start_offset=1)
        if tab2_id and transcript_content:
            self._apply_heading_styles(doc_id, transcript_content, tab2_id, start_offset=1)

        return doc_id

    def _apply_heading_styles(
        self, doc_id: str, content: str, tab_id: str, start_offset: int = 1
    ):
        """Apply HEADING styles and strip # prefixes for all heading lines in content.

        Google Docs always places content at index 1 (after the section break at 0),
        so start_offset=1 is the correct value for all tabs.
        """
        style_ops, delete_ops = _build_heading_ops(content, tab_id, start_offset)
        if style_ops:
            try:
                self.call_tool("batch_update_doc", {
                    "document_id": doc_id,
                    "operations": style_ops,
                })
            except Exception as e:
                print(f"           ↳ Warning: heading style apply failed ({e})")
        if delete_ops:
            try:
                self.call_tool("batch_update_doc", {
                    "document_id": doc_id,
                    "operations": delete_ops,
                })
            except Exception as e:
                print(f"           ↳ Warning: heading prefix strip failed ({e})")


def _parse_doc_list(text: str) -> list[dict]:
    docs = []
    for m in re.finditer(r"-\s+(.+?)\s+\(ID:\s+([A-Za-z0-9_-]{25,})", text):
        docs.append({"title": m.group(1), "id": m.group(2)})
    return docs


# ---------------------------------------------------------------------------
# Doc formatting
# ---------------------------------------------------------------------------

def _date_label(meeting: dict) -> str:
    """Return short date string, e.g. 'May 22, 2026'."""
    parts = meeting["date"].split(" ")[0:3]   # ['May', '22,', '2026']
    return " ".join(parts).rstrip(",")


def format_doc_title(meeting: dict) -> str:
    """Return the Google Doc title string."""
    return f"Granola: {meeting['title']} [{_date_label(meeting)}]"


def format_tab1_notes(meeting: dict) -> str:
    """Return Tab 1 content: header + Granola AI-generated notes.

    Uses plain # markers for headings — these are stripped and styled by
    _apply_heading_styles() after the doc is created.
    No markdown bold/HR syntax; those don't render in Google Docs API.
    """
    participants_section = ""
    if meeting.get("participants"):
        lines = "\n".join(f"- {p}" for p in meeting["participants"])
        participants_section = f"## Attendees\n\n{lines}\n\n"

    return (
        f"# {meeting['title']}\n\n"
        f"Date: {meeting['date']}\n"
        f"Granola Meeting ID: {meeting['id']}\n\n"
        f"{participants_section}"
        f"{meeting.get('summary', '_No summary available._')}\n"
    )


def format_transcript_body(meeting: dict, raw_transcript: str) -> str:
    """Format raw Granola transcript into readable, speaker-labelled paragraphs.

    Rules:
    - All content preserved — nothing deleted, shortened, or summarised.
    - Speaker labels detected from line-start patterns (Them: / Me: / I: / They:).
    - With exactly 2 participants: 'Them:' → participants[1], unlabelled → participants[0].
    - With >2 or ambiguous: 'Them:' → 'Unknown', unlabelled lines → 'Unknown'.
    - No timestamps invented (Granola provides none for this transcript type).
    - Blank lines in source → paragraph breaks within a speaker block.
    """
    participants = meeting.get("participants", [])
    speaker_primary = participants[0] if participants else "Unknown"
    speaker_them = participants[1] if len(participants) >= 2 else "Unknown"

    THEM_RE = re.compile(r'^(Them|Me|I|They):\s*(.*)', re.IGNORECASE)

    segments: list[tuple[str, list[str]]] = []
    current_speaker: str | None = None
    current_lines: list[str] = []

    for raw_line in raw_transcript.splitlines():
        stripped = raw_line.strip()
        m = THEM_RE.match(stripped)
        if m:
            # New speaker turn
            if current_lines:
                segments.append((current_speaker or speaker_primary, current_lines))
                current_lines = []
            tag = m.group(1).lower()
            current_speaker = speaker_them if tag == "them" else speaker_primary
            rest = m.group(2).strip()
            if rest:
                current_lines.append(rest)
        elif stripped == "":
            # Blank line → flush current paragraph block (keep speaker)
            if current_lines:
                segments.append((current_speaker or speaker_primary, current_lines))
                current_lines = []
        else:
            if current_speaker is None:
                current_speaker = speaker_primary
            current_lines.append(stripped)

    if current_lines:
        segments.append((current_speaker or speaker_primary, current_lines))

    # Split each segment's text into readable paragraphs at sentence boundaries
    SENTENCE_END = re.compile(r'(?<=[.!?])\s+')
    MAX_PARA = 400  # chars per paragraph target

    output: list[str] = []
    for speaker, lines in segments:
        full_text = " ".join(lines).strip()
        if not full_text:
            continue
        # Split at sentence boundaries; group into ~MAX_PARA-char paragraphs
        sentences = SENTENCE_END.split(full_text)
        paras: list[str] = []
        current_sents: list[str] = []
        current_len = 0
        for sent in sentences:
            if current_sents and current_len + len(sent) > MAX_PARA:
                paras.append(" ".join(current_sents))
                current_sents = [sent]
                current_len = len(sent)
            else:
                current_sents.append(sent)
                current_len += len(sent)
        if current_sents:
            paras.append(" ".join(current_sents))

        # First paragraph gets the speaker label; subsequent paragraphs are
        # indented continuation (no extra speaker label)
        for i, para in enumerate(paras):
            if i == 0:
                output.append(f"{speaker}: {para}\n")
            else:
                output.append(f"{para}\n")

    return "\n".join(output)


def format_tab2_transcript(meeting: dict, raw_transcript: str) -> str:
    """Return Tab 2 content: header + formatted verbatim transcript.

    Uses plain # markers for headings — stripped and styled by _apply_heading_styles().
    """
    participants_section = ""
    if meeting.get("participants"):
        lines = "\n".join(f"- {p}" for p in meeting["participants"])
        participants_section = f"## Participants\n\n{lines}\n\n"

    body = format_transcript_body(meeting, raw_transcript) if raw_transcript else "_No transcript available._"

    return (
        f"# {meeting['title']}\n\n"
        f"Date: {meeting['date']}\n"
        f"Granola Meeting ID: {meeting['id']}\n\n"
        f"{participants_section}"
        f"## Transcript\n\n"
        f"{body}\n"
    )


# Keep for backfill_transcripts compatibility (operates on old single-tab docs)
def format_doc(meeting: dict, transcript: str = "") -> tuple[str, str]:
    """Legacy helper used only by backfill path. Returns (title, flat_content)."""
    participants_section = ""
    if meeting.get("participants"):
        lines = "\n".join(f"- {p}" for p in meeting["participants"])
        participants_section = f"## Attendees\n\n{lines}\n\n"

    transcript_section = ""
    if transcript:
        transcript_section = f"\n---\n\n## Transcript\n\n{transcript}\n"

    title = format_doc_title(meeting)
    content = (
        f"<!-- granola_id: {meeting['id']} -->\n\n"
        f"# {meeting['title']}\n\n"
        f"**Date:** {meeting['date']}\n\n"
        f"{participants_section}"
        f"---\n\n"
        f"{meeting.get('summary', '_No summary available._')}\n"
        f"{transcript_section}"
    )
    return title, content


# ---------------------------------------------------------------------------
# Deduplication: scan docs in folder for embedded granola_ids
# ---------------------------------------------------------------------------

def build_synced_index(gw: GWorkspaceClient, folder_id: str) -> dict[str, str]:
    """Return {granola_id: doc_id} for all already-synced docs in the folder."""
    text = gw.call_tool("list_docs_in_folder", {"folder_id": folder_id, "page_size": 200})
    index = {}
    doc_ids = re.findall(r"ID[:\s]+([A-Za-z0-9_-]{25,})", text)
    for doc_id in doc_ids:
        try:
            body = gw.get_doc_content(doc_id)
            m = GRANOLA_ID_RE.search(body)
            if m:
                index[m.group(1)] = doc_id
        except Exception:
            pass
    return index


# ---------------------------------------------------------------------------
# Backfill transcripts into existing docs
# ---------------------------------------------------------------------------

def backfill_transcripts(folder_name: str = "Granola Meeting Notes", dry_run: bool = False):
    print(f"{'[DRY RUN] ' if dry_run else ''}Backfilling transcripts into existing Granola docs")
    print(f"  Folder: {folder_name}\n")

    print("Authenticating...")
    granola_token = get_granola_token()
    adaptor_token = get_adaptor_token()

    print("Connecting to Google Workspace MCP gateway...")
    gw = GWorkspaceClient(adaptor_token)

    print(f"Finding Drive folder '{folder_name}'...")
    results = gw.call_tool("search_drive_files", {"query": folder_name, "file_type": "folder"})
    ids = re.findall(r"ID[:\s]+([A-Za-z0-9_-]{25,})", results)
    if not ids:
        print(f"  ERROR: Folder '{folder_name}' not found.")
        return
    folder_id = ids[0]
    print(f"  Folder ID: {folder_id}\n")

    print("Listing docs in folder...")
    text = gw.call_tool("list_docs_in_folder", {"folder_id": folder_id, "page_size": 200})
    doc_ids = re.findall(r"ID[:\s]+([A-Za-z0-9_-]{25,})", text)
    print(f"  Found {len(doc_ids)} docs\n")

    updated = skipped = errors = 0

    for i, doc_id in enumerate(doc_ids, 1):
        try:
            body = gw.get_doc_content(doc_id)
        except Exception as e:
            print(f"  [{i}/{len(doc_ids)}] ERROR reading doc {doc_id}: {e}")
            errors += 1
            continue

        id_match = GRANOLA_ID_RE.search(body)
        if not id_match:
            print(f"  [{i}/{len(doc_ids)}] SKIP  {doc_id} (no granola_id)")
            skipped += 1
            continue

        if "## Transcript" in body:
            print(f"  [{i}/{len(doc_ids)}] SKIP  {doc_id} (transcript already present)")
            skipped += 1
            continue

        meeting_id = id_match.group(1)
        title_match = re.search(r"^#\s+(.+)$", body, re.MULTILINE)
        title = title_match.group(1) if title_match else doc_id
        print(f"  [{i}/{len(doc_ids)}] BACKFILL  {title[:60]}")

        try:
            transcript = granola_get_transcript(granola_token, meeting_id)
        except Exception as e:
            print(f"           ↳ Transcript fetch failed ({e}), skipping")
            errors += 1
            continue

        if not transcript:
            print(f"           ↳ No transcript available, skipping")
            skipped += 1
            continue

        print(f"           ↳ Transcript: {len(transcript)} chars")

        if dry_run:
            print(f"           ↳ Would append transcript to doc {doc_id}")
            updated += 1
            continue

        try:
            gw.append_transcript(doc_id, transcript)
            print(f"           ↳ Done")
            updated += 1
        except Exception as e:
            print(f"           ↳ ERROR appending: {e}")
            errors += 1

    print(f"\nDone. Updated: {updated}  |  Skipped: {skipped}  |  Errors: {errors}")


# ---------------------------------------------------------------------------
# Main sync
# ---------------------------------------------------------------------------

def sync(days: int = 30, folder_name: str = "Granola Meeting Notes", dry_run: bool = False,
         reauth: bool = False):
    print(f"{'[DRY RUN] ' if dry_run else ''}Starting Granola → Google Docs sync")
    print(f"  Range: last {days} days  |  Folder: {folder_name}\n")

    print("Authenticating...")
    granola_token = get_granola_token(force_reauth=reauth)
    adaptor_token = get_adaptor_token()

    print("Connecting to Google Workspace MCP gateway...")
    gw = GWorkspaceClient(adaptor_token)

    print(f"Ensuring Drive folder '{folder_name}'...")
    folder_id = "" if dry_run else gw.ensure_folder(folder_name)
    if not dry_run:
        print(f"  Folder ID: {folder_id}")

    print("Scanning existing synced docs for deduplication...")
    synced = {} if dry_run else build_synced_index(gw, folder_id)
    print(f"  Found {len(synced)} previously synced docs\n")

    print(f"Fetching Granola meetings (last {days} days)...")
    meetings = granola_list_meetings(granola_token, days)
    print(f"  Found {len(meetings)} meetings\n")

    # Separate meetings to sync from already-synced ones
    to_sync = [m for m in meetings if m["id"] not in synced]
    already_synced = [m for m in meetings if m["id"] in synced]

    for m in already_synced:
        print(f"  SKIP  {m['title'][:60]}  (already synced → {synced[m['id']]})")

    skipped = len(already_synced)
    created = errors = 0

    if not to_sync:
        print("\nAll meetings already synced.")
        print(f"\nDone. Created: {created}  |  Skipped: {skipped}  |  Errors: {errors}")
        return

    # Pre-fetch all details in batches of 10 (max allowed by Granola API)
    BATCH = 10
    details: dict[str, dict] = {}
    ids_to_fetch = [m["id"] for m in to_sync]
    total_batches = (len(ids_to_fetch) + BATCH - 1) // BATCH
    print(f"Fetching details in {total_batches} batch(es) of up to {BATCH}...")

    for b, start in enumerate(range(0, len(ids_to_fetch), BATCH), 1):
        batch_ids = ids_to_fetch[start:start + BATCH]
        print(f"  Batch {b}/{total_batches}: {len(batch_ids)} meetings", end="", flush=True)
        for attempt in range(5):
            batch_result = granola_get_meetings_batch(granola_token, batch_ids)
            if batch_result:
                details.update(batch_result)
                print(f" → got {len(batch_result)}")
                break
            wait = 2 ** attempt * 5  # 5, 10, 20, 40, 80s
            print(f" → rate limited, waiting {wait}s...", end="", flush=True)
            time.sleep(wait)
        else:
            print(f" → failed after retries, skipping batch")
            errors += len(batch_ids)
        if b < total_batches:
            time.sleep(3)

    print()

    # Create docs for all successfully fetched meetings
    for i, meeting_meta in enumerate(to_sync, 1):
        mid = meeting_meta["id"]
        title = meeting_meta["title"]
        meeting = details.get(mid)

        if not meeting:
            print(f"  [{i}/{len(to_sync)}] SKIP  {title[:60]}  (no detail, will retry next run)")
            errors += 1
            continue

        print(f"  [{i}/{len(to_sync)}] SYNC  {title[:60]}")
        try:
            transcript = ""
            if not dry_run:
                try:
                    transcript = granola_get_transcript(granola_token, mid)
                    if transcript:
                        print(f"           ↳ Transcript: {len(transcript)} chars")
                except Exception as e:
                    print(f"           ↳ Transcript fetch failed ({e}), continuing without")

            doc_title = format_doc_title(meeting)

            if dry_run:
                print(f"           ↳ Would create: '{doc_title}'")
                created += 1
                continue

            tab1 = format_tab1_notes(meeting)
            tab2 = format_tab2_transcript(meeting, transcript)
            doc_id = gw.create_doc_with_tabs(doc_title, tab1, tab2)
            if folder_id and doc_id:
                gw.move_to_folder(doc_id, folder_id)
            print(f"           ↳ Created doc: {doc_id}")
            synced[mid] = doc_id
            created += 1

        except Exception as e:
            print(f"           ↳ ERROR: {e}")
            errors += 1

    print(f"\nDone. Created: {created}  |  Skipped: {skipped}  |  Errors: {errors}")


# ---------------------------------------------------------------------------
# Fix headings in docs created with the old buggy code
# ---------------------------------------------------------------------------

_FIX_HEADING_PREFIXES = [
    ("### ", "HEADING_3", 4),
    ("## ",  "HEADING_2", 3),
    ("# ",   "HEADING_1", 2),
]


def fix_tab_headings(folder_name: str = "Granola Meeting Notes", dry_run: bool = False):
    """Repair docs created when inspect_doc returned {} and start_offset=0.

    Symptoms in broken docs:
    - Tab 1 is named "Tab 1" instead of "Notes"
    - Tab 1 paragraphs still have raw '# ' / '## ' / '### ' prefix text

    This function detects those docs (Tab 1 title == "Tab 1"), renames the tab,
    then applies heading styles and strips the # prefixes using the actual paragraph
    positions reported by inspect_doc_structure.
    """
    print(f"{'[DRY RUN] ' if dry_run else ''}Fixing tab names and heading styles in Granola docs")
    print(f"  Folder: {folder_name}\n")

    adaptor_token = get_adaptor_token()
    gw = GWorkspaceClient(adaptor_token)

    print(f"Finding Drive folder '{folder_name}'...")
    results = gw.call_tool("search_drive_files", {"query": folder_name, "file_type": "folder"})
    folder_ids = re.findall(r"ID[:\s]+([A-Za-z0-9_-]{25,})", results)
    if not folder_ids:
        print(f"  ERROR: Folder '{folder_name}' not found.")
        return
    folder_id = folder_ids[0]

    print("Listing docs in folder...")
    text = gw.call_tool("list_docs_in_folder", {"folder_id": folder_id, "page_size": 200})
    doc_ids = re.findall(r"ID[:\s]+([A-Za-z0-9_-]{25,})", text)
    print(f"  Found {len(doc_ids)} docs\n")

    fixed = skipped = errors = 0

    for i, doc_id in enumerate(doc_ids, 1):
        try:
            # Check overall structure to determine whether Tab 1 still needs renaming
            structure = gw.inspect_doc(doc_id)
            tabs = structure.get("tabs", [])
            tab1_info = next((t for t in tabs if t.get("tab_id") == "t.0"), None)
            needs_rename = bool(tab1_info and tab1_info.get("title") == "Tab 1")

            # Get Tab 1 element detail (detailed=True is now always on in inspect_doc)
            tab1_struct = gw.inspect_doc(doc_id, tab_id="t.0")
            elements = tab1_struct.get("elements", [])

            # Identify paragraphs that still have raw # / ## / ### prefixes
            style_ops: list[dict] = []
            delete_ops: list[dict] = []
            for elem in elements:
                if elem.get("type") != "paragraph":
                    continue
                preview = elem.get("text_preview", "")
                start = elem.get("start_index")
                end = elem.get("end_index")
                if start is None or end is None:
                    continue
                line = preview.rstrip("\n")
                for prefix, style, pfx_len in _FIX_HEADING_PREFIXES:
                    if line.startswith(prefix):
                        style_ops.append({
                            "type": "update_paragraph_style",
                            "start_index": start,
                            "end_index": end,
                            "named_style_type": style,
                            "tab_id": "t.0",
                        })
                        delete_ops.append({
                            "type": "delete_text",
                            "start_index": start,
                            "end_index": start + pfx_len,
                            "tab_id": "t.0",
                        })
                        break

            # Skip docs that need neither renaming nor heading fixes
            if not style_ops and not needs_rename:
                skipped += 1
                continue

            label = f"({len(style_ops)} headings{', rename' if needs_rename else ''})"
            print(f"  [{i}/{len(doc_ids)}] FIX   {doc_id}  {label}", end="", flush=True)

            if dry_run:
                print(" [dry run]")
                fixed += 1
                continue

            # 1. Rename Tab 1 → "Notes" if still needed
            if needs_rename:
                gw.call_tool("batch_update_doc", {
                    "document_id": doc_id,
                    "operations": [{
                        "type": "update_doc_tab",
                        "tab_id": "t.0",
                        "title": "Notes",
                    }],
                })

            # 2. Apply heading styles, then delete prefixes in reverse order
            if style_ops:
                gw.call_tool("batch_update_doc", {
                    "document_id": doc_id,
                    "operations": style_ops,
                })
            if delete_ops:
                gw.call_tool("batch_update_doc", {
                    "document_id": doc_id,
                    "operations": list(reversed(delete_ops)),
                })

            print("  ✓")
            fixed += 1

        except Exception as e:
            print(f"  ERROR: {e}")
            errors += 1

    print(f"\nDone. Fixed: {fixed}  |  Skipped: {skipped}  |  Errors: {errors}")


# ---------------------------------------------------------------------------
# Single-meeting format test
# ---------------------------------------------------------------------------

def test_single_meeting(meeting_id: str, folder_name: str = "Granola Meeting Notes"):
    """Create one 'TEST - ...' doc with the new two-tab format to verify output.

    The doc is placed in the normal folder but is NOT added to the dedup index,
    so a subsequent full sync will not be affected. Remove or rename it manually
    once satisfied with the format.
    """
    print(f"[TEST] Creating single-meeting format test doc")
    print(f"  Meeting ID: {meeting_id}\n")

    print("Authenticating...")
    granola_token = get_granola_token()
    adaptor_token = get_adaptor_token()

    print("Connecting to Google Workspace MCP gateway...")
    gw = GWorkspaceClient(adaptor_token)

    print(f"Ensuring Drive folder '{folder_name}'...")
    folder_id = gw.ensure_folder(folder_name)
    print(f"  Folder ID: {folder_id}\n")

    print("Fetching meeting details from Granola...")
    detail_map = granola_get_meetings_batch(granola_token, [meeting_id])
    if not detail_map:
        print("  ERROR: Could not fetch meeting details. Check the meeting ID and try again.")
        return
    meeting = detail_map[meeting_id]
    print(f"  Title: {meeting['title']}")
    print(f"  Date:  {meeting['date']}")
    if meeting.get("participants"):
        print(f"  Attendees: {', '.join(meeting['participants'])}")

    print("\nFetching transcript from Granola...")
    transcript = ""
    try:
        transcript = granola_get_transcript(granola_token, meeting_id)
        print(f"  Transcript: {len(transcript)} chars")
    except Exception as e:
        print(f"  Transcript fetch failed ({e}), continuing without")

    doc_title = "TEST - " + format_doc_title(meeting)
    tab1 = format_tab1_notes(meeting)
    tab2 = format_tab2_transcript(meeting, transcript)

    print(f"\nCreating doc '{doc_title}'...")
    doc_id = gw.create_doc_with_tabs(doc_title, tab1, tab2)
    if not doc_id:
        print("  ERROR: Doc creation failed.")
        return
    if folder_id:
        gw.move_to_folder(doc_id, folder_id)
    print(f"\n✓ Test doc created: {doc_id}")
    print(f"  https://docs.google.com/document/d/{doc_id}/edit")
    print("\nReview the doc, then delete or rename it before running a full sync.")


# ---------------------------------------------------------------------------
# Setup check
# ---------------------------------------------------------------------------

def check_setup() -> bool:
    """Verify all prerequisites and print a ✓ / ✗ status for each.

    Returns True if every check passes, False otherwise.
    Exits with code 0 (all pass) or 1 (any fail) when called via --check.
    """
    all_ok = True

    def _check(label: str, passed: bool, hint: str = "") -> bool:
        symbol = "✓" if passed else "✗"
        print(f"  {symbol}  {label}")
        if not passed and hint:
            for line in hint.splitlines():
                print(f"       {line}")
        return passed

    print("Checking prerequisites…\n")

    # 1. Python version
    ver = sys.version_info
    all_ok = _check(
        f"Python {ver.major}.{ver.minor}.{ver.micro}",
        ver >= (3, 9),
        "Python 3.9 or newer is required. Install from python.org or via Homebrew.",
    ) and all_ok

    # 2. CA cert
    ca_exists = Path(CA_CERT).exists()
    all_ok = _check(
        f"CA cert  ({CA_CERT})",
        ca_exists,
        "Install Claude Code and the Google Workspace MCP plugin — the cert ships with them.\n"
        f"Or set GRANOLA_SYNC_CA_CERT=<path> to point at your cert.",
    ) and all_ok

    # 3. Salesforce MCP adaptor token (macOS keychain)
    adaptor_ok = False
    adaptor_hint = ""
    try:
        get_adaptor_token()
        adaptor_ok = True
    except subprocess.CalledProcessError:
        adaptor_hint = (
            f"Keychain entry not found.\n"
            f"  Service : {ADAPTOR_SERVICE}\n"
            f"  Account : {ADAPTOR_ACCOUNT}\n"
            f"If your account name differs, set GRANOLA_SYNC_ADAPTOR_ACCOUNT=<account> and re-run."
        )
    except Exception as e:
        adaptor_hint = f"Token found in keychain but could not be decoded: {e}"
    all_ok = _check(
        "Salesforce MCP adaptor token (keychain)",
        adaptor_ok,
        adaptor_hint,
    ) and all_ok

    # 4. Granola token
    granola_ok = False
    granola_hint = ""
    if GRANOLA_TOKEN_FILE.exists():
        try:
            tokens = json.loads(GRANOLA_TOKEN_FILE.read_text())
            if tokens.get("access_token") or tokens.get("refresh_token"):
                granola_ok = True
            else:
                granola_hint = f"Token file exists but contains no usable token. Run: python3 granola_sync.py --reauth"
        except Exception as e:
            granola_hint = f"Token file exists but could not be parsed: {e}"
    else:
        granola_hint = "No Granola token found. Run:  python3 granola_sync.py --reauth"
    all_ok = _check("Granola OAuth token", granola_ok, granola_hint) and all_ok

    # 5. MCP gateway reachable
    gw_ok = False
    gw_hint = ""
    try:
        ctx = (
            ssl.create_default_context(cafile=CA_CERT)
            if ca_exists
            else ssl.create_default_context()
        )
        req = urllib.request.Request(
            f"{GW_BASE}/v1/profile/{GW_PROFILE}/mcp",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        no_proxy_opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ctx),
        )
        try:
            with no_proxy_opener.open(req, timeout=10):
                pass
        except urllib.error.HTTPError:
            pass  # Any HTTP response means the gateway is reachable
        gw_ok = True
    except Exception as e:
        gw_hint = f"Could not reach {GW_BASE}: {e}"
    all_ok = _check("MCP gateway reachable", gw_ok, gw_hint) and all_ok

    print()
    if all_ok:
        print("All checks passed — you're ready to sync.")
        print(f"\nNext step:  python3 granola_sync.py --dry-run")
    else:
        print("One or more checks failed. Fix the issues above, then re-run --check.")

    return all_ok


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync Granola meeting notes to Google Docs")
    parser.add_argument("--days", type=int, default=30, help="How many days back to sync (default: 30)")
    parser.add_argument("--folder-name", default="Granola Meeting Notes",
                        help="Drive folder name (created if missing)")
    parser.add_argument("--dry-run", action="store_true",
                        help="List what would be created without writing anything")
    parser.add_argument("--reauth", action="store_true",
                        help="Force re-authentication with Granola (opens browser)")
    parser.add_argument("--backfill-transcripts", action="store_true",
                        help="Append transcripts to existing docs that are missing them")
    parser.add_argument("--test", metavar="MEETING_ID",
                        help="Create a single 'TEST - ...' doc with the new two-tab format "
                             "for the given Granola meeting UUID, then exit")
    parser.add_argument("--fix-headings", action="store_true",
                        help="Repair docs created with the old buggy code: rename Tab 1 → 'Notes' "
                             "and apply heading styles / strip # prefixes")
    parser.add_argument("--check", action="store_true",
                        help="Verify prerequisites (Python version, CA cert, keychain token, "
                             "Granola auth, MCP gateway) and print a ✓ / ✗ status for each")
    args = parser.parse_args()

    if args.check:
        sys.exit(0 if check_setup() else 1)
    elif args.test:
        test_single_meeting(args.test, folder_name=args.folder_name)
    elif args.backfill_transcripts:
        backfill_transcripts(folder_name=args.folder_name, dry_run=args.dry_run)
    elif args.fix_headings:
        fix_tab_headings(folder_name=args.folder_name, dry_run=args.dry_run)
    else:
        sync(days=args.days, folder_name=args.folder_name, dry_run=args.dry_run, reauth=args.reauth)
