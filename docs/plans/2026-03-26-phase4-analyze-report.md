# Phase 4: Analyze + Report — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build Python analyzers that process raw session.json into structured insights, and report generators that produce human-readable Markdown reports, API specs, and replay scripts. The `kahlo report` command should produce output similar to the manual analysis in `.research/008-yakitoriya-scan-analysis.md` but fully automated.

**Architecture:** Each analyzer reads session events filtered by module, extracts patterns, and produces a typed Pydantic model. The report generator takes all analyzer outputs and renders them into Markdown/JSON. The replay generator produces curl commands and Python request snippets for each discovered endpoint.

**Tech Stack:** Python (pydantic, rich), Jinja2-like string formatting for templates

**Reference:** `.research/008-yakitoriya-scan-analysis.md` — this is the target quality for automated reports.

**Test data:** `sessions/com.voltmobi.yakitoriya_20260326_122701_5d3395.json` (626 events)

---

### Task 1: Traffic Analyzer (`kahlo/analyze/traffic.py`)

Processes traffic events → produces endpoint map + server inventory.

**Input:** events where module == "traffic"
**Output (Pydantic model):**
```python
class TrafficReport(BaseModel):
    servers: list[ServerInfo]           # unique host:port with IP, role guess
    endpoints: list[EndpointInfo]       # unique URL patterns with method, count
    tcp_connections: list[TCPConnection] # all socket connections
    ssl_sessions: list[SSLRawCapture]   # raw SSL data summaries
    total_requests: int
    total_connections: int

class ServerInfo(BaseModel):
    host: str
    ip: str | None
    port: int
    role: str              # "api", "analytics", "push", "cdn", "error_reporting"
    connection_count: int
    tls: bool

class EndpointInfo(BaseModel):
    url: str
    method: str | None
    count: int
    content_type: str | None
    has_auth: bool
    sample_headers: dict | None
    sample_body_preview: str | None
```

**Role detection heuristics:**
- "firebase", "crashlytics" → "crash_analytics"
- "sentry" → "error_reporting"
- "appsflyer", "branch", "adjust" → "attribution"
- "push", "fcm", "pushwoosh" → "push_notifications"
- domain matches app name → "core_api"
- everything else → "unknown"

---

### Task 2: Vault Analyzer (`kahlo/analyze/vault.py`)

Processes vault events → produces storage map + secret inventory.

**Output:**
```python
class VaultReport(BaseModel):
    prefs_files: list[PrefsFile]       # all SharedPreferences files
    databases: list[DatabaseInfo]       # all SQLite databases
    secrets: list[SecretInfo]          # extracted tokens, keys, IDs
    file_writes: list[FileWriteInfo]   # file system writes
    keystore_entries: list[KeystoreEntry]

class SecretInfo(BaseModel):
    name: str              # human-readable name
    value: str             # the actual value
    source: str            # "prefs:auth:token", "keystore:api_key"
    category: str          # "api_key", "token", "device_id", "encryption_key", "sdk_key"
    sensitivity: str       # "high", "medium", "low"
```

**Secret detection heuristics:**
- Key contains "token", "key", "secret", "password", "auth" → extract
- Value looks like JWT (eyJ...) → category="token"
- Value looks like UUID → category="device_id"
- Value looks like hex 32+ chars → category="encryption_key"
- Known SDK keys (appsflyer, branch, firebase, sentry, pushwoosh) → category="sdk_key"

---

### Task 3: Recon Analyzer (`kahlo/analyze/recon.py`)

Processes recon events → produces privacy/fingerprint profile.

**Output:**
```python
class ReconReport(BaseModel):
    device_info: dict[str, str]        # field → value (MODEL, ANDROID_ID, etc.)
    telecom: dict[str, str]            # operator, PLMN, SIM info
    network_info: list[dict]           # network type, VPN status
    ip_lookups: list[str]              # IP detection services contacted
    competitor_probes: list[str]       # telegram, whatsapp, etc.
    installed_apps_check: bool         # did it scan installed apps?
    vpn_detected: bool | None
    fingerprint_appetite: int          # 0-100 score
    categories: list[str]             # "device", "network", "location", etc.
```

**Fingerprint appetite scoring:**
- Each category collected: +10-20 points
- VPN detection: +20
- IP lookup: +15
- Competitor probes: +25
- Installed apps scan: +20

---

### Task 4: Netmodel Analyzer (`kahlo/analyze/netmodel.py`)

Processes netmodel events → produces crypto inventory + signing recipe.

**Output:**
```python
class NetmodelReport(BaseModel):
    crypto_operations: list[CryptoOp]
    hmac_keys: list[HMACKey]
    hashes: list[HashInfo]
    tls_sessions: list[TLSInfo]
    nonces: list[NonceInfo]
    signing_recipe: SigningRecipe | None   # extracted signing pattern

class SigningRecipe(BaseModel):
    algorithm: str         # "HmacSHA256"
    key_hex: str          # extracted key
    input_pattern: str    # what gets signed (url+body+nonce?)
    nonce_method: str     # "UUID.randomUUID" / "timestamp" / "counter"
```

---

### Task 5: Pattern Detector (`kahlo/analyze/patterns.py`)

Identifies known SDKs and services from all events combined.

**Output:**
```python
class PatternsReport(BaseModel):
    sdks: list[SDKInfo]

class SDKInfo(BaseModel):
    name: str             # "Firebase Crashlytics"
    version: str | None   # "8.28.0"
    category: str         # "analytics", "crash_reporting", "push", "attribution"
    evidence: list[str]   # what triggered detection
    data_collected: list[str]  # what data it sends
```

**Detection patterns (from prefs keys, class names, endpoints):**
- Firebase: prefs containing "firebase", "fcm", "google_app_id"
- Sentry: prefs "sentry", endpoint containing "sentry"
- AppsFlyer: prefs "appsflyer", "AF_", endpoint "appsflyersdk"
- Branch: prefs "branch", "bnc", endpoint "branch.io"
- Pushwoosh: prefs "pushwoosh", "PW_", endpoint "wavesend"
- Yandex Metrica: prefs "appmetrica", "yandex"
- Adjust: prefs "adjust", endpoint "adjust.com"

---

### Task 6: Report Generator (`kahlo/report/markdown.py`)

Takes all analyzer outputs → produces comprehensive Markdown report.

**Sections:**
1. Executive Summary (app name, scan duration, event counts)
2. Network Infrastructure (servers table, roles)
3. API Endpoints (URL, method, auth, sample)
4. Storage & Secrets (prefs, databases, extracted secrets table)
5. Privacy Profile (fingerprint appetite score, what's collected)
6. Cryptography (algorithms, keys, signing patterns)
7. SDK Inventory (name, version, category, data collected)
8. API Recreation Assessment (feasibility, blockers, recipe)

---

### Task 7: Replay Generator (`kahlo/report/replay.py`)

Generates Python/curl replay scripts for discovered endpoints.

For each endpoint in TrafficReport:
- curl command with headers + body
- Python requests snippet
- If signing detected: include signing code

Also generate a thin client skeleton:
```python
class YakitoriyaClient:
    def __init__(self, token=None):
        self.session = requests.Session()
        self.session.headers = {extracted User-Agent, etc.}
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    def endpoint_name(self, params):
        # Generated from captured request
        ...
```

---

### Task 8: API Spec Generator (`kahlo/report/api_spec.py`)

Generates a JSON API specification from TrafficReport.

```json
{
  "app": "com.voltmobi.yakitoriya",
  "base_urls": ["https://beacon2.yakitoriya.ru"],
  "auth": {"type": "bearer", "token_source": "encrypted_prefs:auth_token"},
  "signing": {"algorithm": "HmacSHA256", "key": "..."},
  "endpoints": [
    {
      "path": "/api/v2/orders",
      "method": "POST",
      "headers": {...},
      "body_format": "json",
      "auth_required": true,
      "sample_request": {...},
      "sample_response": {...}
    }
  ]
}
```

---

### Task 9: CLI `kahlo report` Command + Integration

**Modify `kahlo/cli.py`:**
- `kahlo report <session_path_or_id>` — generate all reports from session
- Outputs: report.md, api-spec.json, replay/ directory
- Prints summary to terminal

**Integration test:**
- Run `kahlo report sessions/com.voltmobi.yakitoriya_20260326_122701_5d3395.json`
- Verify report.md generated with all sections
- Verify api-spec.json generated
- Verify replay/ directory with scripts
- Compare quality with manual `.research/008-yakitoriya-scan-analysis.md`
