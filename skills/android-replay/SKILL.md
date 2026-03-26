---
name: android-replay
description: Replay captured API calls and generate thin clients
triggers:
  - "создай клиент"
  - "replay API"
  - "clone app"
  - "повтори API"
  - "клон приложения"
  - "thin client"
  - "generate client"
---

# Android API Replay & Client Generation

You are helping the user replay captured API calls and generate thin clients from Frida-Kahlo analysis results.

## Prerequisites

A completed analysis session with:
- `api-spec.json` — API specification from kahlo analysis
- `replay/` directory — Generated replay scripts
- Session JSON file with raw captured data

## Workflow

### 1. Find Analysis Results

Look in the `sessions/` directory:

```bash
ls sessions/*_report/
```

### 2. Read the API Spec

The `api-spec.json` contains:
- All discovered endpoints with method, URL, headers, body samples
- Auth information (Bearer tokens, API keys, cookies)
- Server inventory with roles
- Crypto/signing details

### 3. Use Generated Replay Scripts

The `replay/` directory contains:
- `curl_commands.sh` — curl commands for each endpoint
- `replay_client.py` — Python HTTP client with all endpoints
- Individual endpoint scripts

### 4. Generate a Full Thin Client

Based on api-spec.json, generate a complete Python client that:

1. **Authenticates** using the captured auth flow
2. **Signs requests** if the app uses HMAC/signature verification
3. **Sets correct headers** (User-Agent, X-App-Version, etc.)
4. **Implements all endpoints** with proper request/response types
5. **Handles sessions** (token refresh, cookie management)

Template structure:
```python
import httpx

class AppClient:
    BASE_URL = "https://api.example.com"

    def __init__(self):
        self.client = httpx.Client(headers={...})
        self.token = None

    def authenticate(self, ...):
        ...

    def endpoint_name(self, ...):
        ...
```

### 5. Key Considerations

- **Device fingerprint**: The server may validate device-specific headers
- **Request signing**: Check netmodel analysis for HMAC/signature details
- **Certificate pinning**: Original app pins certificates — your client may need to match
- **Rate limiting**: Be respectful of API rate limits
- **Token TTL**: Auth tokens expire — implement refresh logic

## Interpreting api-spec.json

Key sections:
- `servers` — Base URLs and their roles
- `endpoints` — All API endpoints with samples
- `auth` — Authentication mechanism details
- `signing` — Request signing algorithm and keys
- `device_profile` — Headers the server expects

## Tips

- Start with the most-called endpoints (highest `count`)
- The `core_api` server is usually the main backend
- Endpoints with `has_auth: true` need authentication first
- Check `sample_headers` for required custom headers
