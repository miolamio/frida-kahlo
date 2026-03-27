<p align="center">
  <img src="assets/banner.jpg" alt="Frida-Kahlo" width="600">
</p>

# Frida-Kahlo

CLI framework for automated Android app analysis via Frida.

Give it an app name — get a full report: network traffic, storage, secrets, telemetry, cryptography, tracking SDKs, and a ready-to-use thin client for API replay.

## Features

- **Full pipeline**: download APK → install → Frida instrumentation → analysis → report
- **4 analysis pillars**: traffic (5 interception levels), storage/secrets, environment recon, network model
- **Stealth**: anti-detection for Frida (port randomization, /proc/maps bypass, ptrace, root hiding)
- **SSL Unpinning**: universal cert pinning bypass (OkHttp, TrustManager, Conscrypt, WebView)
- **Auto-report**: Markdown report + JSON API spec + curl/Python replay scripts + thin client
- **Live monitor**: interactive real-time monitoring with Rich terminal UI
- **Auth capture**: login flow interception, EncryptedSharedPreferences decryption (Tink), JWT decoding
- **Static analysis**: scan jadx decompilation for URLs, secrets, crypto patterns
- **Aggregation & diff**: merge multiple scans, compare sessions
- **Postman export**: ready-to-use request collection

## Installation

```bash
git clone https://github.com/yourname/frida-kahlo.git
cd frida-kahlo
pip install -e ".[dev]"
```

### Requirements

- Python 3.11+
- Frida 17.x (`pip install frida frida-tools`)
- Rooted Android device (Magisk) with USB debugging
- frida-server on device (`/data/local/tmp/frida-server`)

### Optional dependencies

```bash
pip install -e ".[acquire]"   # Playwright for APK downloading
pip install -e ".[static]"    # Androguard for extended analysis
```

## Quick Start

```bash
# Check device
kahlo device

# Start stealth frida-server
kahlo frida-start

# Full scan of an installed app (30 seconds)
kahlo scan com.example.app --duration 30

# Generate report
kahlo report sessions/session.json

# Or everything at once — from name to report
kahlo analyze com.example.app --skip-fetch --duration 60
```

## Commands

| Command | Description |
|---------|-------------|
| `kahlo analyze <app>` | Full pipeline: fetch → install → scan → analyze → report |
| `kahlo scan <package>` | Instrumentation + event collection (4 pillars) |
| `kahlo monitor <package>` | Live monitoring with Rich UI |
| `kahlo report <session>` | Generate reports from session |
| `kahlo fetch <name>` | Download APK from mirrors (APKPure, APKCombo) |
| `kahlo install <apk>` | Install APK on device |
| `kahlo device` | Device and frida-server status |
| `kahlo frida-start` | Start frida-server (stealth mode) |
| `kahlo frida-stop` | Stop frida-server |
| `kahlo stealth-check <pkg>` | Check if app detects Frida |
| `kahlo manifest <apk>` | Parse AndroidManifest.xml |
| `kahlo static <jadx_dir>` | Static analysis of jadx output |
| `kahlo aggregate <s1> <s2>` | Merge multiple sessions |
| `kahlo diff <old> <new>` | Compare two sessions |
| `kahlo export-postman <s>` | Export to Postman Collection |

## Architecture

```
kahlo/
  cli.py                 15 CLI commands (typer + rich)
  pipeline.py            Full pipeline orchestration
  acquire/               APK download (Playwright), extraction, installation
  prepare/               Manifest parsing, jadx decompilation
  device/                ADB wrapper, frida-server lifecycle
  stealth/               Anti-detection (4 escalation levels)
  instrument/            FridaEngine, ScriptLoader, Session
  analyze/               12 analyzers (traffic, vault, recon, netmodel,
                         patterns, auth, jwt, static, decoder, aggregate,
                         diff, flows)
  report/                Markdown, API spec, replay, Postman
  monitor.py             Live monitoring

scripts/
  common.js              Shared utilities
  discovery.js           Class discovery (OkHttp, Retrofit, WS, crypto)
  bypass/stealth.js      Anti-detection (/proc/maps, ptrace, root, files)
  bypass/ssl_unpin.js    Universal SSL unpinning
  hooks/traffic.js       Traffic interception (5 levels: OkHttp3, system
                         OkHttp v2, HttpURLConnection, Conscrypt SSL,
                         native SSL_write/SSL_read)
  hooks/vault.js         Storage (SharedPreferences, SQLite, KeyStore, Tink)
  hooks/recon.js         Recon (device info, VPN, carrier, IP, apps)
  hooks/netmodel.js      Crypto (Cipher, HMAC, Signature, TLS, UUID)
```

## Four Pillars of Analysis

### Traffic — Network traffic
5 cascading interception levels: OkHttp3 Interceptor → system OkHttp v2 (HttpEngine) → HttpURLConnection → Conscrypt SSL stream → native SSL_write/SSL_read. Full request/response with headers, bodies, timing.

### Vault — Storage & secrets
SharedPreferences (including EncryptedSharedPreferences with Tink decryption), SQLite, file system, KeyStore, AccountManager. Automatic extraction of tokens, API keys, device IDs.

### Recon — Environment reconnaissance
What the app learns about the device: Build.*, ANDROID_ID, carrier/PLMN, VPN detection, IP services, installed apps check, geolocation, sensors. Fingerprint appetite score (0-100).

### Netmodel — Network model
Cryptographic operations: AES/RSA encryption, HMAC signing, hashes, TLS parameters, nonce generation. Signing recipe extraction for API replay.

## Analysis Output

After `kahlo scan` + `kahlo report`, the session directory contains:

```
sessions/<session_id>_report/
  report.md                Markdown report (Infrastructure, API, Secrets,
                           Privacy, Crypto, SDKs, Auth Flow, Recreation)
  api-spec.json            JSON API specification
  postman_collection.json  Postman Collection v2.1
  replay/
    client.py              Thin client with per-host routing and signing
    curl/                  curl commands for each endpoint
    python/                Python requests for each endpoint
```

## Stealth — Anti-Detection

4 escalation levels:

| Level | Technique | Coverage |
|-------|-----------|----------|
| 1. Basic | Random port + bypass.js | ~70% of apps |
| 2. Bypass | + /proc/maps filtering, ptrace, root-hide | ~85% |
| 3. hluda | Custom Frida build without artifacts | ~95% |
| 4. Gadget | frida-gadget (no external process) | ~99% |

## Testing

```bash
# All tests (requires device with frida-server)
pytest tests/ -v --timeout=120

# Tests without device
pytest tests/ -v --timeout=60 -k "not (test_discovery or test_spawn or test_scan or test_system_okhttp)"
```

405 tests covering: ADB, frida-server lifecycle, stealth, instrument engine, all 4 hooks, all 12 analyzers, all 4 report generators, monitor, decoder, aggregate, diff, flows, postman.

## License

MIT
