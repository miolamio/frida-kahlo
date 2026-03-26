---
name: android-analysis
description: Analyze Android app — full automated pipeline via Frida
triggers:
  - "проанализируй приложение"
  - "analyze app"
  - "что делает приложение"
  - "как работает API"
  - "analyze android"
  - "reverse engineer"
---

# Android App Analysis

You are helping the user analyze an Android application using the `kahlo` CLI tool (Frida-based automated analysis framework).

## Prerequisites

- Android device connected via USB (check with `kahlo device`)
- frida-server installed on device

## Workflow

### 1. Quick Analysis (installed app)

If the user provides a **package name** (like `com.example.app`):

```bash
kahlo analyze com.example.app --skip-fetch --duration 60
```

This will:
- Verify the app is installed on device
- Parse the AndroidManifest.xml
- Spawn the app with Frida instrumentation (stealth mode)
- Collect traffic, vault, recon, and netmodel events for 60 seconds
- Analyze all captured data
- Generate report.md, api-spec.json, and replay scripts

### 2. Full Pipeline (from app name)

If the user provides an **app name** (like "yakitoriya"):

```bash
kahlo analyze yakitoriya --duration 60
```

This will additionally try to download the APK from APKPure/APKCombo.

### 3. Reading Results

After analysis, read the generated files:

- `sessions/<session_id>_report/report.md` — Full analysis report
- `sessions/<session_id>_report/api-spec.json` — API specification
- `sessions/<session_id>_report/replay/` — Replay scripts (curl, Python)
- `sessions/<session_id>.json` — Raw session data

### 4. Deeper Investigation

If the initial scan is not enough, use interactive monitoring:

```bash
kahlo scan <package> --duration 120
```

Then generate a report from the session:

```bash
kahlo report sessions/<session_file>.json
```

### 5. Manifest Analysis

For quick static analysis without running the app:

```bash
kahlo manifest /path/to/app.apk
kahlo manifest /path/to/xapk_directory/
```

## Interpreting Results

When reading report.md, focus on:

1. **Server Inventory** — What servers the app talks to, their roles
2. **API Endpoints** — What HTTP endpoints are called, with auth info
3. **Secrets** — Tokens, keys, IDs found in storage
4. **SDKs** — Third-party libraries and their data collection
5. **Fingerprint Appetite** — How much device/user data the app collects (0-100)
6. **Crypto Operations** — Signing algorithms, HMAC keys, encryption

## Tips

- Tell the user to **interact with the app** during the scan for better results
- Longer duration (120s) captures more endpoints
- Use `--skip-static` to skip jadx decompilation if not needed
- The `api-spec.json` is machine-readable and can be used to generate clients
