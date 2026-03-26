# Phase 3: Four Pillars (Hooks) — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the four analysis hook scripts (traffic, vault, recon, netmodel) and the Python capture engine that collects their output into structured sessions. Test by running a real scan against yakitoriya on the device.

**Architecture:** Each JS hook module uses `sendEvent()` from common.js to emit structured JSON events. The Python side composes bypass + hooks via ScriptLoader, spawns the app via FridaEngine, and collects events into a Session. A new `kahlo scan` CLI command orchestrates this: spawn → collect for N seconds → save session.

**Tech Stack:** JavaScript (Frida GumJS), Python (frida-python, pydantic, typer, rich)

**Test app:** com.voltmobi.yakitoriya (already installed)

---

### Task 1: Traffic Hook (`scripts/hooks/traffic.js`)

The most important hook. Captures ALL network traffic at multiple levels.

**Levels (cascade — try each, skip if class not found):**

1. **OkHttp Interceptor** — register custom NetworkInterceptor via OkHttpClient$Builder.build. Captures: method, url, headers, body (request + response), status, elapsed.

2. **WebSocket** — hook OkHttp RealWebSocket.send/onReadMessage (text + binary). Also hook any obfuscated WS classes from discovery.

3. **Conscrypt SSL** — ConscryptFileDescriptorSocket$SSLOutputStream.write + SSLInputStream.read. Parse HTTP from raw stream.

4. **Native SSL** — Module.findExportByName for SSL_write/SSL_read in libssl.so, libboringssl.so. Fallback for apps with fully custom TLS.

5. **Socket.connect** — log all TCP connections (IP, port, hostname).

**Event format:**
```json
{"module":"traffic","type":"http_request","data":{"method":"POST","url":"...","headers":{...},"body":"...","body_format":"json"}}
{"module":"traffic","type":"http_response","data":{"url":"...","status":200,"headers":{...},"body":"...","elapsed_ms":142}}
{"module":"traffic","type":"ws_send","data":{"url":"...","text":"...","is_binary":false}}
{"module":"traffic","type":"ws_receive","data":{"url":"...","text":"...","is_binary":false}}
{"module":"traffic","type":"tcp_connect","data":{"host":"...","ip":"...","port":443}}
{"module":"traffic","type":"ssl_raw","data":{"direction":"out","preview":"GET /api/...","length":1234}}
```

**Test:** Spawn yakitoriya, interact for 10 sec, expect at least 1 http_request event.

---

### Task 2: Vault Hook (`scripts/hooks/vault.js`)

Captures everything the app stores on device.

**What to hook:**
- SharedPreferences: getString/putString/getInt/putInt/getBoolean/putBoolean + Editor.apply/commit
- SQLiteDatabase: query/rawQuery/insert/update/delete/execSQL
- FileOutputStream.write (internal storage only — filter /data/data/<package>)
- KeyStore: getKey/getEntry/setEntry/aliases
- AccountManager: getAuthToken

**Initial dump (on load):**
- Read all SharedPreferences files via context.getSharedPreferences()
- List SQLite databases via context.databaseList()

**Event format:**
```json
{"module":"vault","type":"pref_read","data":{"file":"auth","key":"token","value":"eyJ...","value_type":"string"}}
{"module":"vault","type":"pref_write","data":{"file":"settings","key":"vpn_detected","value":"true"}}
{"module":"vault","type":"sqlite_query","data":{"db":"app.db","sql":"SELECT * FROM users","result_count":1}}
{"module":"vault","type":"file_write","data":{"path":"/data/data/com.app/files/cache.json","size":1234}}
{"module":"vault","type":"keystore_read","data":{"alias":"api_key","type":"SecretKey"}}
{"module":"vault","type":"initial_dump","data":{"prefs":{"auth":{"token":"..."}}, "databases":["app.db","analytics.db"]}}
```

**Test:** Spawn yakitoriya, expect initial_dump with at least 1 prefs file.

---

### Task 3: Recon Hook (`scripts/hooks/recon.js`)

Captures what the app tries to learn about the device/user.

**What to hook:**
- Build.* field access (MODEL, MANUFACTURER, FINGERPRINT, SERIAL, DEVICE, BRAND, HARDWARE)
- Settings.Secure.getString (ANDROID_ID)
- TelephonyManager: getDeviceId, getImei, getNetworkOperator, getSimOperator, getNetworkOperatorName, getLine1Number
- NetworkCapabilities.hasTransport (VPN = transport 4)
- ConnectivityManager.getActiveNetwork, getNetworkInfo
- WifiManager.getConnectionInfo (SSID, BSSID, IP)
- LocationManager.getLastKnownLocation, requestLocationUpdates
- PackageManager.getInstalledPackages, getInstalledApplications
- URL.openConnection — filter for IP services (ipify, ifconfig, checkip, etc.)
- Socket.connect — filter for competitor probes (telegram, whatsapp, gosuslugi)
- InetAddress.isReachable — ping probes
- SensorManager.registerListener — motion/proximity sensors

**Event format:**
```json
{"module":"recon","type":"device_info","data":{"field":"MODEL","value":"Redmi Note 5A","stack":"..."}}
{"module":"recon","type":"vpn_check","data":{"transport":4,"result":false,"stack":"..."}}
{"module":"recon","type":"ip_lookup","data":{"service":"ipify.org","url":"https://api.ipify.org"}}
{"module":"recon","type":"competitor_probe","data":{"target":"telegram.org","method":"socket_connect"}}
{"module":"recon","type":"installed_apps","data":{"count":3,"packages":["com.topjohnwu.magisk",...]}}
```

**Test:** Spawn yakitoriya, expect at least device_info events.

---

### Task 4: Netmodel Hook (`scripts/hooks/netmodel.js`)

Captures cryptographic operations and signing mechanisms — the key to recreating API.

**What to hook:**
- javax.crypto.Cipher: init/doFinal — algorithm, key, IV, input/output
- javax.crypto.Mac: init/doFinal — HMAC algorithm, key, input/output
- java.security.Signature: initSign/sign/initVerify/verify
- java.security.MessageDigest: digest — hash algorithm, input/output
- javax.net.ssl.SSLSession: getCipherSuite, getProtocol, getPeerCertificates
- java.security.KeyStore: getKey — key extraction
- java.util.UUID.randomUUID — nonce generation tracking
- System.currentTimeMillis / nanoTime — timestamp usage in request context

**Event format:**
```json
{"module":"netmodel","type":"crypto_op","data":{"op":"encrypt","algorithm":"AES/CBC/PKCS5Padding","key_hex":"a1b2...","iv_hex":"d4e5...","input_preview":"...","output_b64":"..."}}
{"module":"netmodel","type":"hmac","data":{"algorithm":"HmacSHA256","key_hex":"...","input_preview":"...","output_hex":"..."}}
{"module":"netmodel","type":"tls_info","data":{"cipher":"TLS_AES_128_GCM_SHA256","protocol":"TLSv1.3","peer_cn":"*.example.com"}}
{"module":"netmodel","type":"hash","data":{"algorithm":"SHA-256","input_preview":"...","output_hex":"..."}}
```

**Test:** Spawn yakitoriya, expect at least tls_info or hash events.

---

### Task 5: Scan Command + Session Integration

**Files:**
- Modify: `kahlo/cli.py` — add `scan` command
- Modify: `kahlo/instrument/session.py` — add event statistics
- Create: `tests/test_scan.py`

**`kahlo scan <package> [--duration 60]`:**
1. Ensure frida-server running (stealth)
2. Load: bypass/stealth.js + bypass/ssl_unpin.js + all 4 hooks + discovery
3. Spawn app
4. Collect events for `duration` seconds (show live progress with rich)
5. Save session to `sessions/<timestamp>-<package>/`
6. Print summary: events by module, unique endpoints, etc.

**Test:** `kahlo scan com.voltmobi.yakitoriya --duration 30` → session directory with session.json containing events from multiple modules.

---

### Task 6: Integration Test on Device

Run the full scan on yakitoriya for 30 seconds. Report:
- Total events collected
- Events per module (traffic, vault, recon, netmodel)
- Any unique endpoints found
- Any interesting findings (telemetry, stored tokens, etc.)
- Session saved to sessions/

This is the critical test — first real data collection from a live app.
