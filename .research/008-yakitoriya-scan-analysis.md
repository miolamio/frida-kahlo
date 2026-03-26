# Yakitoriya App (com.voltmobi.yakitoriya) - Frida Scan Analysis

**Session:** `com.voltmobi.yakitoriya_20260326_122701_5d3395`
**Date:** 2026-03-26 12:27:01 UTC
**Duration:** ~36 seconds
**Events Captured:** 626
**Device:** Xiaomi Redmi Note 5A (Android 16, SDK 36, Build BP2A.250805.005)
**App Version:** 2.18.13 (build 5740)
**Developer:** VoltMobi

---

## 1. Network Infrastructure

### 1.1 Servers & Domains

| Domain | IP Address | Port | Role | CDN/Infra |
|--------|-----------|------|------|-----------|
| `firebase-settings.crashlytics.com` | 209.85.233.94 | 443 | Firebase Crashlytics config | Google |
| `sentry.inno.co` | 84.201.136.35 | 443 | Error tracking (Sentry) | Yandex Cloud (nginx) |
| `api.wavesend.ru` | 82.147.67.99 | 443 | Push notifications (Pushwoosh API) | QRATOR DDoS protection, nginx, gRPC backend |
| `beacon2.yakitoriya.ru` | 178.248.232.193 | 443 | **Primary app backend** (orders, menu, delivery) | HTTP/2, QRATOR protection |
| `api2.branch.io` | 3.164.240.84 | 443 | Deep linking (Branch.io) | AWS CloudFront |
| `launches.appsflyersdk.com` | 65.9.46.78 | 443 | Attribution analytics (AppsFlyer) | AWS CloudFront (`http-kit` backend) |

### 1.2 Infrastructure Notes

- **QRATOR DDoS protection** present on both `api.wavesend.ru` and `beacon2.yakitoriya.ru` -- visible in response bodies (`QRATORa` markers)
- Backend behind `api.wavesend.ru` uses **gRPC**: `Grpc-Metadata-Content-Type: application/grpc` header in responses
- `beacon2.yakitoriya.ru` uses **HTTP/2** (PRI * HTTP/2.0 upgrade frame captured)
- **nginx** fronts both Russian servers
- All connections are TLS 443 -- no plaintext traffic observed
- The IP 84.201.136.35 (sentry.inno.co) resolves to Yandex Cloud, suggesting the developer (InnoTech/VoltMobi) uses Yandex infrastructure
- The Sentry server uses **Let's Encrypt R13** certificates
- The `beacon2.yakitoriya.ru` server uses **GlobalSign GCC R6 AlphaSSL CA 2025** certificates
- `api2.branch.io` uses **DigiCert** certificates
- `launches.appsflyersdk.com` uses **Amazon RSA 2048 M01** certificates

### 1.3 SSL Certificate Chain Fingerprints (from hash operations)

| Domain | Cert Subject | MD5 |
|--------|-------------|-----|
| App signing cert | RU/Yakitoriya (self-signed, valid 2012-2053) | `d1df3033921178cd91be820bba0a0aa2` |
| sentry.inno.co | Let's Encrypt R13 | `654279274e987144c4fc0b5fc11d283f` |
| sentry.inno.co (root) | ISRG Root X1 | `73b6876195f5d18e048510422aef04e3` |
| api.wavesend.ru | *.wavesend.ru | `58528ff1f2fe92084d7f2690349d7c0e` |
| beacon2.yakitoriya.ru | *.yakitoriya.ru | `9d740a4d4f97e479e686af30107e3c57` |
| beacon2.yakitoriya.ru CA | GlobalSign GCC R6 AlphaSSL CA 2025 | `3cef150b49cb373a638b7c7d39ef0f52` |
| beacon2.yakitoriya.ru root | GlobalSign Root CA - R6 | `521f5c98970d19a8e515ef6eeb6d48ef` |
| api2.branch.io | *.branch.io | `a236ef710d1cc39c780e894c7a222fc1` |
| launches.appsflyersdk.com | DigiCert Global G2 TLS RSA SHA256 2020 CA1 | `f0ab2dd3946de51b1b4465c10611da9a` |
| launches.appsflyersdk.com | conversions.appsflyersdk.com | `7147f03f6f7138c8073471655eba98b1` |

---

## 2. Traffic Analysis

### 2.1 HTTP Endpoints

| Method | Host | Path | Purpose |
|--------|------|------|---------|
| POST | `sentry.inno.co` | `/api/13/envelope/` | Sentry error/session reporting |
| POST | `api.wavesend.ru` | `/json/1.3/postEvent` | Pushwoosh event tracking |
| POST | `api.wavesend.ru` | `/json/1.3/getInApps` | Pushwoosh in-app messages |
| POST | `api.wavesend.ru` | `/json/1.3/applicationOpen` | Pushwoosh app open notification |
| PATCH | `beacon2.yakitoriya.ru` | (HTTP/2, path in frame) | **Core API -- order/delivery/cart operations** |
| POST | `api2.branch.io` | `/v1/install` | Branch.io deep link install attribution |
| POST | `launches.appsflyersdk.com` | `/api/v6.17/androidevent` | AppsFlyer launch/attribution event |

### 2.2 Pushwoosh (Wavesend) API Structure

All requests to `api.wavesend.ru` follow this pattern:

```
POST /json/1.3/{endpoint} HTTP/1.1
Content-Type: application/json; charset=utf-8
Authorization: Token null
User-Agent: Dalvik/2.1.0 (Linux; U; Android 16; Redmi Note 5A Build/BP2A.250805.005)
Host: api.wavesend.ru
```

**Standard request body:**
```json
{
  "request": {
    "application": "4F0CA-D5EC6",
    "hwid": "2ed17728-7d78-4ca1-a2f3-7fa4eab342d1",
    "v": "6.7.48",
    "device_type": 3,
    "userId": "2ed17728-7d78-4ca1-a2f3-7fa4eab342d1",
    "language": "ru",
    ...
  }
}
```

**Observed events sent:**
- `inlineInApp` -- with `attributes.identifier: "banner_id_1"`
- `postEvent` with `attributes.device_type` + `attributes.application_version`
- `applicationOpen` with `language`, `timezone` (10800 = UTC+3, Moscow), `android_package`
- `Abandoned cart` -- user had items in cart
- Screen tracking: `attributes.screen_name: "com.voltmobi.yakitoriya.ui.main.MainActivity"`

**Key observation:** `Authorization: Token null` -- the Pushwoosh API requires **no authentication token**. The `application` ID (`4F0CA-D5EC6`) and `hwid` are the only identifiers.

### 2.3 Core Backend API (beacon2.yakitoriya.ru)

The primary app API communicates over **HTTP/2** via `beacon2.yakitoriya.ru`. A captured PATCH request reveals the **order/delivery API**:

```json
{
  "deliveryType": "delivery",
  "address": {
    "address": {
      "city_name": "............",
      "street_name": ".............. ..........",
      "building": "11/19",
      "entrance": "",
      "description": "............, ............, .............. .........., 11/19",
      "latLngGeo": {"lat": 55.730228, "lng": 37.632368}
    },
    "geo": {"lat": 55.730228, "lng": 37.632368},
    "flat": "",
    "title": ""
  },
  "restaurantId": 22,
  "timeType": "fast",
  "modernPayment": {"nam..."}
}
```

**Key findings:**
- Location: Moscow (lat 55.73, lng 37.63)
- Restaurant ID: 22
- Supports delivery with address geocoding
- Payment system present (`modernPayment` field)
- Street names are in Cyrillic (rendered as dots in the capture)
- Uses HTTP/2 multiplexing (PATCH frame captured alongside other frames)

### 2.4 Sentry Error Reporting

```
POST /api/13/envelope/ HTTP/1.1
User-Agent: sentry.java.android/8.28.0
X-Sentry-Auth: Sentry sentry_version=7,sentry_client=sentry.java.android/8.28.0,sentry_key=fee4d03d5f8cee7487e3616bdf00416a
Content-Encoding: gzip
Content-Type: application/x-sentry-envelope
Host: sentry.inno.co
```

### 2.5 Branch.io Deep Linking

Request sends comprehensive device fingerprint:
```json
{
  "hardware_id": "1f184791a6e1fbab",
  "is_hardware_id_real": true,
  "brand": "Xiaomi",
  "model": "Redmi Note 5A",
  "screen_dpi": 260,
  "screen_height": 1280,
  "screen_width": 720,
  "wifi": true,
  "ui_mode": "UI_MODE_TYPE_NORMAL",
  "os": "Android",
  "os_version": 36,
  "cpu_type": "aar..."
}
```

**Response:** HTTP 400 Bad Request -- likely because Branch was not properly configured or the install referrer was missing. Served via CloudFront (ARN53-P2 edge).

### 2.6 AppsFlyer Attribution

```
POST /api/v6.17/androidevent?app_id=com.voltmobi.yakitoriya&buildnumber=6.17.5
Content-Type: application/octet-stream
Host: launches.appsflyersdk.com
```

Body is **AES-CBC encrypted** (see Cryptographic Operations section). The plaintext includes:
- `appsflyerKey: "JxKoewgyFZTH9mK27cRrc4"`
- `country: "RU"`
- `operator: "MTS RUS"`
- `isFirstCall: "false"`
- `registeredUninstall: false`
- `targetSDKver: 36`
- `platform_extension_v2.platform: "android_native"`
- `platform_extension_v2.version: "6.17.5"`

**Response:** `HTTP 200 OK`, body: `ok` (via CloudFront, `http-kit` backend)

### 2.7 WebSocket Usage

**None detected.** The discovery class_map shows `"websocket": []` -- no WebSocket classes loaded.

---

## 3. Storage & Secrets

### 3.1 SharedPreferences Files (17 files)

| File | Owner/SDK | Key Data |
|------|-----------|----------|
| `com.voltmobi.yakitoriya_preferences.xml` | App main prefs | IABTCF consent (TCF 2.0), Chrome WebView flags |
| `com.voltmobi.yakitoriya.data.preferences_crypto.xml` | App encrypted prefs | **EncryptedSharedPreferences** -- user session, tokens, auth |
| `com.voltmobi.yakitoriya.data.preferences_crypto.independent.xml` | App encrypted prefs (2nd store) | Independent encrypted preference store |
| `com.pushwoosh.registration.xml` | Pushwoosh | App ID, HWID, project ID, base URL, user ID |
| `com.pushwoosh.pushnotifications.xml` | Pushwoosh | Notification settings, rich media config |
| `com.pushwoosh.migration.xml` | Pushwoosh | Migration version |
| `PWAppVersion.xml` | Pushwoosh | Launch version |
| `com.google.firebase.crashlytics.xml` | Firebase Crashlytics | Installation IDs, Firebase installation ID |
| `com.google.firebase.messaging.xml` | FCM | Proxy notification state |
| `com.google.android.gms.measurement.prefs.xml` | Google Analytics | App instance ID, consent, session data |
| `com.google.android.gms.appid.xml` | GMS | Topic queue, FCM sender ID |
| `appsflyer-data.xml` | AppsFlyer | Installation ID, launch count (70), OneLink config, event history |
| `branch_referral_shared_pref.xml` | Branch.io | Branch key, session/identity IDs, install timestamps |
| `BNC_Server_Request_Queue.xml` | Branch.io | Server request queue |
| `WebViewChromiumPrefs.xml` | WebView | Chromium version, cached flags |
| `move_to_de_records.xml` | Data migration | Push client self info |
| `com.mobileapptracking.xml` | TUNE/HasOffers (legacy) | `mat_id` (null -- legacy SDK remnant) |

### 3.2 SQLite Databases

| Database | Purpose | Tables Written |
|----------|---------|----------------|
| `google_app_measurement.db` | Google Analytics for Firebase | `raw_events` (app events: `_vs`, `_e`) |
| `com.google.android.datatransport.events` | Firebase Data Transport | `events`, `event_metadata` |

**Event metadata written to transport DB:**
- `country: RU`
- `product: lineage_Mi8937`
- `mobile-subtype: 100`
- `mcc_mnc: 25001`
- `application_build: 5740`
- `locale: ru`
- `manufacturer: Xiaomi`
- `net-type: 1` (WiFi)
- `os-build: BP2A.250805.005`
- `sdk-version: 36`
- `fingerprint: Xiaomi/land/land:6.0.1/MMB29M/V10.2.2.0.MALMIXM:user/release-keys`
- `model: Redmi Note 5A`
- `tz-offset: 10800`
- `device: ugg` (codename)
- `hardware: qcom`
- Transport name: `FIREBASE_APPQUALITY_SESSION`

### 3.3 Extracted Tokens, API Keys & Device IDs

| Token/Key | Value | Source |
|-----------|-------|--------|
| **Pushwoosh App ID** | `4F0CA-D5EC6` | `com.pushwoosh.registration.xml` |
| **Pushwoosh HWID** | `2ed17728-7d78-4ca1-a2f3-7fa4eab342d1` | `com.pushwoosh.registration.xml` |
| **Pushwoosh User ID** | `2ed17728-7d78-4ca1-a2f3-7fa4eab342d1` | `com.pushwoosh.registration.xml` |
| **Pushwoosh Device ID** | `2ed17728-7d78-4ca1-a2f3-7fa4eab342d1` | `com.pushwoosh.registration.xml` |
| **Pushwoosh Base URL** | `https://api.wavesend.ru/json/1.3/` | `com.pushwoosh.registration.xml` |
| **Pushwoosh API Version** | `6.7.48` | SSL raw capture |
| **Firebase Project Number** | `416039598211` | `com.pushwoosh.registration.xml` |
| **Firebase GMP App ID** | `1:416039598211:android:8db4f630d55519fb` | `com.google.android.gms.measurement.prefs.xml` |
| **Firebase Installation ID** | `djGw237NS5mODUcloA0YAg` | `com.google.firebase.crashlytics.xml` |
| **Crashlytics Installation UUID** | `a33271928e7448f3af03364e57f47716` | `com.google.firebase.crashlytics.xml` |
| **Crashlytics Instance Identifier** | `ee549ebe1d54299e6c1cc1a7859355722a5a32d4` | `com.google.firebase.crashlytics.xml` |
| **GA App Instance ID** | `44b91b740156b0e686b70665e3c894c9` | `com.google.android.gms.measurement.prefs.xml` |
| **Sentry DSN** | `https://fee4d03d5f8cee7487e3616bdf00416a@sentry.inno.co/13` | SHA-1 hash input |
| **Sentry Key** | `fee4d03d5f8cee7487e3616bdf00416a` | SSL raw `X-Sentry-Auth` header |
| **Sentry Project ID** | `13` | Sentry DSN path |
| **Sentry Session ID** | `4d523e49340146f1aabc5fe691145626` | Sentry envelope |
| **Sentry Device ID** | `ef772484c524490cb80e2ca9b36cb30d` | Sentry envelope |
| **Sentry Trace ID** | `5aa077bce7934e5480353d832f3664f1` | trace.json file write |
| **Branch.io Live Key** | `key_live_lb1cVtiq4sOUdOI3WMgyqfhoEEedz7Nc` | `branch_referral_shared_pref.xml` |
| **Branch.io Hardware ID** | `1f184791a6e1fbab` | SSL raw install request |
| **AppsFlyer SDK Key** | `JxKoewgyFZTH9mK27cRrc4` | HMAC init + crypto_op plaintext |
| **AppsFlyer Installation** | `1769191997028-7766830933066783428` | `appsflyer-data.xml` |
| **AppsFlyer Launch Count** | `70` | `appsflyer-data.xml` |
| **AppsFlyer OneLink Domain** | `yaki.onelink.me` | `appsflyer-data.xml` savedProperties |
| **AppsFlyer OneLink Slug** | `At8U` | `appsflyer-data.xml` savedProperties |
| **Git Revision** (build) | `12b855ea8ac41848812d7a0dc567854c2efb0bdf` | Crashlytics version-control-info (base64) |

### 3.4 EncryptedSharedPreferences (AndroidX Security Crypto)

Two encrypted preference stores detected:

**Store 1:** `com.voltmobi.yakitoriya.data.preferences_crypto.xml`
- Key keyset type: `google.crypto.tink.AesSivKey`
- Value keyset type: `google.crypto.tink.AesGcmKey`
- Contains 10+ encrypted key-value pairs (keys and values both encrypted)
- Likely stores: authentication tokens, user session data, saved addresses

**Store 2:** `com.voltmobi.yakitoriya.data.preferences_crypto.independent.xml`
- Same Tink encryption scheme (AesSivKey for keys, AesGcmKey for values)
- Separate keyset from Store 1
- Likely stores: independent session or device-specific data

### 3.5 File System Writes

**Crashlytics session data:**
- `/files/.crashlytics.v3/com.voltmobi.yakitoriya/open-sessions/{session}/report` (813 bytes)
- `/files/.crashlytics.v3/.../internal-keys` (207 bytes, includes git revision)

**Sentry cache:**
- `/cache/sentry/{dsn_hash}/.options-cache/release.json` -- `"com.voltmobi.yakitoriya@2.18.13+5740"`
- `/cache/sentry/{dsn_hash}/.options-cache/sdk-version.json` -- Sentry SDK version info
- `/cache/sentry/{dsn_hash}/.options-cache/environment.json` -- `"production"`
- `/cache/sentry/{dsn_hash}/.scope-cache/contexts.json` -- Current activity name
- `/cache/sentry/{dsn_hash}/.scope-cache/transaction.json` -- `"MainActivity"`
- `/cache/sentry/{dsn_hash}/.scope-cache/trace.json` -- Trace/span IDs
- `/cache/sentry/{dsn_hash}/{envelope_id}.envelope` -- Session envelopes

**Firebase Sessions datastore:**
- `/files/datastore/firebaseSessions/sessionDataStore.data.tmp`

**AppsFlyer request cache:**
- `/files/AFRequestCache/OtherCache/{timestamp}` -- Contains full encrypted request data

---

## 4. Reconnaissance Profile

### 4.1 Device Information Collected

| Field | Value | Access Method |
|-------|-------|---------------|
| SDK_INT | 36 (Android 16) | `android.os.Build$VERSION` via reflection |
| Model | Redmi Note 5A | Branch.io request body |
| Brand | Xiaomi | Branch.io request body |
| Screen DPI | 260 | Branch.io request body |
| Screen Resolution | 720x1280 | Branch.io request body |
| CPU Type | aarch64 (partial) | Branch.io request body |
| UI Mode | UI_MODE_TYPE_NORMAL | Branch.io request body |
| Build Fingerprint | `Xiaomi/land/land:6.0.1/MMB29M/V10.2.2.0.MALMIXM:user/release-keys` | Firebase transport metadata |
| Device Codename | `ugg` | Firebase transport metadata |
| Hardware | `qcom` | Firebase transport metadata |
| OS Build | `BP2A.250805.005` | User-Agent + transport metadata |
| WiFi Status | true | Branch.io request |

### 4.2 Network & Telecom Information

| Method | Value | Frequency |
|--------|-------|-----------|
| `getActiveNetwork` | 122 (network ID) | 8 calls |
| `getSimOperator` | `25001` (MCC/MNC: MTS Russia) | 2 calls |
| `getNetworkOperatorName` | `MTS RUS` | 3 calls |
| `getSimOperatorName` | `MTS RUS` | 1 call |

**Analysis:** The app actively queries the telecom state. MCC 250 = Russia, MNC 01 = MTS (Mobile TeleSystems). This data is sent to:
- AppsFlyer (`operator: "MTS RUS"`, `mcc_mnc: 25001`)
- Firebase Data Transport (`mcc_mnc: 25001`, `mobile-subtype: 100`)
- Branch.io (wifi status)

### 4.3 VPN/Root Detection

No explicit VPN or root detection hooks were observed in this scan. However:
- The app reads `SDK_INT` via **reflection** (not standard API), which could be part of an environment fingerprinting routine
- No `SafetyNet`, `Play Integrity`, or `RootBeer` calls detected
- No VPN interface enumeration observed

### 4.4 Location Data

The app has access to precise geolocation (from the PATCH request):
- **Latitude:** 55.730228
- **Longitude:** 37.632368
- This is **central Moscow** (near Zamoskvorechye district)

---

## 5. Cryptographic Operations

### 5.1 Hash Algorithm Usage

| Algorithm | Count | Primary Purpose |
|-----------|-------|-----------------|
| MD5 | 88 | Certificate fingerprinting, WebView metric names, Yandex Metrica protobuf hashing |
| SHA-1 | 34 | Certificate verification, Sentry DSN hashing, Crashlytics instance ID, APK signing cert hash |
| SHA-256 | 31 | Certificate pinning verification (SHA-256 fingerprints computed for all cert chains) |
| SHA256 | 1 | (alternate naming, same algo) |

### 5.2 HMAC Operations

**Algorithm:** HmacSHA256
**Key (hex):** `4a784b6f65776779465a5448396d4b32376352726334`
**Key (ASCII):** `JxKoewgyFZTH9mK27cRrc4`
**Context:** This is the **AppsFlyer SDK key**, used to HMAC-sign the attribution data before encryption.

Two HMAC init operations were observed with the same key, suggesting the key is used for:
1. Request body signing/integrity
2. Possibly device fingerprint generation

### 5.3 AES Encryption (AppsFlyer)

**Algorithm:** `AES/CBC/PKCS5Padding`
**Key (hex):** `f00ac59eedbf80cd8eaf853cae119b42` (128-bit AES)
**IV (hex):** `8a252c9d0b5b02b89a77088f56f73072`
**Operation:** Encrypt
**Input length:** 1790 bytes
**Output length:** 1792 bytes

**Plaintext content (partial):**
```json
{
  "platform_extension_v2": {
    "platform": "android_native",
    "version": "6.17.5"
  },
  "country": "RU",
  "af_timestamp": "1774528041677",
  "appsflyerKey": "JxKoewgyFZTH9mK27cRrc4",
  "isFirstCall": "false",
  "registeredUninstall": false,
  "targetSDKver": 36,
  "operator": "MTS RUS",
  "app_ve..."
}
```

This encrypted blob is sent as `Content-Type: application/octet-stream` to the AppsFlyer endpoint.

### 5.4 Tink Encryption (Local Storage)

The app uses **Google Tink** via AndroidX EncryptedSharedPreferences:
- **Key encryption:** AesSivKey (deterministic AEAD -- allows key lookup)
- **Value encryption:** AesGcmKey (authenticated encryption)
- Keyset IDs visible in the hex blobs
- Two separate keyset pairs for two encrypted preference stores

### 5.5 Certificate Verification Pattern

The app computes **MD5, SHA-1, and SHA-256** hashes of every certificate in every TLS chain it encounters. This is characteristic of:
- OkHttp's `CertificatePinner`
- Android system certificate verification
- Possibly custom certificate pinning logic

Certificate subjects observed being hashed:
- `sentry.inno.co`
- `*.wavesend.ru`
- `*.yakitoriya.ru`
- `*.branch.io`
- `conversions.appsflyersdk.com`
- Let's Encrypt R13
- ISRG Root X1
- GlobalSign GCC R6 AlphaSSL CA 2025
- GlobalSign Root CA - R6
- DigiCert Global G2 TLS RSA SHA256 2020 CA1
- DigiCert Global Root G2
- Amazon RSA 2048 M01
- Amazon Root CA 1

### 5.6 APK Signing Certificate

```
Subject: C=RU, O=n/a, OU=n/a, CN=Yakitoriya
Valid: 2012-07-03 to 2053-07-28
MD5: d1df3033921178cd91be820bba0a0aa2
SHA-1: 63bd90a5a9f1213ca8cec37f5c2e8b98798f5a35 (second computation)
```

Self-signed certificate, 850 bytes. Created in 2012, valid for 41 years. Standard Android debug/release keystore pattern.

---

## 6. Analytics & Tracking SDKs

### 6.1 SDK Inventory

| SDK | Version | Purpose | Data Collected |
|-----|---------|---------|----------------|
| **Firebase Crashlytics** | 20.0.3 | Crash reporting | Device info, app version, installation UUID, git revision |
| **Firebase Analytics (GA4)** | N/A | App analytics | Events (_vs, _e), app instance ID, consent status, session data |
| **Firebase Cloud Messaging** | N/A | Push notifications | FCM token, proxy notification state |
| **Firebase Sessions** | N/A | Session tracking | Session ID, process data, background time |
| **Firebase Data Transport** | N/A | Event transport layer | All Firebase event metadata |
| **Sentry** | 8.28.0 | Error tracking + performance | Session data, traces, spans, device context, release info |
| **Pushwoosh** | 6.7.48 | Push notifications + in-app messaging | HWID, device type, language, timezone, screen names, events, app open |
| **AppsFlyer** | 6.17.5 | Attribution analytics | Device fingerprint, operator, country, install data, HMAC-signed + AES-encrypted |
| **Branch.io** | N/A | Deep linking + attribution | Full device fingerprint (hardware ID, brand, model, screen, CPU, WiFi, OS) |
| **Yandex Metrica (AppMetrica)** | N/A | Russian analytics | Device info, locale, install source, session data |
| **TUNE/HasOffers** | N/A (legacy) | Attribution (deprecated) | `mat_id` key exists but null -- remnant SDK |

### 6.2 SDK Details

**Pushwoosh (api.wavesend.ru)**
- Uses custom Russian backend (`wavesend.ru`) instead of standard `pushwoosh.com`
- Collects: HWID, device type (3=Android), user ID, language, timezone, app package
- Tracks events: inline in-app views, screen names, app opens, abandoned carts
- In-app messaging: fetches in-app messages via `getInApps`
- Rich media configuration: fullscreen, animations, gestures
- GDPR mode enabled (`pw_gdpr_enable: true`)
- Server communication allowed (`pw_is_server_communication_allowed: true`)

**AppsFlyer**
- Attribution data is HMAC-signed then AES-CBC encrypted before transmission
- Sends to CloudFront-fronted `launches.appsflyersdk.com`
- OneLink configured: `yaki.onelink.me` with slug `At8U`
- Launch count: 70 (app has been opened many times)
- First install: 2026-01-23

**Yandex Metrica**
- Detected via extensive class loading: `com.yandex.metrica.*` (hundreds of classes)
- UUID generation at `com.yandex.metrica.impl.ob.A3` class initialization
- Network task management classes present
- Request body encryption support (`RequestBodyEncryptionMode`, `RequestBodyEncrypter`)
- Custom HTTP connection management

**Sentry**
- DSN project: 13 at sentry.inno.co (self-hosted)
- Packages: sentry, sentry-android-core, sentry-android-replay, sentry-okhttp
- Session replay capability present
- OkHttp integration for network breadcrumbs
- Production environment
- Tracks UI load performance (traces, spans)

**Branch.io**
- Deep link attribution with comprehensive device fingerprinting
- Currently returning 400 errors -- possibly misconfigured
- Sends hardware_id, brand, model, screen specs, CPU type

### 6.3 Discovery Class Map

The class discovery module found loaded classes in these categories:
- **HTTP:** 100+ OkHttp classes (system `com.android.okhttp` + app `okhttp3`), Sentry OkHttp integration
- **WebSocket:** Empty (none loaded)
- **gRPC/Protobuf:** Extensive protobuf classes from Android framework, Google Tink, AndroidX DataStore
- **Crypto:** Conscrypt SSL, Cipher, MacAddress utils, StateMachine
- **Analytics:** ~400+ classes from AppsFlyer, Yandex Metrica, Firebase Crashlytics, Firebase Analytics, Firebase Sessions, Firebase Messaging

---

## 7. API Recreation Assessment

### 7.1 Feasibility: HIGH (for core ordering API)

The core Yakitoriya ordering API on `beacon2.yakitoriya.ru` appears **feasible to recreate** based on the following observations:

### 7.2 Authentication Mechanisms

**Pushwoosh API (api.wavesend.ru):**
- `Authorization: Token null` -- **NO authentication**
- Only requires `application` ID and `hwid`
- Trivially replayable

**Core Backend (beacon2.yakitoriya.ru):**
- Uses HTTP/2
- Authentication method **not fully visible** in this scan (encrypted preferences likely contain auth tokens)
- The encrypted preference store (`preferences_crypto.xml`) likely contains the user session/auth token
- Would need to reverse the EncryptedSharedPreferences or observe login flow

**AppsFlyer:**
- Uses AES-CBC encryption with known key/IV
- HMAC-SHA256 signing with known key (`JxKoewgyFZTH9mK27cRrc4`)
- Fully reversible but not needed for API recreation

### 7.3 Headers & Fingerprints to Replicate

For `beacon2.yakitoriya.ru`:
```
User-Agent: Dalvik/2.1.0 (Linux; U; Android 16; Redmi Note 5A Build/BP2A.250805.005)
Accept-Encoding: gzip
```
HTTP/2 must be supported.

For `api.wavesend.ru`:
```
Content-Type: application/json; charset=utf-8
Authorization: Token null
User-Agent: Dalvik/2.1.0 (Linux; U; Android 16; Redmi Note 5A Build/BP2A.250805.005)
```

### 7.4 Key Challenges

1. **HTTP/2 + QRATOR DDoS protection:** The beacon API is behind QRATOR and uses HTTP/2. Must use an HTTP/2 client and may need to handle DDoS challenges.

2. **EncryptedSharedPreferences:** The auth token for the core API is likely stored in the Tink-encrypted preference store. Would need either:
   - A login flow capture to extract the token
   - Reverse engineering of the Tink key derivation

3. **Certificate Pinning:** The app computes SHA-256 fingerprints for all certificate chains, suggesting certificate pinning may be in place. A thin client would need to use legitimate certificates (not self-signed proxies).

4. **Session Management:** The encrypted preferences contain multiple encrypted key-value pairs that likely include session tokens, refresh tokens, and possibly JWT. The login/registration flow was not captured in this 30-second scan.

5. **Missing API Surface:** Only one PATCH request to the core API was captured. A full menu/catalog, search, cart, and checkout flow would need additional scanning during active use.

6. **gRPC Backend:** The `Grpc-Metadata-Content-Type: application/grpc` header on Pushwoosh responses suggests gRPC. If the core API also uses gRPC (possible given protobuf classes are loaded), a `.proto` definition would be needed.

### 7.5 Recommended Next Steps

1. **Extended scan during login flow** to capture authentication token exchange
2. **Extended scan during full ordering flow** to map all API endpoints on `beacon2.yakitoriya.ru`
3. **Decrypt EncryptedSharedPreferences** by hooking Tink `Aead.decrypt()` and `DeterministicAead.decryptDeterministically()` to reveal plaintext keys and values
4. **Monitor HTTP/2 frames** more granularly to capture full request/response bodies on the beacon API
5. **Check for gRPC** on the core API -- if so, extract proto definitions from the APK

### 7.6 What We Already Have for a Thin Client

- Full Pushwoosh API structure (trivially replayable, no auth)
- Pushwoosh application ID, HWID, device type mappings
- Sentry DSN (could send fake errors)
- AppsFlyer SDK key and encryption keys (could forge attribution)
- Branch.io live key
- Core API base domain and port
- Delivery address structure and restaurant ID format
- User-Agent and header format
- Certificate chain for pinning validation

---

## Appendix A: Event Count Summary

| Module | Type | Count |
|--------|------|-------|
| vault | pref_read | 299 |
| netmodel | hash | 154 |
| vault | pref_write | 41 |
| vault | file_write | 34 |
| traffic | ssl_raw | 31 |
| vault | sqlite_write | 18 |
| netmodel | nonce | 12 |
| traffic | tcp_connect | 9 |
| recon | network_info | 8 |
| recon | telecom | 6 |
| traffic | hook_status | 3 |
| netmodel | hmac_init | 2 |
| recon | device_info | 1 |
| discovery | class_map | 1 |
| vault | initial_dump | 1 |
| netmodel | crypto_init | 1 |
| netmodel | crypto_op | 1 |
| vault | sqlite_query | 1 |
| **Total** | | **626** |

## Appendix B: Nonce/UUID Generation

12 UUIDs generated during the scan, used by:
- Firebase Crashlytics (CLSUUID): session identifiers
- Yandex Metrica: instance ID generation
- Pushwoosh/AndroidX Work: notification work requests
- Firebase Sessions: session IDs
- Sentry: session/envelope IDs

## Appendix C: Timeline

| Time (UTC) | Event |
|------------|-------|
| 12:27:06.856 | Hooks loaded (traffic, vault, recon, netmodel) |
| 12:27:07.557 | First pref reads begin (Pushwoosh migration) |
| 12:27:07.712 | First hash operation (SHA-1, Crashlytics instance) |
| 12:27:08.072 | Crashlytics session report written |
| 12:27:08.122 | First TCP connection (firebase-settings.crashlytics.com) |
| 12:27:08.756 | Sentry DSN hashed |
| 12:27:08.811 | First recon event (getActiveNetwork) |
| 12:27:09.205 | Sentry TCP connection opened |
| 12:27:09.792 | First Sentry envelope sent |
| 12:27:10.122 | Branch.io prefs read |
| 12:27:10.291 | First telecom query (getSimOperator: 25001) |
| 12:27:10.387 | AppsFlyer initialization |
| 12:27:10.570 | HMAC key initialized (AppsFlyer signing) |
| 12:27:19.208 | WebView prefs loaded |
| 12:27:19.491 | Class map discovery event |
| 12:27:20+ | Pushwoosh API calls begin |
| 12:27:24+ | Beacon API PATCH request (delivery/order) |
| 12:27:25+ | Branch.io install request |
| 12:27:26+ | AppsFlyer launch event (encrypted) |
| 12:27:28+ | Final Pushwoosh events |
