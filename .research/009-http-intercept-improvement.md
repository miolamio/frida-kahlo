# 009: OkHttp Interceptor Failure Analysis & HTTP Interception Improvement Plan

Date: 2026-03-27
Session analyzed: `com.voltmobi.yakitoriya_20260326_122701_5d3395`

---

## 1. Root Cause Analysis

### 1.1 The Symptom

The OkHttp Interceptor hook (Level 1 in `traffic.js`) did not fire on yakitoriya. The session data shows:

- **hook_status events:** `traffic_module` (loaded), `conscrypt_ssl` (active), `socket_connect` (active)
- **MISSING:** No `okhttp_interceptor` hook_status event
- **MISSING:** Zero `http_request` or `http_response` events
- **31 ssl_raw events** captured as fallback (via Conscrypt SSLOutputStream/SSLInputStream)
- **9 tcp_connect events** captured

The OkHttp interceptor hook failed silently because of the outer `try/catch` on line 133-136 of `traffic.js`.

### 1.2 The Root Cause: Wrong OkHttp Package

The current hook targets:

```javascript
var OkHttpClientBuilder = Java.use('okhttp3.OkHttpClient$Builder');
var Interceptor = Java.use('okhttp3.Interceptor');
```

But the discovery class_map reveals that yakitoriya has **NO `okhttp3.OkHttpClient$Builder` class loaded**. The only okhttp3 classes present are:

```
okhttp3.internal.publicsuffix.PublicSuffixDatabase
okhttp3.internal.platform.PlatformInitializer
```

These are stub/utility classes, not the full OkHttp3 stack. The actual HTTP client is **Android's built-in OkHttp** under the `com.android.okhttp` package:

```
com.android.okhttp.OkHttpClient         (the client)
com.android.okhttp.OkHttpClient$1       (anonymous inner class)
com.android.okhttp.internal.http.HttpEngine       (the actual HTTP engine)
com.android.okhttp.internal.http.HttpEngine$1
com.android.okhttp.internal.http.HttpEngine$2
com.android.okhttp.internal.http.HttpEngine$NetworkInterceptorChain
com.android.okhttp.Interceptor$Chain
com.android.okhttp.internal.http.StreamAllocation
com.android.okhttp.internal.http.Http1xStream
com.android.okhttp.internal.http.Http2xStream
com.android.okhttp.Request
com.android.okhttp.Request$Builder
com.android.okhttp.Response
com.android.okhttp.Response$Builder
com.android.okhttp.Headers
com.android.okhttp.Headers$Builder
com.android.okhttp.HttpUrl
com.android.okhttp.HttpUrl$Builder
com.android.okhttp.RequestBody
com.android.okhttp.ResponseBody
com.android.okhttp.internal.http.RealResponseBody
com.android.okhttp.internal.huc.HttpURLConnectionImpl
com.android.okhttp.internal.huc.HttpsURLConnectionImpl
com.android.okhttp.internal.huc.DelegatingHttpsURLConnection
com.android.okhttp.internalandroidapi.HttpURLConnectionFactory
```

### 1.3 Why This Matters

The `com.android.okhttp` package is Android's **internal OkHttp fork** (OkHttp v2.x era). It is the underlying implementation for `java.net.HttpURLConnection` on Android. This means yakitoriya uses `HttpURLConnection` (or the Android platform HTTP stack) rather than bundling the `okhttp3` library directly.

Key architectural differences from `okhttp3`:

| Aspect | `okhttp3` (library) | `com.android.okhttp` (system) |
|--------|---------------------|-------------------------------|
| Builder class | `okhttp3.OkHttpClient$Builder` | `com.android.okhttp.OkHttpClient` (no Builder pattern) |
| Interceptor | `okhttp3.Interceptor` | `com.android.okhttp.Interceptor` (different package) |
| Interceptor chain | `addNetworkInterceptor()` on Builder | `networkInterceptors()` returns List on OkHttpClient |
| HTTP engine | `RealCall` / `ExchangeFinder` | `HttpEngine` / `StreamAllocation` |
| Request/Response | `okhttp3.Request` / `okhttp3.Response` | `com.android.okhttp.Request` / `com.android.okhttp.Response` |

### 1.4 Additional Evidence: `method_targets` is Empty

The discovery script's `method_targets` scan found zero classes with any of these methods:

```json
{
  "addNetworkInterceptor": [],
  "newWebSocket": [],
  "newCall": [],
  "enqueue": [],
  "execute": []
}
```

This confirms that among the discovered HTTP classes (which are all `com.android.okhttp.*`), the method enumeration did not find `addNetworkInterceptor` -- because in the system OkHttp v2.x API, the method is `networkInterceptors()` returning a `List` that can be modified, or `interceptors()` directly on the client.

### 1.5 The Sentry OkHttp Integration Red Herring

The `io.sentry.okhttp.a/c/d/e/g` classes are present but these are **obfuscated** Sentry OkHttp integration classes (ProGuard/R8 renamed). Sentry's `sentry-okhttp` package is an OkHttp interceptor for breadcrumb tracking. However, these classes alone don't provide a full OkHttp3 client -- they piggyback on whatever HTTP client the app uses. The `okhttp3.internal.platform.PlatformInitializer` is likely loaded by Sentry's dependency resolution but the core `okhttp3.OkHttpClient` class is NOT loaded.

### 1.6 HTTP/2 on beacon2.yakitoriya.ru

The core API at `beacon2.yakitoriya.ru` uses HTTP/2. The ssl_raw captures show `PRI * HTTP/2.0` upgrade frames. The `com.android.okhttp.internal.http.Http2xStream` class is loaded, confirming HTTP/2 goes through the system OkHttp stack.

---

## 2. What Currently Works (and Its Limitations)

### 2.1 Conscrypt SSL Capture (Level 3)

The fallback Conscrypt hooks at `com.android.org.conscrypt.ConscryptEngineSocket$SSLOutputStream` and `SSLInputStream` successfully captured 31 ssl_raw events. The traffic analyzer (`analyze/traffic.py`) already parses these into endpoints via regex on the raw HTTP/1.1 previews.

**What it captures well:**
- HTTP/1.1 requests with method, URL, headers, and body in cleartext
- HTTP/1.1 responses with status code and headers
- Works for Sentry, Pushwoosh (api.wavesend.ru), Branch.io, AppsFlyer

**Limitations:**
- **HTTP/2 frames are binary**, not human-readable. The beacon2.yakitoriya.ru traffic shows as garbled binary in previews
- Body is truncated to 512 bytes in the preview
- No request-response correlation (each ssl_raw event is independent)
- Gzipped bodies appear as binary garbage after the headers
- The `..` separator heuristic for line splitting is fragile (dots in URLs or binary data cause false splits)
- No structured parsing of headers into proper key-value pairs at capture time

### 2.2 Socket.connect (Level 5)

Successfully captured 9 TCP connection events with resolved hostnames and IPs. This works perfectly and needs no changes.

### 2.3 Native SSL (Level 4)

No `ssl_native` events in the session. The `Module.findExportByName("libssl.so", "SSL_write")` may not have found the symbol, or the Conscrypt Java hooks fired first (same data path). Not a problem -- Java-level hooks are preferable.

---

## 3. Fix Plan: Multi-Strategy HTTP Interception

### Strategy A: Hook `com.android.okhttp` (System OkHttp v2.x)

**Priority: HIGH -- direct fix for yakitoriya and any app using HttpURLConnection**

The system OkHttp has a different API than okhttp3. The key interception points:

#### A1. Hook `HttpEngine.sendRequest()` and `HttpEngine.readResponse()`

```
Target class: com.android.okhttp.internal.http.HttpEngine
```

`HttpEngine` is the core class that orchestrates request sending and response reading. It has:

- `sendRequest()` -- prepares and sends the HTTP request
- `readResponse()` -- reads and parses the HTTP response
- Field `userRequest` (type `com.android.okhttp.Request`) -- the original request
- Field `userResponse` (type `com.android.okhttp.Response`) -- the parsed response
- Field `networkRequest` (type `com.android.okhttp.Request`) -- the request as sent on wire (with all interceptor modifications)
- Field `networkResponse` (type `com.android.okhttp.Response`) -- the raw network response

**Hook approach:**
1. Hook `HttpEngine.readResponse()` -- after it returns, both `networkRequest` and `networkResponse` are populated
2. Read the fields via reflection: `this.networkRequest.value` for the final request, `this.networkResponse.value` for the response
3. Extract method, URL, headers, body from the Request/Response objects

**Why `readResponse()` and not `sendRequest()`:** After `readResponse()`, we have BOTH the request and response. The `networkRequest` contains all modifications (redirects, auth headers added by interceptors), and `networkResponse` contains the server's reply.

**Extracting headers from `com.android.okhttp.Request`:**
- `request.method()` -- returns String
- `request.urlString()` -- returns String (note: `urlString()` not `url().toString()` in v2)
- `request.headers()` -- returns `com.android.okhttp.Headers`
- `request.body()` -- returns `com.android.okhttp.RequestBody`

**Extracting headers from `com.android.okhttp.Response`:**
- `response.code()` -- returns int
- `response.headers()` -- returns `com.android.okhttp.Headers`
- `response.body()` -- returns `com.android.okhttp.ResponseBody`

**Reading body from `com.android.okhttp.ResponseBody`:**
- `body.source()` -- returns `com.android.okhttp.okio.BufferedSource`
- `source.buffer()` -- returns `com.android.okhttp.okio.Buffer`
- Note: uses `com.android.okhttp.okio.Buffer`, NOT `okio.Buffer`

#### A2. Hook `HttpURLConnectionImpl.getInputStream()` / `getOutputStream()`

```
Target class: com.android.okhttp.internal.huc.HttpURLConnectionImpl
```

If apps use the standard `java.net.HttpURLConnection` API:
- `getInputStream()` triggers the actual request
- After calling `getInputStream()`, the response is available
- `getResponseCode()`, `getHeaderFields()` etc. can be read

**Less preferred** than A1 because: (a) higher-level, may miss some details; (b) body reading is more complex (stream-based); (c) some frameworks bypass HttpURLConnection entirely.

#### A3. Hook `com.android.okhttp.OkHttpClient` interceptor list

```
Target class: com.android.okhttp.OkHttpClient
```

In the system OkHttp v2, the client has:
- `networkInterceptors()` -- returns `List<Interceptor>`
- `interceptors()` -- returns `List<Interceptor>`

These return **mutable lists** in v2.x. We could:
1. Hook the constructor or a frequently-called method
2. Add our interceptor to the `networkInterceptors()` list

**Complication:** We need to use `com.android.okhttp.Interceptor` (not `okhttp3.Interceptor`). The `Java.registerClass()` call must `implements: [com.android.okhttp.Interceptor]` and the `intercept(chain)` method receives a `com.android.okhttp.Interceptor$Chain`.

**Chain API differences in v2:**
- `chain.request()` returns `com.android.okhttp.Request`
- `chain.proceed(request)` returns `com.android.okhttp.Response`
- Request: `method()`, `urlString()`, `headers()`, `body()`
- Response: `code()`, `headers()`, `body()`
- Buffer: `com.android.okhttp.okio.Buffer` (not `okio.Buffer`)
- Charset: same Java standard `java.nio.charset.Charset`

### Strategy B: Hook `okhttp3` with Obfuscation Awareness

**Priority: HIGH -- for apps that DO bundle okhttp3**

The current hook targets `okhttp3.OkHttpClient$Builder` which works when the class is not obfuscated. But many apps (especially those using R8/ProGuard) rename OkHttp classes.

#### B1. Dynamic class discovery from class_map

Before attempting to hook `okhttp3.OkHttpClient$Builder`, check the discovery class_map for:

1. Exact match: `okhttp3.OkHttpClient$Builder` -- use current approach
2. Obfuscated: Look for classes that have `addNetworkInterceptor` or `addInterceptor` methods
3. Retrofit marker: If `retrofit2.Retrofit` or `retrofit2.Retrofit$Builder` is present, OkHttp3 MUST be present (Retrofit depends on it). Find the client class by tracing Retrofit's `callFactory` field.

#### B2. Enumerate OkHttp3 classes by method signature

Use the discovery script's `method_targets` data. If `addNetworkInterceptor` is found in any class, that class is an OkHttpClient.Builder (possibly obfuscated). Hook its `build()` method.

#### B3. Hook `RealCall.execute()` and `RealCall.enqueue()`

```
Possible classes:
  okhttp3.RealCall
  okhttp3.internal.connection.RealCall  (newer versions)
  <obfuscated>.execute()  (found via method_targets)
```

If we can find the `RealCall` class (or its obfuscated equivalent), hooking `execute()` and `enqueue()` gives us access to the request, and we can use `getResponseWithInterceptorChain()` timing to capture responses.

### Strategy C: Enhanced SSL Raw Parser (Robust Fallback)

**Priority: MEDIUM -- improves existing fallback that already works**

The ssl_raw capture already works but produces raw text previews. Improve it by:

#### C1. HTTP/1.1 Parser for SSL Raw Data

Move HTTP parsing from `analyze/traffic.py` (post-processing) into the Frida hook itself. At the Conscrypt `write()` hook:

1. Detect HTTP request: first bytes match `GET `, `POST `, `PUT `, `PATCH `, `DELETE `, `HEAD `, `OPTIONS `
2. Parse the request line: method, path, HTTP version
3. Parse headers: everything until `\r\n\r\n`
4. Capture body: everything after `\r\n\r\n` up to Content-Length or MAX_BODY

At the Conscrypt `read()` hook:

1. Detect HTTP response: first bytes match `HTTP/`
2. Parse status line: version, status code, reason
3. Parse headers until `\r\n\r\n`
4. Capture body

**Emit structured events** (`http_request` and `http_response`) from the SSL layer, instead of raw `ssl_raw` events. This gives the analyzer clean structured data regardless of whether the OkHttp hook worked.

#### C2. HTTP/2 Frame Parser for SSL Raw Data

The beacon2.yakitoriya.ru API uses HTTP/2. HTTP/2 frames have a well-defined binary structure:

```
+-----------------------------------------------+
|                 Length (24 bits)               |
+---------------+---------------+---------------+
|   Type (8)    |   Flags (8)   |
+-+-------------+---------------+------+--------+
|R|                 Stream ID (31 bits)          |
+=+=============================================+
|                   Frame Payload               |
+-----------------------------------------------+
```

Key frame types:
- `0x01` HEADERS -- contains HPACK-encoded headers
- `0x00` DATA -- contains request/response body
- `0x05` PUSH_PROMISE
- `0x03` RST_STREAM

**Complexity:** HPACK decompression is non-trivial to implement in Frida JS. However, for basic visibility we could:
1. Detect HTTP/2 connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`)
2. Parse frame boundaries (length + type + flags + stream_id)
3. For DATA frames (type 0x00), capture the payload (which is the raw body, often uncompressed JSON)
4. For HEADERS frames (type 0x01), do a best-effort HPACK decode or at least capture raw bytes

**Alternative for HTTP/2:** Hook at a higher level (Strategy A with `HttpEngine` or `Http2xStream`) where headers are already decoded. The system OkHttp's `Http2xStream` class handles HTTP/2 framing internally.

#### C3. Request-Response Correlation

Current ssl_raw events have no correlation -- we don't know which response belongs to which request. Add correlation by:

1. Track the SSL socket instance (via `this` in the Conscrypt hook)
2. Assign a connection ID per socket
3. On the same connection ID, pair outgoing request with next incoming response
4. Emit paired events or at least add `connection_id` to each event

### Strategy D: Hook `java.net.HttpURLConnection` Directly

**Priority: MEDIUM -- catches apps using the standard Java HTTP API**

```
Target class: java.net.HttpURLConnection
```

This is the highest-level Java HTTP API. Hook:

1. `HttpURLConnection.connect()` -- log the URL, method, request headers
2. `HttpURLConnection.getInputStream()` -- after return, read response code and headers
3. `HttpURLConnection.getResponseCode()` -- log the status code
4. `HttpURLConnection.getOutputStream()` -- intercept the body being written

**Complications:**
- Body capture is hard because it's written as a stream
- The actual implementation is `com.android.okhttp.internal.huc.HttpURLConnectionImpl` which Strategy A already covers
- Overlapping events with Strategy A if both are active

**Decision:** Use Strategy A (HttpEngine) as the primary hook, and Strategy D only as a diagnostic fallback to confirm that HttpURLConnection is indeed the entry point.

---

## 4. Discovery Script Improvements

### 4.1 Detect System OkHttp vs Library OkHttp

Add to discovery.js:

```
httpPatterns should also match:
  "com.android.okhttp"   (system OkHttp v2.x)
  "com.android.okhttp.internal.http.HttpEngine"
  "com.android.okhttp.internal.huc.HttpURLConnectionImpl"
```

Currently, `"com.android.okhttp"` classes are already matched by the pattern `"okhttp."` in `httpPatterns`. But they are NOT matched by `"okhttp3."`. The discovery script finds them, but the important thing is to **distinguish** between `com.android.okhttp` (system) and `okhttp3` (library).

### 4.2 Report HTTP Client Type

Add to the discovery result:

```json
{
  "http_client_type": "system_okhttp_v2",  // or "okhttp3", "okhttp3_obfuscated", "httpurlconnection", "volley", etc.
  "http_client_classes": {
    "client": "com.android.okhttp.OkHttpClient",
    "engine": "com.android.okhttp.internal.http.HttpEngine",
    "request": "com.android.okhttp.Request",
    "response": "com.android.okhttp.Response",
    "buffer": "com.android.okhttp.okio.Buffer"
  }
}
```

### 4.3 Expanded Method Enumeration

The current `method_targets` only searches the first 20 HTTP classes. Expand to search for:

```
"sendRequest"       -> HttpEngine (system okhttp)
"readResponse"      -> HttpEngine (system okhttp)
"networkInterceptors" -> OkHttpClient (system okhttp)
"getResponseCode"   -> HttpURLConnection
"openConnection"    -> URL
"newBuilder"        -> OkHttpClient (okhttp3)
```

---

## 5. Implementation Plan

### Phase 1: Fix for System OkHttp (Direct fix for yakitoriya)

**Files to modify:** `scripts/hooks/traffic.js`

1. After the existing `okhttp3.OkHttpClient$Builder` hook attempt (Level 1), add a new Level 1b:
   - Try `com.android.okhttp.internal.http.HttpEngine`
   - Hook `readResponse()` method
   - After `readResponse()` returns, read `this.networkRequest.value` and `this.networkResponse.value`
   - Extract method, URL, headers, body from both Request and Response
   - Emit `http_request` and `http_response` events with same structure as the okhttp3 interceptor
   - Send `hook_status` with `level: "system_okhttp_engine"`

2. Alternative approach for Level 1b (if field access is problematic):
   - Try `com.android.okhttp.OkHttpClient`
   - Get the `networkInterceptors()` list
   - Register a `com.android.okhttp.Interceptor` implementation
   - Add it to the list
   - The interceptor's `intercept(chain)` captures request and response

3. Also try `com.android.okhttp.internal.huc.HttpURLConnectionImpl`:
   - Hook `getInputStream()`
   - After return, read `this.getURL()`, `this.getRequestMethod()`, `this.getResponseCode()`, `this.getHeaderFields()`

### Phase 2: Enhanced SSL Raw Parser

**Files to modify:** `scripts/hooks/traffic.js`, `scripts/common.js`

1. Add `parseHttpRequest(buf, off, len)` function to `common.js`:
   - Returns structured `{method, path, version, headers: {}, body_preview, body_length}` or null
   - Handles `\r\n` line splitting on raw bytes
   - Extracts Content-Length for body boundary

2. Add `parseHttpResponse(buf, off, len)` function to `common.js`:
   - Returns structured `{version, status, reason, headers: {}, body_preview, body_length}` or null

3. Modify the Conscrypt write hook (Level 3):
   - First, attempt to parse as HTTP request
   - If successful, emit `http_request` event (structured) INSTEAD of `ssl_raw`
   - If not parseable as HTTP, emit `ssl_raw` as before

4. Modify the Conscrypt read hook (Level 3):
   - First, attempt to parse as HTTP response
   - If successful, emit `http_response` event (structured)
   - If not parseable, emit `ssl_raw` as before

5. Add connection tracking:
   - Maintain a Map of socket -> connection_id
   - Add `connection_id` to events for request-response pairing

### Phase 3: Discovery-Driven Hook Selection

**Files to modify:** `scripts/discovery.js`, `scripts/hooks/traffic.js`, `kahlo/instrument/loader.py`

1. Run discovery BEFORE hooks (currently it runs concurrently with a 3-second delay)
2. Discovery reports the detected HTTP client type
3. Hook loader selects appropriate hook strategy based on discovery result
4. This requires a two-phase instrumentation:
   - Phase A: Load discovery script, wait for class_map
   - Phase B: Based on class_map, compose and load the appropriate hook scripts

**Alternative (simpler):** Keep the current approach where traffic.js tries ALL strategies in sequence (okhttp3, system_okhttp, HttpURLConnection). The first one that works emits events. The cost is a few extra try/catch blocks, which is negligible.

### Phase 4: HTTP/2 Awareness

**Files to modify:** `scripts/hooks/traffic.js` or new `scripts/hooks/http2.js`

1. Hook `com.android.okhttp.internal.http.Http2xStream`:
   - `writeRequestHeaders()` -- captures request headers as they're written to the HTTP/2 stream
   - `readResponseHeaders()` -- captures response headers
   - `createRequestBody()` -- captures request body sink
   - This is MUCH better than parsing binary HTTP/2 frames from ssl_raw

2. If the app uses `okhttp3.internal.http2.Http2Stream`:
   - Similar hooks on the stream's header/body methods

3. Deprecate binary HTTP/2 frame parsing from ssl_raw -- it's too complex and fragile for JS

---

## 6. Priority Order

| # | Task | Impact | Effort | Priority |
|---|------|--------|--------|----------|
| 1 | System OkHttp HttpEngine hook (Phase 1, item 1) | Fixes yakitoriya + all HttpURLConnection apps | Medium | **P0** |
| 2 | Enhanced SSL raw parser (Phase 2) | Better structured data from existing fallback | Medium | **P1** |
| 3 | System OkHttp interceptor injection (Phase 1, item 2) | Alternative approach, captures full chain | Medium | **P1** |
| 4 | Http2xStream hook (Phase 4) | Fixes HTTP/2 visibility for beacon2 API | Low-Medium | **P1** |
| 5 | Discovery-driven hook selection (Phase 3) | Better automation, fewer blind hooks | Medium | **P2** |
| 6 | HttpURLConnection hook (Phase 1, item 3) | Diagnostic, partially redundant with HttpEngine | Low | **P2** |
| 7 | OkHttp3 obfuscation handling (Strategy B) | Future-proofing for obfuscated apps | High | **P2** |
| 8 | HTTP/2 binary frame parser (Strategy C2) | Marginal benefit if Http2xStream hook works | Very High | **P3** |

---

## 7. Specific Classes and Methods to Hook

### For yakitoriya (and similar HttpURLConnection-based apps)

```
com.android.okhttp.internal.http.HttpEngine
    .readResponse()
    Fields: userRequest, userResponse, networkRequest, networkResponse

com.android.okhttp.internal.http.Http2xStream
    .writeRequestHeaders(com.android.okhttp.Request)
    .readResponseHeaders()

com.android.okhttp.Request
    .method() -> String
    .urlString() -> String
    .headers() -> com.android.okhttp.Headers
    .body() -> com.android.okhttp.RequestBody

com.android.okhttp.Response
    .code() -> int
    .message() -> String
    .headers() -> com.android.okhttp.Headers
    .body() -> com.android.okhttp.ResponseBody

com.android.okhttp.Headers
    .size() -> int
    .name(int) -> String
    .value(int) -> String

com.android.okhttp.RequestBody
    .writeTo(com.android.okhttp.okio.BufferedSink)

com.android.okhttp.ResponseBody
    .source() -> com.android.okhttp.okio.BufferedSource

com.android.okhttp.okio.Buffer
    .$new()
    .readString(java.nio.charset.Charset) -> String

com.android.okhttp.okio.BufferedSource
    .request(long) -> boolean
    .buffer() -> com.android.okhttp.okio.Buffer
```

### For apps with standard okhttp3 (existing hook, already works)

```
okhttp3.OkHttpClient$Builder
    .build() -> OkHttpClient
    .addNetworkInterceptor(okhttp3.Interceptor) -> Builder

okhttp3.Interceptor
    .intercept(okhttp3.Interceptor$Chain) -> okhttp3.Response
```

---

## 8. Verification Plan

After implementing the fix:

1. Run `kahlo scan com.voltmobi.yakitoriya --duration 60`
2. Verify `hook_status` event with `level: "system_okhttp_engine"` or `"system_okhttp_interceptor"` appears
3. Verify `http_request` and `http_response` events appear for:
   - Sentry envelope POST (`sentry.inno.co/api/13/envelope/`)
   - Pushwoosh API calls (`api.wavesend.ru/json/1.3/*`)
   - Beacon core API (`beacon2.yakitoriya.ru` PATCH)
   - Branch.io install (`api2.branch.io/v1/install`)
   - AppsFlyer launch (`launches.appsflyersdk.com/api/v6.17/androidevent`)
4. Verify structured headers and body are captured (not just raw previews)
5. Verify `unique_endpoints` in session stats is no longer empty
6. Compare event quality: structured http_request/http_response vs raw ssl_raw

---

## 9. Key Insight: The Lab Script Also Would Have Failed

The working Lab experiment (`08-max-full-capture.js`) uses the same `okhttp3.OkHttpClient$Builder` approach. It would also have failed silently on yakitoriya for the same reason -- the app doesn't load `okhttp3.OkHttpClient$Builder`. The Lab experiment worked on a different app (MAX/OneMe) that bundles `okhttp3` directly.

This confirms the fix must be a multi-strategy approach: try `okhttp3` first, fall back to `com.android.okhttp`, and always have the SSL raw parser as the final safety net.
