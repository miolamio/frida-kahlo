// scripts/hooks/traffic.js
// Frida-Kahlo Traffic Hook — captures ALL network traffic at multiple levels
// Levels: 1a OkHttp3 Interceptor > 1b System OkHttp v2 > 1c HttpURLConnection
//         > 2 WebSocket > 3 Conscrypt SSL (with HTTP parser) > 4 Native SSL > 5 Socket.connect

(function() {
    "use strict";

    var MAX_BODY = 4096;
    var requestIndex = 0;
    var _connIdCounter = 0;
    var _socketConnMap = {};  // socket hashCode -> connection_id

    // Track which hook levels are active to suppress duplicate events
    var _activeLevel = "none"; // "okhttp3", "system_okhttp", "httpurlconnection", "ssl_parsed"
    var _conscryptHooked = false; // Set to true when Conscrypt SSL hooks are active

    function truncBody(s) {
        if (!s) return "";
        if (s.length <= MAX_BODY) return s;
        return s.substring(0, MAX_BODY);
    }

    function getConnId(socketObj) {
        // Track connection IDs by socket identity for request-response correlation
        try {
            var hash = socketObj.hashCode();
            if (!(hash in _socketConnMap)) {
                _socketConnMap[hash] = ++_connIdCounter;
            }
            return _socketConnMap[hash];
        } catch(e) {
            return 0;
        }
    }

    // === Level 1a: OkHttp3 Interceptor injection (bundled okhttp3) ===
    try {
        Java.perform(function() {
            try {
                var OkHttpClientBuilder = Java.use('okhttp3.OkHttpClient$Builder');
                var Interceptor3 = Java.use('okhttp3.Interceptor');
                var Buffer3 = Java.use('okio.Buffer');
                var Charset = Java.use('java.nio.charset.Charset');
                var UTF8 = Charset.forName("UTF-8");

                var KahloInterceptor3 = Java.registerClass({
                    name: 'com.kahlo.traffic.NetworkCapture3',
                    implements: [Interceptor3],
                    methods: {
                        intercept: function(chain) {
                            var idx = ++requestIndex;
                            try {
                                var request = chain.request();
                                var method = request.method();
                                var url = request.url().toString();

                                var reqHeaders = extractHeaders(request.headers());

                                var reqBody = "";
                                var reqBodyLen = 0;
                                var reqFormat = "empty";
                                try {
                                    var requestBody = request.body();
                                    if (requestBody != null) {
                                        var buf = Buffer3.$new();
                                        requestBody.writeTo(buf);
                                        var bodyStr = buf.readString(UTF8);
                                        reqBodyLen = bodyStr.length;
                                        reqBody = truncBody(bodyStr);
                                        reqFormat = guessBodyFormat(reqBody);
                                    }
                                } catch (e) {}

                                sendEvent("traffic", "http_request", {
                                    index: idx,
                                    method: method,
                                    url: url,
                                    headers: reqHeaders,
                                    body: reqBody,
                                    body_length: reqBodyLen,
                                    body_format: reqFormat,
                                    source: "okhttp3"
                                });

                                var t0 = Date.now();
                                var response = chain.proceed(request);
                                var elapsed = Date.now() - t0;

                                var status = response.code();
                                var resHeaders = extractHeaders(response.headers());

                                var resBody = "";
                                var resBodyLen = 0;
                                var resFormat = "empty";
                                try {
                                    var responseBody = response.body();
                                    if (responseBody != null) {
                                        var source = responseBody.source();
                                        source.request(Java.long("9223372036854775807"));
                                        var resBuf = source.buffer().clone();
                                        var resStr = resBuf.readString(UTF8);
                                        resBodyLen = resStr.length;
                                        resBody = truncBody(resStr);
                                        resFormat = guessBodyFormat(resBody);
                                    }
                                } catch (e) {}

                                sendEvent("traffic", "http_response", {
                                    index: idx,
                                    url: url,
                                    status: status,
                                    headers: resHeaders,
                                    body: resBody,
                                    body_length: resBodyLen,
                                    body_format: resFormat,
                                    elapsed_ms: elapsed,
                                    source: "okhttp3"
                                });

                                return response;
                            } catch(e) {
                                return chain.proceed(chain.request());
                            }
                        }
                    }
                });

                OkHttpClientBuilder.build.implementation = function() {
                    this.addNetworkInterceptor(KahloInterceptor3.$new());
                    return this.build.call(this);
                };

                _activeLevel = "okhttp3";
                sendEvent("traffic", "hook_status", {level: "okhttp3_interceptor", status: "active"});
            } catch (e) {
                // OkHttp3 not available — skip silently
            }
        });
    } catch(e) {}

    // === Level 1b: System OkHttp v2 (com.android.okhttp) — HttpEngine hook ===
    try {
        Java.perform(function() {
            try {
                var HttpEngine = Java.use('com.android.okhttp.internal.http.HttpEngine');

                // Cache Java reflection field accessors for HttpEngine
                var engineClass = HttpEngine.class;
                var fUserRequest = null;
                var fUserResponse = null;
                var fNetworkRequest = null;
                var fNetworkResponse = null;
                try {
                    fUserRequest = engineClass.getDeclaredField("userRequest");
                    fUserRequest.setAccessible(true);
                } catch(e) {}
                try {
                    fUserResponse = engineClass.getDeclaredField("userResponse");
                    fUserResponse.setAccessible(true);
                } catch(e) {}
                try {
                    fNetworkRequest = engineClass.getDeclaredField("networkRequest");
                    fNetworkRequest.setAccessible(true);
                } catch(e) {}
                try {
                    fNetworkResponse = engineClass.getDeclaredField("networkResponse");
                    fNetworkResponse.setAccessible(true);
                } catch(e) {}

                var SysRequest = Java.use('com.android.okhttp.Request');
                var SysResponse = Java.use('com.android.okhttp.Response');

                HttpEngine.readResponse.implementation = function() {
                    // Call original readResponse first
                    this.readResponse();

                    // Skip event emission if Conscrypt SSL parser is active
                    // (it captures richer data with full bodies and headers from the wire)
                    if (_conscryptHooked) return;

                    try {
                        var idx = ++requestIndex;
                        var thisObj = this;

                        // Read fields via reflection
                        var request = null;
                        var response = null;

                        try {
                            if (fNetworkRequest) {
                                var nr = fNetworkRequest.get(thisObj);
                                if (nr) request = Java.cast(nr, SysRequest);
                            }
                            if (!request && fUserRequest) {
                                var ur = fUserRequest.get(thisObj);
                                if (ur) request = Java.cast(ur, SysRequest);
                            }
                        } catch(e) {}

                        try {
                            if (fNetworkResponse) {
                                var nres = fNetworkResponse.get(thisObj);
                                if (nres) response = Java.cast(nres, SysResponse);
                            }
                            if (!response && fUserResponse) {
                                var ures = fUserResponse.get(thisObj);
                                if (ures) response = Java.cast(ures, SysResponse);
                            }
                        } catch(e) {}

                        if (request) {
                            var method = "";
                            var url = "";
                            var reqHeaders = {};

                            try { method = request.method(); } catch(e) {}
                            try { url = request.urlString(); } catch(e) {}
                            try { reqHeaders = extractHeaders(request.headers()); } catch(e) {}

                            // Request body
                            var reqBody = "";
                            var reqBodyLen = 0;
                            var reqFormat = "empty";
                            try {
                                var requestBody = request.body();
                                if (requestBody != null) {
                                    var SysBuffer = Java.use('com.android.okhttp.okio.Buffer');
                                    var SysCharset = Java.use('java.nio.charset.Charset');
                                    var sysUtf8 = SysCharset.forName("UTF-8");
                                    var buf = SysBuffer.$new();
                                    requestBody.writeTo(buf);
                                    var bodyStr = buf.readString(sysUtf8);
                                    reqBodyLen = bodyStr.length;
                                    reqBody = truncBody(bodyStr);
                                    reqFormat = guessBodyFormat(reqBody);
                                }
                            } catch(e) {}

                            sendEvent("traffic", "http_request", {
                                index: idx,
                                method: method,
                                url: url,
                                headers: reqHeaders,
                                body: reqBody,
                                body_length: reqBodyLen,
                                body_format: reqFormat,
                                source: "system_okhttp"
                            });
                        }

                        if (response) {
                            var status = 0;
                            var resUrl = "";
                            var resHeaders = {};

                            try { status = response.code(); } catch(e) {}
                            try { resUrl = request ? request.urlString() : ""; } catch(e) {}
                            try { resHeaders = extractHeaders(response.headers()); } catch(e) {}

                            // Response body — peek without consuming
                            var resBody = "";
                            var resBodyLen = 0;
                            var resFormat = "empty";
                            try {
                                var responseBody = response.body();
                                if (responseBody != null) {
                                    var SysBuffer2 = Java.use('com.android.okhttp.okio.Buffer');
                                    var SysCharset2 = Java.use('java.nio.charset.Charset');
                                    var sysUtf82 = SysCharset2.forName("UTF-8");
                                    var src = responseBody.source();
                                    src.request(Java.long("9223372036854775807"));
                                    var resBuf = src.buffer().clone();
                                    var resStr = resBuf.readString(sysUtf82);
                                    resBodyLen = resStr.length;
                                    resBody = truncBody(resStr);
                                    resFormat = guessBodyFormat(resBody);
                                }
                            } catch(e) {}

                            sendEvent("traffic", "http_response", {
                                index: idx,
                                url: resUrl,
                                status: status,
                                headers: resHeaders,
                                body: resBody,
                                body_length: resBodyLen,
                                body_format: resFormat,
                                source: "system_okhttp"
                            });
                        }
                    } catch(e) {
                        // Non-fatal: some calls may not have request/response yet
                    }
                };

                if (_activeLevel !== "okhttp3") {
                    _activeLevel = "system_okhttp";
                }
                sendEvent("traffic", "hook_status", {level: "system_okhttp_engine", status: "active"});
            } catch(e) {
                // com.android.okhttp.internal.http.HttpEngine not available — skip
            }
        });
    } catch(e) {}

    // === Level 1c: java.net.HttpURLConnection fallback ===
    // Only emits events if no higher-level hook (okhttp3, system_okhttp) captured the same request
    try {
        Java.perform(function() {
            try {
                var HttpURLConn = Java.use('com.android.okhttp.internal.huc.HttpURLConnectionImpl');

                HttpURLConn.getInputStream.implementation = function() {
                    var stream = this.getInputStream();
                    try {
                        // Skip if higher-level hooks are active (they capture richer data)
                        if (_activeLevel === "okhttp3" || _activeLevel === "system_okhttp") {
                            return stream;
                        }
                        var idx = ++requestIndex;
                        var url = "";
                        var method = "";
                        var statusCode = 0;

                        try { url = this.getURL().toString(); } catch(e) {}
                        try { method = this.getRequestMethod(); } catch(e) {}
                        try { statusCode = this.getResponseCode(); } catch(e) {}

                        // Get response headers
                        var resHeaders = {};
                        try {
                            var headerFields = this.getHeaderFields();
                            var keySet = headerFields.keySet();
                            var iter = keySet.iterator();
                            while (iter.hasNext()) {
                                var key = iter.next();
                                if (key != null) {
                                    var values = headerFields.get(key);
                                    if (values != null && values.size() > 0) {
                                        resHeaders[key] = values.get(0);
                                    }
                                }
                            }
                        } catch(e) {}

                        sendEvent("traffic", "http_request", {
                            index: idx,
                            method: method,
                            url: url,
                            headers: {},
                            body: "",
                            body_length: 0,
                            body_format: "empty",
                            source: "httpurlconnection"
                        });

                        sendEvent("traffic", "http_response", {
                            index: idx,
                            url: url,
                            status: statusCode,
                            headers: resHeaders,
                            body: "",
                            body_length: 0,
                            body_format: "empty",
                            source: "httpurlconnection"
                        });
                    } catch(e) {}
                    return stream;
                };

                sendEvent("traffic", "hook_status", {level: "httpurlconnection", status: "active"});
            } catch(e) {
                // HttpURLConnectionImpl not available — skip
            }
        });
    } catch(e) {}

    // === Level 2: WebSocket (OkHttp RealWebSocket) ===
    try {
        Java.perform(function() {
            try {
                var RealWebSocket = Java.use("okhttp3.internal.ws.RealWebSocket");

                try {
                    RealWebSocket.send.overload('java.lang.String').implementation = function(text) {
                        sendEvent("traffic", "ws_send", {
                            url: this.url ? this.url.toString() : "",
                            text: truncBody(text),
                            text_length: text ? text.length : 0,
                            is_binary: false
                        });
                        return this.send(text);
                    };
                } catch(e) {}

                try {
                    RealWebSocket.send.overload('okio.ByteString').implementation = function(bytes) {
                        sendEvent("traffic", "ws_send", {
                            url: this.url ? this.url.toString() : "",
                            text: "[binary " + bytes.size() + " bytes]",
                            text_length: bytes.size(),
                            is_binary: true
                        });
                        return this.send(bytes);
                    };
                } catch(e) {}

                try {
                    RealWebSocket.onReadMessage.overload('java.lang.String').implementation = function(text) {
                        sendEvent("traffic", "ws_receive", {
                            url: this.url ? this.url.toString() : "",
                            text: truncBody(text),
                            text_length: text ? text.length : 0,
                            is_binary: false
                        });
                        return this.onReadMessage(text);
                    };
                } catch(e) {}

                try {
                    RealWebSocket.onReadMessage.overload('okio.ByteString').implementation = function(bytes) {
                        sendEvent("traffic", "ws_receive", {
                            url: this.url ? this.url.toString() : "",
                            text: "[binary " + bytes.size() + " bytes]",
                            text_length: bytes.size(),
                            is_binary: true
                        });
                        return this.onReadMessage(bytes);
                    };
                } catch(e) {}

                sendEvent("traffic", "hook_status", {level: "websocket", status: "active"});
            } catch(e) {
                // WebSocket not available — skip
            }
        });
    } catch(e) {}

    // === Level 3: Conscrypt SSL streams (with HTTP/1.1 parser) ===
    try {
        Java.perform(function() {
            var conscryptClasses = [
                'com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream',
                'com.android.org.conscrypt.ConscryptEngineSocket$SSLOutputStream',
                'org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream',
                'org.conscrypt.ConscryptEngineSocket$SSLOutputStream'
            ];

            var hooked = false;
            conscryptClasses.forEach(function(className) {
                try {
                    var clazz = Java.use(className);
                    clazz.write.overload('[B', 'int', 'int').implementation = function(buf, off, len) {
                        try {
                            // Skip SSL parsing if okhttp3 interceptor is active (it captures everything)
                            if (_activeLevel === "okhttp3") {
                                return this.write(buf, off, len);
                            }
                            // Try to parse as HTTP/1.1 request first
                            if (isHttpRequest(buf, off, len)) {
                                var rawStr = rawBytesToString(buf, off, len, 8192);
                                var parsed = parseHttpRequest(rawStr);
                                if (parsed) {
                                    var connId = 0;
                                    try { connId = getConnId(this.$holder || this); } catch(e) {}
                                    var fullUrl = parsed.host ? ("https://" + parsed.host + parsed.path) : parsed.path;
                                    sendEvent("traffic", "http_request", {
                                        index: ++requestIndex,
                                        method: parsed.method,
                                        url: fullUrl,
                                        headers: parsed.headers,
                                        body: truncBody(parsed.body_preview),
                                        body_length: parsed.body_length,
                                        body_format: guessBodyFormat(parsed.body_preview),
                                        source: "ssl_parsed",
                                        connection_id: connId
                                    });
                                } else {
                                    // Fallback to raw preview
                                    var preview = readableBytes(buf, off, len, 512);
                                    sendEvent("traffic", "ssl_raw", {
                                        direction: "out",
                                        preview: truncBody(preview),
                                        length: len,
                                        source: className
                                    });
                                }
                            } else {
                                // Check for interesting content (JSON, HTTP fragments)
                                var preview = readableBytes(buf, off, len, 512);
                                if (preview.indexOf("GET ") !== -1 || preview.indexOf("POST ") !== -1 ||
                                    preview.indexOf("PUT ") !== -1 || preview.indexOf("HTTP/") !== -1 ||
                                    preview.indexOf("{") !== -1) {
                                    sendEvent("traffic", "ssl_raw", {
                                        direction: "out",
                                        preview: truncBody(preview),
                                        length: len,
                                        source: className
                                    });
                                }
                            }
                        } catch(e) {}
                        return this.write(buf, off, len);
                    };
                    hooked = true;
                } catch (e) {}
            });

            // Hook the read side
            var readClasses = [
                'com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream',
                'com.android.org.conscrypt.ConscryptEngineSocket$SSLInputStream',
                'org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream',
                'org.conscrypt.ConscryptEngineSocket$SSLInputStream'
            ];

            readClasses.forEach(function(className) {
                try {
                    var clazz = Java.use(className);
                    clazz.read.overload('[B', 'int', 'int').implementation = function(buf, off, len) {
                        var result = this.read(buf, off, len);
                        try {
                            // Skip SSL parsing if okhttp3 interceptor is active
                            if (_activeLevel === "okhttp3") {
                                return result;
                            }
                            if (result > 0) {
                                // Try to parse as HTTP/1.1 response
                                if (isHttpResponse(buf, off, result)) {
                                    var rawStr = rawBytesToString(buf, off, result, 8192);
                                    var parsed = parseHttpResponse(rawStr);
                                    if (parsed) {
                                        var connId = 0;
                                        try { connId = getConnId(this.$holder || this); } catch(e) {}
                                        sendEvent("traffic", "http_response", {
                                            index: requestIndex, // correlate with last request
                                            url: "",
                                            status: parsed.status,
                                            headers: parsed.headers,
                                            body: truncBody(parsed.body_preview),
                                            body_length: parsed.body_length,
                                            body_format: guessBodyFormat(parsed.body_preview),
                                            source: "ssl_parsed",
                                            connection_id: connId
                                        });
                                    } else {
                                        var preview = readableBytes(buf, off, result, 512);
                                        sendEvent("traffic", "ssl_raw", {
                                            direction: "in",
                                            preview: truncBody(preview),
                                            length: result,
                                            source: className
                                        });
                                    }
                                } else {
                                    var preview = readableBytes(buf, off, result, 512);
                                    if (preview.indexOf("HTTP/") !== -1 || preview.indexOf("{") !== -1) {
                                        sendEvent("traffic", "ssl_raw", {
                                            direction: "in",
                                            preview: truncBody(preview),
                                            length: result,
                                            source: className
                                        });
                                    }
                                }
                            }
                        } catch(e) {}
                        return result;
                    };
                    hooked = true;
                } catch (e) {}
            });

            if (hooked) {
                _conscryptHooked = true;
                sendEvent("traffic", "hook_status", {level: "conscrypt_ssl", status: "active"});
            }
        });
    } catch(e) {}

    // === Level 4: Native SSL_write/SSL_read ===
    try {
        var sslLibs = ["libssl.so", "libboringssl.so"];
        var nativeHooked = false;

        sslLibs.forEach(function(lib) {
            try {
                var sslWritePtr = Module.findExportByName(lib, "SSL_write");
                if (sslWritePtr) {
                    Interceptor.attach(sslWritePtr, {
                        onEnter: function(args) {
                            try {
                                var len = args[2].toInt32();
                                if (len > 0 && len < 65536) {
                                    var buf = args[1];
                                    var preview = "";
                                    var end = Math.min(len, 256);
                                    for (var i = 0; i < end; i++) {
                                        var b = buf.add(i).readU8();
                                        preview += (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".";
                                    }
                                    if (preview.indexOf("GET ") !== -1 || preview.indexOf("POST ") !== -1 ||
                                        preview.indexOf("PUT ") !== -1) {
                                        sendEvent("traffic", "ssl_native", {
                                            direction: "out",
                                            preview: preview,
                                            length: len,
                                            lib: lib
                                        });
                                    }
                                }
                            } catch(e) {}
                        }
                    });
                    nativeHooked = true;
                }
            } catch(e) {}

            try {
                var sslReadPtr = Module.findExportByName(lib, "SSL_read");
                if (sslReadPtr) {
                    Interceptor.attach(sslReadPtr, {
                        onEnter: function(args) {
                            this.buf = args[1];
                            this.len = args[2].toInt32();
                        },
                        onLeave: function(retval) {
                            try {
                                var bytesRead = retval.toInt32();
                                if (bytesRead > 0 && bytesRead < 65536) {
                                    var preview = "";
                                    var end = Math.min(bytesRead, 256);
                                    for (var i = 0; i < end; i++) {
                                        var b = this.buf.add(i).readU8();
                                        preview += (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".";
                                    }
                                    if (preview.indexOf("HTTP/") !== -1) {
                                        sendEvent("traffic", "ssl_native", {
                                            direction: "in",
                                            preview: preview,
                                            length: bytesRead,
                                            lib: lib
                                        });
                                    }
                                }
                            } catch(e) {}
                        }
                    });
                    nativeHooked = true;
                }
            } catch(e) {}
        });

        if (nativeHooked) {
            sendEvent("traffic", "hook_status", {level: "native_ssl", status: "active"});
        }
    } catch(e) {}

    // === Level 5: Socket.connect logging ===
    try {
        Java.perform(function() {
            try {
                var Socket = Java.use("java.net.Socket");
                Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function(addr, timeout) {
                    try {
                        var addrStr = addr.toString();
                        // Parse host:port from the InetSocketAddress
                        var host = "";
                        var ip = "";
                        var port = 0;
                        try {
                            var inetAddr = Java.cast(addr, Java.use("java.net.InetSocketAddress"));
                            host = inetAddr.getHostName();
                            port = inetAddr.getPort();
                            var resolved = inetAddr.getAddress();
                            if (resolved) ip = resolved.getHostAddress();
                        } catch(e) {
                            // Fallback: parse string
                            host = addrStr;
                        }
                        sendEvent("traffic", "tcp_connect", {
                            host: host,
                            ip: ip,
                            port: port,
                            raw: addrStr
                        });
                    } catch(e) {}
                    return this.connect(addr, timeout);
                };
                sendEvent("traffic", "hook_status", {level: "socket_connect", status: "active"});
            } catch(e) {}
        });
    } catch(e) {}

    sendEvent("traffic", "hook_status", {level: "traffic_module", status: "loaded"});
})();
