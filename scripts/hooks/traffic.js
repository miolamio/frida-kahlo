// scripts/hooks/traffic.js
// Frida-Kahlo Traffic Hook — captures ALL network traffic at multiple levels
// Levels: OkHttp Interceptor > WebSocket > Conscrypt SSL > Native SSL > Socket.connect

(function() {
    "use strict";

    var MAX_BODY = 4096;
    var requestIndex = 0;

    function truncBody(s) {
        if (!s) return "";
        if (s.length <= MAX_BODY) return s;
        return s.substring(0, MAX_BODY);
    }

    function headersToObj(headers) {
        var obj = {};
        try {
            var count = headers.size();
            for (var i = 0; i < count; i++) {
                obj[headers.name(i)] = headers.value(i);
            }
        } catch(e) {}
        return obj;
    }

    function guessFormat(s) {
        if (!s || s.length === 0) return "empty";
        var c = s.charAt(0);
        if (c === '{' || c === '[') return "json";
        if (s.indexOf("<?xml") === 0) return "xml";
        if (s.indexOf("--") === 0) return "multipart";
        return "text";
    }

    // === Level 1: OkHttp Interceptor injection ===
    try {
        Java.perform(function() {
            try {
                var OkHttpClientBuilder = Java.use('okhttp3.OkHttpClient$Builder');
                var Interceptor = Java.use('okhttp3.Interceptor');
                var Buffer = Java.use('okio.Buffer');
                var Charset = Java.use('java.nio.charset.Charset');
                var UTF8 = Charset.forName("UTF-8");

                var KahloInterceptor = Java.registerClass({
                    name: 'com.kahlo.traffic.NetworkCapture',
                    implements: [Interceptor],
                    methods: {
                        intercept: function(chain) {
                            var idx = ++requestIndex;
                            var request = chain.request();
                            var method = request.method();
                            var url = request.url().toString();

                            // Request headers
                            var reqHeaders = headersToObj(request.headers());

                            // Request body
                            var reqBody = "";
                            var reqBodyLen = 0;
                            var reqFormat = "empty";
                            try {
                                var requestBody = request.body();
                                if (requestBody != null) {
                                    var buf = Buffer.$new();
                                    requestBody.writeTo(buf);
                                    var bodyStr = buf.readString(UTF8);
                                    reqBodyLen = bodyStr.length;
                                    reqBody = truncBody(bodyStr);
                                    reqFormat = guessFormat(reqBody);
                                }
                            } catch (e) {}

                            sendEvent("traffic", "http_request", {
                                index: idx,
                                method: method,
                                url: url,
                                headers: reqHeaders,
                                body: reqBody,
                                body_length: reqBodyLen,
                                body_format: reqFormat
                            });

                            // Execute request and capture response
                            var t0 = Date.now();
                            var response = chain.proceed(request);
                            var elapsed = Date.now() - t0;

                            var status = response.code();
                            var resHeaders = headersToObj(response.headers());

                            // Response body
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
                                    resFormat = guessFormat(resBody);
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
                                elapsed_ms: elapsed
                            });

                            return response;
                        }
                    }
                });

                OkHttpClientBuilder.build.implementation = function() {
                    this.addNetworkInterceptor(KahloInterceptor.$new());
                    return this.build.call(this);
                };

                sendEvent("traffic", "hook_status", {level: "okhttp_interceptor", status: "active"});
            } catch (e) {
                // OkHttp not available — skip silently
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

    // === Level 3: Conscrypt SSL streams ===
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
                        } catch(e) {}
                        return this.write(buf, off, len);
                    };
                    hooked = true;
                } catch (e) {}
            });

            // Also try to hook the read side
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
                            if (result > 0) {
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
                        } catch(e) {}
                        return result;
                    };
                    hooked = true;
                } catch (e) {}
            });

            if (hooked) {
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
