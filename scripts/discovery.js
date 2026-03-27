// scripts/discovery.js
// Class enumeration and HTTP/WS/crypto/analytics discovery
// Sends result as JSON class_map via send()

Java.perform(function() {
    "use strict";

    // Delay to let app classes load
    setTimeout(function() {
        try {
            var classMap = {
                http: [],
                websocket: [],
                grpc: [],
                crypto: [],
                analytics: [],
                retrofit: [],
                other_interesting: []
            };

            // Patterns for classification
            var httpPatterns = [
                "okhttp3.", "okhttp.", "OkHttpClient", "CertificatePinner",
                "HttpUrl", "HttpsURLConnection",
                "org.apache.http", "HttpClient",
                "com.android.volley", "Volley"
            ];
            var wsPatterns = [
                "WebSocket", "okhttp3.internal.ws", "WebSocketListener",
                "org.java_websocket", "io.socket"
            ];
            var grpcPatterns = [
                "io.grpc", "grpc.", "ManagedChannel", "ClientCall",
                "protobuf", "com.google.protobuf"
            ];
            var cryptoPatterns = [
                "javax.crypto", "Cipher", "SecretKey", "KeyGenerator",
                "MessageDigest", "Signature", "Mac", "HMAC",
                "AES", "RSA", "KeyStore"
            ];
            var analyticsPatterns = [
                "firebase.analytics", "com.google.firebase",
                "com.google.android.gms.analytics",
                "com.amplitude", "com.mixpanel", "com.segment",
                "com.appsflyer", "com.adjust",
                "com.yandex.metrica", "AppMetrica"
            ];
            var retrofitPatterns = [
                "retrofit2.", "retrofit.", "Retrofit"
            ];

            // System class prefixes to skip
            var systemPrefixes = [
                "java.", "javax.", "sun.", "com.sun.",
                "android.", "androidx.", "dalvik.",
                "com.android.internal", "com.android.org",
                "libcore.", "org.xmlpull.", "org.xml.",
                "org.json.", "org.w3c.", "kotlin.",
                "kotlinx.", "org.jetbrains.",
                "org.apache.harmony"
            ];

            function isSystemClass(name) {
                for (var i = 0; i < systemPrefixes.length; i++) {
                    if (name.indexOf(systemPrefixes[i]) === 0) return true;
                }
                return false;
            }

            function matchesAny(name, patterns) {
                for (var i = 0; i < patterns.length; i++) {
                    if (name.indexOf(patterns[i]) !== -1) return true;
                }
                return false;
            }

            // Enumerate loaded classes
            var allClasses = Java.enumerateLoadedClassesSync();
            var total = allClasses.length;
            var classified = 0;

            // Track HTTP client variant classes separately
            var okhttp3Classes = [];
            var systemOkhttpClasses = [];
            var httpUrlConnClasses = [];
            var volleyClasses = [];

            for (var i = 0; i < total; i++) {
                var cls = allClasses[i];

                // Special tracking for HTTP client variants (including system classes)
                if (cls.indexOf("com.android.okhttp.") === 0) {
                    systemOkhttpClasses.push(cls);
                }
                if (cls.indexOf("okhttp3.") === 0) {
                    okhttp3Classes.push(cls);
                }
                if (cls.indexOf("com.android.volley.") === 0) {
                    volleyClasses.push(cls);
                }
                if (cls === "com.android.okhttp.internal.huc.HttpURLConnectionImpl" ||
                    cls === "com.android.okhttp.internal.huc.HttpsURLConnectionImpl") {
                    httpUrlConnClasses.push(cls);
                }

                // Skip system classes for the general class_map
                if (isSystemClass(cls)) continue;

                if (matchesAny(cls, httpPatterns)) {
                    classMap.http.push(cls);
                    classified++;
                } else if (matchesAny(cls, wsPatterns)) {
                    classMap.websocket.push(cls);
                    classified++;
                } else if (matchesAny(cls, grpcPatterns)) {
                    classMap.grpc.push(cls);
                    classified++;
                } else if (matchesAny(cls, cryptoPatterns)) {
                    classMap.crypto.push(cls);
                    classified++;
                } else if (matchesAny(cls, analyticsPatterns)) {
                    classMap.analytics.push(cls);
                    classified++;
                } else if (matchesAny(cls, retrofitPatterns)) {
                    classMap.retrofit.push(cls);
                    classified++;
                }
            }

            // Find classes with interesting methods (expanded list)
            var methodTargets = {
                "addNetworkInterceptor": [],
                "newWebSocket": [],
                "newCall": [],
                "enqueue": [],
                "execute": [],
                "sendRequest": [],
                "readResponse": [],
                "networkInterceptors": [],
                "getResponseCode": [],
                "newBuilder": []
            };

            // Check HTTP classes + system OkHttp classes for key methods
            var classesToCheck = classMap.http.slice(0, 20);
            // Also check key system OkHttp classes
            var sysCheckClasses = [
                "com.android.okhttp.OkHttpClient",
                "com.android.okhttp.internal.http.HttpEngine",
                "com.android.okhttp.internal.huc.HttpURLConnectionImpl",
                "com.android.okhttp.Request$Builder",
                "com.android.okhttp.Response$Builder"
            ];
            for (var s = 0; s < sysCheckClasses.length; s++) {
                if (classesToCheck.indexOf(sysCheckClasses[s]) === -1) {
                    classesToCheck.push(sysCheckClasses[s]);
                }
            }

            for (var j = 0; j < classesToCheck.length; j++) {
                try {
                    var clazz = Java.use(classesToCheck[j]);
                    var methods = clazz.class.getDeclaredMethods();
                    for (var k = 0; k < methods.length; k++) {
                        var methodName = methods[k].getName();
                        if (methodName in methodTargets) {
                            methodTargets[methodName].push(classesToCheck[j]);
                        }
                    }
                } catch(e) {}
            }

            // Determine HTTP client type
            var httpClientType = "unknown";
            var httpClientClasses = {};

            // Check for full okhttp3 stack (not just stubs)
            var hasOkhttp3Client = false;
            for (var oi = 0; oi < okhttp3Classes.length; oi++) {
                if (okhttp3Classes[oi] === "okhttp3.OkHttpClient$Builder" ||
                    okhttp3Classes[oi] === "okhttp3.OkHttpClient") {
                    hasOkhttp3Client = true;
                    break;
                }
            }

            // Check for system OkHttp engine
            var hasSystemEngine = false;
            for (var si = 0; si < systemOkhttpClasses.length; si++) {
                if (systemOkhttpClasses[si] === "com.android.okhttp.internal.http.HttpEngine") {
                    hasSystemEngine = true;
                    break;
                }
            }

            if (hasOkhttp3Client) {
                httpClientType = "okhttp3";
                httpClientClasses = {
                    client: "okhttp3.OkHttpClient",
                    builder: "okhttp3.OkHttpClient$Builder"
                };
            } else if (hasSystemEngine) {
                httpClientType = "system_okhttp_v2";
                httpClientClasses = {
                    client: "com.android.okhttp.OkHttpClient",
                    engine: "com.android.okhttp.internal.http.HttpEngine",
                    request: "com.android.okhttp.Request",
                    response: "com.android.okhttp.Response",
                    buffer: "com.android.okhttp.okio.Buffer"
                };
            } else if (okhttp3Classes.length > 0) {
                httpClientType = "okhttp3_stubs_only";
                httpClientClasses = { stubs: okhttp3Classes };
            } else if (volleyClasses.length > 0) {
                httpClientType = "volley";
                httpClientClasses = { classes: volleyClasses };
            } else if (httpUrlConnClasses.length > 0) {
                httpClientType = "httpurlconnection";
                httpClientClasses = { classes: httpUrlConnClasses };
            }

            var result = {
                class_map: classMap,
                method_targets: methodTargets,
                http_client: {
                    type: httpClientType,
                    classes: httpClientClasses,
                    okhttp3_count: okhttp3Classes.length,
                    system_okhttp_count: systemOkhttpClasses.length,
                    httpurlconnection_classes: httpUrlConnClasses,
                    volley_count: volleyClasses.length
                },
                stats: {
                    total_classes: total,
                    classified: classified,
                    http: classMap.http.length,
                    websocket: classMap.websocket.length,
                    grpc: classMap.grpc.length,
                    crypto: classMap.crypto.length,
                    analytics: classMap.analytics.length,
                    retrofit: classMap.retrofit.length
                }
            };

            send(JSON.stringify({
                ts: new Date().toISOString(),
                module: "discovery",
                type: "class_map",
                data: result
            }));

            console.log("[kahlo-discovery] Enumerated " + total + " classes, classified " + classified +
                        ", http_client: " + httpClientType);

        } catch(e) {
            send(JSON.stringify({
                ts: new Date().toISOString(),
                module: "discovery",
                type: "error",
                data: { error: e.toString() }
            }));
        }
    }, 3000); // 3s delay for classes to load
});
