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

            for (var i = 0; i < total; i++) {
                var cls = allClasses[i];

                // Skip system classes
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

            // Find classes with interesting methods
            var methodTargets = {
                "addNetworkInterceptor": [],
                "newWebSocket": [],
                "newCall": [],
                "enqueue": [],
                "execute": []
            };

            // Check OkHttp classes for key methods
            var httpClasses = classMap.http.slice(0, 20); // limit to avoid slowness
            for (var j = 0; j < httpClasses.length; j++) {
                try {
                    var clazz = Java.use(httpClasses[j]);
                    var methods = clazz.class.getDeclaredMethods();
                    for (var k = 0; k < methods.length; k++) {
                        var methodName = methods[k].getName();
                        if (methodName in methodTargets) {
                            methodTargets[methodName].push(httpClasses[j]);
                        }
                    }
                } catch(e) {}
            }

            var result = {
                class_map: classMap,
                method_targets: methodTargets,
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

            console.log("[kahlo-discovery] Enumerated " + total + " classes, classified " + classified);

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
