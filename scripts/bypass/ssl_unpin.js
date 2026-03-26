// scripts/bypass/ssl_unpin.js
// Universal SSL certificate pinning bypass
// Covers: OkHttp, TrustManager, Conscrypt, WebView, NetworkSecurityConfig

Java.perform(function() {
    "use strict";

    // === 1. OkHttp3 CertificatePinner ===
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        try {
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
                return; // no-op
            };
        } catch(e) {}
        try {
            CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function() {
                return; // no-op
            };
        } catch(e) {}
        try {
            CertificatePinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function() {
                return; // no-op
            };
        } catch(e) {}
        console.log("[kahlo-ssl] OkHttp3 CertificatePinner bypassed");
    } catch(e) {}

    // === 2. TrustManagerImpl (Android system / Conscrypt) ===
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        try {
            TrustManagerImpl.verifyChain.implementation = function(untrustedChain) {
                return untrustedChain;
            };
            console.log("[kahlo-ssl] TrustManagerImpl.verifyChain bypassed");
        } catch(e) {
            // Older API: checkTrustedRecursive
            try {
                TrustManagerImpl.checkTrustedRecursive.implementation = function(certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used) {
                    return Java.use("java.util.ArrayList").$new();
                };
                console.log("[kahlo-ssl] TrustManagerImpl.checkTrustedRecursive bypassed");
            } catch(e2) {}
        }
    } catch(e) {}

    // === 3. Custom X509TrustManager + SSLContext.init ===
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");

        var EmptyTrustManager = Java.registerClass({
            name: "com.kahlo.EmptyTrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() {
                    return [];
                }
            }
        });

        // Hook SSLContext.init to inject our trust manager
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
            .implementation = function(keyManagers, trustManagers, secureRandom) {
                var emptyTm = EmptyTrustManager.$new();
                var tmArray = Java.array("javax.net.ssl.TrustManager", [emptyTm]);
                this.init(keyManagers, tmArray, secureRandom);
            };
        console.log("[kahlo-ssl] SSLContext.init bypassed with EmptyTrustManager");
    } catch(e) {}

    // === 4. OkHttp3 HostnameVerifier ===
    try {
        var OkHostnameVerifier = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
        OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
            .implementation = function() { return true; };
        console.log("[kahlo-ssl] OkHostnameVerifier bypassed");
    } catch(e) {}

    // === 5. WebViewClient SSL errors ===
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            handler.proceed();
        };
        console.log("[kahlo-ssl] WebViewClient.onReceivedSslError bypassed");
    } catch(e) {}

    // === 6. HttpsURLConnection default verifier ===
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
            // no-op — don't let app set custom verifier
        };
        console.log("[kahlo-ssl] HttpsURLConnection.setDefaultHostnameVerifier bypassed");
    } catch(e) {}

    // === 7. Conscrypt (newer Android versions) ===
    try {
        var ConscryptPlatform = Java.use("org.conscrypt.Platform");
        ConscryptPlatform.checkServerTrusted.implementation = function() {};
        console.log("[kahlo-ssl] Conscrypt Platform bypassed");
    } catch(e) {}

    // === 8. Network Security Config (Android 7+) ===
    try {
        var NetworkSecurityTrustManager = Java.use("android.security.net.config.NetworkSecurityTrustManager");
        NetworkSecurityTrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String')
            .implementation = function(chain, authType) {};
        console.log("[kahlo-ssl] NetworkSecurityTrustManager bypassed");
    } catch(e) {}

    // === 9. Apache HTTP client (legacy apps) ===
    try {
        var AbstractVerifier = Java.use("org.apache.http.conn.ssl.AbstractVerifier");
        AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean')
            .implementation = function() {};
        console.log("[kahlo-ssl] Apache AbstractVerifier bypassed");
    } catch(e) {}

    console.log("[kahlo-ssl] SSL unpinning loaded");
});
