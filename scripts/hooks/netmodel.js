// scripts/hooks/netmodel.js
// Frida-Kahlo Netmodel Hook — captures crypto, signing, and TLS operations
// Cipher, Mac (HMAC), Signature, MessageDigest, SSLSession, UUID

(function() {
    "use strict";

    var MAX_PREVIEW = 256;

    function bytesToHex(arr, maxLen) {
        maxLen = maxLen || 64;
        var hex = "";
        try {
            var len = Math.min(arr.length, maxLen);
            for (var i = 0; i < len; i++) {
                var b = arr[i] & 0xFF;
                hex += ("0" + b.toString(16)).slice(-2);
            }
            if (arr.length > maxLen) hex += "...";
        } catch(e) {}
        return hex;
    }

    function byteArrayToHex(byteArray, maxLen) {
        maxLen = maxLen || 64;
        var hex = "";
        try {
            var len = Math.min(byteArray.length, maxLen);
            for (var i = 0; i < len; i++) {
                var b = byteArray[i] & 0xFF;
                hex += ("0" + b.toString(16)).slice(-2);
            }
            if (byteArray.length > maxLen) hex += "...";
        } catch(e) {}
        return hex;
    }

    function previewBytes(arr, maxLen) {
        maxLen = maxLen || MAX_PREVIEW;
        var s = "";
        try {
            var len = Math.min(arr.length, maxLen);
            for (var i = 0; i < len; i++) {
                var b = arr[i] & 0xFF;
                s += (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".";
            }
        } catch(e) {}
        return s;
    }

    // === 1. javax.crypto.Cipher — encrypt/decrypt ===
    try {
        Java.perform(function() {
            safeHook("javax.crypto.Cipher", function(cls) {
                // Track cipher instances with their config
                var cipherInfo = {};

                // init (mode, key)
                try {
                    cls.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
                        try {
                            var algo = this.getAlgorithm();
                            var modeStr = (mode === 1) ? "encrypt" : (mode === 2) ? "decrypt" : "mode_" + mode;
                            var keyHex = "";
                            try { keyHex = byteArrayToHex(key.getEncoded()); } catch(e) {}
                            cipherInfo[this.hashCode()] = {
                                algorithm: algo,
                                mode: modeStr,
                                key_hex: keyHex
                            };
                            sendEvent("netmodel", "crypto_init", {
                                op: modeStr,
                                algorithm: algo,
                                key_hex: keyHex,
                                key_algorithm: key.getAlgorithm()
                            });
                        } catch(e) {}
                        return this.init(mode, key);
                    };
                } catch(e) {}

                // init (mode, key, params) — captures IV
                try {
                    cls.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(mode, key, params) {
                        try {
                            var algo = this.getAlgorithm();
                            var modeStr = (mode === 1) ? "encrypt" : (mode === 2) ? "decrypt" : "mode_" + mode;
                            var keyHex = "";
                            var ivHex = "";
                            try { keyHex = byteArrayToHex(key.getEncoded()); } catch(e) {}
                            try {
                                var ivSpec = Java.cast(params, Java.use("javax.crypto.spec.IvParameterSpec"));
                                ivHex = byteArrayToHex(ivSpec.getIV());
                            } catch(e) {}
                            cipherInfo[this.hashCode()] = {
                                algorithm: algo,
                                mode: modeStr,
                                key_hex: keyHex,
                                iv_hex: ivHex
                            };
                            sendEvent("netmodel", "crypto_init", {
                                op: modeStr,
                                algorithm: algo,
                                key_hex: keyHex,
                                iv_hex: ivHex,
                                key_algorithm: key.getAlgorithm()
                            });
                        } catch(e) {}
                        return this.init(mode, key, params);
                    };
                } catch(e) {}

                // doFinal
                try {
                    cls.doFinal.overload('[B').implementation = function(input) {
                        var result = this.doFinal(input);
                        try {
                            var info = cipherInfo[this.hashCode()] || {};
                            sendEvent("netmodel", "crypto_op", {
                                op: info.mode || "unknown",
                                algorithm: info.algorithm || this.getAlgorithm(),
                                key_hex: info.key_hex || "",
                                iv_hex: info.iv_hex || "",
                                input_preview: previewBytes(input),
                                input_hex: byteArrayToHex(input, 32),
                                output_hex: byteArrayToHex(result, 32),
                                input_length: input.length,
                                output_length: result.length
                            });
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === 2. javax.crypto.Mac — HMAC ===
    try {
        Java.perform(function() {
            safeHook("javax.crypto.Mac", function(cls) {
                var macInfo = {};

                // init
                try {
                    cls.init.overload('java.security.Key').implementation = function(key) {
                        try {
                            var algo = this.getAlgorithm();
                            var keyHex = "";
                            try { keyHex = byteArrayToHex(key.getEncoded()); } catch(e) {}
                            macInfo[this.hashCode()] = { algorithm: algo, key_hex: keyHex };
                            sendEvent("netmodel", "hmac_init", {
                                algorithm: algo,
                                key_hex: keyHex,
                                key_algorithm: key.getAlgorithm()
                            });
                        } catch(e) {}
                        return this.init(key);
                    };
                } catch(e) {}

                // doFinal (byte[])
                try {
                    cls.doFinal.overload('[B').implementation = function(input) {
                        var result = this.doFinal(input);
                        try {
                            var info = macInfo[this.hashCode()] || {};
                            sendEvent("netmodel", "hmac", {
                                algorithm: info.algorithm || this.getAlgorithm(),
                                key_hex: info.key_hex || "",
                                input_preview: previewBytes(input),
                                input_hex: byteArrayToHex(input, 32),
                                output_hex: byteArrayToHex(result),
                                input_length: input.length
                            });
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}

                // doFinal () — no-arg version
                try {
                    cls.doFinal.overload().implementation = function() {
                        var result = this.doFinal();
                        try {
                            var info = macInfo[this.hashCode()] || {};
                            sendEvent("netmodel", "hmac", {
                                algorithm: info.algorithm || this.getAlgorithm(),
                                key_hex: info.key_hex || "",
                                output_hex: byteArrayToHex(result),
                                input_preview: "(streaming)"
                            });
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === 3. java.security.Signature — sign/verify ===
    try {
        Java.perform(function() {
            safeHook("java.security.Signature", function(cls) {
                try {
                    cls.sign.overload().implementation = function() {
                        var result = this.sign();
                        try {
                            sendEvent("netmodel", "signature", {
                                op: "sign",
                                algorithm: this.getAlgorithm(),
                                output_hex: byteArrayToHex(result),
                                output_length: result.length
                            });
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}

                try {
                    cls.verify.overload('[B').implementation = function(sig) {
                        var result = this.verify(sig);
                        try {
                            sendEvent("netmodel", "signature", {
                                op: "verify",
                                algorithm: this.getAlgorithm(),
                                input_hex: byteArrayToHex(sig, 32),
                                result: result
                            });
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === 4. MessageDigest — hashing ===
    try {
        Java.perform(function() {
            safeHook("java.security.MessageDigest", function(cls) {
                try {
                    cls.digest.overload('[B').implementation = function(input) {
                        var result = this.digest(input);
                        try {
                            sendEvent("netmodel", "hash", {
                                algorithm: this.getAlgorithm(),
                                input_preview: previewBytes(input),
                                input_hex: byteArrayToHex(input, 32),
                                output_hex: byteArrayToHex(result),
                                input_length: input.length
                            });
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}

                try {
                    cls.digest.overload().implementation = function() {
                        var result = this.digest();
                        try {
                            sendEvent("netmodel", "hash", {
                                algorithm: this.getAlgorithm(),
                                output_hex: byteArrayToHex(result),
                                input_preview: "(streaming)"
                            });
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === 5. SSLSession info ===
    try {
        Java.perform(function() {
            safeHook("javax.net.ssl.SSLSocket", function(cls) {
                try {
                    cls.startHandshake.implementation = function() {
                        this.startHandshake.call(this);
                        try {
                            var session = this.getSession();
                            var cipher = session.getCipherSuite();
                            var protocol = session.getProtocol();
                            var peerHost = session.getPeerHost();
                            var peerPort = session.getPeerPort();
                            var peerCn = "";
                            try {
                                var certs = session.getPeerCertificates();
                                if (certs && certs.length > 0) {
                                    peerCn = certs[0].getSubjectDN().toString();
                                }
                            } catch(e) {}
                            sendEvent("netmodel", "tls_info", {
                                cipher: cipher,
                                protocol: protocol,
                                peer_host: peerHost,
                                peer_port: peerPort,
                                peer_cn: peerCn
                            });
                        } catch(e) {}
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === 6. UUID.randomUUID — nonce tracking ===
    try {
        Java.perform(function() {
            safeHook("java.util.UUID", function(cls) {
                try {
                    cls.randomUUID.implementation = function() {
                        var result = this.randomUUID();
                        sendEvent("netmodel", "nonce", {
                            type: "uuid",
                            value: result.toString(),
                            stack: stackTrace()
                        });
                        return result;
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === 7. System.currentTimeMillis usage tracking ===
    // (High volume — only log from non-system stacks)
    // Skipped by default to avoid noise; uncomment if needed for specific analysis

    sendEvent("netmodel", "hook_status", {status: "loaded"});
})();
