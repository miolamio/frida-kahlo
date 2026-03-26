// scripts/hooks/recon.js
// Frida-Kahlo Recon Hook — captures environment reconnaissance by the app
// Device info, network, VPN detection, installed apps, IP lookups

(function() {
    "use strict";

    // === 1. Build.* field access (static fields, hook via reflection) ===
    try {
        Java.perform(function() {
            safeHook("android.os.Build", function(Build) {
                var fields = ["MODEL", "MANUFACTURER", "FINGERPRINT", "SERIAL",
                              "DEVICE", "BRAND", "HARDWARE", "PRODUCT", "BOARD",
                              "DISPLAY", "HOST", "ID", "TYPE"];
                fields.forEach(function(field) {
                    try {
                        var value = Build[field].value;
                        // We can't easily hook static field reads, but we capture on load
                        // and hook the class loader to detect reflection
                    } catch(e) {}
                });
            });

            // Hook Build field reflection access via Field.get
            safeHook("java.lang.reflect.Field", function(cls) {
                try {
                    cls.get.implementation = function(obj) {
                        var result = this.get.call(this, obj);
                        try {
                            var declaringClass = this.getDeclaringClass().getName();
                            var fieldName = this.getName();
                            if (declaringClass === "android.os.Build" ||
                                declaringClass === "android.os.Build$VERSION") {
                                sendEvent("recon", "device_info", {
                                    field: fieldName,
                                    value: result ? result.toString() : "null",
                                    source: declaringClass,
                                    access: "reflection"
                                });
                            }
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === 2. Settings.Secure (ANDROID_ID, etc.) ===
    try {
        Java.perform(function() {
            safeHook("android.provider.Settings$Secure", function(cls) {
                try {
                    cls.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
                        var result = this.getString(cr, name);
                        sendEvent("recon", "device_info", {
                            field: name,
                            value: result ? result.toString() : "null",
                            source: "Settings.Secure"
                        });
                        return result;
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === 3. TelephonyManager ===
    try {
        Java.perform(function() {
            safeHook("android.telephony.TelephonyManager", function(cls) {
                var methods = [
                    "getDeviceId", "getImei", "getNetworkOperator",
                    "getSimOperator", "getNetworkOperatorName",
                    "getSimOperatorName", "getLine1Number",
                    "getNetworkCountryIso", "getSimCountryIso"
                ];

                methods.forEach(function(method) {
                    try {
                        cls[method].overload().implementation = function() {
                            var result = this[method]();
                            sendEvent("recon", "telecom", {
                                method: method,
                                value: result ? result.toString() : "null"
                            });
                            return result;
                        };
                    } catch(e) {}
                });
            });
        });
    } catch(e) {}

    // === 4. VPN Detection — NetworkCapabilities.hasTransport ===
    try {
        Java.perform(function() {
            safeHook("android.net.NetworkCapabilities", function(cls) {
                try {
                    cls.hasTransport.implementation = function(transport) {
                        var result = this.hasTransport(transport);
                        // TRANSPORT_VPN = 4
                        if (transport === 4) {
                            sendEvent("recon", "vpn_check", {
                                transport: transport,
                                result: result,
                                stack: stackTrace()
                            });
                        }
                        return result;
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === 5. ConnectivityManager ===
    try {
        Java.perform(function() {
            safeHook("android.net.ConnectivityManager", function(cls) {
                try {
                    cls.getActiveNetwork.implementation = function() {
                        var result = this.getActiveNetwork();
                        sendEvent("recon", "network_info", {
                            method: "getActiveNetwork",
                            value: result ? result.toString() : "null"
                        });
                        return result;
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === 6. WifiManager ===
    try {
        Java.perform(function() {
            safeHook("android.net.wifi.WifiManager", function(cls) {
                try {
                    cls.getConnectionInfo.implementation = function() {
                        var result = this.getConnectionInfo();
                        try {
                            sendEvent("recon", "wifi_info", {
                                ssid: result.getSSID(),
                                bssid: result.getBSSID(),
                                ip: result.getIpAddress(),
                                rssi: result.getRssi()
                            });
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === 7. LocationManager ===
    try {
        Java.perform(function() {
            safeHook("android.location.LocationManager", function(cls) {
                try {
                    cls.getLastKnownLocation.implementation = function(provider) {
                        var result = this.getLastKnownLocation(provider);
                        sendEvent("recon", "location", {
                            method: "getLastKnownLocation",
                            provider: provider,
                            has_result: result !== null,
                            lat: result ? result.getLatitude() : null,
                            lng: result ? result.getLongitude() : null
                        });
                        return result;
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === 8. PackageManager — installed apps enumeration ===
    try {
        Java.perform(function() {
            safeHook("android.app.ApplicationPackageManager", function(cls) {
                try {
                    cls.getInstalledPackages.overload('int').implementation = function(flags) {
                        var result = this.getInstalledPackages(flags);
                        try {
                            var pkgs = [];
                            for (var i = 0; i < result.size() && i < 200; i++) {
                                pkgs.push(result.get(i).packageName.value);
                            }
                            sendEvent("recon", "installed_apps", {
                                count: result.size(),
                                packages: pkgs,
                                flags: flags,
                                stack: stackTrace()
                            });
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}

                try {
                    cls.getInstalledApplications.overload('int').implementation = function(flags) {
                        var result = this.getInstalledApplications(flags);
                        try {
                            var pkgs = [];
                            for (var i = 0; i < result.size() && i < 200; i++) {
                                pkgs.push(result.get(i).packageName.value);
                            }
                            sendEvent("recon", "installed_apps", {
                                count: result.size(),
                                packages: pkgs,
                                flags: flags,
                                method: "getInstalledApplications"
                            });
                        } catch(e) {}
                        return result;
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === 9. URL.openConnection — IP lookup services ===
    try {
        Java.perform(function() {
            safeHook("java.net.URL", function(cls) {
                try {
                    cls.openConnection.overload().implementation = function() {
                        var urlStr = this.toString();
                        var ipServices = ["ipify", "ifconfig", "checkip", "ip.mail.ru",
                                          "whatismyip", "myip", "icanhazip", "ip-api"];
                        for (var i = 0; i < ipServices.length; i++) {
                            if (urlStr.indexOf(ipServices[i]) !== -1) {
                                sendEvent("recon", "ip_lookup", {
                                    service: ipServices[i],
                                    url: urlStr,
                                    stack: stackTrace()
                                });
                                break;
                            }
                        }

                        // Competitor probes
                        var probeHosts = ["telegram.org", "whatsapp.net", "gosuslugi.ru",
                                          "vk.com", "ok.ru", "mail.ru"];
                        for (var j = 0; j < probeHosts.length; j++) {
                            if (urlStr.indexOf(probeHosts[j]) !== -1) {
                                sendEvent("recon", "competitor_probe", {
                                    target: probeHosts[j],
                                    url: urlStr,
                                    method: "url_openConnection"
                                });
                                break;
                            }
                        }

                        return this.openConnection();
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === 10. InetAddress.isReachable — ping probes ===
    try {
        Java.perform(function() {
            safeHook("java.net.InetAddress", function(cls) {
                try {
                    cls.isReachable.overload('int').implementation = function(timeout) {
                        var result = this.isReachable(timeout);
                        sendEvent("recon", "ping_probe", {
                            host: this.getHostName(),
                            ip: this.getHostAddress(),
                            reachable: result,
                            timeout: timeout
                        });
                        return result;
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === 11. SensorManager — motion/proximity sensors ===
    try {
        Java.perform(function() {
            safeHook("android.hardware.SensorManager", function(cls) {
                try {
                    cls.registerListener.overload('android.hardware.SensorEventListener', 'android.hardware.Sensor', 'int').implementation = function(listener, sensor, rate) {
                        try {
                            sendEvent("recon", "sensor_access", {
                                sensor_type: sensor.getType(),
                                sensor_name: sensor.getName(),
                                rate: rate
                            });
                        } catch(e) {}
                        return this.registerListener(listener, sensor, rate);
                    };
                } catch(e) {}
            });
        });
    } catch(e) {}

    sendEvent("recon", "hook_status", {status: "loaded"});
})();
