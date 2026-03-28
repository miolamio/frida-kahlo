// scripts/bypass/stealth.js
// Frida-Kahlo Stealth Layer — anti-Frida + anti-root bypass
// Loaded FIRST before any analysis hooks

(function() {
    "use strict";

    // === Helper (local to stealth — renamed to avoid confusion with common.js safeHook) ===
    function _stealthSafeHook(className, callback) {
        try {
            var clazz = Java.use(className);
            callback(clazz);
        } catch (e) {}
    }

    var hiddenPaths = ["frida", "magisk", "/su", "supersu", "busybox",
                       "daemonsu", "Superuser", "titanium", ".magisk",
                       "kernelsu", "superuser"];

    function shouldHide(path) {
        if (!path) return false;
        var lp = path.toLowerCase();
        for (var i = 0; i < hiddenPaths.length; i++) {
            if (lp.indexOf(hiddenPaths[i].toLowerCase()) !== -1) return true;
        }
        return false;
    }

    // === 1. /proc/self/maps filtering ===
    // Hide frida-agent.so from maps reading
    try {
        var openPtr = Module.findExportByName("libc.so", "open");
        var readPtr = Module.findExportByName("libc.so", "read");

        var mapsFdSet = {};

        if (openPtr) {
            Interceptor.attach(openPtr, {
                onEnter: function(args) {
                    try {
                        var path = args[0].readCString();
                        this.isMaps = (path && path.indexOf("/proc") !== -1 &&
                                       path.indexOf("maps") !== -1);
                    } catch(e) {
                        this.isMaps = false;
                    }
                },
                onLeave: function(retval) {
                    if (this.isMaps) {
                        var fd = retval.toInt32();
                        if (fd > 0) {
                            mapsFdSet[fd] = true;
                        }
                    }
                }
            });
        }

        if (readPtr) {
            Interceptor.attach(readPtr, {
                onEnter: function(args) {
                    this.fd = args[0].toInt32();
                    this.buf = args[1];
                    this.isMaps = (this.fd in mapsFdSet);
                },
                onLeave: function(retval) {
                    if (this.isMaps && retval.toInt32() > 0) {
                        try {
                            var content = this.buf.readCString();
                            if (content && (content.indexOf("frida") !== -1 ||
                                            content.indexOf("gum-js") !== -1 ||
                                            content.indexOf("gmain") !== -1)) {
                                var filtered = content.split("\n")
                                    .filter(function(line) {
                                        return line.indexOf("frida") === -1 &&
                                               line.indexOf("gum-js") === -1 &&
                                               line.indexOf("gmain") === -1;
                                    }).join("\n");
                                this.buf.writeUtf8String(filtered);
                                retval.replace(filtered.length);
                            }
                        } catch(e) {}
                    }
                }
            });
        }
    } catch(e) {}

    // === 1b. close() hook — clean up mapsFdSet to prevent memory leak ===
    try {
        var closePtr = Module.findExportByName("libc.so", "close");
        if (closePtr) {
            Interceptor.attach(closePtr, {
                onEnter: function(args) {
                    var fd = args[0].toInt32();
                    if (fd in mapsFdSet) {
                        delete mapsFdSet[fd];
                    }
                }
            });
        }
    } catch(e) {}

    // === 2. openat hook (many apps use openat instead of open) ===
    try {
        var openatPtr = Module.findExportByName("libc.so", "openat");
        if (openatPtr) {
            Interceptor.attach(openatPtr, {
                onEnter: function(args) {
                    try {
                        var path = args[1].readCString();
                        this.isMaps = (path && path.indexOf("/proc") !== -1 &&
                                       path.indexOf("maps") !== -1);
                    } catch(e) {
                        this.isMaps = false;
                    }
                },
                onLeave: function(retval) {
                    if (this.isMaps) {
                        var fd = retval.toInt32();
                        if (fd > 0) {
                            mapsFdSet[fd] = true;
                        }
                    }
                }
            });
        }
    } catch(e) {}

    // === 3. File existence hiding ===
    try {
        var accessPtr = Module.findExportByName("libc.so", "access");
        if (accessPtr) {
            Interceptor.attach(accessPtr, {
                onEnter: function(args) {
                    try {
                        var path = args[0].readCString();
                        if (shouldHide(path)) {
                            this.fakeIt = true;
                            this.origPath = args[0];
                            args[0] = Memory.allocUtf8String("/nonexistent_kahlo_" + Math.random());
                        }
                    } catch(e) {}
                }
            });
        }
    } catch(e) {}

    try {
        var statPtr = Module.findExportByName("libc.so", "stat");
        if (statPtr) {
            Interceptor.attach(statPtr, {
                onEnter: function(args) {
                    try {
                        var path = args[0].readCString();
                        if (shouldHide(path)) {
                            args[0] = Memory.allocUtf8String("/nonexistent_kahlo_" + Math.random());
                        }
                    } catch(e) {}
                }
            });
        }
    } catch(e) {}

    // === 4. Port scan blocking ===
    try {
        var connectPtr = Module.findExportByName("libc.so", "connect");
        if (connectPtr) {
            Interceptor.attach(connectPtr, {
                onEnter: function(args) {
                    try {
                        var sa = args[1];
                        var family = sa.readU16();
                        if (family === 2) { // AF_INET
                            var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                            if (port === 27042 || port === 27043) {
                                // Redirect to 0.0.0.0 — connection will fail
                                sa.add(4).writeU32(0x00000000);
                            }
                        }
                    } catch(e) {}
                }
            });
        }
    } catch(e) {}

    // === 5. ptrace bypass ===
    try {
        var ptracePtr = Module.findExportByName("libc.so", "ptrace");
        if (ptracePtr) {
            Interceptor.replace(ptracePtr, new NativeCallback(function(request, pid, addr, data) {
                if (request === 0) return 0; // PTRACE_TRACEME -> success
                return -1;
            }, 'long', ['int', 'int', 'pointer', 'pointer']));
        }
    } catch(e) {}

    // === 6. /proc/self/status TracerPid filter ===
    try {
        var fopenPtr = Module.findExportByName("libc.so", "fopen");
        var fgetsPtr = Module.findExportByName("libc.so", "fgets");

        if (fopenPtr && fgetsPtr) {
            var statusFiles = {};

            Interceptor.attach(fopenPtr, {
                onEnter: function(args) {
                    try {
                        var path = args[0].readCString();
                        this.isStatus = (path && path.indexOf("/proc") !== -1 &&
                                         path.indexOf("status") !== -1);
                    } catch(e) {
                        this.isStatus = false;
                    }
                },
                onLeave: function(retval) {
                    if (this.isStatus && !retval.isNull()) {
                        statusFiles[retval.toString()] = true;
                    }
                }
            });

            Interceptor.attach(fgetsPtr, {
                onEnter: function(args) {
                    this.buf = args[0];
                    this.fp = args[2];
                },
                onLeave: function(retval) {
                    if (!retval.isNull() && this.fp && (this.fp.toString() in statusFiles)) {
                        try {
                            var line = this.buf.readCString();
                            if (line && line.indexOf("TracerPid") !== -1) {
                                this.buf.writeUtf8String("TracerPid:\t0\n");
                            }
                        } catch(e) {}
                    }
                }
            });

            // fclose — clean up statusFiles to prevent unbounded growth
            var fclosePtr = Module.findExportByName("libc.so", "fclose");
            if (fclosePtr) {
                Interceptor.attach(fclosePtr, {
                    onEnter: function(args) {
                        var fp = args[0];
                        if (!fp.isNull()) {
                            var key = fp.toString();
                            if (key in statusFiles) {
                                delete statusFiles[key];
                            }
                        }
                    }
                });
            }
        }
    } catch(e) {}

    // === 7. Java-level root & Frida detection bypass ===
    try {
        Java.perform(function() {

            // RootBeer bypass
            _stealthSafeHook("com.scottyab.rootbeer.RootBeer", function(cls) {
                var methods = ["isRooted", "isRootedWithoutBusyBoxCheck",
                              "checkForSuBinary", "checkForBusyBoxBinary",
                              "checkForRootManagementApps", "checkForDangerousProps",
                              "checkSuExists", "checkForMagiskBinary",
                              "detectRootManagementApps", "detectPotentiallyDangerousApps",
                              "detectTestKeys", "checkForRWPaths"];
                methods.forEach(function(m) {
                    try { cls[m].implementation = function() { return false; }; } catch(e) {}
                });
            });

            // Generic root check — File.exists
            _stealthSafeHook("java.io.File", function(cls) {
                cls.exists.implementation = function() {
                    var path = this.getAbsolutePath();
                    if (shouldHide(path)) return false;
                    return this.exists.call(this);
                };
            });

            // PackageManager — hide root/hack/xposed packages
            // Extended list from RootBeer's Const.java (N7.a)
            _stealthSafeHook("android.app.ApplicationPackageManager", function(cls) {
                try {
                    var hiddenPackages = [
                        "com.topjohnwu.magisk", "eu.chainfire.supersu",
                        "me.weishu.kernelsu", "com.noshufou.android.su",
                        "com.noshufou.android.su.elite", "com.thirdparty.superuser",
                        "com.koushikdutta.superuser", "com.yellowes.su",
                        "com.kingroot.kinguser", "com.kingo.root",
                        "com.smedialink.oneclickroot", "com.zhiqupk.root.global",
                        "com.alephzain.framaroot",
                        // "Potentially dangerous" apps (RootBeer list)
                        "com.koushikdutta.rommanager", "com.koushikdutta.rommanager.license",
                        "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
                        "com.chelpus.luckypatcher", "com.blackmartalpha",
                        "org.blackmart.market", "com.allinone.free",
                        "com.solohsu.android.edxp.manager", "org.meowcat.edxposed.manager",
                        "com.xmodgame", "cc.madkite.freedom",
                        "catch_.me_.if_.you_.can_"
                    ];
                    cls.getPackageInfo.overload('java.lang.String', 'int').implementation = function(name, flags) {
                        for (var i = 0; i < hiddenPackages.length; i++) {
                            if (name === hiddenPackages[i]) {
                                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
                            }
                        }
                        return this.getPackageInfo(name, flags);
                    };
                } catch(e) {}
            });

            // System property check for ro.debuggable, ro.secure
            _stealthSafeHook("android.os.SystemProperties", function(cls) {
                try {
                    cls.get.overload('java.lang.String').implementation = function(key) {
                        if (key === "ro.debuggable") return "0";
                        if (key === "ro.secure") return "1";
                        return this.get(key);
                    };
                } catch(e) {}
            });

            // === 7b. Runtime.exec bypass — block root-probing commands ===
            // Many apps run "getprop", "mount", or ["which","su"] to detect root
            // instead of using Java File.exists or SystemProperties.
            _stealthSafeHook("java.lang.Runtime", function(cls) {
                try {
                    cls.exec.overload('java.lang.String').implementation = function(cmd) {
                        if (cmd && (cmd === "getprop" || cmd === "mount" ||
                                    cmd.indexOf("which su") !== -1)) {
                            return this.exec("echo");
                        }
                        return this.exec(cmd);
                    };
                } catch(e) {}
                try {
                    cls.exec.overload('[Ljava.lang.String;').implementation = function(cmdArr) {
                        if (cmdArr && cmdArr.length > 0) {
                            var joined = Array.prototype.join.call(cmdArr, " ");
                            if (joined.indexOf("which") !== -1 && joined.indexOf("su") !== -1) {
                                return this.exec("echo");
                            }
                        }
                        return this.exec(cmdArr);
                    };
                } catch(e) {}
            });

            // === 7c. Build.TAGS bypass — spoof test-keys to release-keys ===
            try {
                var Build = Java.use("android.os.Build");
                var tagsField = Build.class.getDeclaredField("TAGS");
                tagsField.setAccessible(true);
                var currentTags = tagsField.get(null);
                if (currentTags && currentTags.toString().indexOf("test-keys") !== -1) {
                    tagsField.set(null, Java.use("java.lang.String").$new("release-keys"));
                }
            } catch(e) {}

            // === 7d. RootBeerNative JNI bypass ===
            _stealthSafeHook("com.scottyab.rootbeer.RootBeerNative", function(cls) {
                try {
                    cls.checkForRoot.implementation = function(paths) { return 0; };
                } catch(e) {}
            });
        });
    } catch(e) {}

    // === 8. SharedPreferences root flag interception ===
    // Many apps store root detection result in prefs (key_is_rooted, is_rooted, root_detected, etc.)
    // Intercept putBoolean to block writing true for root-related keys
    try {
        Java.perform(function() {
            var rootKeys = ["key_is_rooted", "is_rooted", "root_detected", "rooted",
                            "device_rooted", "isRooted", "isDeviceRooted"];

            _stealthSafeHook("android.app.SharedPreferencesImpl$EditorImpl", function(cls) {
                cls.putBoolean.implementation = function(key, value) {
                    for (var i = 0; i < rootKeys.length; i++) {
                        if (key === rootKeys[i] && value === true) {
                            return this.putBoolean(key, false);
                        }
                    }
                    return this.putBoolean(key, value);
                };
            });

            _stealthSafeHook("android.app.SharedPreferencesImpl", function(cls) {
                cls.getBoolean.implementation = function(key, defValue) {
                    for (var i = 0; i < rootKeys.length; i++) {
                        if (key === rootKeys[i]) {
                            return false;
                        }
                    }
                    return this.getBoolean(key, defValue);
                };
            });
        });
    } catch(e) {}

    console.log("[kahlo-stealth] Anti-detection bypass loaded");
})();
