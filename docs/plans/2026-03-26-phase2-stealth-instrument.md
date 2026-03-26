# Phase 2: Stealth + Instrument — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the stealth layer (anti-detection bypass scripts) and Frida instrumentation engine that can spawn an app, inject scripts, and collect structured JSON events. Test everything against 2GIS on real device.

**Architecture:** Stealth Layer wraps frida-server startup with port randomization and bypass script injection. Instrument Engine uses frida-python to spawn/attach to apps, inject composed JS scripts, and collect events via `on('message')` callback into a Session object. Discovery script auto-detects HTTP/WS/crypto classes.

**Tech Stack:** Python (frida-python, pydantic), JavaScript (Frida GumJS API)

**Test app:** 2GIS (`ru.dublgis.dgismobile`) — must be installed first.

---

### Task 1: Install 2GIS on Device

**Step 1: Check if 2GIS is available on APKMirror or device**

We need to get 2GIS APK and install it. Use Playwright or manual download.
If Playwright is complex for now, download manually via curl/wget from a direct link, or use an existing APK.

Run: `adb shell pm list packages | grep dgis`
If not installed, we need to acquire the APK.

Alternative: use `com.voltmobi.yakitoriya` (already installed) for initial testing, install 2GIS in Phase 5 when Acquire module is ready.

**Decision:** Use yakitoriya for Phase 2 testing (already installed, has network activity). Switch to 2GIS in Phase 5.

**Step 2: Verify yakitoriya launches**

Run: `frida -U -f com.voltmobi.yakitoriya --no-pause -e "console.log('ok')" --timeout=10`
Expected: App launches, prints "ok", no crash

---

### Task 2: Stealth Layer — Port Randomization + Manager

**Files:**
- Create: `kahlo/stealth/__init__.py`
- Create: `kahlo/stealth/port.py`
- Create: `kahlo/stealth/manager.py`
- Create: `kahlo/stealth/checker.py`
- Create: `tests/test_stealth.py`

**Step 1: Write tests**

```python
# tests/test_stealth.py
import pytest
from kahlo.stealth.port import random_port
from kahlo.stealth.manager import StealthManager, StealthLevel
from kahlo.device.adb import ADB
from kahlo.device.frida_server import FridaServer


def test_random_port_in_range():
    port = random_port()
    assert 10000 <= port <= 60000


def test_random_port_not_27042():
    # Generate 100 ports, none should be 27042
    ports = [random_port() for _ in range(100)]
    assert 27042 not in ports


class TestStealthManager:
    @pytest.fixture
    def manager(self):
        adb = ADB()
        devices = adb.devices()
        adb = ADB(serial=devices[0].serial)
        fs = FridaServer(adb)
        return StealthManager(adb, fs)

    def test_initial_level(self, manager):
        assert manager.level == StealthLevel.BASIC

    def test_start_stealth_server(self, manager):
        manager.start()
        assert manager.fs.is_running()
        assert manager.port is not None
        assert manager.port != 27042
        manager.stop()

    def test_escalate(self, manager):
        manager.escalate()
        assert manager.level == StealthLevel.BYPASS
```

**Step 2: Implement stealth modules**

```python
# kahlo/stealth/port.py
import random

def random_port(low: int = 10000, high: int = 60000, exclude: set[int] | None = None) -> int:
    exclude = exclude or {27042, 27043}
    while True:
        port = random.randint(low, high)
        if port not in exclude:
            return port
```

```python
# kahlo/stealth/manager.py
from __future__ import annotations
from enum import IntEnum
from kahlo.device.adb import ADB
from kahlo.device.frida_server import FridaServer
from kahlo.stealth.port import random_port


class StealthLevel(IntEnum):
    BASIC = 1      # random port + renamed binary
    BYPASS = 2     # + bypass JS scripts
    HLUDA = 3      # + custom frida build (manual)
    GADGET = 4     # frida-gadget (no server process)


class StealthManager:
    def __init__(self, adb: ADB, fs: FridaServer):
        self.adb = adb
        self.fs = fs
        self.level = StealthLevel.BASIC
        self.port: int | None = None

    def start(self) -> None:
        self.port = random_port()
        self.fs.stop()
        self.fs.start(port=self.port)

    def stop(self) -> None:
        self.fs.stop()
        self.port = None

    def escalate(self) -> None:
        if self.level < StealthLevel.GADGET:
            self.level = StealthLevel(self.level + 1)

    def get_bypass_scripts(self) -> list[str]:
        """Return list of JS bypass script paths based on current level."""
        import os
        scripts_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'scripts', 'bypass')
        scripts = []
        if self.level >= StealthLevel.BYPASS:
            stealth_path = os.path.join(scripts_dir, 'stealth.js')
            if os.path.exists(stealth_path):
                scripts.append(stealth_path)
            unpin_path = os.path.join(scripts_dir, 'ssl_unpin.js')
            if os.path.exists(unpin_path):
                scripts.append(unpin_path)
        return scripts
```

```python
# kahlo/stealth/checker.py
from __future__ import annotations
import frida
import time


def check_detection(package: str, device_id: str | None = None, port: int | None = None) -> dict:
    """Spawn app briefly, check if it crashes (sign of Frida detection)."""
    try:
        if port:
            manager = frida.get_device_manager()
            device = manager.add_remote_device(f"127.0.0.1:{port}")
        elif device_id:
            device = frida.get_usb_device()
        else:
            device = frida.get_usb_device()

        pid = device.spawn([package])
        device.resume(pid)
        time.sleep(3)

        # Check if process still alive
        try:
            session = device.attach(pid)
            session.detach()
            device.kill(pid)
            return {"detected": False, "status": "clean"}
        except frida.ProcessNotFoundError:
            return {"detected": True, "status": "crashed", "detail": "App crashed within 3s — likely Frida detection"}

    except Exception as e:
        return {"detected": None, "status": "error", "detail": str(e)}
```

**Step 3: Run tests, verify pass**

Run: `pytest tests/test_stealth.py -v --timeout=30`

**Step 4: Commit**

---

### Task 3: Bypass Scripts (JS)

**Files:**
- Create: `scripts/bypass/stealth.js`
- Create: `scripts/bypass/ssl_unpin.js`
- Create: `scripts/common.js`

**Step 1: Create common.js — shared utilities**

```javascript
// scripts/common.js
// Shared utilities for all Frida-Kahlo scripts

function sendEvent(module, type, data) {
    send(JSON.stringify({
        ts: new Date().toISOString(),
        module: module,
        type: type,
        data: data
    }));
}

function safeHook(className, callback) {
    try {
        var clazz = Java.use(className);
        callback(clazz);
        return true;
    } catch (e) {
        return false;
    }
}

function stackTrace() {
    try {
        return Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new())
            .substring(0, 500);
    } catch (e) {
        return "";
    }
}

function readableBytes(buf, off, len, maxLen) {
    maxLen = maxLen || 4096;
    var output = "";
    var end = Math.min(len, maxLen);
    for (var i = 0; i < end; i++) {
        var b = buf[off + i] & 0xFF;
        output += (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".";
    }
    return output;
}

function detectFormat(bytes, len) {
    if (len < 1) return "empty";
    var first = bytes[0] & 0xFF;
    if (first === 0x7B || first === 0x5B) return "json";         // { or [
    if (first === 0x08 || first === 0x0A) return "protobuf";     // common tags
    if (first >= 0x80 && first <= 0x8F) return "msgpack_map";
    if (first >= 0x90 && first <= 0x9F) return "msgpack_array";
    if (first === 0x1F && len > 1 && (bytes[1] & 0xFF) === 0x8B) return "gzip";
    return "binary";
}
```

**Step 2: Create stealth.js — unified anti-detection**

```javascript
// scripts/bypass/stealth.js
// Frida-Kahlo Stealth Layer — anti-Frida + anti-root bypass
// Loaded FIRST before any analysis hooks

(function() {
    // === 1. /proc/self/maps filtering ===
    // Hide frida-agent.so from maps reading
    var openPtr = Module.findExportByName("libc.so", "open");
    var readPtr = Module.findExportByName("libc.so", "read");

    var mapsfd = -1;

    if (openPtr) {
        Interceptor.attach(openPtr, {
            onEnter: function(args) {
                var path = args[0].readCString();
                this.isMaps = (path && path.indexOf("/proc") !== -1 &&
                               path.indexOf("maps") !== -1);
            },
            onLeave: function(retval) {
                if (this.isMaps) {
                    mapsfd = retval.toInt32();
                }
            }
        });
    }

    if (readPtr) {
        Interceptor.attach(readPtr, {
            onLeave: function(retval) {
                if (this.fd === mapsfd && retval.toInt32() > 0) {
                    try {
                        var buf = this.buf;
                        var content = buf.readCString();
                        if (content && content.indexOf("frida") !== -1) {
                            // Filter out frida lines
                            var filtered = content.split("\n")
                                .filter(function(line) {
                                    return line.indexOf("frida") === -1 &&
                                           line.indexOf("gum-js") === -1 &&
                                           line.indexOf("gmain") === -1;
                                }).join("\n");
                            buf.writeUtf8String(filtered);
                        }
                    } catch(e) {}
                }
            },
            onEnter: function(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
            }
        });
    }

    // === 2. File existence hiding ===
    var accessPtr = Module.findExportByName("libc.so", "access");
    var statPtr = Module.findExportByName("libc.so", "stat");

    var hiddenPaths = ["frida", "magisk", "/su", "supersu", "busybox",
                       "daemonsu", "Superuser", "titanium"];

    function shouldHide(path) {
        if (!path) return false;
        for (var i = 0; i < hiddenPaths.length; i++) {
            if (path.indexOf(hiddenPaths[i]) !== -1) return true;
        }
        return false;
    }

    if (accessPtr) {
        Interceptor.attach(accessPtr, {
            onEnter: function(args) {
                var path = args[0].readCString();
                if (shouldHide(path)) {
                    args[0] = Memory.allocUtf8String("/nonexistent_kahlo");
                }
            }
        });
    }

    // === 3. Port scan blocking ===
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
                            // Redirect to invalid address
                            sa.add(4).writeU32(0x00000000); // 0.0.0.0
                        }
                    }
                } catch(e) {}
            }
        });
    }

    // === 4. ptrace bypass ===
    var ptracePtr = Module.findExportByName("libc.so", "ptrace");
    if (ptracePtr) {
        Interceptor.replace(ptracePtr, new NativeCallback(function(request, pid, addr, data) {
            if (request === 0) return 0; // PTRACE_TRACEME → success
            return -1;
        }, 'long', ['int', 'int', 'pointer', 'pointer']));
    }

    // === 5. Java-level root & Frida detection bypass ===
    Java.perform(function() {

        // RootBeer bypass
        safeHook("com.scottyab.rootbeer.RootBeer", function(cls) {
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

        // Generic root check patterns
        safeHook("java.io.File", function(cls) {
            cls.exists.implementation = function() {
                var path = this.getAbsolutePath();
                if (shouldHide(path)) return false;
                return this.exists.call(this);
            };
        });

        // PackageManager — hide Magisk/SuperSU
        safeHook("android.app.ApplicationPackageManager", function(cls) {
            cls.getPackageInfo.overload('java.lang.String', 'int').implementation = function(name, flags) {
                if (name === "com.topjohnwu.magisk" || name === "eu.chainfire.supersu" ||
                    name === "me.weishu.kernelsu") {
                    throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
                }
                return this.getPackageInfo(name, flags);
            };
        });
    });

    // Helper used above
    function safeHook(className, callback) {
        try {
            var clazz = Java.use(className);
            callback(clazz);
        } catch (e) {}
    }
})();
```

**Step 3: Create ssl_unpin.js — universal SSL unpinning**

Based on httptoolkit/frida-interception-and-unpinning patterns:

```javascript
// scripts/bypass/ssl_unpin.js
// Universal SSL certificate pinning bypass
// Covers: OkHttp, TrustManager, Conscrypt, WebView, NetworkSecurityConfig

Java.perform(function() {

    // === 1. OkHttp3 CertificatePinner ===
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
            return; // no-op
        };
        try {
            CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function() {
                return;
            };
        } catch(e) {}
    } catch(e) {}

    // === 2. TrustManagerImpl (Android system) ===
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain) {
            return untrustedChain;
        };
    } catch(e) {}

    // === 3. Custom X509TrustManager ===
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var TrustManager = Java.use("javax.net.ssl.TrustManager");

        var EmptyTrustManager = Java.registerClass({
            name: "com.kahlo.EmptyTrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function() {},
                checkServerTrusted: function() {},
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
    } catch(e) {}

    // === 4. OkHttp3 HostnameVerifier ===
    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        var OkHostnameVerifier = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
        OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
            .implementation = function() { return true; };
    } catch(e) {}

    // === 5. WebViewClient SSL errors ===
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            handler.proceed();
        };
    } catch(e) {}

    // === 6. HttpsURLConnection default verifier ===
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
            // no-op — don't let app set custom verifier
        };
    } catch(e) {}
});
```

**Step 4: Verify scripts load without errors on device**

Run: `frida -U -f com.voltmobi.yakitoriya -l scripts/bypass/stealth.js --no-pause --timeout=10`
Expected: App launches, no script errors

Run: `frida -U -f com.voltmobi.yakitoriya -l scripts/bypass/ssl_unpin.js --no-pause --timeout=10`
Expected: App launches, SSL unpin hooks set

**Step 5: Commit**

---

### Task 4: Frida Instrument Engine

**Files:**
- Create: `kahlo/instrument/__init__.py`
- Create: `kahlo/instrument/engine.py`
- Create: `kahlo/instrument/loader.py`
- Create: `kahlo/instrument/session.py`
- Create: `tests/test_instrument.py`

**Step 1: Write tests**

```python
# tests/test_instrument.py
import pytest
import time
import json
from pathlib import Path
from kahlo.device.adb import ADB
from kahlo.device.frida_server import FridaServer
from kahlo.stealth.manager import StealthManager
from kahlo.instrument.engine import FridaEngine
from kahlo.instrument.loader import ScriptLoader
from kahlo.instrument.session import Session

TEST_PACKAGE = "com.voltmobi.yakitoriya"


@pytest.fixture
def engine():
    adb = ADB()
    devices = adb.devices()
    adb = ADB(serial=devices[0].serial)
    fs = FridaServer(adb)
    fs.ensure()
    stealth = StealthManager(adb, fs)
    eng = FridaEngine(stealth)
    yield eng
    eng.cleanup()


class TestScriptLoader:
    def test_load_common(self):
        loader = ScriptLoader()
        source = loader.load(["common"])
        assert "sendEvent" in source

    def test_load_bypass(self):
        loader = ScriptLoader()
        source = loader.load(["bypass/stealth"])
        assert "proc" in source.lower() or "frida" in source.lower()

    def test_compose(self):
        loader = ScriptLoader()
        source = loader.compose(
            bypass=["bypass/stealth"],
            hooks=[]
        )
        assert len(source) > 100


class TestFridaEngine:
    def test_spawn_and_detach(self, engine):
        engine.spawn(TEST_PACKAGE)
        assert engine.is_attached
        engine.cleanup()
        assert not engine.is_attached

    def test_spawn_with_script(self, engine):
        script_source = 'Java.perform(function() { send("hello"); });'
        messages = []
        engine.spawn(TEST_PACKAGE, script_source=script_source,
                     on_message=lambda msg, data: messages.append(msg))
        time.sleep(2)
        engine.cleanup()
        assert any("hello" in str(m) for m in messages)


class TestSession:
    def test_create_session(self, tmp_path):
        session = Session(package="com.test.app", output_dir=str(tmp_path))
        assert session.session_id is not None
        assert "com.test.app" in session.session_id

    def test_add_event(self, tmp_path):
        session = Session(package="com.test.app", output_dir=str(tmp_path))
        session.add_event({"module": "traffic", "type": "http_request", "data": {"url": "https://example.com"}})
        assert len(session.events) == 1

    def test_save(self, tmp_path):
        session = Session(package="com.test.app", output_dir=str(tmp_path))
        session.add_event({"module": "test", "type": "test", "data": {}})
        path = session.save()
        assert Path(path).exists()
        with open(path) as f:
            data = json.load(f)
        assert len(data["events"]) == 1
```

**Step 2: Implement engine, loader, session**

engine.py — Frida spawn/attach/inject wrapper
loader.py — loads JS files from scripts/ directory, composes bypass + hooks
session.py — collects events into list, saves as JSON

**Step 3: Run tests**

Run: `pytest tests/test_instrument.py -v --timeout=60`
Expected: All pass

**Step 4: Commit**

---

### Task 5: Discovery Script

**Files:**
- Create: `scripts/discovery.js`
- Create: `tests/test_discovery.py`

**Step 1: Create discovery.js**

Enumerates loaded classes, finds: OkHttp, Retrofit, WebSocket, gRPC, crypto, analytics.
Sends result as JSON via send().

**Step 2: Test discovery on yakitoriya**

```python
# tests/test_discovery.py
import pytest
import time
import json
from kahlo.device.adb import ADB
from kahlo.device.frida_server import FridaServer
from kahlo.stealth.manager import StealthManager
from kahlo.instrument.engine import FridaEngine
from kahlo.instrument.loader import ScriptLoader

TEST_PACKAGE = "com.voltmobi.yakitoriya"


class TestDiscovery:
    @pytest.fixture
    def engine(self):
        adb = ADB()
        devices = adb.devices()
        adb = ADB(serial=devices[0].serial)
        fs = FridaServer(adb)
        fs.ensure()
        stealth = StealthManager(adb, fs)
        eng = FridaEngine(stealth)
        yield eng
        eng.cleanup()

    def test_discovery_finds_classes(self, engine):
        loader = ScriptLoader()
        source = loader.load(["discovery"])
        results = []
        engine.spawn(TEST_PACKAGE, script_source=source,
                     on_message=lambda msg, data: results.append(msg))
        time.sleep(8)  # discovery needs time to enumerate
        engine.cleanup()

        # Should have received at least one class_map message
        class_maps = [r for r in results
                      if r.get("type") == "send" and "class_map" in str(r.get("payload", ""))]
        assert len(class_maps) > 0
```

**Step 3: Run and verify**

Run: `pytest tests/test_discovery.py -v --timeout=60`

**Step 4: Commit**

---

### Task 6: CLI Stealth Commands + Integration Test

**Files:**
- Modify: `kahlo/cli.py` — add `stealth check` and `stealth escalate` commands

**Step 1: Add stealth commands to CLI**

- `kahlo stealth-check <package>` — spawn app, check if it crashes
- `kahlo frida-start` — start frida-server with stealth (random port)
- `kahlo frida-stop` — stop frida-server

**Step 2: Full integration test on device**

Run sequence:
1. `kahlo device` — verify device connected
2. `kahlo frida-start` — start stealth frida
3. `kahlo stealth-check com.voltmobi.yakitoriya` — verify no detection
4. Manually: spawn yakitoriya with discovery script, verify class enumeration
5. `kahlo frida-stop` — cleanup

**Step 3: Final commit for Phase 2**
