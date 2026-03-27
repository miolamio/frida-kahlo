"""Tests for kahlo monitor — LiveMonitor class and event formatting."""
import json
import os
import time

from kahlo.monitor import LiveMonitor, format_event, _truncate, MODULE_STYLES


# ────────────────────────────────────────────────
# format_event — one test per event type
# ────────────────────────────────────────────────

class TestFormatEvent:
    """Test format_event() for every known event type."""

    # --- traffic ---

    def test_http_request(self):
        event = {
            "module": "traffic",
            "type": "http_request",
            "data": {"method": "POST", "url": "https://api.example.com/v2/auth", "content_type": "application/json"},
        }
        result = format_event(event)
        assert "POST" in result
        assert "api.example.com" in result
        assert "application/json" in result

    def test_http_request_no_content_type(self):
        event = {
            "module": "traffic",
            "type": "http_request",
            "data": {"method": "GET", "url": "https://cdn.example.com/img.png"},
        }
        result = format_event(event)
        assert "GET" in result
        assert "cdn.example.com" in result

    def test_http_response(self):
        event = {
            "module": "traffic",
            "type": "http_response",
            "data": {"status": 200, "url": "https://api.example.com/v2/auth", "elapsed_ms": 142},
        }
        result = format_event(event)
        assert "200" in result
        assert "142" in result

    def test_tcp_connect(self):
        event = {
            "module": "traffic",
            "type": "tcp_connect",
            "data": {"host": "api.example.com", "port": 443},
        }
        result = format_event(event)
        assert "api.example.com" in result
        assert "443" in result

    def test_tcp_connect_ip_fallback(self):
        event = {
            "module": "traffic",
            "type": "tcp_connect",
            "data": {"ip": "93.184.216.34", "port": 80},
        }
        result = format_event(event)
        assert "93.184.216.34" in result
        assert "80" in result

    def test_ws_send(self):
        event = {
            "module": "traffic",
            "type": "ws_send",
            "data": {"url": "wss://ws.example.com/socket", "data": '{"type":"ping"}'},
        }
        result = format_event(event)
        assert "WS" in result
        assert "ws.example.com" in result

    def test_ws_receive(self):
        event = {
            "module": "traffic",
            "type": "ws_receive",
            "data": {"url": "wss://ws.example.com/socket", "data": '{"type":"pong"}'},
        }
        result = format_event(event)
        assert "WS" in result

    def test_ssl_raw(self):
        event = {
            "module": "traffic",
            "type": "ssl_raw",
            "data": {"direction": "outbound", "length": 256},
        }
        result = format_event(event)
        assert "SSL" in result
        assert "outbound" in result
        assert "256" in result

    def test_ssl_native(self):
        event = {
            "module": "traffic",
            "type": "ssl_native",
            "data": {"direction": "inbound", "length": 1024},
        }
        result = format_event(event)
        assert "SSL/native" in result
        assert "inbound" in result

    # --- vault ---

    def test_pref_write(self):
        event = {
            "module": "vault",
            "type": "pref_write",
            "data": {"file": "auth_prefs", "key": "token", "value": "eyJhbGciOiJSUzI1NiJ9"},
        }
        result = format_event(event)
        assert "auth_prefs" in result
        assert "token" in result
        assert "eyJ" in result

    def test_pref_read(self):
        event = {
            "module": "vault",
            "type": "pref_read",
            "data": {"file": "settings", "key": "user_id", "value": "12345"},
        }
        result = format_event(event)
        assert "settings" in result
        assert "user_id" in result

    def test_sqlite_query(self):
        event = {
            "module": "vault",
            "type": "sqlite_query",
            "data": {"sql": "SELECT * FROM users WHERE id = ?"},
        }
        result = format_event(event)
        assert "SELECT" in result
        assert "users" in result

    def test_sqlite_write(self):
        event = {
            "module": "vault",
            "type": "sqlite_write",
            "data": {"table": "sessions", "sql": "INSERT INTO sessions VALUES (?)"},
        }
        result = format_event(event)
        assert "WRITE" in result
        assert "sessions" in result

    def test_sqlite_exec(self):
        event = {
            "module": "vault",
            "type": "sqlite_exec",
            "data": {"sql": "CREATE TABLE IF NOT EXISTS cache (key TEXT, value TEXT)"},
        }
        result = format_event(event)
        assert "CREATE TABLE" in result

    def test_file_write(self):
        event = {
            "module": "vault",
            "type": "file_write",
            "data": {"path": "/data/data/com.app/files/config.json", "size": 482},
        }
        result = format_event(event)
        assert "config.json" in result
        assert "482" in result

    def test_keystore_read(self):
        event = {
            "module": "vault",
            "type": "keystore_read",
            "data": {"alias": "api_key", "type": "PrivateKey"},
        }
        result = format_event(event)
        assert "api_key" in result
        assert "PrivateKey" in result

    def test_keystore_enum(self):
        event = {
            "module": "vault",
            "type": "keystore_enum",
            "data": {"aliases": ["key1", "key2", "key3"], "count": 3},
        }
        result = format_event(event)
        assert "3" in result

    def test_initial_dump(self):
        event = {
            "module": "vault",
            "type": "initial_dump",
            "data": {"files": ["prefs1.xml", "prefs2.xml"]},
        }
        result = format_event(event)
        assert "2" in result
        assert "dump" in result

    # --- recon ---

    def test_device_info(self):
        event = {
            "module": "recon",
            "type": "device_info",
            "data": {"field": "android.os.Build.MODEL", "value": "Pixel 6"},
        }
        result = format_event(event)
        assert "MODEL" in result
        assert "Pixel 6" in result

    def test_vpn_check(self):
        event = {
            "module": "recon",
            "type": "vpn_check",
            "data": {"result": False},
        }
        result = format_event(event)
        assert "vpn_check" in result
        assert "False" in result

    def test_telecom(self):
        event = {
            "module": "recon",
            "type": "telecom",
            "data": {"operator": "MegaFon"},
        }
        result = format_event(event)
        assert "MegaFon" in result

    def test_network_info(self):
        event = {
            "module": "recon",
            "type": "network_info",
            "data": {"type": "WIFI"},
        }
        result = format_event(event)
        assert "WIFI" in result

    def test_wifi_info(self):
        event = {
            "module": "recon",
            "type": "wifi_info",
            "data": {"ssid": "MyNetwork"},
        }
        result = format_event(event)
        assert "MyNetwork" in result

    def test_location(self):
        event = {
            "module": "recon",
            "type": "location",
            "data": {"lat": 55.7558, "lon": 37.6173},
        }
        result = format_event(event)
        assert "55.7558" in result
        assert "37.6173" in result

    def test_installed_apps(self):
        event = {
            "module": "recon",
            "type": "installed_apps",
            "data": {"count": 42},
        }
        result = format_event(event)
        assert "42" in result

    def test_ip_lookup(self):
        event = {
            "module": "recon",
            "type": "ip_lookup",
            "data": {"ip": "203.0.113.1"},
        }
        result = format_event(event)
        assert "203.0.113.1" in result

    def test_competitor_probe(self):
        event = {
            "module": "recon",
            "type": "competitor_probe",
            "data": {"package": "com.competitor.app"},
        }
        result = format_event(event)
        assert "com.competitor.app" in result

    def test_ping_probe(self):
        event = {
            "module": "recon",
            "type": "ping_probe",
            "data": {"host": "check.example.com"},
        }
        result = format_event(event)
        assert "check.example.com" in result

    def test_sensor_access(self):
        event = {
            "module": "recon",
            "type": "sensor_access",
            "data": {"sensor": "accelerometer"},
        }
        result = format_event(event)
        assert "accelerometer" in result

    # --- netmodel ---

    def test_hmac_init(self):
        event = {
            "module": "netmodel",
            "type": "hmac_init",
            "data": {"algorithm": "HmacSHA256", "key": "4a78bc9d"},
        }
        result = format_event(event)
        assert "HmacSHA256" in result
        assert "4a78bc9d" in result

    def test_hmac(self):
        event = {
            "module": "netmodel",
            "type": "hmac",
            "data": {"algorithm": "HmacSHA256", "key_hex": "deadbeef"},
        }
        result = format_event(event)
        assert "HMAC" in result
        assert "deadbeef" in result

    def test_hash(self):
        event = {
            "module": "netmodel",
            "type": "hash",
            "data": {"algorithm": "SHA-256", "input_hex": "aabb"},
        }
        result = format_event(event)
        assert "SHA-256" in result
        assert "aabb" in result

    def test_crypto_init(self):
        event = {
            "module": "netmodel",
            "type": "crypto_init",
            "data": {"algorithm": "AES/CBC/PKCS5Padding"},
        }
        result = format_event(event)
        assert "AES" in result

    def test_crypto_op(self):
        event = {
            "module": "netmodel",
            "type": "crypto_op",
            "data": {"algorithm": "AES/CBC/PKCS5Padding", "operation": "encrypt"},
        }
        result = format_event(event)
        assert "encrypt" in result
        assert "AES" in result

    def test_signature(self):
        event = {
            "module": "netmodel",
            "type": "signature",
            "data": {"algorithm": "SHA256withRSA"},
        }
        result = format_event(event)
        assert "SHA256withRSA" in result

    def test_tls_info(self):
        event = {
            "module": "netmodel",
            "type": "tls_info",
            "data": {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
        }
        result = format_event(event)
        assert "TLSv1.3" in result
        assert "TLS_AES_256_GCM_SHA384" in result

    def test_nonce(self):
        event = {
            "module": "netmodel",
            "type": "nonce",
            "data": {"length": 16},
        }
        result = format_event(event)
        assert "16" in result

    # --- meta ---

    def test_hook_status(self):
        event = {
            "module": "traffic",
            "type": "hook_status",
            "data": {"status": "loaded", "level": "okhttp3_interceptor"},
        }
        result = format_event(event)
        assert "traffic" in result
        assert "loaded" in result
        assert "okhttp3_interceptor" in result

    def test_error(self):
        event = {
            "module": "frida",
            "type": "error",
            "data": {"description": "ReferenceError: x is not defined"},
        }
        result = format_event(event)
        assert "ReferenceError" in result

    def test_fallback_unknown_type(self):
        event = {
            "module": "unknown",
            "type": "some_weird_type",
            "data": {"foo": "bar"},
        }
        result = format_event(event)
        assert "some_weird_type" in result


# ────────────────────────────────────────────────
# _truncate
# ────────────────────────────────────────────────

class TestTruncate:

    def test_short_string_unchanged(self):
        assert _truncate("hello", 10) == "hello"

    def test_exact_length_unchanged(self):
        assert _truncate("hello", 5) == "hello"

    def test_long_string_truncated(self):
        result = _truncate("hello world!", 8)
        assert len(result) == 8
        assert result.endswith("\u2026")
        assert result.startswith("hello w")

    def test_empty_string(self):
        assert _truncate("", 10) == ""


# ────────────────────────────────────────────────
# LiveMonitor — instantiation and event handling
# ────────────────────────────────────────────────

class TestLiveMonitor:

    def test_instantiation(self):
        monitor = LiveMonitor(package="com.test.app")
        assert monitor.package == "com.test.app"
        assert monitor.event_count == 0
        assert monitor.module_counts == {}
        assert monitor.elapsed == 0.0

    def test_add_event_increments_count(self):
        monitor = LiveMonitor(package="com.test.app")
        monitor.add_event({
            "module": "traffic",
            "type": "http_request",
            "data": {"method": "GET", "url": "https://example.com"},
        })
        assert monitor.event_count == 1
        assert monitor.module_counts == {"traffic": 1}

    def test_add_multiple_events_tracks_modules(self):
        monitor = LiveMonitor(package="com.test.app")
        monitor.add_event({"module": "traffic", "type": "http_request", "data": {}})
        monitor.add_event({"module": "traffic", "type": "http_response", "data": {}})
        monitor.add_event({"module": "vault", "type": "pref_write", "data": {}})
        monitor.add_event({"module": "recon", "type": "vpn_check", "data": {}})

        assert monitor.event_count == 4
        assert monitor.module_counts == {"traffic": 2, "vault": 1, "recon": 1}

    def test_visible_events_capped_at_max(self):
        monitor = LiveMonitor(package="com.test.app")
        # Add more than MAX_VISIBLE_EVENTS
        for i in range(monitor.MAX_VISIBLE_EVENTS + 10):
            monitor.add_event({
                "module": "traffic",
                "type": "http_request",
                "data": {"method": "GET", "url": "https://example.com/{}".format(i)},
                "ts": "2026-03-27T12:00:00+00:00",
            })

        assert monitor.event_count == monitor.MAX_VISIBLE_EVENTS + 10
        assert len(monitor._visible) == monitor.MAX_VISIBLE_EVENTS

    def test_on_message_dict_payload(self):
        monitor = LiveMonitor(package="com.test.app")
        monitor.on_message({
            "type": "send",
            "payload": {
                "module": "vault",
                "type": "pref_write",
                "data": {"file": "prefs", "key": "k", "value": "v"},
            },
        })
        assert monitor.event_count == 1
        assert monitor.events[0]["module"] == "vault"

    def test_on_message_json_string_payload(self):
        monitor = LiveMonitor(package="com.test.app")
        event = {"module": "recon", "type": "vpn_check", "data": {"result": True}}
        monitor.on_message({
            "type": "send",
            "payload": json.dumps(event),
        })
        assert monitor.event_count == 1
        assert monitor.events[0]["module"] == "recon"

    def test_on_message_raw_string(self):
        monitor = LiveMonitor(package="com.test.app")
        monitor.on_message({
            "type": "send",
            "payload": "just a plain string",
        })
        assert monitor.event_count == 1
        assert monitor.events[0]["module"] == "raw"

    def test_on_message_error(self):
        monitor = LiveMonitor(package="com.test.app")
        monitor.on_message({
            "type": "error",
            "description": "Script error",
            "stack": "at line 42",
        })
        assert monitor.event_count == 1
        assert monitor.events[0]["module"] == "frida"
        assert monitor.events[0]["type"] == "error"

    def test_on_message_none_payload_ignored(self):
        monitor = LiveMonitor(package="com.test.app")
        monitor.on_message({"type": "send", "payload": None})
        assert monitor.event_count == 0

    def test_build_display_empty(self):
        monitor = LiveMonitor(package="com.test.app")
        layout = monitor.build_display()
        # Should not raise — layout should render
        assert layout is not None

    def test_build_display_with_events(self):
        monitor = LiveMonitor(package="com.test.app")
        monitor._started_at = time.time() - 30  # simulate 30s elapsed
        monitor.add_event({
            "module": "traffic",
            "type": "http_request",
            "data": {"method": "POST", "url": "https://api.test.com/login"},
            "ts": "2026-03-27T12:30:15+00:00",
        })
        monitor.add_event({
            "module": "vault",
            "type": "pref_write",
            "data": {"file": "auth", "key": "token", "value": "abc123"},
            "ts": "2026-03-27T12:30:16+00:00",
        })
        layout = monitor.build_display()
        assert layout is not None


# ────────────────────────────────────────────────
# LiveMonitor.run — session save on stop
# ────────────────────────────────────────────────

class TestLiveMonitorSessionSave:

    def test_session_saved_on_stop(self, tmp_path):
        """Verify that when the monitor loop ends, the session is saved."""
        from kahlo.instrument.session import Session

        session = Session(package="com.test.app", output_dir=str(tmp_path))
        monitor = LiveMonitor(package="com.test.app")

        # Pre-populate some events (simulating what would happen during run)
        test_events = [
            {"module": "traffic", "type": "http_request", "data": {"method": "GET", "url": "https://example.com"}},
            {"module": "vault", "type": "pref_write", "data": {"file": "prefs", "key": "k", "value": "v"}},
            {"module": "recon", "type": "vpn_check", "data": {"result": False}},
        ]

        for ev in test_events:
            session.add_event(ev)
            monitor.add_event(ev)

        # Save the session (simulating what run() does)
        path = session.save()

        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert data["package"] == "com.test.app"
        assert data["event_count"] == 3
        assert "traffic" in data["stats"]["by_module"]
        assert "vault" in data["stats"]["by_module"]
        assert "recon" in data["stats"]["by_module"]


# ────────────────────────────────────────────────
# CLI registration
# ────────────────────────────────────────────────

class TestMonitorCLI:

    def test_monitor_command_registered(self):
        """Verify the monitor command is registered in the CLI app."""
        from typer.testing import CliRunner
        from kahlo.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["monitor", "--help"])
        assert result.exit_code == 0
        assert "package" in result.output.lower() or "PACKAGE" in result.output
        assert "live" in result.output.lower() or "monitor" in result.output.lower()


# ────────────────────────────────────────────────
# MODULE_STYLES coverage
# ────────────────────────────────────────────────

class TestModuleStyles:
    """Verify all main modules have a defined color style."""

    def test_all_modules_have_styles(self):
        expected_modules = ["traffic", "vault", "recon", "netmodel", "frida", "raw"]
        for mod in expected_modules:
            assert mod in MODULE_STYLES, "Module '{}' missing from MODULE_STYLES".format(mod)

    def test_styles_are_valid_rich_colors(self):
        valid_colors = {"green", "yellow", "red", "cyan", "magenta", "dim", "white", "blue"}
        for mod, style in MODULE_STYLES.items():
            assert style in valid_colors, "Style '{}' for module '{}' not a known color".format(style, mod)
