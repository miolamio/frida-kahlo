"""Tests for hook scripts — syntax validation and basic device loading."""
import json
import time

import pytest

from kahlo.device.adb import ADB
from kahlo.device.frida_server import FridaServer
from kahlo.instrument.engine import FridaEngine
from kahlo.instrument.loader import ScriptLoader
from kahlo.instrument.session import Session
from kahlo.stealth.manager import StealthManager

TEST_PACKAGE = "com.voltmobi.yakitoriya"


@pytest.fixture(scope="module")
def engine():
    """Shared engine fixture for all hook tests (module-scoped to reduce spawn overhead)."""
    adb = ADB()
    devices = adb.devices()
    assert len(devices) > 0, "No devices connected"
    adb = ADB(serial=devices[0].serial)
    fs = FridaServer(adb)
    if not fs.is_running():
        fs.start()
        time.sleep(1)
    stealth = StealthManager(adb, fs)
    eng = FridaEngine(stealth)
    yield eng
    eng.cleanup()


class TestHookScriptSyntax:
    """Verify each hook script loads without JS syntax errors."""

    def _load_and_run(self, engine, hook_name, wait_sec=10):
        """Load common + a hook script, spawn app, collect messages."""
        loader = ScriptLoader()
        source = loader.compose(
            bypass=["bypass/stealth"],
            hooks=["common", f"hooks/{hook_name}"],
        )

        session = Session(package=TEST_PACKAGE)
        engine.spawn(
            TEST_PACKAGE,
            script_source=source,
            on_message=session.on_message,
        )
        time.sleep(wait_sec)
        engine.cleanup()
        return session

    def test_traffic_loads(self, engine):
        session = self._load_and_run(engine, "traffic", wait_sec=8)
        # Should have at least a hook_status event
        status_events = [
            e for e in session.events
            if e.get("module") == "traffic" and e.get("type") == "hook_status"
        ]
        assert len(status_events) > 0, f"No traffic hook_status events. Got: {session.events[:5]}"
        # Check no fatal JS errors
        errors = [e for e in session.events if e.get("module") == "frida" and e.get("type") == "error"]
        # Some non-fatal errors are ok (class not found, etc.), but there should not be syntax errors
        syntax_errors = [e for e in errors if "SyntaxError" in str(e.get("data", {}))]
        assert len(syntax_errors) == 0, f"Syntax errors: {syntax_errors}"

    def test_vault_loads(self, engine):
        session = self._load_and_run(engine, "vault", wait_sec=8)
        status_events = [
            e for e in session.events
            if e.get("module") == "vault" and e.get("type") == "hook_status"
        ]
        assert len(status_events) > 0, f"No vault hook_status events. Got: {session.events[:5]}"
        errors = [e for e in session.events if "SyntaxError" in str(e.get("data", {}))]
        assert len(errors) == 0, f"Syntax errors: {errors}"

    def test_recon_loads(self, engine):
        session = self._load_and_run(engine, "recon", wait_sec=8)
        status_events = [
            e for e in session.events
            if e.get("module") == "recon" and e.get("type") == "hook_status"
        ]
        assert len(status_events) > 0, f"No recon hook_status events. Got: {session.events[:5]}"
        errors = [e for e in session.events if "SyntaxError" in str(e.get("data", {}))]
        assert len(errors) == 0, f"Syntax errors: {errors}"

    def test_netmodel_loads(self, engine):
        session = self._load_and_run(engine, "netmodel", wait_sec=8)
        status_events = [
            e for e in session.events
            if e.get("module") == "netmodel" and e.get("type") == "hook_status"
        ]
        assert len(status_events) > 0, f"No netmodel hook_status events. Got: {session.events[:5]}"
        errors = [e for e in session.events if "SyntaxError" in str(e.get("data", {}))]
        assert len(errors) == 0, f"Syntax errors: {errors}"


class TestHookComposition:
    """Test that all hooks can be loaded together without conflicts."""

    def test_all_hooks_together(self, engine):
        loader = ScriptLoader()
        source = loader.compose(
            bypass=["bypass/stealth", "bypass/ssl_unpin"],
            hooks=["common", "hooks/traffic", "hooks/vault", "hooks/recon", "hooks/netmodel"],
        )

        session = Session(package=TEST_PACKAGE)
        engine.spawn(
            TEST_PACKAGE,
            script_source=source,
            on_message=session.on_message,
        )
        time.sleep(12)
        engine.cleanup()

        # Should have hook_status from all 4 modules
        modules_loaded = set()
        for e in session.events:
            if e.get("type") == "hook_status":
                modules_loaded.add(e.get("module"))

        assert "traffic" in modules_loaded, f"Traffic not loaded. Modules: {modules_loaded}"
        assert "vault" in modules_loaded, f"Vault not loaded. Modules: {modules_loaded}"
        assert "recon" in modules_loaded, f"Recon not loaded. Modules: {modules_loaded}"
        assert "netmodel" in modules_loaded, f"Netmodel not loaded. Modules: {modules_loaded}"

    def test_script_loader_finds_hooks(self):
        loader = ScriptLoader()
        scripts = loader.list_scripts()
        assert "hooks/traffic" in scripts
        assert "hooks/vault" in scripts
        assert "hooks/recon" in scripts
        assert "hooks/netmodel" in scripts


class TestSessionStats:
    """Test session event_stats method."""

    def test_event_stats_basic(self):
        session = Session(package="test", output_dir="/tmp/test_sessions")
        session.add_event({"module": "traffic", "type": "http_request", "data": {"url": "https://a.com/api"}})
        session.add_event({"module": "traffic", "type": "http_response", "data": {"url": "https://a.com/api"}})
        session.add_event({"module": "vault", "type": "pref_read", "data": {}})

        stats = session.event_stats()
        assert stats["total"] == 3
        assert stats["by_module"]["traffic"] == 2
        assert stats["by_module"]["vault"] == 1
        assert "https://a.com/api" in stats["unique_endpoints"]

    def test_event_stats_empty(self):
        session = Session(package="test", output_dir="/tmp/test_sessions")
        stats = session.event_stats()
        assert stats["total"] == 0
