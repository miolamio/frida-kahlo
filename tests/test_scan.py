"""Integration test for kahlo scan command. Requires connected rooted device."""
import json
import os
import time

import pytest

from kahlo.device.adb import ADB
from kahlo.device.frida_server import FridaServer
from kahlo.instrument.engine import FridaEngine
from kahlo.instrument.loader import ScriptLoader
from kahlo.instrument.session import Session
from kahlo.stealth.manager import StealthManager

TEST_PACKAGE = "com.voltmobi.yakitoriya"
SCAN_DURATION = 25


class TestScanIntegration:
    """Full integration test: load all hooks, spawn app, collect events."""

    @pytest.fixture
    def engine(self):
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

    def test_full_scan_collects_events(self, engine, tmp_path):
        """Run a full scan with all hooks and verify events are collected."""
        loader = ScriptLoader()

        # Compose full script (same as kahlo scan does)
        source = loader.compose(
            bypass=["bypass/stealth", "bypass/ssl_unpin"],
            hooks=["common", "hooks/traffic", "hooks/vault", "hooks/recon", "hooks/netmodel", "discovery"],
        )

        session = Session(package=TEST_PACKAGE, output_dir=str(tmp_path))

        # Spawn
        pid = engine.spawn(
            TEST_PACKAGE,
            script_source=source,
            on_message=session.on_message,
        )
        assert pid > 0

        # Collect for SCAN_DURATION seconds
        time.sleep(SCAN_DURATION)

        # Cleanup
        engine.cleanup()

        # Save session
        path = session.save()
        assert os.path.exists(path)

        # Load and verify
        with open(path) as f:
            data = json.load(f)

        assert data["package"] == TEST_PACKAGE
        assert data["event_count"] > 0, "No events collected!"

        # Should have events from multiple modules
        modules = set(e.get("module") for e in data["events"])
        # At minimum we expect hook_status events from all modules
        assert "traffic" in modules or "vault" in modules or "recon" in modules, \
            f"Expected events from analysis modules, got: {modules}"

        # Verify stats are included
        assert "stats" in data
        assert data["stats"]["total"] == data["event_count"]

        # Print summary for test output
        print(f"\n=== SCAN RESULTS ===")
        print(f"Events collected: {data['event_count']}")
        print(f"Modules: {data['stats']['by_module']}")
        if data['stats'].get('unique_endpoints'):
            print(f"Endpoints: {data['stats']['unique_endpoints'][:10]}")

    def test_scan_cli_command_exists(self):
        """Verify the scan command is registered in the CLI app."""
        from typer.testing import CliRunner
        from kahlo.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "duration" in result.output
        assert "package" in result.output.lower() or "PACKAGE" in result.output
