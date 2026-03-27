"""Tests for discovery script. Requires connected rooted device."""
import json
import time

import pytest

from kahlo.device.adb import ADB
from kahlo.device.frida_server import FridaServer
from kahlo.instrument.engine import FridaEngine
from kahlo.instrument.loader import ScriptLoader
from kahlo.stealth.manager import StealthManager

TEST_PACKAGE = "com.voltmobi.yakitoriya"


class TestDiscovery:
    @pytest.fixture
    def engine(self):
        import time as _time
        adb = ADB()
        devices = adb.devices()
        assert len(devices) > 0, "No devices connected"
        adb = ADB(serial=devices[0].serial)
        fs = FridaServer(adb)
        stealth = StealthManager(adb, fs)
        # Always restart stealth to ensure clean port forwarding
        stealth.stop()
        _time.sleep(1)
        stealth.start()
        _time.sleep(2)
        eng = FridaEngine(stealth)
        yield eng
        eng.cleanup()

    def test_discovery_finds_classes(self, engine):
        loader = ScriptLoader()
        source = loader.load(["discovery"])
        results = []
        engine.spawn(
            TEST_PACKAGE,
            script_source=source,
            on_message=lambda msg, data: results.append(msg),
        )
        # Discovery script has 3s delay + class enumeration can take 8-10s
        # on devices with many loaded classes (38k+). Wait up to 30s.
        for _ in range(30):
            time.sleep(1)
            if any("class_map" in str(r.get("payload", "")) for r in results):
                break
        engine.cleanup()

        # Should have received at least one class_map message
        class_maps = [
            r for r in results
            if r.get("type") == "send" and "class_map" in str(r.get("payload", ""))
        ]
        assert len(class_maps) > 0, f"No class_map received. Got {len(results)} messages: {results[:5]}"

        # Parse and verify structure
        payload = class_maps[0].get("payload", "")
        if isinstance(payload, str):
            data = json.loads(payload)
        else:
            data = payload
        assert "data" in data
        assert "class_map" in data["data"]
        assert "stats" in data["data"]
        assert data["data"]["stats"]["total_classes"] > 0
