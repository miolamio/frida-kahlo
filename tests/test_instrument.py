"""Tests for Frida instrument engine. Requires connected rooted device."""
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


@pytest.fixture
def engine():
    import time
    adb = ADB()
    devices = adb.devices()
    assert len(devices) > 0, "No devices connected"
    adb = ADB(serial=devices[0].serial)
    fs = FridaServer(adb)
    # Stop any leftover frida-server from previous tests, then start fresh
    if not fs.is_running():
        fs.start()
        time.sleep(1)
    stealth = StealthManager(adb, fs)
    eng = FridaEngine(stealth)
    yield eng
    eng.cleanup()


class TestScriptLoader:
    def test_load_common(self):
        loader = ScriptLoader()
        source = loader.load(["common"])
        assert "sendEvent" in source
        assert "safeHook" in source
        assert "detectFormat" in source

    def test_load_bypass(self):
        loader = ScriptLoader()
        source = loader.load(["bypass/stealth"])
        assert "proc" in source.lower() or "frida" in source.lower()

    def test_load_ssl_unpin(self):
        loader = ScriptLoader()
        source = loader.load(["bypass/ssl_unpin"])
        assert "CertificatePinner" in source or "TrustManager" in source

    def test_compose(self):
        loader = ScriptLoader()
        source = loader.compose(
            bypass=["bypass/stealth"],
            hooks=[],
        )
        assert len(source) > 100

    def test_compose_with_extra(self):
        loader = ScriptLoader()
        source = loader.compose(
            bypass=["bypass/stealth"],
            extra_source='console.log("extra");',
        )
        assert "extra" in source
        assert "BYPASS" in source

    def test_list_scripts(self):
        loader = ScriptLoader()
        scripts = loader.list_scripts()
        assert "common" in scripts
        assert "bypass/stealth" in scripts
        assert "bypass/ssl_unpin" in scripts
        assert "discovery" in scripts

    def test_list_bypass_scripts(self):
        loader = ScriptLoader()
        scripts = loader.list_scripts(category="bypass")
        assert len(scripts) >= 2


class TestFridaEngine:
    def test_spawn_and_detach(self, engine):
        engine.spawn(TEST_PACKAGE)
        assert engine.is_attached
        engine.cleanup()
        assert not engine.is_attached

    def test_spawn_with_script(self, engine):
        script_source = 'Java.perform(function() { send("hello"); });'
        messages = []
        engine.spawn(
            TEST_PACKAGE,
            script_source=script_source,
            on_message=lambda msg, data: messages.append(msg),
        )
        time.sleep(3)
        engine.cleanup()
        assert any("hello" in str(m) for m in messages)


class TestSession:
    def test_create_session(self, tmp_path):
        session = Session(package="com.test.app", output_dir=str(tmp_path))
        assert session.session_id is not None
        assert "com.test.app" in session.session_id

    def test_add_event(self, tmp_path):
        session = Session(package="com.test.app", output_dir=str(tmp_path))
        session.add_event({
            "module": "traffic",
            "type": "http_request",
            "data": {"url": "https://example.com"},
        })
        assert len(session.events) == 1
        assert session.events[0]["module"] == "traffic"

    def test_add_event_auto_timestamp(self, tmp_path):
        session = Session(package="com.test.app", output_dir=str(tmp_path))
        session.add_event({"module": "test", "type": "test", "data": {}})
        assert "ts" in session.events[0]

    def test_on_message_send(self, tmp_path):
        session = Session(package="com.test.app", output_dir=str(tmp_path))
        msg = {"type": "send", "payload": '{"module":"test","type":"event","data":{}}'}
        session.on_message(msg, None)
        assert len(session.events) == 1
        assert session.events[0]["module"] == "test"

    def test_on_message_raw_string(self, tmp_path):
        session = Session(package="com.test.app", output_dir=str(tmp_path))
        msg = {"type": "send", "payload": "just a string"}
        session.on_message(msg, None)
        assert len(session.events) == 1
        assert session.events[0]["module"] == "raw"

    def test_on_message_error(self, tmp_path):
        session = Session(package="com.test.app", output_dir=str(tmp_path))
        msg = {"type": "error", "description": "ReferenceError", "stack": "..."}
        session.on_message(msg, None)
        assert len(session.events) == 1
        assert session.events[0]["type"] == "error"

    def test_save(self, tmp_path):
        session = Session(package="com.test.app", output_dir=str(tmp_path))
        session.add_event({"module": "test", "type": "test", "data": {}})
        path = session.save()
        assert path.endswith(".json")
        with open(path) as f:
            data = json.load(f)
        assert len(data["events"]) == 1
        assert data["package"] == "com.test.app"
        assert data["event_count"] == 1

    def test_save_creates_directory(self, tmp_path):
        outdir = str(tmp_path / "nested" / "sessions")
        session = Session(package="com.test.app", output_dir=outdir)
        session.add_event({"module": "test", "type": "test", "data": {}})
        path = session.save()
        assert path.endswith(".json")
