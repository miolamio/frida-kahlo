"""Tests for stealth layer. Requires connected rooted device."""
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
    assert 27043 not in ports


def test_random_port_custom_range():
    port = random_port(low=50000, high=50010)
    assert 50000 <= port <= 50010


class TestStealthManager:
    @pytest.fixture
    def manager(self):
        adb = ADB()
        devices = adb.devices()
        assert len(devices) > 0, "No devices connected"
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
        assert manager.port != 27043
        manager.stop()

    def test_stop_stealth_server(self, manager):
        manager.start()
        assert manager.fs.is_running()
        manager.stop()
        assert not manager.fs.is_running()
        assert manager.port is None

    def test_escalate(self, manager):
        assert manager.level == StealthLevel.BASIC
        manager.escalate()
        assert manager.level == StealthLevel.BYPASS
        manager.escalate()
        assert manager.level == StealthLevel.HLUDA
        manager.escalate()
        assert manager.level == StealthLevel.GADGET
        # Should not escalate beyond GADGET
        manager.escalate()
        assert manager.level == StealthLevel.GADGET

    def test_bypass_scripts_at_basic_level(self, manager):
        # At BASIC level, no bypass scripts
        scripts = manager.get_bypass_scripts()
        assert len(scripts) == 0

    def test_bypass_scripts_at_bypass_level(self, manager):
        manager.level = StealthLevel.BYPASS
        scripts = manager.get_bypass_scripts()
        assert len(scripts) >= 1
        assert any("stealth.js" in s for s in scripts)
