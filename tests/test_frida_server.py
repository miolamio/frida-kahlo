"""Tests for frida-server lifecycle. Requires connected rooted device."""
import pytest
from kahlo.device.adb import ADB
from kahlo.device.frida_server import FridaServer


@pytest.fixture
def fs():
    adb = ADB()
    return FridaServer(adb)


class TestFridaServerStatus:
    def test_server_exists_on_device(self, fs):
        assert fs.is_installed()

    def test_server_version(self, fs):
        # frida-server binary exists at expected path
        assert fs.server_path is not None


class TestFridaServerLifecycle:
    def test_ensure_starts_server(self, fs):
        fs.ensure()
        assert fs.is_running()

    def test_stop_server(self, fs):
        fs.ensure()
        assert fs.is_running()
        fs.stop()
        assert not fs.is_running()

    def test_ensure_is_idempotent(self, fs):
        fs.ensure()
        fs.ensure()  # second call should not fail
        assert fs.is_running()

    def test_start_on_custom_port(self, fs):
        fs.stop()
        fs.start(port=47293)
        assert fs.is_running()
        fs.stop()
