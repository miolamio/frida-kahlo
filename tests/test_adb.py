"""Tests for ADB wrapper. Requires connected Android device."""
import pytest
from kahlo.device.adb import ADB


@pytest.fixture
def adb():
    return ADB()


class TestADBDevices:
    def test_devices_returns_list(self, adb):
        devices = adb.devices()
        assert isinstance(devices, list)

    def test_at_least_one_device(self, adb):
        devices = adb.devices()
        assert len(devices) >= 1

    def test_device_has_serial(self, adb):
        devices = adb.devices()
        assert any(d.serial == "28e37107" for d in devices)


class TestADBShell:
    def test_shell_whoami(self, adb):
        result = adb.shell("whoami")
        assert "shell" in result or "root" in result

    def test_shell_su(self, adb):
        result = adb.shell("whoami", su=True)
        assert "root" in result

    def test_shell_getprop(self, adb):
        result = adb.shell("getprop ro.product.model")
        assert len(result) > 0


class TestADBDeviceInfo:
    def test_device_info_model(self, adb):
        info = adb.get_device_info()
        assert info.model == "Redmi Note 5A"

    def test_device_info_rooted(self, adb):
        info = adb.get_device_info()
        assert info.rooted is True

    def test_device_info_android_version(self, adb):
        info = adb.get_device_info()
        assert info.android_version  # non-empty


class TestADBPackages:
    def test_list_packages(self, adb):
        packages = adb.list_packages()
        assert isinstance(packages, list)
        assert len(packages) > 0

    def test_list_packages_contains_magisk(self, adb):
        packages = adb.list_packages()
        assert "com.topjohnwu.magisk" in packages
