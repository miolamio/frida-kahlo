"""Tests for ADB wrapper. Requires connected Android device."""
import os
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

    def test_device_has_expected_serial(self, adb):
        expected = os.environ.get("KAHLO_TEST_DEVICE", "")
        if not expected:
            pytest.skip("KAHLO_TEST_DEVICE not set")
        devices = adb.devices()
        assert any(d.serial == expected for d in devices)


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
        assert info.model  # non-empty

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

    def test_list_third_party_packages(self, adb):
        packages = adb.list_packages(third_party_only=True)
        assert isinstance(packages, list)
