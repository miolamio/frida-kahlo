"""Tests for the acquire module — APK extraction, fetcher, installer."""
import json
import os
import tempfile
import zipfile

import pytest

from kahlo.acquire.extractor import APKExtractor, APKExtractorError, APKFormat, APKInfo


# ==============================================================
# APK Extractor tests
# ==============================================================

YAKITORIYA_DIR = os.environ.get("KAHLO_TEST_APK_DIR", "")


class TestAPKFormatDetection:
    """Test format detection for various APK types."""

    def test_detect_directory(self):
        ext = APKExtractor()
        fmt = ext.detect_format(YAKITORIYA_DIR)
        assert fmt == APKFormat.DIRECTORY

    def test_detect_single_apk(self):
        ext = APKExtractor()
        apk_path = os.path.join(YAKITORIYA_DIR, "com.voltmobi.yakitoriya.apk")
        fmt = ext.detect_format(apk_path)
        assert fmt == APKFormat.SINGLE_APK

    def test_detect_unknown_file(self, tmp_path):
        ext = APKExtractor()
        txt = tmp_path / "test.txt"
        txt.write_text("not an apk")
        fmt = ext.detect_format(str(txt))
        assert fmt == APKFormat.UNKNOWN

    def test_detect_empty_directory(self, tmp_path):
        ext = APKExtractor()
        fmt = ext.detect_format(str(tmp_path))
        assert fmt == APKFormat.UNKNOWN

    def test_detect_xapk_extension(self, tmp_path):
        ext = APKExtractor()
        # Create a fake XAPK file
        xapk_path = tmp_path / "test.xapk"
        with zipfile.ZipFile(str(xapk_path), "w") as zf:
            zf.writestr("base.apk", b"fake apk content")
            zf.writestr("manifest.json", json.dumps({"package_name": "com.test"}))
        fmt = ext.detect_format(str(xapk_path))
        assert fmt == APKFormat.XAPK

    def test_detect_apkm_extension(self, tmp_path):
        ext = APKExtractor()
        apkm_path = tmp_path / "test.apkm"
        with zipfile.ZipFile(str(apkm_path), "w") as zf:
            zf.writestr("base.apk", b"fake apk content")
            zf.writestr("info.json", json.dumps({"package_name": "com.test"}))
        fmt = ext.detect_format(str(apkm_path))
        assert fmt == APKFormat.APKM


class TestAPKExtraction:
    """Test APK extraction from various formats."""

    def test_extract_directory(self):
        ext = APKExtractor()
        apks = ext.extract(YAKITORIYA_DIR)
        assert len(apks) > 0
        # Should include the base APK
        base_apk = [a for a in apks if "com.voltmobi.yakitoriya.apk" in a]
        assert len(base_apk) == 1
        # All paths should be absolute
        for a in apks:
            assert os.path.isabs(a)
            assert os.path.exists(a)

    def test_extract_single_apk(self):
        ext = APKExtractor()
        apk_path = os.path.join(YAKITORIYA_DIR, "com.voltmobi.yakitoriya.apk")
        apks = ext.extract(apk_path)
        assert len(apks) == 1
        assert apks[0].endswith("com.voltmobi.yakitoriya.apk")

    def test_extract_xapk(self, tmp_path):
        ext = APKExtractor()
        # Create a fake XAPK
        xapk_path = tmp_path / "test.xapk"
        with zipfile.ZipFile(str(xapk_path), "w") as zf:
            zf.writestr("base.apk", b"fake apk content 1")
            zf.writestr("config.arm64_v8a.apk", b"fake apk content 2")
            zf.writestr("manifest.json", json.dumps({"package_name": "com.test"}))

        output_dir = str(tmp_path / "extracted")
        apks = ext.extract(str(xapk_path), output_dir)
        assert len(apks) == 2
        assert any("base.apk" in a for a in apks)

    def test_extract_unknown_raises(self, tmp_path):
        ext = APKExtractor()
        txt = tmp_path / "test.txt"
        txt.write_text("not an apk")
        with pytest.raises(APKExtractorError):
            ext.extract(str(txt))

    def test_extract_yakitoriya_has_config_apks(self):
        ext = APKExtractor()
        apks = ext.extract(YAKITORIYA_DIR)
        # Should have base + config APKs
        assert len(apks) >= 10  # yakitoriya has 20 APKs
        config_apks = [a for a in apks if "config." in os.path.basename(a)]
        assert len(config_apks) > 0


class TestAPKInfo:
    """Test metadata extraction."""

    def test_get_info_from_directory(self):
        ext = APKExtractor()
        info = ext.get_info(YAKITORIYA_DIR)
        assert info.package_name == "com.voltmobi.yakitoriya"
        assert info.app_name is not None
        assert info.version_name is not None
        assert len(info.permissions) > 0

    def test_get_info_from_xapk(self, tmp_path):
        ext = APKExtractor()
        xapk_path = tmp_path / "test.xapk"
        manifest = {
            "package_name": "com.test.app",
            "name": "Test App",
            "version_name": "1.0.0",
            "version_code": "100",
            "min_sdk_version": "26",
            "target_sdk_version": "34",
            "permissions": ["android.permission.INTERNET"],
        }
        with zipfile.ZipFile(str(xapk_path), "w") as zf:
            zf.writestr("base.apk", b"fake")
            zf.writestr("manifest.json", json.dumps(manifest))

        info = ext.get_info(str(xapk_path))
        assert info.package_name == "com.test.app"
        assert info.app_name == "Test App"
        assert info.version_name == "1.0.0"
        assert "android.permission.INTERNET" in info.permissions

    def test_get_info_from_single_apk(self):
        ext = APKExtractor()
        apk_path = os.path.join(YAKITORIYA_DIR, "com.voltmobi.yakitoriya.apk")
        info = ext.get_info(apk_path)
        # Single APK won't have XAPK manifest, so info may be minimal
        assert isinstance(info, APKInfo)

    def test_yakitoriya_permissions(self):
        ext = APKExtractor()
        info = ext.get_info(YAKITORIYA_DIR)
        assert "android.permission.INTERNET" in info.permissions
        assert "android.permission.CAMERA" in info.permissions


# ==============================================================
# Manifest Analyzer tests
# ==============================================================

class TestManifestAnalyzer:
    """Test manifest analysis."""

    def test_analyze_xapk_directory(self):
        from kahlo.prepare.manifest import ManifestAnalyzer
        analyzer = ManifestAnalyzer()
        info = analyzer.analyze(YAKITORIYA_DIR)
        assert info.package_name == "com.voltmobi.yakitoriya"
        assert len(info.permissions) > 0

    def test_analyze_nonexistent(self, tmp_path):
        from kahlo.prepare.manifest import ManifestAnalyzer
        analyzer = ManifestAnalyzer()
        info = analyzer.analyze(str(tmp_path / "nonexistent"))
        # Should return empty info, not crash
        assert info.package_name is None


# ==============================================================
# Decompiler tests
# ==============================================================

class TestDecompiler:
    """Test jadx decompiler wrapper."""

    def test_jadx_available(self):
        from kahlo.prepare.decompiler import Decompiler
        dec = Decompiler()
        assert dec.available is True  # jadx at /opt/homebrew/bin/jadx

    def test_jadx_not_available(self):
        from kahlo.prepare.decompiler import Decompiler
        dec = Decompiler(jadx_path="/nonexistent/jadx")
        assert dec.available is False

    def test_decompile_missing_apk_raises(self, tmp_path):
        from kahlo.prepare.decompiler import Decompiler, DecompilerError
        dec = Decompiler()
        with pytest.raises(DecompilerError):
            dec.decompile(str(tmp_path / "missing.apk"), str(tmp_path / "out"))


# ==============================================================
# Installer tests (integration — requires device)
# ==============================================================

class TestAPKInstaller:
    """Test APK installer (requires connected device)."""

    def test_install_yakitoriya_skip_if_installed(self):
        """Test that installer detects already-installed app and skips."""
        from kahlo.acquire.installer import APKInstaller
        from kahlo.device.adb import ADB, ADBError

        adb = ADB()
        devices = adb.devices()
        if not devices:
            pytest.skip("No device connected")

        adb = ADB(serial=devices[0].serial)
        installer = APKInstaller(adb)
        try:
            package = installer.install(YAKITORIYA_DIR, skip_if_installed=True)
            assert package == "com.voltmobi.yakitoriya"
        except ADBError as e:
            # pm may not be accessible if device shell is restricted
            if "inaccessible" in str(e) or "not found" in str(e):
                pytest.skip(f"Device shell restricted: {e}")
            raise
