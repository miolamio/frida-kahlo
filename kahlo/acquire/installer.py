"""APK Installer — extract + install wrapper combining extractor and ADB."""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile

from kahlo.acquire.extractor import APKExtractor, APKExtractorError, APKInfo
from kahlo.device.adb import ADB, ADBError

logger = logging.getLogger(__name__)


class APKInstallerError(Exception):
    pass


class APKInstaller:
    """Extracts APK(s) from any format and installs on device via ADB."""

    def __init__(self, adb: ADB | None = None):
        self.adb = adb
        self.extractor = APKExtractor()

    def _get_adb(self) -> ADB:
        """Get or create ADB instance."""
        if self.adb is not None:
            return self.adb
        adb = ADB()
        devices = adb.devices()
        if not devices:
            raise APKInstallerError("No devices connected")
        return ADB(serial=devices[0].serial)

    def install(self, apk_path: str, skip_if_installed: bool = True) -> str:
        """Extract if needed, install on device.

        Args:
            apk_path: Path to APK, XAPK, APKM, or directory with split APKs.
            skip_if_installed: Skip installation if package is already on device.

        Returns:
            Package name of installed app.
        """
        adb = self._get_adb()

        # Get package info first
        info = self.extractor.get_info(apk_path)
        package_name = info.package_name

        # If we don't have package name from manifest, try to detect from APK
        if not package_name:
            apks = self.extractor.extract(apk_path)
            if apks:
                package_name = self._detect_package_name(apks[0])
        else:
            apks = None  # Lazy — extract only if needed

        if not package_name:
            raise APKInstallerError("Could not determine package name")

        # Check if already installed
        if skip_if_installed:
            installed = adb.list_packages()
            if package_name in installed:
                logger.info("Package %s already installed, skipping", package_name)
                return package_name

        # Extract APKs if not done yet
        if apks is None:
            apks = self.extractor.extract(apk_path)

        if not apks:
            raise APKInstallerError(f"No APK files to install from {apk_path}")

        # Install
        logger.info("Installing %d APK(s) for %s", len(apks), package_name)
        try:
            adb.install(apks)
        except ADBError as e:
            raise APKInstallerError(f"Installation failed: {e}") from e

        return package_name

    def _detect_package_name(self, apk_path: str) -> str | None:
        """Detect package name from APK file using jadx or binary parsing."""
        # Try jadx first
        name = self._detect_via_jadx(apk_path)
        if name:
            return name

        # Try basic binary parsing of AndroidManifest.xml
        name = self._detect_via_binary(apk_path)
        if name:
            return name

        return None

    def _detect_via_jadx(self, apk_path: str) -> str | None:
        """Use jadx to extract package name."""
        jadx_path = shutil.which("jadx") or "/opt/homebrew/bin/jadx"
        if not os.path.exists(jadx_path):
            return None

        try:
            with tempfile.TemporaryDirectory(prefix="kahlo_jadx_") as tmpdir:
                result = subprocess.run(
                    [jadx_path, "--no-src", "--no-res", "-d", tmpdir, apk_path],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                # Parse AndroidManifest.xml from output
                manifest_path = os.path.join(tmpdir, "resources", "AndroidManifest.xml")
                if os.path.exists(manifest_path):
                    with open(manifest_path, "r", encoding="utf-8") as f:
                        content = f.read()
                    import re
                    match = re.search(r'package="([^"]+)"', content)
                    if match:
                        return match.group(1)
        except (subprocess.TimeoutExpired, OSError, Exception) as e:
            logger.debug("jadx detection failed: %s", e)
        return None

    def _detect_via_binary(self, apk_path: str) -> str | None:
        """Try to find package name in APK using basic ZIP + string search."""
        import zipfile
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    data = zf.read("AndroidManifest.xml")
                    # Binary AndroidManifest — look for package strings
                    # This is a heuristic: look for common package patterns
                    text = data.decode("utf-8", errors="ignore")
                    import re
                    # Look for package name pattern (any.xxx.yyy)
                    matches = re.findall(r'([a-z][a-z0-9]*\.[a-z][a-z0-9]*\.[a-z][a-z0-9.]*)', text)
                    if matches:
                        # Return the most likely one (shortest, most common pattern)
                        candidates = [m for m in matches if not m.endswith(".")]
                        if candidates:
                            return min(candidates, key=len)
        except Exception:
            pass
        return None
