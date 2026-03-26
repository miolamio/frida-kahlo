"""Manifest Analyzer — extract AndroidManifest.xml info from APK."""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
import zipfile
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ActivityInfo(BaseModel):
    """An Android activity from the manifest."""
    name: str
    exported: bool = False
    is_launcher: bool = False


class ServiceInfo(BaseModel):
    """An Android service from the manifest."""
    name: str
    exported: bool = False


class ReceiverInfo(BaseModel):
    """An Android broadcast receiver from the manifest."""
    name: str
    exported: bool = False


class ManifestInfo(BaseModel):
    """Parsed AndroidManifest.xml data."""
    package_name: str | None = None
    app_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    permissions: list[str] = Field(default_factory=list)
    activities: list[ActivityInfo] = Field(default_factory=list)
    services: list[ServiceInfo] = Field(default_factory=list)
    receivers: list[ReceiverInfo] = Field(default_factory=list)
    uses_cleartext: bool = False
    debuggable: bool = False


class ManifestAnalyzer:
    """Extracts manifest information from APK files.

    Strategy:
    1. If XAPK directory with manifest.json — parse that (fast, reliable)
    2. Use jadx to decompile AndroidManifest.xml (most complete)
    3. Binary heuristic parsing as last resort
    """

    def __init__(self, jadx_path: str = "/opt/homebrew/bin/jadx"):
        self.jadx_path = jadx_path

    def analyze(self, apk_path: str) -> ManifestInfo:
        """Extract manifest info from APK, XAPK directory, or archive.

        Args:
            apk_path: Path to base APK file, XAPK directory, or XAPK/APKM archive.
        """
        # Check for XAPK directory with manifest.json
        if os.path.isdir(apk_path):
            manifest_json = os.path.join(apk_path, "manifest.json")
            if os.path.exists(manifest_json):
                info = self._parse_xapk_manifest(manifest_json)
                # Try to enrich with jadx
                base_apk = self._find_base_apk(apk_path)
                if base_apk:
                    enriched = self._analyze_via_jadx(base_apk)
                    if enriched:
                        info = self._merge_info(info, enriched)
                return info
            # Directory with APKs but no manifest.json
            base_apk = self._find_base_apk(apk_path)
            if base_apk:
                apk_path = base_apk

        # Single APK file
        if os.path.isfile(apk_path) and apk_path.endswith(".apk"):
            # Try jadx first
            info = self._analyze_via_jadx(apk_path)
            if info and info.package_name:
                return info
            # Fallback
            return self._analyze_heuristic(apk_path)

        return ManifestInfo()

    def _find_base_apk(self, directory: str) -> str | None:
        """Find the base APK in a directory (the one without config. prefix)."""
        import glob
        apks = glob.glob(os.path.join(directory, "*.apk"))
        for apk in sorted(apks):
            basename = os.path.basename(apk)
            if not basename.startswith("config."):
                return apk
        # Return first APK if none match
        return apks[0] if apks else None

    def _parse_xapk_manifest(self, manifest_path: str) -> ManifestInfo:
        """Parse XAPK manifest.json."""
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return ManifestInfo(
                package_name=data.get("package_name"),
                app_name=data.get("name"),
                version_name=data.get("version_name"),
                version_code=str(data.get("version_code", "")),
                min_sdk=str(data.get("min_sdk_version", "")) or None,
                target_sdk=str(data.get("target_sdk_version", "")) or None,
                permissions=data.get("permissions", []),
            )
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse XAPK manifest: %s", e)
            return ManifestInfo()

    def _analyze_via_jadx(self, apk_path: str) -> ManifestInfo | None:
        """Use jadx to decompile and parse AndroidManifest.xml."""
        if not os.path.exists(self.jadx_path):
            logger.debug("jadx not found at %s", self.jadx_path)
            return None

        try:
            with tempfile.TemporaryDirectory(prefix="kahlo_manifest_") as tmpdir:
                result = subprocess.run(
                    [self.jadx_path, "--no-src", "-d", tmpdir, apk_path],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                manifest_path = os.path.join(tmpdir, "resources", "AndroidManifest.xml")
                if not os.path.exists(manifest_path):
                    logger.debug("jadx did not produce AndroidManifest.xml")
                    return None

                with open(manifest_path, "r", encoding="utf-8") as f:
                    xml_content = f.read()

                return self._parse_manifest_xml(xml_content)

        except subprocess.TimeoutExpired:
            logger.warning("jadx timed out")
            return None
        except Exception as e:
            logger.warning("jadx analysis failed: %s", e)
            return None

    def _parse_manifest_xml(self, xml: str) -> ManifestInfo:
        """Parse decompiled AndroidManifest.xml text."""
        info = ManifestInfo()

        # Package name
        m = re.search(r'<manifest[^>]*package="([^"]+)"', xml)
        if m:
            info.package_name = m.group(1)

        # Version
        m = re.search(r'android:versionName="([^"]+)"', xml)
        if m:
            info.version_name = m.group(1)
        m = re.search(r'android:versionCode="([^"]+)"', xml)
        if m:
            info.version_code = m.group(1)

        # SDK versions
        m = re.search(r'android:minSdkVersion="(\d+)"', xml)
        if m:
            info.min_sdk = m.group(1)
        m = re.search(r'android:targetSdkVersion="(\d+)"', xml)
        if m:
            info.target_sdk = m.group(1)

        # Permissions
        perms = re.findall(r'<uses-permission[^>]*android:name="([^"]+)"', xml)
        info.permissions = sorted(set(perms))

        # Activities
        activities = []
        for m in re.finditer(
            r'<activity\s[^>]*android:name="([^"]+)"[^>]*>', xml
        ):
            name = m.group(1)
            block_start = m.start()
            # Find the corresponding closing tag or self-close
            exported = 'android:exported="true"' in xml[block_start:block_start + 500]
            is_launcher = "android.intent.action.MAIN" in xml[block_start:block_start + 1000]
            activities.append(ActivityInfo(name=name, exported=exported, is_launcher=is_launcher))
        info.activities = activities

        # Services
        services = []
        for m in re.finditer(
            r'<service\s[^>]*android:name="([^"]+)"[^>]*>', xml
        ):
            name = m.group(1)
            block_start = m.start()
            exported = 'android:exported="true"' in xml[block_start:block_start + 300]
            services.append(ServiceInfo(name=name, exported=exported))
        info.services = services

        # Receivers
        receivers = []
        for m in re.finditer(
            r'<receiver\s[^>]*android:name="([^"]+)"[^>]*>', xml
        ):
            name = m.group(1)
            block_start = m.start()
            exported = 'android:exported="true"' in xml[block_start:block_start + 300]
            receivers.append(ReceiverInfo(name=name, exported=exported))
        info.receivers = receivers

        # Cleartext traffic
        info.uses_cleartext = 'android:usesCleartextTraffic="true"' in xml

        # Debuggable
        info.debuggable = 'android:debuggable="true"' in xml

        return info

    def _analyze_heuristic(self, apk_path: str) -> ManifestInfo:
        """Heuristic APK analysis without jadx."""
        info = ManifestInfo()
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    data = zf.read("AndroidManifest.xml")
                    text = data.decode("utf-8", errors="ignore")
                    # Try to find package name
                    matches = re.findall(r'(com\.[a-z][a-z0-9]*\.[a-z][a-z0-9.]*)', text)
                    if matches:
                        candidates = [m for m in matches if not m.endswith(".")]
                        if candidates:
                            info.package_name = min(candidates, key=len)
        except Exception:
            pass
        return info

    def _merge_info(self, base: ManifestInfo, enriched: ManifestInfo) -> ManifestInfo:
        """Merge enriched info (from jadx) into base info (from XAPK manifest)."""
        return ManifestInfo(
            package_name=base.package_name or enriched.package_name,
            app_name=base.app_name or enriched.app_name,
            version_name=base.version_name or enriched.version_name,
            version_code=base.version_code or enriched.version_code,
            min_sdk=base.min_sdk or enriched.min_sdk,
            target_sdk=base.target_sdk or enriched.target_sdk,
            permissions=base.permissions or enriched.permissions,
            activities=enriched.activities or base.activities,
            services=enriched.services or base.services,
            receivers=enriched.receivers or base.receivers,
            uses_cleartext=enriched.uses_cleartext or base.uses_cleartext,
            debuggable=enriched.debuggable or base.debuggable,
        )
