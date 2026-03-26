"""APK Extractor — detect format and extract split APKs from XAPK/APKM/directory."""
from __future__ import annotations

import glob
import json
import os
import shutil
import tempfile
import zipfile
from enum import Enum
from typing import Any

from pydantic import BaseModel


class APKFormat(str, Enum):
    """Detected APK format."""
    SINGLE_APK = "apk"
    XAPK = "xapk"
    APKM = "apkm"
    DIRECTORY = "directory"
    UNKNOWN = "unknown"


class APKInfo(BaseModel):
    """Metadata extracted from XAPK/APKM manifest."""
    package_name: str | None = None
    app_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    permissions: list[str] = []
    split_configs: list[str] = []


class APKExtractorError(Exception):
    pass


class APKExtractor:
    """Handles APK format detection and extraction of split APKs."""

    def detect_format(self, path: str) -> APKFormat:
        """Detect APK format from file path or directory."""
        if os.path.isdir(path):
            apks = glob.glob(os.path.join(path, "*.apk"))
            if apks:
                return APKFormat.DIRECTORY
            return APKFormat.UNKNOWN

        lower = path.lower()
        if lower.endswith(".xapk"):
            return APKFormat.XAPK
        if lower.endswith(".apkm"):
            return APKFormat.APKM
        if lower.endswith(".apk"):
            return APKFormat.SINGLE_APK

        # Try to detect by content
        if os.path.isfile(path) and zipfile.is_zipfile(path):
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    names = zf.namelist()
                    if "manifest.json" in names:
                        return APKFormat.XAPK
                    if "info.json" in names:
                        return APKFormat.APKM
                    if any(n.endswith(".apk") for n in names):
                        return APKFormat.XAPK
            except zipfile.BadZipFile:
                pass

        return APKFormat.UNKNOWN

    def extract(self, path: str, output_dir: str | None = None) -> list[str]:
        """Extract APK(s) from any format.

        Args:
            path: Path to APK, XAPK, APKM file, or directory with APKs.
            output_dir: Directory to extract split APKs to. Auto-created if None.

        Returns:
            List of APK file paths ready for installation.
        """
        fmt = self.detect_format(path)

        if fmt == APKFormat.UNKNOWN:
            raise APKExtractorError(f"Unknown APK format: {path}")

        if fmt == APKFormat.SINGLE_APK:
            return [os.path.abspath(path)]

        if fmt == APKFormat.DIRECTORY:
            return self._extract_directory(path)

        if fmt in (APKFormat.XAPK, APKFormat.APKM):
            if output_dir is None:
                output_dir = tempfile.mkdtemp(prefix="kahlo_extract_")
            return self._extract_archive(path, output_dir)

        raise APKExtractorError(f"Cannot extract format: {fmt}")

    def get_info(self, path: str) -> APKInfo:
        """Extract metadata from XAPK/APKM manifest or directory manifest.json."""
        fmt = self.detect_format(path)

        if fmt == APKFormat.DIRECTORY:
            manifest_path = os.path.join(path, "manifest.json")
            if os.path.exists(manifest_path):
                return self._parse_xapk_manifest(manifest_path)
            return APKInfo()

        if fmt in (APKFormat.XAPK, APKFormat.APKM):
            return self._get_archive_info(path)

        return APKInfo()

    def _extract_directory(self, path: str) -> list[str]:
        """Get all APK files from a directory."""
        apks = sorted(glob.glob(os.path.join(path, "*.apk")))
        if not apks:
            raise APKExtractorError(f"No APK files found in {path}")
        return [os.path.abspath(a) for a in apks]

    def _extract_archive(self, archive_path: str, output_dir: str) -> list[str]:
        """Extract XAPK/APKM archive to individual APK files."""
        os.makedirs(output_dir, exist_ok=True)

        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                apk_names = [n for n in zf.namelist() if n.endswith(".apk")]
                if not apk_names:
                    raise APKExtractorError(f"No APK files inside archive: {archive_path}")

                extracted = []
                for name in apk_names:
                    # Extract APK file
                    zf.extract(name, output_dir)
                    extracted_path = os.path.join(output_dir, name)
                    extracted.append(os.path.abspath(extracted_path))

                return sorted(extracted)

        except zipfile.BadZipFile as e:
            raise APKExtractorError(f"Invalid archive: {archive_path}: {e}") from e

    def _get_archive_info(self, archive_path: str) -> APKInfo:
        """Extract metadata from archive manifest."""
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                # Try XAPK manifest
                if "manifest.json" in zf.namelist():
                    data = json.loads(zf.read("manifest.json"))
                    return self._parse_manifest_data(data)
                # Try APKM info
                if "info.json" in zf.namelist():
                    data = json.loads(zf.read("info.json"))
                    return self._parse_manifest_data(data)
        except (zipfile.BadZipFile, json.JSONDecodeError, KeyError):
            pass
        return APKInfo()

    def _parse_xapk_manifest(self, manifest_path: str) -> APKInfo:
        """Parse a manifest.json from an XAPK directory."""
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return self._parse_manifest_data(data)
        except (json.JSONDecodeError, OSError):
            return APKInfo()

    def _parse_manifest_data(self, data: dict[str, Any]) -> APKInfo:
        """Parse XAPK/APKM manifest data dict into APKInfo."""
        return APKInfo(
            package_name=data.get("package_name"),
            app_name=data.get("name"),
            version_name=data.get("version_name"),
            version_code=str(data.get("version_code", "")),
            min_sdk=str(data.get("min_sdk_version", "")) or None,
            target_sdk=str(data.get("target_sdk_version", "")) or None,
            permissions=data.get("permissions", []),
            split_configs=data.get("split_configs", []),
        )
