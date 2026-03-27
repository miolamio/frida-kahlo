"""Quick string extraction from APK without full jadx decompilation."""
from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class APKStrings(BaseModel):
    """Strings extracted from an APK file."""
    urls: list[str] = Field(default_factory=list)
    interesting: list[str] = Field(default_factory=list)
    total_count: int = 0


# URL regex for raw strings
_URL_RE = re.compile(r'https?://[^\s"\'<>\\]{10,}')

# Skip common framework URLs
_URL_SKIP_PREFIXES = (
    "http://www.w3.org/",
    "http://www.apache.org/",
    "http://schemas.android.com/",
    "http://schemas.xmlsoap.org/",
    "http://xml.org/",
    "http://ns.adobe.com/",
    "http://java.sun.com/",
    "http://xmlns.jcp.org/",
    "http://developer.android.com/",
    "https://developer.android.com/",
    "http://www.ietf.org/",
    "https://www.w3.org/",
    "http://www.google.com/schemas/",
    "https://www.googleapis.com/auth/",
    "http://json-schema.org/",
    "http://schema.org/",
    "https://schema.org/",
    "http://g.co/",
    "https://g.co/",
)

# Interesting string patterns
_INTERESTING_RE = [
    re.compile(r'(?:api[_-]?key|apikey|secret|token|password)\s*[=:]\s*.{8,}', re.I),
    re.compile(r'AIza[0-9A-Za-z_-]{35}'),
    re.compile(r'sk-[a-zA-Z0-9]{20,}'),
    re.compile(r'Bearer\s+[A-Za-z0-9._-]{20,}'),
]


def extract_strings(apk_path: str) -> APKStrings:
    """Extract strings from an APK using the `strings` command.

    Fast alternative to full jadx decompilation for quick URL/secret scanning.

    Args:
        apk_path: Path to the APK file.

    Returns:
        APKStrings with extracted URLs and interesting strings.
    """
    if not os.path.isfile(apk_path):
        logger.warning("APK not found: %s", apk_path)
        return APKStrings()

    try:
        result = subprocess.run(
            ["strings", "-n", "10", apk_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        raw_strings = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.warning("strings command failed: %s", e)
        return APKStrings()

    lines = raw_strings.splitlines()
    total_count = len(lines)

    # Extract URLs
    seen_urls: set[str] = set()
    urls: list[str] = []
    for line in lines:
        for m in _URL_RE.finditer(line):
            url = m.group(0).rstrip(".,;:)")
            if url in seen_urls:
                continue
            if any(url.startswith(prefix) for prefix in _URL_SKIP_PREFIXES):
                continue
            seen_urls.add(url)
            urls.append(url)

    # Extract interesting strings
    seen_interesting: set[str] = set()
    interesting: list[str] = []
    for line in lines:
        for pattern in _INTERESTING_RE:
            for m in pattern.finditer(line):
                val = m.group(0)[:200]
                if val not in seen_interesting:
                    seen_interesting.add(val)
                    interesting.append(val)

    return APKStrings(
        urls=sorted(urls),
        interesting=interesting,
        total_count=total_count,
    )
