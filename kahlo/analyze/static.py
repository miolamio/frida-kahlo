"""Static Code Analyzer — scan jadx decompiled output for patterns."""
from __future__ import annotations

import logging
import os
import re
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Max file size to scan (skip huge generated files)
_MAX_FILE_SIZE = 100_000  # 100 KB

# Context snippet length
_CONTEXT_LENGTH = 100


# --- Models ---


class URLFinding(BaseModel):
    """A hardcoded URL found in decompiled source."""
    url: str
    file: str
    line: int | None = None
    context: str = ""


class SecretFinding(BaseModel):
    """A hardcoded key/token found in decompiled source."""
    name: str
    value: str
    file: str
    line: int | None = None
    pattern: str = ""
    confidence: str = "medium"  # high, medium, low


class CryptoFinding(BaseModel):
    """A crypto API usage pattern found in decompiled source."""
    algorithm: str
    file: str
    line: int | None = None
    context: str = ""
    usage: str = ""  # encrypt, decrypt, sign, hash, key_creation


class ObfuscationInfo(BaseModel):
    """Assessment of code obfuscation level."""
    tool: str | None = None
    level: str = "none"  # none, light, heavy
    evidence: list[str] = Field(default_factory=list)
    short_class_count: int = 0
    total_class_count: int = 0


class StaticReport(BaseModel):
    """Complete static analysis results from jadx output."""
    urls: list[URLFinding] = Field(default_factory=list)
    secrets: list[SecretFinding] = Field(default_factory=list)
    crypto_usage: list[CryptoFinding] = Field(default_factory=list)
    obfuscation: ObfuscationInfo = Field(default_factory=ObfuscationInfo)
    interesting_classes: list[str] = Field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0


# --- Detection Patterns ---


URL_PATTERNS = [
    re.compile(r'https?://[^\s"\'<>\\\)]+'),
]

# Filter out common non-interesting URLs
_URL_SKIP_PREFIXES = (
    "http://www.w3.org/",
    "http://www.apache.org/",
    "http://schemas.android.com/",
    "http://schemas.xmlsoap.org/",
    "http://xml.org/",
    "http://ns.adobe.com/",
    "http://java.sun.com/",
    "http://xmlns.jcp.org/",
    "http://www.google.com/schemas/",
    "https://www.googleapis.com/auth/",
    "http://json-schema.org/",
    "http://developer.android.com/",
    "https://developer.android.com/",
    "http://www.ietf.org/",
    "https://www.w3.org/",
    "http://schema.org/",
    "https://schema.org/",
    "http://g.co/",
    "https://g.co/",
)

# Secrets: (compiled regex, name, confidence)
SECRET_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']{8,})["\']', re.I), "api_key", "high"),
    (re.compile(r'(?:secret|token|password)\s*[=:]\s*["\']([^"\']{8,})["\']', re.I), "secret", "high"),
    (re.compile(r'(AIza[0-9A-Za-z_-]{35})'), "google_api_key", "high"),
    (re.compile(r'(sk-[a-zA-Z0-9]{20,})'), "stripe_key", "high"),
    (re.compile(r'(?:Bearer\s+)([A-Za-z0-9._-]{20,})'), "bearer_token", "medium"),
    (re.compile(r'["\']([0-9a-fA-F]{32,64})["\']'), "hex_key", "medium"),
    (re.compile(r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']'), "base64_key", "low"),
]

# Crypto: (regex, api_type, usage)
CRYPTO_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r'Cipher\.getInstance\(\s*["\']([^"\']+)'), "cipher", "encrypt/decrypt"),
    (re.compile(r'Mac\.getInstance\(\s*["\']([^"\']+)'), "mac", "sign"),
    (re.compile(r'MessageDigest\.getInstance\(\s*["\']([^"\']+)'), "hash", "hash"),
    (re.compile(r'KeyGenerator\.getInstance\(\s*["\']([^"\']+)'), "keygen", "generate"),
    (re.compile(r'Signature\.getInstance\(\s*["\']([^"\']+)'), "signature", "sign/verify"),
    (re.compile(r'SecretKeySpec\('), "secret_key_spec", "key_creation"),
]

# Short class name pattern (single or double letter package segments like a.b.c.ClassName)
_SHORT_CLASS_RE = re.compile(r'^[a-z]{1,2}$')


# --- Main Analyzer ---


def analyze_static(jadx_dir: str) -> StaticReport:
    """Scan jadx output directory for static patterns.

    Args:
        jadx_dir: Path to jadx decompiled output (containing sources/).

    Returns:
        StaticReport with all findings.
    """
    if not jadx_dir or not os.path.isdir(jadx_dir):
        logger.warning("jadx output directory not found: %s", jadx_dir)
        return StaticReport()

    # Find the sources directory
    sources_dir = os.path.join(jadx_dir, "sources")
    if not os.path.isdir(sources_dir):
        # Some jadx versions put code directly in the output dir
        sources_dir = jadx_dir

    # Collect all .java and .kt files
    source_files: list[str] = []
    for root, _dirs, files in os.walk(sources_dir):
        for fname in files:
            if fname.endswith((".java", ".kt")):
                source_files.append(os.path.join(root, fname))

    if not source_files:
        logger.warning("No source files found in %s", jadx_dir)
        return StaticReport()

    logger.info("Scanning %d source files in %s", len(source_files), jadx_dir)

    urls: list[URLFinding] = []
    secrets: list[SecretFinding] = []
    crypto_usage: list[CryptoFinding] = []
    files_scanned = 0
    files_skipped = 0

    # Track seen values to deduplicate
    seen_urls: set[str] = set()
    seen_secrets: set[str] = set()
    seen_crypto: set[str] = set()

    for fpath in source_files:
        try:
            fsize = os.path.getsize(fpath)
        except OSError:
            files_skipped += 1
            continue

        if fsize > _MAX_FILE_SIZE:
            files_skipped += 1
            continue

        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            files_skipped += 1
            continue

        files_scanned += 1
        rel_path = os.path.relpath(fpath, jadx_dir)

        # Scan line by line for line number tracking
        for line_num, line in enumerate(content.splitlines(), 1):
            # --- URLs ---
            for pattern in URL_PATTERNS:
                for m in pattern.finditer(line):
                    url = m.group(0).rstrip(".,;:)")
                    if url in seen_urls:
                        continue
                    if any(url.startswith(prefix) for prefix in _URL_SKIP_PREFIXES):
                        continue
                    # Skip very short URLs (likely fragments)
                    if len(url) < 15:
                        continue
                    seen_urls.add(url)
                    ctx = line.strip()[:_CONTEXT_LENGTH]
                    urls.append(URLFinding(
                        url=url,
                        file=rel_path,
                        line=line_num,
                        context=ctx,
                    ))

            # --- Secrets ---
            for pattern, name, confidence in SECRET_PATTERNS:
                for m in pattern.finditer(line):
                    # Group 1 is the captured value for most patterns
                    value = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                    dedup_key = f"{name}:{value}"
                    if dedup_key in seen_secrets:
                        continue
                    # Skip common false positives
                    if _is_secret_false_positive(value):
                        continue
                    seen_secrets.add(dedup_key)
                    secrets.append(SecretFinding(
                        name=name,
                        value=value,
                        file=rel_path,
                        line=line_num,
                        pattern=pattern.pattern[:60],
                        confidence=confidence,
                    ))

            # --- Crypto ---
            for pattern, api_type, usage in CRYPTO_PATTERNS:
                for m in pattern.finditer(line):
                    if api_type == "secret_key_spec":
                        algo = "SecretKeySpec"
                    else:
                        algo = m.group(1) if m.lastindex and m.lastindex >= 1 else api_type
                    dedup_key = f"{algo}:{rel_path}"
                    if dedup_key in seen_crypto:
                        continue
                    seen_crypto.add(dedup_key)
                    ctx = line.strip()[:_CONTEXT_LENGTH]
                    crypto_usage.append(CryptoFinding(
                        algorithm=algo,
                        file=rel_path,
                        line=line_num,
                        context=ctx,
                        usage=usage,
                    ))

    # Assess obfuscation
    obfuscation = _assess_obfuscation(jadx_dir, source_files)

    # Find interesting classes
    interesting = _find_interesting_classes(source_files, jadx_dir)

    # Sort findings
    urls.sort(key=lambda u: u.url)
    secrets.sort(key=lambda s: ({"high": 0, "medium": 1, "low": 2}.get(s.confidence, 3), s.name))
    crypto_usage.sort(key=lambda c: c.algorithm)

    return StaticReport(
        urls=urls,
        secrets=secrets,
        crypto_usage=crypto_usage,
        obfuscation=obfuscation,
        interesting_classes=interesting,
        files_scanned=files_scanned,
        files_skipped=files_skipped,
    )


def _is_secret_false_positive(value: str) -> bool:
    """Check if a detected secret value is likely a false positive."""
    if not value:
        return True
    # All same character
    if len(set(value)) <= 2:
        return True
    # Common placeholder patterns
    placeholders = (
        "xxxxxxxx", "00000000", "11111111", "aaaaaaaa",
        "YOUR_API_KEY", "your_api_key", "INSERT_KEY_HERE",
        "PLACEHOLDER", "TODO", "FIXME",
    )
    v_lower = value.lower()
    if any(p in v_lower for p in placeholders):
        return True
    # Too short for a real key
    if len(value) < 8:
        return True
    return False


def _assess_obfuscation(jadx_dir: str, source_files: list[str]) -> ObfuscationInfo:
    """Assess the level of code obfuscation."""
    evidence: list[str] = []
    tool: str | None = None

    # Check for proguard/mapping files
    for name in ("proguard-rules.txt", "mapping.txt", "proguard-rules.pro"):
        candidate = os.path.join(jadx_dir, name)
        if os.path.exists(candidate):
            evidence.append(f"Found {name}")
            tool = "proguard"

    # Check for R8 markers in resources
    resources_dir = os.path.join(jadx_dir, "resources")
    if os.path.isdir(resources_dir):
        for rname in ("META-INF/com.android.tools.r8.residualsignature",):
            candidate = os.path.join(resources_dir, rname)
            if os.path.exists(candidate):
                evidence.append(f"Found {rname}")
                tool = "r8"

    # Count classes with short package names
    total_classes = 0
    short_classes = 0

    sources_dir = os.path.join(jadx_dir, "sources")
    if not os.path.isdir(sources_dir):
        sources_dir = jadx_dir

    for fpath in source_files:
        rel = os.path.relpath(fpath, sources_dir)
        parts = rel.replace(os.sep, "/").split("/")
        # Count only the package segments (excluding the filename)
        pkg_parts = parts[:-1]
        total_classes += 1
        short_segments = sum(1 for p in pkg_parts if _SHORT_CLASS_RE.match(p))
        if short_segments > 0 and len(pkg_parts) > 0:
            ratio = short_segments / len(pkg_parts)
            if ratio >= 0.5:
                short_classes += 1

    # Determine obfuscation level
    if total_classes == 0:
        level = "none"
    else:
        ratio = short_classes / total_classes
        if ratio > 0.30:
            level = "heavy"
            if not evidence:
                evidence.append(f"{short_classes}/{total_classes} classes ({ratio:.0%}) have short package names")
            if tool is None:
                tool = "unknown"
        elif ratio > 0.10:
            level = "light"
            if not evidence:
                evidence.append(f"{short_classes}/{total_classes} classes ({ratio:.0%}) have short package names")
            if tool is None:
                tool = "unknown"
        else:
            level = "none"

    if short_classes > 0:
        evidence.append(f"{short_classes} classes with short (1-2 char) package segments out of {total_classes}")

    return ObfuscationInfo(
        tool=tool,
        level=level,
        evidence=evidence,
        short_class_count=short_classes,
        total_class_count=total_classes,
    )


def _find_interesting_classes(source_files: list[str], jadx_dir: str) -> list[str]:
    """Find class names that suggest interesting functionality."""
    interesting_keywords = (
        "encrypt", "decrypt", "cipher", "crypto", "signing",
        "auth", "login", "oauth", "token",
        "api", "client", "service", "interceptor",
        "certificate", "pinning", "ssl", "tls",
        "root", "emulator", "detect", "tamper",
        "license", "billing", "payment",
        "firebase", "analytics", "tracking",
        "webview", "bridge", "native",
    )

    interesting: list[str] = []
    seen: set[str] = set()

    sources_dir = os.path.join(jadx_dir, "sources")
    if not os.path.isdir(sources_dir):
        sources_dir = jadx_dir

    for fpath in source_files:
        rel = os.path.relpath(fpath, sources_dir)
        # Convert to Java-like class name
        class_name = rel.replace(os.sep, ".").replace("/", ".")
        class_name = class_name.replace(".java", "").replace(".kt", "")

        name_lower = class_name.lower()
        for keyword in interesting_keywords:
            if keyword in name_lower:
                if class_name not in seen:
                    seen.add(class_name)
                    interesting.append(class_name)
                break

    interesting.sort()
    return interesting[:100]  # Limit to top 100
