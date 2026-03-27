"""SDK/Pattern Detector — identify known SDKs and services from all events."""
from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field


class SDKInfo(BaseModel):
    """A detected SDK or third-party service."""
    name: str
    version: str | None = None
    category: str  # "analytics", "crash_reporting", "push", "attribution", "deep_linking", "error_reporting"
    evidence: list[str] = Field(default_factory=list)
    data_collected: list[str] = Field(default_factory=list)


class PatternsReport(BaseModel):
    """SDK and pattern detection results."""
    sdks: list[SDKInfo] = Field(default_factory=list)


# SDK detection rules: (name, category, pref_patterns, host_patterns, class_patterns, data_collected)
_SDK_RULES: list[dict[str, Any]] = [
    {
        "name": "Firebase Crashlytics",
        "category": "crash_reporting",
        "pref_patterns": ["firebase.crashlytics", "crashlytics.installation", "existing_instance_identifier"],
        "host_patterns": ["crashlytics.com", "firebase-settings.crashlytics"],
        "class_patterns": ["com.google.firebase.crashlytics"],
        "data_collected": ["device info", "app version", "crash data", "installation UUID", "git revision"],
        "version_keys": {
            "com.google.firebase.crashlytics.xml": None,
        },
    },
    {
        "name": "Firebase Analytics (GA4)",
        "category": "analytics",
        "pref_patterns": ["com.google.android.gms.measurement", "app_instance_id", "google_app_id", "gmp_app_id"],
        "host_patterns": [],
        "class_patterns": ["com.google.android.gms.measurement"],
        "data_collected": ["app events", "session data", "consent status", "app instance ID"],
        "version_keys": {},
    },
    {
        "name": "Firebase Cloud Messaging",
        "category": "push",
        "pref_patterns": ["com.google.firebase.messaging", "proxy_notification_initialized"],
        "host_patterns": [],
        "class_patterns": ["com.google.firebase.messaging"],
        "data_collected": ["FCM token", "notification state"],
        "version_keys": {},
    },
    {
        "name": "Firebase Sessions",
        "category": "analytics",
        "pref_patterns": [],
        "host_patterns": [],
        "class_patterns": ["com.google.firebase.sessions"],
        "data_collected": ["session ID", "process data", "background time"],
        "version_keys": {},
    },
    {
        "name": "Firebase Data Transport",
        "category": "analytics",
        "pref_patterns": [],
        "host_patterns": [],
        "class_patterns": ["com.google.android.datatransport"],
        "data_collected": ["event metadata", "device fingerprint", "locale"],
        "version_keys": {},
    },
    {
        "name": "Sentry",
        "category": "error_reporting",
        "pref_patterns": ["sentry"],
        "host_patterns": ["sentry"],
        "class_patterns": ["io.sentry"],
        "data_collected": ["session data", "traces", "spans", "device context", "release info"],
        "version_keys": {},
    },
    {
        "name": "Pushwoosh",
        "category": "push",
        "pref_patterns": ["pushwoosh", "pw_", "wavesend"],
        "host_patterns": ["wavesend", "pushwoosh"],
        "class_patterns": ["com.pushwoosh"],
        "data_collected": ["HWID", "device type", "language", "timezone", "screen names", "events"],
        "version_keys": {},
    },
    {
        "name": "AppsFlyer",
        "category": "attribution",
        "pref_patterns": ["appsflyer", "AF_"],
        "host_patterns": ["appsflyersdk", "appsflyer"],
        "class_patterns": ["com.appsflyer"],
        "data_collected": ["device fingerprint", "operator", "country", "install data", "HMAC-signed + AES-encrypted"],
        "version_keys": {},
    },
    {
        "name": "Branch.io",
        "category": "deep_linking",
        "pref_patterns": ["branch_referral", "bnc_", "BNC_"],
        "host_patterns": ["branch.io"],
        "class_patterns": ["io.branch"],
        "data_collected": ["hardware ID", "brand", "model", "screen specs", "CPU type", "WiFi status"],
        "version_keys": {},
    },
    {
        "name": "Yandex Metrica (AppMetrica)",
        "category": "analytics",
        "pref_patterns": ["appmetrica", "yandex.metrica"],
        "host_patterns": ["appmetrica", "metrica.yandex"],
        "class_patterns": ["com.yandex.metrica"],
        "data_collected": ["device info", "locale", "session data"],
        "version_keys": {},
    },
    {
        "name": "Adjust",
        "category": "attribution",
        "pref_patterns": ["adjust"],
        "host_patterns": ["adjust.com"],
        "class_patterns": ["com.adjust"],
        "data_collected": ["attribution data", "device info"],
        "version_keys": {},
    },
    {
        "name": "TUNE/HasOffers",
        "category": "attribution",
        "pref_patterns": ["mobileapptracking", "mat_id"],
        "host_patterns": ["mobileapptracking", "hasoffers"],
        "class_patterns": ["com.mobileapptracker", "com.tune"],
        "data_collected": ["attribution data (legacy)"],
        "version_keys": {},
    },
    {
        "name": "Google Analytics",
        "category": "analytics",
        "pref_patterns": ["google_analytics"],
        "host_patterns": ["google-analytics.com"],
        "class_patterns": ["com.google.analytics"],
        "data_collected": ["events", "pageviews"],
        "version_keys": {},
    },
    {
        "name": "Amplitude",
        "category": "analytics",
        "pref_patterns": ["amplitude"],
        "host_patterns": ["amplitude.com"],
        "class_patterns": ["com.amplitude"],
        "data_collected": ["events", "user properties"],
        "version_keys": {},
    },
    {
        "name": "Mixpanel",
        "category": "analytics",
        "pref_patterns": ["mixpanel"],
        "host_patterns": ["mixpanel.com"],
        "class_patterns": ["com.mixpanel"],
        "data_collected": ["events", "user profiles"],
        "version_keys": {},
    },
]


def analyze_patterns(
    events: list[dict[str, Any]],
    traffic_hosts: list[str] | None = None,
) -> PatternsReport:
    """Detect known SDKs and services from session events.

    Args:
        events: All session events.
        traffic_hosts: List of server hostnames from traffic analysis.

    Returns:
        PatternsReport with detected SDKs.
    """
    # Collect all evidence sources
    pref_files: set[str] = set()
    pref_keys: set[str] = set()
    pref_values: dict[str, str] = {}  # key → value for version extraction
    class_names: set[str] = set()
    hosts: set[str] = set(traffic_hosts or [])
    ssl_previews: list[str] = []
    file_paths: set[str] = set()
    nonce_stacks: list[str] = []

    for event in events:
        module = event.get("module", "")
        etype = event.get("type", "")
        data = event.get("data", {})

        if module == "vault":
            if etype == "pref_read":
                file = data.get("file", "")
                key = data.get("key", "")
                value = data.get("value")
                pref_files.add(file)
                pref_keys.add(key)
                if value is not None:
                    pref_values[key] = str(value)
            elif etype == "initial_dump":
                prefs = data.get("prefs", {})
                for file_name, kv in prefs.items():
                    pref_files.add(file_name)
                    for k, v in kv.items():
                        pref_keys.add(k)
                        if v is not None:
                            pref_values[k] = str(v)
            elif etype == "file_write":
                path = data.get("path", "")
                file_paths.add(path)
                preview = data.get("preview", "")
                if preview:
                    ssl_previews.append(preview)
            elif etype in ("sqlite_write", "sqlite_query"):
                db = data.get("db", "")
                file_paths.add(db)

        elif module == "traffic":
            if etype == "tcp_connect":
                host = data.get("host", "")
                if host:
                    hosts.add(host)
            elif etype == "ssl_raw":
                preview = data.get("preview", "")
                if preview:
                    ssl_previews.append(preview)

        elif module == "discovery":
            if etype == "class_map":
                class_map = data.get("class_map", {})
                for category_classes in class_map.values():
                    if isinstance(category_classes, list):
                        class_names.update(category_classes)

        elif module == "netmodel":
            if etype == "nonce":
                stack = data.get("stack", "")
                if stack:
                    nonce_stacks.append(stack)

    # All text for searching
    all_pref_text = " ".join(pref_files) + " " + " ".join(pref_keys)
    all_host_text = " ".join(hosts)
    all_class_text = " ".join(class_names)
    all_ssl_text = " ".join(ssl_previews)
    all_file_text = " ".join(file_paths)
    all_nonce_text = " ".join(nonce_stacks)

    detected_sdks: list[SDKInfo] = []

    for rule in _SDK_RULES:
        evidence: list[str] = []

        # Check pref patterns
        for pattern in rule["pref_patterns"]:
            pattern_lower = pattern.lower()
            matching_files = [f for f in pref_files if pattern_lower in f.lower()]
            matching_keys = [k for k in pref_keys if pattern_lower in k.lower()]
            if matching_files:
                evidence.append(f"prefs file: {', '.join(matching_files[:3])}")
            if matching_keys:
                evidence.append(f"prefs key: {', '.join(matching_keys[:3])}")

        # Check host patterns
        for pattern in rule["host_patterns"]:
            pattern_lower = pattern.lower()
            matching_hosts = [h for h in hosts if pattern_lower in h.lower()]
            if matching_hosts:
                evidence.append(f"server: {', '.join(matching_hosts[:3])}")

        # Check class patterns
        for pattern in rule["class_patterns"]:
            pattern_lower = pattern.lower()
            matching_classes = [c for c in class_names if pattern_lower in c.lower()]
            if matching_classes:
                evidence.append(f"classes: {len(matching_classes)} loaded")
            # Also check nonce stacks and file paths
            if pattern_lower in all_nonce_text.lower():
                evidence.append(f"nonce generation: stack contains {pattern}")
            if pattern_lower in all_file_text.lower():
                evidence.append(f"file path contains: {pattern}")

        if not evidence:
            continue

        # Try to extract version
        version = _extract_version(rule, all_ssl_text, pref_values, all_file_text)

        detected_sdks.append(SDKInfo(
            name=rule["name"],
            version=version,
            category=rule["category"],
            evidence=evidence,
            data_collected=rule["data_collected"],
        ))

    return PatternsReport(sdks=detected_sdks)


def _extract_version(rule: dict, ssl_text: str, pref_values: dict, file_text: str) -> str | None:
    """Try to extract SDK version from available data."""
    name = rule["name"].lower()

    # Sentry: look for sentry_client=sentry.java.android/X.Y.Z in SSL
    if "sentry" in name:
        m = re.search(r'sentry\.java\.android/(\d+\.\d+\.\d+)', ssl_text)
        if m:
            return m.group(1)

    # Pushwoosh: look for "v":"X.Y.Z" in SSL raw
    if "pushwoosh" in name:
        m = re.search(r'"v"\s*:\s*"(\d+\.\d+\.\d+)"', ssl_text)
        if m:
            return m.group(1)

    # AppsFlyer: look for buildnumber=X.Y.Z or version in SSL/prefs
    if "appsflyer" in name:
        m = re.search(r'buildnumber=(\d+\.\d+\.\d+)', ssl_text)
        if m:
            return m.group(1)
        m = re.search(r'"version"\s*:\s*"(\d+\.\d+\.\d+)"', ssl_text)
        if m:
            return m.group(1)

    # Firebase Crashlytics: look for sdkVersion in file_write previews
    if "crashlytics" in name:
        m = re.search(r'"sdkVersion"\s*:\s*"(\d+\.\d+\.\d+)"', file_text + " " + ssl_text)
        if m:
            return m.group(1)

    return None
