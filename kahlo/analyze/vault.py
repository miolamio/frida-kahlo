"""Vault Analyzer — parse vault events into storage map and secret inventory."""
from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field


class PrefsFile(BaseModel):
    """A SharedPreferences file observed during the session."""
    file: str
    keys_read: int = 0
    keys_written: int = 0
    sample_keys: list[str] = Field(default_factory=list)
    is_encrypted: bool = False


class DatabaseInfo(BaseModel):
    """A SQLite database written to during the session."""
    path: str
    name: str
    tables: list[str] = Field(default_factory=list)
    write_count: int = 0
    sample_values: list[str] = Field(default_factory=list)


class SecretInfo(BaseModel):
    """An extracted token, key, or ID."""
    name: str
    value: str
    source: str  # e.g. "prefs:com.pushwoosh.registration:pw_hwid"
    category: str  # "api_key", "token", "device_id", "encryption_key", "sdk_key", "session_id"
    sensitivity: str  # "high", "medium", "low"


class FileWriteInfo(BaseModel):
    """A file system write observed during the session."""
    path: str
    size: int = 0
    preview: str = ""
    ts: str | None = None


class KeystoreEntry(BaseModel):
    """A keystore entry (Tink encrypted preferences keyset)."""
    store: str
    key_type: str  # "AesSivKey", "AesGcmKey"
    role: str  # "key_encryption", "value_encryption"
    keyset_hex: str = ""


class DecryptedPrefEntry(BaseModel):
    """A decrypted value from EncryptedSharedPreferences or Tink."""
    key: str
    value: str | None = None
    value_type: str = ""
    source: str = ""


class VaultReport(BaseModel):
    """Complete vault analysis from a session."""
    prefs_files: list[PrefsFile] = Field(default_factory=list)
    databases: list[DatabaseInfo] = Field(default_factory=list)
    secrets: list[SecretInfo] = Field(default_factory=list)
    file_writes: list[FileWriteInfo] = Field(default_factory=list)
    keystore_entries: list[KeystoreEntry] = Field(default_factory=list)
    decrypted_prefs: list[DecryptedPrefEntry] = Field(default_factory=list)
    tink_decrypts: int = 0
    total_pref_reads: int = 0
    total_pref_writes: int = 0


# --- Secret detection patterns ---

_SECRET_KEY_PATTERNS = [
    (re.compile(r'(token|auth|session_id|bearer)', re.I), "token", "high"),
    (re.compile(r'(password|passwd|pwd|secret)', re.I), "token", "high"),
    (re.compile(r'(api_?key|app_?key|sdk_?key|sentry_?key|dev_key)', re.I), "api_key", "medium"),
    (re.compile(r'(encryption|cipher|aes|crypto)', re.I), "encryption_key", "high"),
    (re.compile(r'(device_?id|hwid|hardware_?id|android_?id|installation)', re.I), "device_id", "medium"),
    (re.compile(r'(instance_?id|app_?instance|installation_id)', re.I), "device_id", "medium"),
    (re.compile(r'(project_?id|sender_?id|application_?id|app_?id)', re.I), "sdk_key", "medium"),
    (re.compile(r'(user_?id|uid)', re.I), "device_id", "medium"),
    (re.compile(r'(gmp_app_id|google_app_id|firebase)', re.I), "sdk_key", "medium"),
    (re.compile(r'(base_?url|endpoint)', re.I), "config", "low"),
    (re.compile(r'(branch_?key|bnc_branch_key)', re.I), "api_key", "medium"),
    (re.compile(r'(appsflyer|AF_)', re.I), "sdk_key", "medium"),
]

# Value patterns
_JWT_RE = re.compile(r'^eyJ[A-Za-z0-9_-]{10,}')
_UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
_HEX_KEY_RE = re.compile(r'^[0-9a-f]{32,}$', re.I)
_LONG_BASE64_RE = re.compile(r'^[A-Za-z0-9+/=]{20,}$')

# Known SDK key names that are interesting
_KNOWN_INTERESTING_KEYS = {
    "pw_hwid", "device_id", "user_id", "project_id", "application_id",
    "pw_base_url", "registration_id", "app_version",
    "existing_instance_identifier", "firebase.installation.id",
    "crashlytics.installation.id", "gmp_app_id", "app_instance_id",
    "bnc_branch_key", "AF_INSTALLATION", "appsFlyerCount",
    "savedProperties", "appsFlyerFirstInstall",
    "pw_registered_for_push", "app_set_id",
}


def _is_encrypted_key(key: str) -> bool:
    """Detect if a pref key is Tink-encrypted (base64 blob)."""
    if not key:
        return False
    return key.startswith("AQ") and len(key) > 30 and ("/" in key or "+" in key or "=" in key)


def _classify_secret(key: str, value: Any, file: str) -> SecretInfo | None:
    """Try to classify a pref key/value as a secret."""
    if value is None or value == "" or value == -1:
        return None

    str_value = str(value)

    # Skip very short or boolean values
    if str_value in ("true", "false", "0", "1", "-1", ""):
        return None

    # Skip encrypted values (we can't read them anyway)
    if _is_encrypted_key(key):
        return None
    if isinstance(value, str) and value.startswith("AQ") and len(value) > 30:
        return None

    # Check key name patterns
    for pattern, category, sensitivity in _SECRET_KEY_PATTERNS:
        if pattern.search(key):
            name = _human_readable_name(key, file)
            return SecretInfo(
                name=name,
                value=str_value,
                source=f"prefs:{file}:{key}",
                category=category,
                sensitivity=sensitivity,
            )

    # Check known interesting keys
    if key in _KNOWN_INTERESTING_KEYS:
        name = _human_readable_name(key, file)
        category, sensitivity = _categorize_known_key(key, str_value)
        return SecretInfo(
            name=name,
            value=str_value,
            source=f"prefs:{file}:{key}",
            category=category,
            sensitivity=sensitivity,
        )

    # Check value patterns (JWT, UUID, hex key)
    if isinstance(value, str) and len(value) >= 16:
        if _JWT_RE.match(value):
            return SecretInfo(
                name=_human_readable_name(key, file),
                value=str_value,
                source=f"prefs:{file}:{key}",
                category="token",
                sensitivity="high",
            )
        if _HEX_KEY_RE.match(value) and len(value) >= 32:
            return SecretInfo(
                name=_human_readable_name(key, file),
                value=str_value,
                source=f"prefs:{file}:{key}",
                category="device_id",
                sensitivity="medium",
            )

    return None


def _human_readable_name(key: str, file: str) -> str:
    """Generate a human-readable name for a secret."""
    # Extract SDK name from file
    file_clean = file.replace(".xml", "").replace("com.google.", "").replace("com.", "")
    parts = file_clean.split(".")
    sdk_prefix = parts[-1] if parts else "unknown"

    # Clean up key name
    key_clean = key.replace("_", " ").replace(".", " ").title()
    return f"{sdk_prefix.title()} {key_clean}"


def _categorize_known_key(key: str, value: str) -> tuple[str, str]:
    """Categorize a known interesting key."""
    if "id" in key.lower() or "hwid" in key.lower():
        if _UUID_RE.match(value):
            return "device_id", "medium"
        return "device_id", "medium"
    if "url" in key.lower():
        return "config", "low"
    if "key" in key.lower():
        return "api_key", "medium"
    if "count" in key.lower() or "version" in key.lower():
        return "config", "low"
    return "sdk_key", "medium"


def analyze_vault(events: list[dict[str, Any]], package: str | None = None) -> VaultReport:
    """Analyze vault events from a session.

    Args:
        events: All session events (will be filtered to module=="vault").
        package: Package name for context.

    Returns:
        VaultReport with prefs files, databases, secrets, and file writes.
    """
    vault_events = [e for e in events if e.get("module") == "vault"]

    # Track pref files
    pref_files_map: dict[str, dict[str, int]] = {}  # file → {reads, writes}
    pref_keys_map: dict[str, set[str]] = {}  # file → set of keys

    # Track databases
    db_map: dict[str, dict[str, Any]] = {}  # db_path → {tables, count, samples}

    # Track secrets (deduplicate by name+value to avoid dupes from initial_dump + pref_read)
    secrets_map: dict[str, SecretInfo] = {}  # key = f"{name}|{value}"

    # Track file writes
    file_writes: list[FileWriteInfo] = []

    # Track keystore entries
    keystore_entries: list[KeystoreEntry] = []

    # Track decrypted prefs from EncryptedSharedPreferences / Tink hooks
    decrypted_prefs: list[DecryptedPrefEntry] = []
    decrypted_keys_seen: set[str] = set()  # dedup by key
    tink_decrypts = 0

    total_reads = 0
    total_writes = 0

    # Process initial_dump first (contains snapshot of all prefs)
    for event in vault_events:
        if event.get("type") == "initial_dump":
            data = event.get("data", {})
            prefs_dump = data.get("prefs", {})
            for file_name, kv_pairs in prefs_dump.items():
                if file_name not in pref_files_map:
                    pref_files_map[file_name] = {"reads": 0, "writes": 0}
                    pref_keys_map[file_name] = set()

                is_encrypted = "__androidx_security_crypto_encrypted_prefs_key_keyset__" in kv_pairs

                for key, value in kv_pairs.items():
                    pref_keys_map[file_name].add(key)

                    # Extract keystore entries
                    if key == "__androidx_security_crypto_encrypted_prefs_key_keyset__":
                        keystore_entries.append(KeystoreEntry(
                            store=file_name,
                            key_type="AesSivKey",
                            role="key_encryption",
                            keyset_hex=str(value)[:100],
                        ))
                        continue
                    if key == "__androidx_security_crypto_encrypted_prefs_value_keyset__":
                        keystore_entries.append(KeystoreEntry(
                            store=file_name,
                            key_type="AesGcmKey",
                            role="value_encryption",
                            keyset_hex=str(value)[:100],
                        ))
                        continue

                    # Skip encrypted values in encrypted stores
                    if is_encrypted and _is_encrypted_key(key):
                        continue

                    secret = _classify_secret(key, value, file_name)
                    if secret:
                        dedup_key = f"{secret.name}|{secret.value}"
                        if dedup_key not in secrets_map:
                            secrets_map[dedup_key] = secret

            # Track databases from initial dump
            db_list = data.get("databases", [])
            for db_path in db_list:
                if db_path.endswith("-journal"):
                    continue
                db_name = db_path.split("/")[-1] if "/" in db_path else db_path
                if db_path not in db_map:
                    db_map[db_path] = {"name": db_name, "tables": set(), "count": 0, "samples": []}

    # Process individual events
    for event in vault_events:
        etype = event.get("type", "")
        data = event.get("data", {})
        ts = event.get("ts")

        if etype == "pref_read":
            total_reads += 1
            file = data.get("file", "unknown")
            key = data.get("key", "")
            value = data.get("value")

            if file not in pref_files_map:
                pref_files_map[file] = {"reads": 0, "writes": 0}
                pref_keys_map[file] = set()
            pref_files_map[file]["reads"] += 1
            pref_keys_map[file].add(key)

            # Try to extract secrets
            if not _is_encrypted_key(key):
                secret = _classify_secret(key, value, file)
                if secret:
                    dedup_key = f"{secret.name}|{secret.value}"
                    if dedup_key not in secrets_map:
                        secrets_map[dedup_key] = secret

        elif etype == "pref_write":
            total_writes += 1
            key = data.get("key", "")
            value = data.get("value")

        elif etype == "file_write":
            path = data.get("path", "")
            size = data.get("size", 0)
            preview = data.get("preview", "")
            file_writes.append(FileWriteInfo(
                path=path,
                size=size,
                preview=preview[:500] if preview else "",
                ts=ts,
            ))

        elif etype == "encrypted_pref_read":
            key = data.get("key", "")
            value = data.get("value")
            value_type = data.get("value_type", "")
            source = data.get("source", "EncryptedSharedPreferences")

            if key and key not in decrypted_keys_seen:
                decrypted_keys_seen.add(key)
                decrypted_prefs.append(DecryptedPrefEntry(
                    key=key,
                    value=str(value) if value is not None else None,
                    value_type=value_type,
                    source=source,
                ))

            # Also try to classify as a secret
            if value is not None and not _is_encrypted_key(key):
                secret = _classify_secret(key, value, f"encrypted_prefs:{source}")
                if secret:
                    secret.sensitivity = "high"  # Encrypted prefs are always high sensitivity
                    dedup_key = f"{secret.name}|{secret.value}"
                    if dedup_key not in secrets_map:
                        secrets_map[dedup_key] = secret

        elif etype == "encrypted_pref_write":
            key = data.get("key", "")
            value = data.get("value")
            value_type = data.get("value_type", "")
            source = data.get("source", "EncryptedSharedPreferences")
            total_writes += 1

            if key and key not in decrypted_keys_seen:
                decrypted_keys_seen.add(key)
                decrypted_prefs.append(DecryptedPrefEntry(
                    key=key,
                    value=str(value) if value is not None else None,
                    value_type=value_type,
                    source=f"{source}:write",
                ))

            # Also try to classify as a secret
            if value is not None and not _is_encrypted_key(key):
                secret = _classify_secret(key, value, f"encrypted_prefs:{source}")
                if secret:
                    secret.sensitivity = "high"
                    dedup_key = f"{secret.name}|{secret.value}"
                    if dedup_key not in secrets_map:
                        secrets_map[dedup_key] = secret

        elif etype == "encrypted_pref_dump":
            entries = data.get("entries", {})
            source = data.get("source", "EncryptedSharedPreferences")
            for k, v in entries.items():
                if k and k not in decrypted_keys_seen:
                    decrypted_keys_seen.add(k)
                    decrypted_prefs.append(DecryptedPrefEntry(
                        key=k,
                        value=str(v) if v is not None else None,
                        value_type="string",
                        source=source,
                    ))

                if v is not None and not _is_encrypted_key(k):
                    secret = _classify_secret(k, v, f"encrypted_prefs:{source}")
                    if secret:
                        secret.sensitivity = "high"
                        dedup_key = f"{secret.name}|{secret.value}"
                        if dedup_key not in secrets_map:
                            secrets_map[dedup_key] = secret

        elif etype == "tink_decrypt":
            tink_decrypts += 1

        elif etype in ("sqlite_write", "sqlite_query"):
            db_path = data.get("db", "")
            table = data.get("table", "")
            values = data.get("values", "")
            db_name = db_path.split("/")[-1] if "/" in db_path else db_path

            if db_path not in db_map:
                db_map[db_path] = {"name": db_name, "tables": set(), "count": 0, "samples": []}
            db_map[db_path]["tables"].add(table)
            db_map[db_path]["count"] += 1
            if values and len(db_map[db_path]["samples"]) < 5:
                db_map[db_path]["samples"].append(values[:200])

    # Merge pref files that differ only by .xml suffix (initial_dump vs pref_read)
    merged_prefs: dict[str, dict[str, Any]] = {}
    for file, counters in pref_files_map.items():
        # Normalize: prefer the .xml version
        base = file.replace(".xml", "")
        xml_name = file if file.endswith(".xml") else f"{file}.xml"
        canonical = xml_name  # prefer .xml name

        if canonical in merged_prefs:
            merged_prefs[canonical]["reads"] += counters["reads"]
            merged_prefs[canonical]["writes"] += counters["writes"]
            merged_prefs[canonical]["keys"].update(pref_keys_map.get(file, set()))
        elif base in merged_prefs:
            # Already have the non-.xml version, merge into it
            old = merged_prefs.pop(base)
            old["reads"] += counters["reads"]
            old["writes"] += counters["writes"]
            old["keys"].update(pref_keys_map.get(file, set()))
            merged_prefs[canonical] = old
        else:
            merged_prefs[canonical] = {
                "reads": counters["reads"],
                "writes": counters["writes"],
                "keys": set(pref_keys_map.get(file, set())),
            }

    # Build pref files list
    prefs_files: list[PrefsFile] = []
    for file, info in sorted(merged_prefs.items()):
        is_encrypted = any(
            _is_encrypted_key(k)
            for k in info["keys"]
        ) or "crypto" in file.lower()

        sample_keys = sorted(
            k for k in info["keys"]
            if not _is_encrypted_key(k) and not k.startswith("__androidx_security")
        )[:10]

        prefs_files.append(PrefsFile(
            file=file,
            keys_read=info["reads"],
            keys_written=info["writes"],
            sample_keys=sample_keys,
            is_encrypted=is_encrypted,
        ))

    # Build databases list — merge entries that have the same name (from initial_dump vs sqlite_write)
    merged_dbs: dict[str, dict[str, Any]] = {}
    for db_path, info in db_map.items():
        name = info["name"]
        if name in merged_dbs:
            merged_dbs[name]["tables"].update(info["tables"])
            merged_dbs[name]["count"] += info["count"]
            merged_dbs[name]["samples"].extend(info["samples"])
            if len(db_path) > len(merged_dbs[name]["path"]):
                merged_dbs[name]["path"] = db_path  # prefer full path
        else:
            merged_dbs[name] = {
                "path": db_path,
                "name": name,
                "tables": set(info["tables"]),
                "count": info["count"],
                "samples": list(info["samples"]),
            }

    databases: list[DatabaseInfo] = []
    for info in sorted(merged_dbs.values(), key=lambda x: x["count"], reverse=True):
        databases.append(DatabaseInfo(
            path=info["path"],
            name=info["name"],
            tables=sorted(info["tables"]),
            write_count=info["count"],
            sample_values=info["samples"][:5],
        ))

    return VaultReport(
        prefs_files=prefs_files,
        databases=databases,
        secrets=sorted(secrets_map.values(), key=lambda s: ({"high": 0, "medium": 1, "low": 2}.get(s.sensitivity, 3), s.name)),
        file_writes=file_writes,
        keystore_entries=keystore_entries,
        decrypted_prefs=decrypted_prefs,
        tink_decrypts=tink_decrypts,
        total_pref_reads=total_reads,
        total_pref_writes=total_writes,
    )
