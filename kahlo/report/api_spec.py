"""API Spec Generator — produce JSON API specification from analysis results."""
from __future__ import annotations

import json
from typing import Any

from kahlo.analyze.netmodel import NetmodelReport
from kahlo.analyze.traffic import TrafficReport
from kahlo.analyze.vault import VaultReport


def generate_api_spec(
    session: dict[str, Any],
    traffic: TrafficReport,
    vault: VaultReport,
    netmodel: NetmodelReport,
) -> str:
    """Generate a JSON API specification from analysis results.

    Args:
        session: Raw session data dict.
        traffic: Traffic analysis results.
        vault: Vault analysis results.
        netmodel: Netmodel analysis results.

    Returns:
        JSON string with API specification.
    """
    package = session.get("package", "unknown")

    # Determine base URLs from servers
    base_urls: list[str] = []
    for server in traffic.servers:
        url = f"https://{server.host}"
        if server.port != 443:
            url += f":{server.port}"
        base_urls.append(url)

    # Determine auth model
    auth_model: dict[str, Any] = {"type": "unknown"}
    for ep in traffic.endpoints:
        if ep.auth_value:
            if ep.auth_value == "Token null":
                auth_model = {"type": "none", "note": "Authorization header present but value is 'Token null'"}
            elif ep.auth_value.startswith("Bearer "):
                auth_model = {"type": "bearer", "token_source": "encrypted_prefs"}
            else:
                auth_model = {"type": "token", "header": "Authorization", "sample": ep.auth_value[:30]}
            break

    # Signing info
    signing: dict[str, Any] | None = None
    if netmodel.signing_recipe:
        sr = netmodel.signing_recipe
        signing = {
            "algorithm": sr.algorithm,
            "key_hex": sr.key_hex,
            "key_ascii": sr.key_ascii,
            "input_pattern": sr.input_pattern,
            "nonce_method": sr.nonce_method,
        }

    # Encryption info
    encryption: dict[str, Any] | None = None
    if netmodel.crypto_operations:
        op = netmodel.crypto_operations[0]
        encryption = {
            "algorithm": op.algorithm,
            "key_hex": op.key_hex,
            "iv_hex": op.iv_hex,
            "note": f"Used for {op.op}ing {op.input_length} byte payloads",
        }

    # Build endpoints
    endpoints: list[dict[str, Any]] = []
    for ep in traffic.endpoints:
        endpoint_entry: dict[str, Any] = {
            "path": ep.path or "/",
            "method": ep.method or "GET",
            "host": ep.host or "",
            "url": ep.url,
            "content_type": ep.content_type,
            "auth_required": ep.has_auth and ep.auth_value != "Token null",
            "count": ep.count,
        }

        if ep.sample_headers:
            endpoint_entry["sample_headers"] = ep.sample_headers

        if ep.sample_body_preview:
            endpoint_entry["sample_body_preview"] = ep.sample_body_preview[:500]

            # Try to parse JSON body
            body = ep.sample_body_preview.strip()
            if body.startswith("{"):
                try:
                    # Body might be truncated, so try to parse what we can
                    parsed = json.loads(body)
                    endpoint_entry["sample_body_json"] = parsed
                except json.JSONDecodeError:
                    pass

        endpoints.append(endpoint_entry)

    # Extracted keys and tokens relevant to API usage
    api_keys: dict[str, str] = {}
    for secret in vault.secrets:
        if secret.category in ("api_key", "sdk_key", "token"):
            api_keys[secret.name] = secret.value

    spec: dict[str, Any] = {
        "app": package,
        "session_id": session.get("session_id", ""),
        "generated_at": session.get("started_at", ""),
        "base_urls": base_urls,
        "auth": auth_model,
        "signing": signing,
        "encryption": encryption,
        "endpoints": endpoints,
        "extracted_keys": api_keys,
        "servers": [
            {
                "host": s.host,
                "ip": s.ip,
                "port": s.port,
                "role": s.role,
                "connections": s.connection_count,
            }
            for s in traffic.servers
        ],
    }

    return json.dumps(spec, indent=2, ensure_ascii=False)
