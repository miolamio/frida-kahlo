"""API Spec Generator — produce JSON API specification from analysis results."""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from kahlo.analyze.netmodel import NetmodelReport
from kahlo.analyze.traffic import TrafficReport
from kahlo.analyze.vault import VaultReport


def _endpoint_base_url(url: str, host: str | None, port: int = 443) -> str:
    """Extract the base URL (scheme + host + optional port) for an endpoint."""
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    hostname = parsed.hostname or host or ""
    p = parsed.port or port
    if p and p not in (443, 80):
        return f"{scheme}://{hostname}:{p}"
    return f"{scheme}://{hostname}"


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

    # Determine auth models — collect all distinct auth types across endpoints
    auth_models: list[dict[str, Any]] = []
    seen_auth: set[str] = set()
    for ep in traffic.endpoints:
        if ep.auth_value and ep.auth_value not in seen_auth:
            seen_auth.add(ep.auth_value)
            if ep.auth_value == "Token null":
                auth_models.append({
                    "type": "none",
                    "header_value": "Token null",
                    "note": "Authorization header present but value is 'Token null'",
                    "hosts": [ep.host or ""],
                })
            elif ep.auth_value.startswith("Bearer "):
                auth_models.append({
                    "type": "bearer",
                    "token_source": "encrypted_prefs",
                    "hosts": [ep.host or ""],
                })
            else:
                auth_models.append({
                    "type": "token",
                    "header": "Authorization",
                    "sample": ep.auth_value[:30],
                    "hosts": [ep.host or ""],
                })

    # Backward-compatible single auth_model — pick the first one
    auth_model: dict[str, Any] = {"type": "unknown"}
    if auth_models:
        auth_model = {k: v for k, v in auth_models[0].items() if k != "hosts"}

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

    # Build endpoints with per-endpoint base_url and auth
    endpoints: list[dict[str, Any]] = []
    for ep in traffic.endpoints:
        base_url = _endpoint_base_url(ep.url, ep.host)

        endpoint_entry: dict[str, Any] = {
            "path": ep.path or "/",
            "method": ep.method or "GET",
            "host": ep.host or "",
            "base_url": base_url,
            "url": ep.url,
            "content_type": ep.content_type,
            "auth_required": ep.has_auth and ep.auth_value != "Token null",
            "auth_value": ep.auth_value,
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

        # Body decoding info (Improvement 6)
        if ep.request_body_format:
            endpoint_entry["request_body_format"] = ep.request_body_format
        if ep.request_body_fields:
            endpoint_entry["request_body_fields"] = ep.request_body_fields
        if ep.response_body_format:
            endpoint_entry["response_body_format"] = ep.response_body_format
        if ep.response_body_fields:
            endpoint_entry["response_body_fields"] = ep.response_body_fields
        if ep.body_schema:
            endpoint_entry["body_schema"] = ep.body_schema

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
