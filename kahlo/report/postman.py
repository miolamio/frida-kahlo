"""Postman Export — generate Postman Collection v2.1 JSON from analysis results."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

from kahlo.analyze.traffic import EndpointInfo, TrafficReport
from kahlo.analyze.vault import VaultReport


def _safe_name(method: str, url: str, host: str | None = None) -> str:
    """Create a human-readable name for a Postman request item."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    # Take the last meaningful path segment
    segments = [s for s in path.split("/") if s]
    if segments:
        # CamelCase to readable
        name_part = segments[-1]
        name_part = re.sub(r'([a-z])([A-Z])', r'\1 \2', name_part)
    else:
        name_part = "root"

    return f"{method} {name_part}"


def _parse_url(url: str) -> dict[str, Any]:
    """Parse a URL into Postman URL format."""
    parsed = urlparse(url)
    host_parts = (parsed.hostname or "").split(".")
    path_parts = [p for p in (parsed.path or "/").split("/") if p]

    result: dict[str, Any] = {
        "raw": url,
        "protocol": parsed.scheme or "https",
        "host": host_parts,
        "path": path_parts,
    }

    if parsed.port:
        result["port"] = str(parsed.port)

    if parsed.query:
        query_params: list[dict[str, str]] = []
        for param in parsed.query.split("&"):
            if "=" in param:
                key, value = param.split("=", 1)
                query_params.append({"key": key, "value": value})
            else:
                query_params.append({"key": param, "value": ""})
        result["query"] = query_params

    return result


def _build_request_item(ep: EndpointInfo) -> dict[str, Any]:
    """Build a Postman request item from an EndpointInfo."""
    method = ep.method or "GET"

    # Build headers
    headers: list[dict[str, str]] = []
    for key, value in (ep.sample_headers or {}).items():
        if key.lower() in ("content-length", "host"):
            continue
        headers.append({
            "key": key,
            "value": value,
        })

    request: dict[str, Any] = {
        "method": method,
        "header": headers,
        "url": _parse_url(ep.url),
    }

    # Add body for POST/PUT/PATCH
    if ep.sample_body_preview and method.upper() in ("POST", "PUT", "PATCH"):
        body = ep.sample_body_preview

        # Determine mode
        content_type = ep.content_type or ""

        if "json" in content_type or body.strip().startswith("{"):
            # Try to pretty-print JSON
            try:
                parsed_body = json.loads(body)
                body = json.dumps(parsed_body, indent=2, ensure_ascii=False)
            except json.JSONDecodeError:
                pass

            request["body"] = {
                "mode": "raw",
                "raw": body,
                "options": {
                    "raw": {
                        "language": "json"
                    }
                }
            }
        elif "x-www-form-urlencoded" in content_type:
            # Parse form data
            form_data: list[dict[str, str]] = []
            for param in body.split("&"):
                if "=" in param:
                    key, value = param.split("=", 1)
                    form_data.append({"key": key, "value": value})
            request["body"] = {
                "mode": "urlencoded",
                "urlencoded": form_data,
            }
        else:
            request["body"] = {
                "mode": "raw",
                "raw": body,
            }

    # Add auth if present
    if ep.auth_value:
        if ep.auth_value.startswith("Bearer "):
            token = ep.auth_value[7:]
            request["auth"] = {
                "type": "bearer",
                "bearer": [{"key": "token", "value": token, "type": "string"}]
            }
        elif ep.auth_value.startswith("Token "):
            # Custom token auth — keep as header
            pass  # Already in headers
        else:
            # Generic auth header
            pass  # Already in headers

    item: dict[str, Any] = {
        "name": _safe_name(method, ep.url, ep.host),
        "request": request,
        "response": [],
    }

    return item


def generate_postman_collection(
    traffic: TrafficReport,
    vault: VaultReport | None = None,
    package: str = "app",
) -> dict[str, Any]:
    """Generate a Postman Collection v2.1 JSON.

    Items are grouped by server (folders in Postman).
    Includes auth headers, sample bodies, content types.

    Args:
        traffic: Traffic analysis results.
        vault: Vault analysis results (optional, for additional auth info).
        package: App package name for the collection title.

    Returns:
        Postman Collection v2.1 as a Python dict.
    """
    app_name = package.split(".")[-1].title() if "." in package else package

    # Group endpoints by host
    host_groups: dict[str, list[EndpointInfo]] = defaultdict(list)
    for ep in traffic.endpoints:
        host = ep.host or urlparse(ep.url).hostname or "unknown"
        host_groups[host].append(ep)

    # Build folder items grouped by host
    items: list[dict[str, Any]] = []

    for host in sorted(host_groups.keys()):
        endpoints = host_groups[host]
        folder_items: list[dict[str, Any]] = []

        for ep in endpoints:
            folder_items.append(_build_request_item(ep))

        # If only one host, don't wrap in folder
        if len(host_groups) == 1:
            items.extend(folder_items)
        else:
            folder: dict[str, Any] = {
                "name": host,
                "item": folder_items,
            }
            items.append(folder)

    # Build collection
    collection: dict[str, Any] = {
        "info": {
            "name": f"{app_name} API",
            "description": f"API collection for {package}, generated by Frida-Kahlo",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "item": items,
    }

    # Add collection-level variables for common values
    variables: list[dict[str, str]] = []

    # Add base URLs as variables
    seen_hosts: set[str] = set()
    for s in traffic.servers:
        if s.host not in seen_hosts:
            seen_hosts.add(s.host)
            var_name = s.host.replace(".", "_").replace("-", "_")
            scheme = "https" if s.tls else "http"
            port_str = f":{s.port}" if s.port not in (443, 80) else ""
            variables.append({
                "key": f"base_url_{var_name}",
                "value": f"{scheme}://{s.host}{port_str}",
            })

    # Add API keys from vault
    if vault:
        for secret in vault.secrets:
            if secret.category in ("api_key", "sdk_key"):
                variables.append({
                    "key": secret.name,
                    "value": secret.value,
                })

    if variables:
        collection["variable"] = variables

    return collection
