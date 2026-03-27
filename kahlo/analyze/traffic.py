"""Traffic Analyzer — parse traffic events into endpoint map and server inventory."""
from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from kahlo.analyze.decoder import BodyDecoder, DecodedBody


class ServerInfo(BaseModel):
    """A unique server (host:port) observed in TCP connections."""
    host: str
    ip: str | None = None
    port: int = 443
    role: str = "unknown"
    connection_count: int = 1
    tls: bool = True


class EndpointInfo(BaseModel):
    """A unique HTTP endpoint extracted from SSL raw data."""
    url: str
    method: str | None = None
    host: str | None = None
    path: str | None = None
    count: int = 1
    content_type: str | None = None
    has_auth: bool = False
    auth_value: str | None = None
    sample_headers: dict[str, str] = Field(default_factory=dict)
    sample_body_preview: str | None = None
    # Body decoding fields (Improvement 6)
    request_body_format: str | None = None
    request_body_fields: list[str] | None = None
    response_body_format: str | None = None
    response_body_fields: list[str] | None = None
    body_schema: list[str] | None = None  # merged field names from req+resp


class TCPConnection(BaseModel):
    """A single TCP connection event."""
    host: str
    ip: str | None = None
    port: int = 443
    ts: str | None = None


class SSLRawCapture(BaseModel):
    """Summary of an SSL raw data capture."""
    direction: str  # "in" or "out"
    preview: str = ""
    length: int = 0
    source: str | None = None
    ts: str | None = None
    parsed_method: str | None = None
    parsed_url: str | None = None
    parsed_host: str | None = None
    parsed_status: int | None = None
    parsed_headers: dict[str, str] = Field(default_factory=dict)
    parsed_body_preview: str | None = None


class TrafficReport(BaseModel):
    """Complete traffic analysis from a session."""
    servers: list[ServerInfo] = Field(default_factory=list)
    endpoints: list[EndpointInfo] = Field(default_factory=list)
    tcp_connections: list[TCPConnection] = Field(default_factory=list)
    ssl_sessions: list[SSLRawCapture] = Field(default_factory=list)
    total_requests: int = 0
    total_connections: int = 0


# --- Role detection ---

_ROLE_PATTERNS: list[tuple[str, str]] = [
    ("firebase", "crash_analytics"),
    ("crashlytics", "crash_analytics"),
    ("sentry", "error_reporting"),
    ("appsflyer", "attribution"),
    ("appsflyersdk", "attribution"),
    ("branch", "attribution"),
    ("adjust", "attribution"),
    ("pushwoosh", "push_notifications"),
    ("wavesend", "push_notifications"),
    ("fcm", "push_notifications"),
    ("push", "push_notifications"),
    ("metrica", "analytics"),
    ("appmetrica", "analytics"),
    ("amplitude", "analytics"),
    ("mixpanel", "analytics"),
    ("analytics", "analytics"),
    ("cdn", "cdn"),
    ("cloudfront", "cdn"),
    ("googleapis", "google_services"),
]


def _detect_role(host: str, package: str | None = None) -> str:
    """Detect server role from hostname."""
    host_lower = host.lower()
    for pattern, role in _ROLE_PATTERNS:
        if pattern in host_lower:
            return role
    # Check if domain matches app name → core_api
    if package:
        # e.g. com.voltmobi.yakitoriya → "yakitoriya"
        parts = package.split(".")
        for part in parts:
            if len(part) > 3 and part.lower() in host_lower:
                return "core_api"
    return "unknown"


# --- HTTP parsing from SSL raw previews ---

_HTTP_REQUEST_RE = re.compile(
    r'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/[\d.]+',
)

_HTTP_RESPONSE_RE = re.compile(
    r'^HTTP/[\d.]+\s+(\d+)\s+(.+?)(?:\.\.|$)',
)

_HEADER_RE = re.compile(r'^([A-Za-z][\w-]+):\s*(.+?)(?:\.\.|$)')


def _parse_ssl_preview(preview: str, direction: str) -> dict[str, Any]:
    """Extract HTTP method, URL, headers, body from an SSL raw preview string.

    The preview uses '..' as line separator (two dots replace \\r\\n).
    """
    result: dict[str, Any] = {}
    if not preview:
        return result

    # Split on '..' which represents CRLF in the captured preview
    lines = preview.split("..")
    headers: dict[str, str] = {}
    body_start = False
    body_parts: list[str] = []

    for line in lines:
        line = line.strip()
        if not line and not body_start:
            body_start = True
            continue

        if body_start:
            body_parts.append(line)
            continue

        if direction == "out":
            m = _HTTP_REQUEST_RE.match(line)
            if m:
                result["method"] = m.group(1)
                result["path"] = m.group(2)
                continue

        if direction == "in":
            m = _HTTP_RESPONSE_RE.match(line)
            if m:
                result["status"] = int(m.group(1))
                continue

        hm = _HEADER_RE.match(line)
        if hm:
            headers[hm.group(1)] = hm.group(2).strip()

    if headers:
        result["headers"] = headers
    if body_parts:
        body = "..".join(body_parts).strip()
        if body:
            result["body_preview"] = body

    return result


def analyze_traffic(events: list[dict[str, Any]], package: str | None = None) -> TrafficReport:
    """Analyze traffic events from a session.

    Args:
        events: All session events (will be filtered to module=="traffic").
        package: Package name for role detection heuristics.

    Returns:
        TrafficReport with servers, endpoints, connections, and SSL captures.
    """
    traffic_events = [e for e in events if e.get("module") == "traffic"]

    connections: list[TCPConnection] = []
    ssl_captures: list[SSLRawCapture] = []

    # Track unique servers: key = (host, ip, port)
    server_map: dict[tuple[str, str | None, int], int] = {}
    # Track unique endpoints: key = (method, host, path)
    endpoint_map: dict[tuple[str | None, str | None, str | None], EndpointInfo] = {}
    # Map request index to endpoint key for response correlation
    index_to_ep_key: dict[int, tuple[str | None, str | None, str | None]] = {}

    for event in traffic_events:
        etype = event.get("type", "")
        data = event.get("data", {})
        ts = event.get("ts")

        if etype == "tcp_connect":
            host = data.get("host", "")
            ip = data.get("ip")
            port = data.get("port", 443)
            connections.append(TCPConnection(host=host, ip=ip, port=port, ts=ts))
            key = (host, ip, port)
            server_map[key] = server_map.get(key, 0) + 1

        elif etype == "http_request":
            # Structured HTTP request from OkHttp interceptor or SSL parser
            method = data.get("method", "")
            url = data.get("url", "")
            req_headers = data.get("headers", {})
            body = data.get("body", "")
            req_index = data.get("index", 0)

            # Extract host and path from URL
            host = ""
            path = ""
            if url:
                # Parse URL to get host and path
                if "://" in url:
                    after_scheme = url.split("://", 1)[1]
                    slash_idx = after_scheme.find("/")
                    if slash_idx >= 0:
                        host = after_scheme[:slash_idx]
                        path = after_scheme[slash_idx:]
                    else:
                        host = after_scheme
                        path = "/"
                else:
                    path = url
                    host = req_headers.get("Host", "")

            # Decode request body
            content_type = req_headers.get("Content-Type") or req_headers.get("content-type")
            req_decoded: DecodedBody | None = None
            req_body_format: str | None = None
            req_body_fields: list[str] | None = None

            # Use JS-side fields if available, else decode Python-side
            js_format = data.get("body_format")
            js_fields = data.get("body_fields")

            if body:
                req_decoded = BodyDecoder.decode(body, content_type=content_type)
                req_body_format = req_decoded.format
                req_body_fields = req_decoded.fields
            elif js_format and js_format != "empty":
                req_body_format = js_format
                req_body_fields = js_fields

            ep_key = (method, host, path)
            if ep_key in endpoint_map:
                endpoint_map[ep_key].count += 1
            else:
                auth_header = req_headers.get("Authorization") or req_headers.get("authorization")
                endpoint_map[ep_key] = EndpointInfo(
                    url=url or f"https://{host}{path}",
                    method=method,
                    host=host,
                    path=path,
                    count=1,
                    content_type=content_type,
                    has_auth=bool(auth_header and auth_header != "Token null"),
                    auth_value=auth_header,
                    sample_headers=req_headers,
                    sample_body_preview=body[:500] if body else None,
                    request_body_format=req_body_format,
                    request_body_fields=req_body_fields,
                )

            # Track index -> endpoint key for response correlation
            if req_index:
                index_to_ep_key[req_index] = ep_key

        elif etype == "http_response":
            # Structured HTTP response — enrich endpoint with response body info
            res_body = data.get("body", "")
            res_headers = data.get("headers", {})
            res_index = data.get("index", 0)
            res_url = data.get("url", "")

            # Decode response body
            res_content_type = res_headers.get("Content-Type") or res_headers.get("content-type")
            res_body_format: str | None = None
            res_body_fields: list[str] | None = None

            if res_body:
                res_decoded = BodyDecoder.decode(res_body, content_type=res_content_type)
                res_body_format = res_decoded.format
                res_body_fields = res_decoded.fields

            # Correlate response to request endpoint
            ep_key_for_res = index_to_ep_key.get(res_index)
            if ep_key_for_res and ep_key_for_res in endpoint_map:
                ep = endpoint_map[ep_key_for_res]
                if res_body_format and not ep.response_body_format:
                    ep.response_body_format = res_body_format
                if res_body_fields and not ep.response_body_fields:
                    ep.response_body_fields = res_body_fields

        elif etype == "ssl_raw":
            direction = data.get("direction", "out")
            preview = data.get("preview", "")
            length = data.get("length", 0)
            source = data.get("source")

            parsed = _parse_ssl_preview(preview, direction)

            capture = SSLRawCapture(
                direction=direction,
                preview=preview[:500] if preview else "",
                length=length,
                source=source,
                ts=ts,
                parsed_method=parsed.get("method"),
                parsed_url=parsed.get("path"),
                parsed_host=parsed.get("headers", {}).get("Host"),
                parsed_status=parsed.get("status"),
                parsed_headers=parsed.get("headers", {}),
                parsed_body_preview=parsed.get("body_preview", "")[:500] if parsed.get("body_preview") else None,
            )
            ssl_captures.append(capture)

            # Build endpoint info from outgoing requests (fallback from raw SSL)
            if direction == "out" and capture.parsed_method:
                host = capture.parsed_host or ""
                path = capture.parsed_url or ""
                ep_key = (capture.parsed_method, host, path)

                if ep_key in endpoint_map:
                    endpoint_map[ep_key].count += 1
                else:
                    ssl_content_type = parsed.get("headers", {}).get("Content-Type")
                    auth_header = parsed.get("headers", {}).get("Authorization")
                    url = f"https://{host}{path}" if host else path
                    ssl_body_preview = parsed.get("body_preview", "")[:500] if parsed.get("body_preview") else None

                    # Decode SSL body if present
                    ssl_req_format: str | None = None
                    ssl_req_fields: list[str] | None = None
                    if ssl_body_preview:
                        ssl_decoded = BodyDecoder.decode(ssl_body_preview, content_type=ssl_content_type)
                        ssl_req_format = ssl_decoded.format
                        ssl_req_fields = ssl_decoded.fields

                    endpoint_map[ep_key] = EndpointInfo(
                        url=url,
                        method=capture.parsed_method,
                        host=host,
                        path=path,
                        count=1,
                        content_type=ssl_content_type,
                        has_auth=bool(auth_header and auth_header != "Token null"),
                        auth_value=auth_header,
                        sample_headers=parsed.get("headers", {}),
                        sample_body_preview=ssl_body_preview,
                        request_body_format=ssl_req_format,
                        request_body_fields=ssl_req_fields,
                    )

    # Compute body_schema: merge request + response field names per endpoint
    for ep in endpoint_map.values():
        schema_fields: list[str] = []
        if ep.request_body_fields:
            for f in ep.request_body_fields:
                if f not in schema_fields:
                    schema_fields.append(f)
        if ep.response_body_fields:
            for f in ep.response_body_fields:
                if f not in schema_fields:
                    schema_fields.append(f)
        if schema_fields:
            ep.body_schema = schema_fields

    # Build server list
    servers: list[ServerInfo] = []
    for (host, ip, port), count in server_map.items():
        role = _detect_role(host, package)
        servers.append(ServerInfo(
            host=host,
            ip=ip,
            port=port,
            role=role,
            connection_count=count,
            tls=port == 443,
        ))

    # Sort servers by connection count descending
    servers.sort(key=lambda s: s.connection_count, reverse=True)

    # Deduplicate endpoints and sort by count
    endpoints = sorted(endpoint_map.values(), key=lambda e: e.count, reverse=True)

    # Count requests from both structured http_request events and parsed ssl_raw
    structured_requests = sum(
        1 for e in traffic_events if e.get("type") == "http_request"
    )
    ssl_parsed_requests = sum(
        1 for c in ssl_captures if c.direction == "out" and c.parsed_method
    )
    total_requests = structured_requests + ssl_parsed_requests

    return TrafficReport(
        servers=servers,
        endpoints=endpoints,
        tcp_connections=connections,
        ssl_sessions=ssl_captures,
        total_requests=total_requests,
        total_connections=len(connections),
    )
