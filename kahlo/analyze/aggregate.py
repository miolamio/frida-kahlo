"""Session Aggregator — merge multiple sessions into a unified API map."""
from __future__ import annotations

import json
import os
from typing import Any

from pydantic import BaseModel, Field

from kahlo.analyze.patterns import SDKInfo
from kahlo.analyze.traffic import EndpointInfo, ServerInfo, TrafficReport, analyze_traffic
from kahlo.analyze.vault import SecretInfo, VaultReport, analyze_vault


class SessionSummary(BaseModel):
    """Metadata for a single session within an aggregated report."""
    session_id: str
    package: str
    started_at: str
    ended_at: str
    event_count: int
    server_count: int = 0
    endpoint_count: int = 0
    secret_count: int = 0


class AggregatedReport(BaseModel):
    """Merged findings from multiple sessions."""
    sessions: list[SessionSummary] = Field(default_factory=list)
    all_endpoints: list[EndpointInfo] = Field(default_factory=list)
    all_servers: list[ServerInfo] = Field(default_factory=list)
    all_secrets: list[SecretInfo] = Field(default_factory=list)
    all_sdks: list[SDKInfo] = Field(default_factory=list)
    endpoint_first_seen: dict[str, str] = Field(default_factory=dict)
    endpoint_frequency: dict[str, int] = Field(default_factory=dict)


def _endpoint_key(ep: EndpointInfo) -> str:
    """Create a dedup key for an endpoint: host + path + method."""
    return f"{ep.method or 'GET'}|{ep.host or ''}|{ep.path or '/'}"


def _server_key(s: ServerInfo) -> str:
    """Create a dedup key for a server: host + port."""
    return f"{s.host}:{s.port}"


def _secret_key(s: SecretInfo) -> str:
    """Create a dedup key for a secret by its value."""
    return s.value


class SessionAggregator:
    """Merge multiple session JSONs into a unified report."""

    def aggregate(self, session_paths: list[str]) -> AggregatedReport:
        """Load multiple session JSON files and merge their findings.

        Dedup logic:
        - Endpoints matched by (host + path + method). Headers/bodies merged from all sessions.
        - Servers matched by (host + port).
        - Secrets matched by value.
        - SDKs matched by name.

        Args:
            session_paths: List of paths to session JSON files.

        Returns:
            AggregatedReport with deduplicated, merged data.
        """
        sessions: list[SessionSummary] = []
        endpoint_map: dict[str, EndpointInfo] = {}
        endpoint_first_seen: dict[str, str] = {}
        endpoint_frequency: dict[str, int] = {}
        server_map: dict[str, ServerInfo] = {}
        secret_map: dict[str, SecretInfo] = {}
        sdk_map: dict[str, SDKInfo] = {}

        for path in session_paths:
            with open(path, "r", encoding="utf-8") as f:
                session_data = json.load(f)

            events = session_data.get("events", [])
            package = session_data.get("package", "unknown")
            session_id = session_data.get("session_id", "unknown")

            # Run analyzers
            traffic = analyze_traffic(events, package)
            vault = analyze_vault(events, package)

            # Patterns analysis (need traffic hosts)
            from kahlo.analyze.patterns import analyze_patterns
            traffic_hosts = [s.host for s in traffic.servers]
            patterns = analyze_patterns(events, traffic_hosts)

            # Session summary
            sessions.append(SessionSummary(
                session_id=session_id,
                package=package,
                started_at=session_data.get("started_at", ""),
                ended_at=session_data.get("ended_at", ""),
                event_count=session_data.get("event_count", len(events)),
                server_count=len(traffic.servers),
                endpoint_count=len(traffic.endpoints),
                secret_count=len(vault.secrets),
            ))

            # Merge endpoints
            for ep in traffic.endpoints:
                key = _endpoint_key(ep)
                if key in endpoint_map:
                    # Merge: accumulate count, merge headers
                    existing = endpoint_map[key]
                    existing.count += ep.count
                    # Merge sample headers (new keys only)
                    for hk, hv in ep.sample_headers.items():
                        if hk not in existing.sample_headers:
                            existing.sample_headers[hk] = hv
                    # Prefer non-None body previews
                    if not existing.sample_body_preview and ep.sample_body_preview:
                        existing.sample_body_preview = ep.sample_body_preview
                    # Merge body format/fields
                    if not existing.request_body_format and ep.request_body_format:
                        existing.request_body_format = ep.request_body_format
                    if not existing.request_body_fields and ep.request_body_fields:
                        existing.request_body_fields = ep.request_body_fields
                    if not existing.response_body_format and ep.response_body_format:
                        existing.response_body_format = ep.response_body_format
                    if not existing.response_body_fields and ep.response_body_fields:
                        existing.response_body_fields = ep.response_body_fields
                else:
                    endpoint_map[key] = ep.model_copy(deep=True)
                    endpoint_first_seen[key] = session_id

                endpoint_frequency[key] = endpoint_frequency.get(key, 0) + 1

            # Merge servers
            for s in traffic.servers:
                key = _server_key(s)
                if key in server_map:
                    server_map[key].connection_count += s.connection_count
                else:
                    server_map[key] = s.model_copy(deep=True)

            # Merge secrets (dedup by value)
            for secret in vault.secrets:
                key = _secret_key(secret)
                if key not in secret_map:
                    secret_map[key] = secret.model_copy(deep=True)

            # Merge SDKs (dedup by name)
            for sdk in patterns.sdks:
                if sdk.name not in sdk_map:
                    sdk_map[sdk.name] = sdk.model_copy(deep=True)
                else:
                    # Merge evidence
                    existing_sdk = sdk_map[sdk.name]
                    for ev in sdk.evidence:
                        if ev not in existing_sdk.evidence:
                            existing_sdk.evidence.append(ev)
                    # Prefer non-None version
                    if not existing_sdk.version and sdk.version:
                        existing_sdk.version = sdk.version

        # Sort endpoints by count descending
        all_endpoints = sorted(endpoint_map.values(), key=lambda e: e.count, reverse=True)
        all_servers = sorted(server_map.values(), key=lambda s: s.connection_count, reverse=True)

        return AggregatedReport(
            sessions=sessions,
            all_endpoints=all_endpoints,
            all_servers=all_servers,
            all_secrets=list(secret_map.values()),
            all_sdks=list(sdk_map.values()),
            endpoint_first_seen=endpoint_first_seen,
            endpoint_frequency=endpoint_frequency,
        )


def generate_aggregated_markdown(report: AggregatedReport) -> str:
    """Generate a Markdown report from aggregated session data."""
    lines: list[str] = []

    lines.append("# Aggregated Analysis Report")
    lines.append("")
    lines.append(f"**Sessions merged:** {len(report.sessions)}")
    total_events = sum(s.event_count for s in report.sessions)
    lines.append(f"**Total events:** {total_events}")
    lines.append("")

    # Session table
    lines.append("## Sessions")
    lines.append("")
    lines.append("| Session ID | Package | Events | Servers | Endpoints | Secrets |")
    lines.append("|------------|---------|--------|---------|-----------|---------|")
    for s in report.sessions:
        lines.append(
            f"| `{s.session_id}` | {s.package} | {s.event_count} | "
            f"{s.server_count} | {s.endpoint_count} | {s.secret_count} |"
        )
    lines.append("")

    # Servers
    if report.all_servers:
        lines.append("## Servers (Deduplicated)")
        lines.append("")
        lines.append("| Host | IP | Port | Role | Total Connections |")
        lines.append("|------|-----|------|------|-------------------|")
        for s in report.all_servers:
            lines.append(f"| `{s.host}` | {s.ip or 'N/A'} | {s.port} | {s.role} | {s.connection_count} |")
        lines.append("")

    # Endpoints
    if report.all_endpoints:
        lines.append("## Endpoints (Deduplicated)")
        lines.append("")
        lines.append("| Method | Host | Path | Sessions | Total Count | First Seen |")
        lines.append("|--------|------|------|----------|-------------|------------|")
        for ep in report.all_endpoints:
            key = _endpoint_key(ep)
            freq = report.endpoint_frequency.get(key, 1)
            first = report.endpoint_first_seen.get(key, "?")
            # Shorten first_seen to just the session suffix
            first_short = first[-10:] if len(first) > 10 else first
            lines.append(
                f"| {ep.method or 'N/A'} | `{ep.host or 'N/A'}` | `{ep.path or '/'}` | "
                f"{freq} | {ep.count} | ...{first_short} |"
            )
        lines.append("")

    # Secrets
    if report.all_secrets:
        lines.append("## Secrets (Deduplicated)")
        lines.append("")
        lines.append("| Name | Category | Sensitivity | Value Preview |")
        lines.append("|------|----------|-------------|---------------|")
        for secret in report.all_secrets:
            val = secret.value[:20] + "..." if len(secret.value) > 20 else secret.value
            lines.append(f"| {secret.name} | {secret.category} | {secret.sensitivity} | `{val}` |")
        lines.append("")

    # SDKs
    if report.all_sdks:
        lines.append("## SDKs (Deduplicated)")
        lines.append("")
        lines.append("| SDK | Version | Category |")
        lines.append("|-----|---------|----------|")
        for sdk in report.all_sdks:
            lines.append(f"| **{sdk.name}** | {sdk.version or 'N/A'} | {sdk.category} |")
        lines.append("")

    return "\n".join(lines)


def generate_aggregated_api_spec(report: AggregatedReport, package: str = "app") -> str:
    """Generate a JSON API specification from aggregated data."""
    endpoints: list[dict[str, Any]] = []
    for ep in report.all_endpoints:
        key = _endpoint_key(ep)
        entry: dict[str, Any] = {
            "path": ep.path or "/",
            "method": ep.method or "GET",
            "host": ep.host or "",
            "url": ep.url,
            "content_type": ep.content_type,
            "auth_required": ep.has_auth,
            "count": ep.count,
            "sessions_seen": report.endpoint_frequency.get(key, 1),
            "first_seen": report.endpoint_first_seen.get(key, ""),
        }
        if ep.sample_headers:
            entry["sample_headers"] = ep.sample_headers
        if ep.sample_body_preview:
            entry["sample_body_preview"] = ep.sample_body_preview[:500]
        if ep.request_body_format:
            entry["request_body_format"] = ep.request_body_format
        if ep.request_body_fields:
            entry["request_body_fields"] = ep.request_body_fields
        if ep.response_body_format:
            entry["response_body_format"] = ep.response_body_format
        if ep.response_body_fields:
            entry["response_body_fields"] = ep.response_body_fields
        endpoints.append(entry)

    spec: dict[str, Any] = {
        "app": package,
        "aggregated": True,
        "sessions_count": len(report.sessions),
        "session_ids": [s.session_id for s in report.sessions],
        "servers": [
            {
                "host": s.host,
                "ip": s.ip,
                "port": s.port,
                "role": s.role,
                "total_connections": s.connection_count,
            }
            for s in report.all_servers
        ],
        "endpoints": endpoints,
        "secrets": [
            {
                "name": s.name,
                "category": s.category,
                "sensitivity": s.sensitivity,
            }
            for s in report.all_secrets
        ],
        "sdks": [
            {
                "name": sdk.name,
                "version": sdk.version,
                "category": sdk.category,
            }
            for sdk in report.all_sdks
        ],
    }

    return json.dumps(spec, indent=2, ensure_ascii=False)
