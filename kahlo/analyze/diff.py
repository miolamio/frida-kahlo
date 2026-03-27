"""Session Differ — compare two sessions to find changes."""
from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from kahlo.analyze.patterns import SDKInfo, analyze_patterns
from kahlo.analyze.traffic import EndpointInfo, TrafficReport, analyze_traffic
from kahlo.analyze.vault import SecretInfo, VaultReport, analyze_vault


class EndpointDiff(BaseModel):
    """An endpoint that exists in both sessions but with different behavior."""
    url: str
    method: str
    host: str
    changes: list[str] = Field(default_factory=list)  # human-readable change descriptions


class SessionDiff(BaseModel):
    """Differences between two sessions."""
    new_endpoints: list[str] = Field(default_factory=list)      # in new but not old
    removed_endpoints: list[str] = Field(default_factory=list)  # in old but not new
    changed_endpoints: list[EndpointDiff] = Field(default_factory=list)
    new_secrets: list[SecretInfo] = Field(default_factory=list)
    removed_secrets: list[SecretInfo] = Field(default_factory=list)
    new_sdks: list[str] = Field(default_factory=list)
    removed_sdks: list[str] = Field(default_factory=list)
    event_count_old: int = 0
    event_count_new: int = 0
    server_count_old: int = 0
    server_count_new: int = 0
    new_servers: list[str] = Field(default_factory=list)
    removed_servers: list[str] = Field(default_factory=list)


def _endpoint_key(ep: EndpointInfo) -> str:
    """Create a dedup key for an endpoint: method + host + path."""
    return f"{ep.method or 'GET'}|{ep.host or ''}|{ep.path or '/'}"


def _endpoint_display(ep: EndpointInfo) -> str:
    """Human-readable endpoint identifier."""
    return f"{ep.method or 'GET'} {ep.host or ''}{ep.path or '/'}"


class SessionDiffer:
    """Compare two sessions to find changes."""

    def diff(self, old_path: str, new_path: str) -> SessionDiff:
        """Compare two sessions.

        Args:
            old_path: Path to the older session JSON.
            new_path: Path to the newer session JSON.

        Returns:
            SessionDiff describing what changed.
        """
        old_data = self._load_session(old_path)
        new_data = self._load_session(new_path)

        old_events = old_data.get("events", [])
        new_events = new_data.get("events", [])
        old_package = old_data.get("package", "unknown")
        new_package = new_data.get("package", "unknown")

        # Run analyzers
        old_traffic = analyze_traffic(old_events, old_package)
        new_traffic = analyze_traffic(new_events, new_package)
        old_vault = analyze_vault(old_events, old_package)
        new_vault = analyze_vault(new_events, new_package)

        old_hosts = [s.host for s in old_traffic.servers]
        new_hosts = [s.host for s in new_traffic.servers]
        old_patterns = analyze_patterns(old_events, old_hosts)
        new_patterns = analyze_patterns(new_events, new_hosts)

        # Diff endpoints
        old_ep_map = {_endpoint_key(ep): ep for ep in old_traffic.endpoints}
        new_ep_map = {_endpoint_key(ep): ep for ep in new_traffic.endpoints}

        old_ep_keys = set(old_ep_map.keys())
        new_ep_keys = set(new_ep_map.keys())

        new_endpoints = [
            _endpoint_display(new_ep_map[k]) for k in sorted(new_ep_keys - old_ep_keys)
        ]
        removed_endpoints = [
            _endpoint_display(old_ep_map[k]) for k in sorted(old_ep_keys - new_ep_keys)
        ]

        # Changed endpoints (same key, different properties)
        changed_endpoints: list[EndpointDiff] = []
        for key in sorted(old_ep_keys & new_ep_keys):
            old_ep = old_ep_map[key]
            new_ep = new_ep_map[key]
            changes: list[str] = []

            if old_ep.count != new_ep.count:
                changes.append(f"count: {old_ep.count} -> {new_ep.count}")
            if old_ep.has_auth != new_ep.has_auth:
                changes.append(f"auth: {old_ep.has_auth} -> {new_ep.has_auth}")
            if old_ep.content_type != new_ep.content_type:
                changes.append(f"content_type: {old_ep.content_type} -> {new_ep.content_type}")
            if old_ep.request_body_format != new_ep.request_body_format:
                changes.append(f"body_format: {old_ep.request_body_format} -> {new_ep.request_body_format}")

            # Check for new headers
            old_headers = set(old_ep.sample_headers.keys())
            new_headers = set(new_ep.sample_headers.keys())
            added_headers = new_headers - old_headers
            removed_headers = old_headers - new_headers
            if added_headers:
                changes.append(f"new headers: {', '.join(sorted(added_headers))}")
            if removed_headers:
                changes.append(f"removed headers: {', '.join(sorted(removed_headers))}")

            if changes:
                changed_endpoints.append(EndpointDiff(
                    url=new_ep.url,
                    method=new_ep.method or "GET",
                    host=new_ep.host or "",
                    changes=changes,
                ))

        # Diff secrets
        old_secret_values = {s.value for s in old_vault.secrets}
        new_secret_values = {s.value for s in new_vault.secrets}

        new_secrets = [s for s in new_vault.secrets if s.value not in old_secret_values]
        removed_secrets = [s for s in old_vault.secrets if s.value not in new_secret_values]

        # Diff SDKs
        old_sdk_names = {sdk.name for sdk in old_patterns.sdks}
        new_sdk_names = {sdk.name for sdk in new_patterns.sdks}

        new_sdks = sorted(new_sdk_names - old_sdk_names)
        removed_sdks = sorted(old_sdk_names - new_sdk_names)

        # Diff servers
        old_server_hosts = {s.host for s in old_traffic.servers}
        new_server_hosts = {s.host for s in new_traffic.servers}

        new_servers = sorted(new_server_hosts - old_server_hosts)
        removed_servers = sorted(old_server_hosts - new_server_hosts)

        return SessionDiff(
            new_endpoints=new_endpoints,
            removed_endpoints=removed_endpoints,
            changed_endpoints=changed_endpoints,
            new_secrets=new_secrets,
            removed_secrets=removed_secrets,
            new_sdks=new_sdks,
            removed_sdks=removed_sdks,
            event_count_old=len(old_events),
            event_count_new=len(new_events),
            server_count_old=len(old_traffic.servers),
            server_count_new=len(new_traffic.servers),
            new_servers=new_servers,
            removed_servers=removed_servers,
        )

    @staticmethod
    def _load_session(path: str) -> dict[str, Any]:
        """Load a session JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)


def generate_diff_markdown(diff: SessionDiff) -> str:
    """Generate a Markdown diff report with additions/removals."""
    lines: list[str] = []

    lines.append("# Session Diff Report")
    lines.append("")
    lines.append("## Overview")
    lines.append("")
    lines.append(f"| Metric | Old | New |")
    lines.append(f"|--------|-----|-----|")
    lines.append(f"| Events | {diff.event_count_old} | {diff.event_count_new} |")
    lines.append(f"| Servers | {diff.server_count_old} | {diff.server_count_new} |")
    lines.append("")

    has_changes = (
        diff.new_endpoints
        or diff.removed_endpoints
        or diff.changed_endpoints
        or diff.new_secrets
        or diff.removed_secrets
        or diff.new_sdks
        or diff.removed_sdks
        or diff.new_servers
        or diff.removed_servers
    )

    if not has_changes:
        lines.append("**No differences found between sessions.**")
        lines.append("")
        return "\n".join(lines)

    # Servers
    if diff.new_servers or diff.removed_servers:
        lines.append("## Server Changes")
        lines.append("")
        for s in diff.new_servers:
            lines.append(f"+ `{s}` (new)")
        for s in diff.removed_servers:
            lines.append(f"- `{s}` (removed)")
        lines.append("")

    # Endpoints
    if diff.new_endpoints or diff.removed_endpoints or diff.changed_endpoints:
        lines.append("## Endpoint Changes")
        lines.append("")

        if diff.new_endpoints:
            lines.append("### New Endpoints")
            lines.append("")
            for ep in diff.new_endpoints:
                lines.append(f"+ `{ep}`")
            lines.append("")

        if diff.removed_endpoints:
            lines.append("### Removed Endpoints")
            lines.append("")
            for ep in diff.removed_endpoints:
                lines.append(f"- `{ep}`")
            lines.append("")

        if diff.changed_endpoints:
            lines.append("### Changed Endpoints")
            lines.append("")
            for ep_diff in diff.changed_endpoints:
                lines.append(f"**{ep_diff.method} {ep_diff.host}{ep_diff.url}**")
                for change in ep_diff.changes:
                    lines.append(f"  ~ {change}")
                lines.append("")

    # Secrets
    if diff.new_secrets or diff.removed_secrets:
        lines.append("## Secret Changes")
        lines.append("")
        for s in diff.new_secrets:
            val = s.value[:20] + "..." if len(s.value) > 20 else s.value
            lines.append(f"+ {s.name} ({s.category}): `{val}`")
        for s in diff.removed_secrets:
            val = s.value[:20] + "..." if len(s.value) > 20 else s.value
            lines.append(f"- {s.name} ({s.category}): `{val}`")
        lines.append("")

    # SDKs
    if diff.new_sdks or diff.removed_sdks:
        lines.append("## SDK Changes")
        lines.append("")
        for sdk in diff.new_sdks:
            lines.append(f"+ **{sdk}**")
        for sdk in diff.removed_sdks:
            lines.append(f"- **{sdk}**")
        lines.append("")

    return "\n".join(lines)
