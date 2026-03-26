"""Recon Analyzer — parse recon events into privacy/fingerprint profile."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ReconReport(BaseModel):
    """Privacy and fingerprint analysis from recon events."""
    device_info: dict[str, str] = Field(default_factory=dict)
    telecom: dict[str, str] = Field(default_factory=dict)
    network_info: list[dict[str, Any]] = Field(default_factory=list)
    ip_lookups: list[str] = Field(default_factory=list)
    competitor_probes: list[str] = Field(default_factory=list)
    installed_apps_check: bool = False
    vpn_detected: bool | None = None
    fingerprint_appetite: int = 0
    categories: list[str] = Field(default_factory=list)
    telecom_queries: int = 0
    network_queries: int = 0


def analyze_recon(events: list[dict[str, Any]]) -> ReconReport:
    """Analyze recon events from a session.

    Args:
        events: All session events (will be filtered to module=="recon").

    Returns:
        ReconReport with device info, telecom, network, and fingerprint score.
    """
    recon_events = [e for e in events if e.get("module") == "recon"]

    device_info: dict[str, str] = {}
    telecom: dict[str, str] = {}
    network_info: list[dict[str, Any]] = []
    categories: set[str] = set()
    telecom_queries = 0
    network_queries = 0

    # Unique network info entries to avoid duplicates
    seen_network: set[str] = set()

    for event in recon_events:
        etype = event.get("type", "")
        data = event.get("data", {})

        if etype == "device_info":
            field = data.get("field", "")
            value = data.get("value", "")
            source = data.get("source", "")
            access = data.get("access", "")
            device_info[field] = value
            if access:
                device_info[f"{field}_access"] = access
            if source:
                device_info[f"{field}_source"] = source
            categories.add("device")

        elif etype == "telecom":
            method = data.get("method", "")
            value = data.get("value", "")
            telecom[method] = value
            telecom_queries += 1
            categories.add("telecom")

        elif etype == "network_info":
            method = data.get("method", "")
            value = data.get("value", "")
            network_queries += 1
            entry_key = f"{method}:{value}"
            if entry_key not in seen_network:
                seen_network.add(entry_key)
                network_info.append({"method": method, "value": value})
            categories.add("network")

        elif etype == "ip_lookup":
            service = data.get("service", data.get("url", ""))
            categories.add("ip_lookup")

        elif etype == "competitor_probe":
            pkg = data.get("package", "")
            categories.add("competitor_probes")

        elif etype == "installed_apps":
            categories.add("installed_apps")

        elif etype == "vpn_check":
            categories.add("vpn")

        elif etype == "location":
            categories.add("location")

    # Calculate fingerprint appetite score
    score = 0
    if "device" in categories:
        score += 15
    if "network" in categories:
        score += 15
    if "telecom" in categories:
        score += 15
    if "location" in categories:
        score += 15
    if "vpn" in categories:
        score += 20
    if "ip_lookup" in categories:
        score += 15
    if "competitor_probes" in categories:
        score += 25
    if "installed_apps" in categories:
        score += 20

    # Extra points for frequency of queries
    if telecom_queries > 3:
        score += 5
    if network_queries > 5:
        score += 5

    # Cap at 100
    score = min(score, 100)

    return ReconReport(
        device_info=device_info,
        telecom=telecom,
        network_info=network_info,
        ip_lookups=[],
        competitor_probes=[],
        installed_apps_check="installed_apps" in categories,
        vpn_detected=True if "vpn" in categories else None,
        fingerprint_appetite=score,
        categories=sorted(categories),
        telecom_queries=telecom_queries,
        network_queries=network_queries,
    )
