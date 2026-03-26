"""Session — collects events from Frida scripts and saves as JSON."""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any


class Session:
    """Collects structured events from Frida instrumentation and persists to JSON."""

    def __init__(self, package: str, output_dir: str | None = None):
        self.package = package
        self.session_id = f"{package}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        self.output_dir = output_dir or os.path.join(os.getcwd(), "sessions")
        self.events: list[dict[str, Any]] = []
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.metadata: dict[str, Any] = {}

    def add_event(self, event: dict[str, Any]) -> None:
        """Add a structured event to the session."""
        if "ts" not in event:
            event["ts"] = datetime.now(timezone.utc).isoformat()
        self.events.append(event)

    def on_message(self, message: dict, data: Any = None) -> None:
        """Frida on('message') callback — parses and adds events.

        Handles both raw payloads and JSON-encoded event dicts.
        """
        if message.get("type") == "send":
            payload = message.get("payload")
            if payload is None:
                return

            # Try to parse as JSON event
            if isinstance(payload, str):
                try:
                    event = json.loads(payload)
                    if isinstance(event, dict):
                        self.add_event(event)
                        return
                except (json.JSONDecodeError, TypeError):
                    pass
                # Treat as raw string message
                self.add_event({
                    "module": "raw",
                    "type": "message",
                    "data": {"payload": payload},
                })
            elif isinstance(payload, dict):
                self.add_event(payload)
            else:
                self.add_event({
                    "module": "raw",
                    "type": "message",
                    "data": {"payload": str(payload)},
                })

        elif message.get("type") == "error":
            self.add_event({
                "module": "frida",
                "type": "error",
                "data": {
                    "description": message.get("description", ""),
                    "stack": message.get("stack", ""),
                },
            })

    def event_stats(self) -> dict[str, Any]:
        """Return event statistics grouped by module and type."""
        by_module: dict[str, int] = {}
        by_type: dict[str, int] = {}
        by_module_type: dict[str, dict[str, int]] = {}

        for event in self.events:
            module = event.get("module", "unknown")
            etype = event.get("type", "unknown")

            by_module[module] = by_module.get(module, 0) + 1
            key = f"{module}.{etype}"
            by_type[key] = by_type.get(key, 0) + 1

            if module not in by_module_type:
                by_module_type[module] = {}
            by_module_type[module][etype] = by_module_type[module].get(etype, 0) + 1

        # Extract unique endpoints from traffic events
        endpoints: set[str] = set()
        for event in self.events:
            if event.get("module") == "traffic" and event.get("type") in ("http_request", "http_response"):
                url = event.get("data", {}).get("url", "")
                if url:
                    # Normalize: strip query params for grouping
                    base = url.split("?")[0]
                    endpoints.add(base)

        return {
            "total": len(self.events),
            "by_module": by_module,
            "by_type": by_type,
            "by_module_type": by_module_type,
            "unique_endpoints": sorted(endpoints),
        }

    def save(self) -> str:
        """Save session to JSON file. Returns the file path."""
        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, f"{self.session_id}.json")

        stats = self.event_stats()

        data = {
            "session_id": self.session_id,
            "package": self.package,
            "started_at": self.started_at,
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "event_count": len(self.events),
            "stats": stats,
            "metadata": self.metadata,
            "events": self.events,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return path
