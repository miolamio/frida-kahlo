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

    def save(self) -> str:
        """Save session to JSON file. Returns the file path."""
        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, f"{self.session_id}.json")

        data = {
            "session_id": self.session_id,
            "package": self.package,
            "started_at": self.started_at,
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "event_count": len(self.events),
            "metadata": self.metadata,
            "events": self.events,
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return path
