"""LiveMonitor — interactive real-time event display for kahlo monitor."""
from __future__ import annotations

import signal
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Module color map
MODULE_STYLES: dict[str, str] = {
    "traffic": "green",
    "vault": "yellow",
    "recon": "red",
    "netmodel": "cyan",
    "frida": "magenta",
    "raw": "dim",
}

# Default style for unknown modules
DEFAULT_STYLE = "white"


def format_event(event: dict[str, Any]) -> str:
    """Format a single event into a human-readable one-line summary.

    Returns a plain string (without Rich markup) — the caller adds color.
    """
    module = event.get("module", "?")
    etype = event.get("type", "?")
    data = event.get("data", {})

    # --- traffic ---
    if etype == "http_request":
        method = data.get("method", "?")
        url = _truncate(data.get("url", "?"), 80)
        ctype = data.get("content_type", "")
        extra = f" [{ctype}]" if ctype else ""
        auth_tag = " [AUTH]" if data.get("auth_flow") else ""
        return f"\u2192 {method} {url}{extra}{auth_tag}"

    if etype == "http_response":
        status = data.get("status", "?")
        url = _truncate(data.get("url", "?"), 70)
        elapsed = data.get("elapsed_ms", "?")
        auth_tag = " [AUTH]" if data.get("auth_flow") else ""
        return f"\u2190 {status} {url} ({elapsed}ms){auth_tag}"

    if etype == "tcp_connect":
        host = data.get("host", data.get("ip", "?"))
        port = data.get("port", "?")
        return f"\u21c4 {host}:{port}"

    if etype == "ws_send":
        url = _truncate(data.get("url", "?"), 60)
        payload = _truncate(str(data.get("data", "")), 40)
        return f"\u2191 WS {url} | {payload}"

    if etype == "ws_receive":
        url = _truncate(data.get("url", "?"), 60)
        payload = _truncate(str(data.get("data", "")), 40)
        return f"\u2193 WS {url} | {payload}"

    if etype == "ssl_raw":
        direction = data.get("direction", "?")
        length = data.get("length", data.get("len", "?"))
        return f"\u26bf SSL {direction} {length} bytes"

    if etype == "ssl_native":
        direction = data.get("direction", "?")
        length = data.get("length", data.get("len", "?"))
        return f"\u26bf SSL/native {direction} {length} bytes"

    # --- vault ---
    if etype == "pref_write":
        file = data.get("file", "?")
        key = data.get("key", "?")
        value = _truncate(str(data.get("value", "")), 50)
        return f"\u270e {file}:{key} = {value}"

    if etype == "pref_read":
        file = data.get("file", "?")
        key = data.get("key", "?")
        value = _truncate(str(data.get("value", "")), 50)
        return f"\u25b7 {file}:{key} = {value}"

    if etype in ("sqlite_query", "sqlite_exec"):
        sql = _truncate(data.get("sql", data.get("query", "?")), 70)
        return f"\u2637 {sql}"

    if etype == "sqlite_write":
        table = data.get("table", "?")
        sql = _truncate(data.get("sql", "?"), 60)
        return f"\u2637 WRITE {table} {sql}"

    if etype == "file_write":
        path = _truncate(data.get("path", "?"), 60)
        size = data.get("size", data.get("length", "?"))
        return f"\u270d {path} ({size} bytes)"

    if etype == "keystore_read":
        alias = data.get("alias", "?")
        ktype = data.get("type", "?")
        return f"\u26bf keystore:{alias} ({ktype})"

    if etype == "keystore_enum":
        count = data.get("count", len(data.get("aliases", [])))
        return f"\u26bf keystore enum ({count} aliases)"

    if etype == "encrypted_pref_read":
        key = data.get("key", "?")
        value = _truncate(str(data.get("value", "")), 50)
        return f"\u26bf DECRYPTED {key} = {value}"

    if etype == "encrypted_pref_write":
        key = data.get("key", "?")
        value = _truncate(str(data.get("value", "")), 50)
        return f"\u270e ENCRYPTED_WRITE {key} = {value}"

    if etype == "encrypted_pref_dump":
        count = data.get("count", "?")
        return f"\u26bf encrypted pref dump ({count} entries)"

    if etype == "tink_decrypt":
        algo = data.get("algorithm", "?")
        length = data.get("plaintext_length", "?")
        preview = _truncate(data.get("plaintext_preview", ""), 40)
        return f"\u26bf Tink {algo} decrypt ({length} bytes) {preview}"

    if etype == "initial_dump":
        files = data.get("files") or data.get("prefs") or []
        count = len(files) if isinstance(files, list) else "?"
        return f"\u2606 initial pref dump ({count} files)"

    # --- recon ---
    if etype == "device_info":
        field = data.get("field", data.get("property", "?"))
        value = _truncate(str(data.get("value", "")), 50)
        return f"\u2139 {field} = {value}"

    if etype == "vpn_check":
        result = data.get("result", data.get("value", "?"))
        return f"\u26a0 vpn_check \u2192 {result}"

    if etype == "telecom":
        op = data.get("operator", data.get("value", "?"))
        return f"\u260e telecom: {op}"

    if etype == "network_info":
        ntype = data.get("type", data.get("network_type", "?"))
        return f"\u2601 network: {ntype}"

    if etype == "wifi_info":
        ssid = data.get("ssid", data.get("value", "?"))
        return f"\u2601 wifi: {ssid}"

    if etype == "location":
        lat = data.get("lat", data.get("latitude", "?"))
        lon = data.get("lon", data.get("longitude", "?"))
        return f"\u2316 location: {lat}, {lon}"

    if etype == "installed_apps":
        count = data.get("count", "?")
        return f"\u2692 installed_apps query ({count})"

    if etype == "ip_lookup":
        ip = data.get("ip", data.get("address", "?"))
        return f"\u2316 ip_lookup: {ip}"

    if etype == "competitor_probe":
        pkg = data.get("package", data.get("target", "?"))
        return f"\u2691 competitor probe: {pkg}"

    if etype == "ping_probe":
        host = data.get("host", data.get("target", "?"))
        return f"\u21cc ping: {host}"

    if etype == "sensor_access":
        sensor = data.get("sensor", data.get("type", "?"))
        return f"\u269b sensor: {sensor}"

    # --- netmodel ---
    if etype == "hmac_init":
        algo = data.get("algorithm", "?")
        key = _truncate(data.get("key", data.get("key_hex", "?")), 16)
        return f"\u2622 HMAC init {algo} key={key}..."

    if etype == "hmac":
        algo = data.get("algorithm", "?")
        key = _truncate(data.get("key", data.get("key_hex", "?")), 16)
        return f"\u2622 HMAC {algo} key={key}..."

    if etype == "hash":
        algo = data.get("algorithm", "?")
        input_hex = _truncate(data.get("input", data.get("input_hex", "?")), 20)
        return f"\u2699 hash {algo} input={input_hex}..."

    if etype == "crypto_init":
        algo = data.get("algorithm", "?")
        return f"\u26bf crypto init: {algo}"

    if etype == "crypto_op":
        algo = data.get("algorithm", "?")
        op = data.get("operation", data.get("op", "?"))
        return f"\u26bf crypto {op}: {algo}"

    if etype == "signature":
        algo = data.get("algorithm", "?")
        return f"\u270d signature: {algo}"

    if etype == "tls_info":
        version = data.get("version", data.get("protocol", "?"))
        cipher = data.get("cipher", "?")
        return f"\u26bf TLS {version} [{cipher}]"

    if etype == "nonce":
        length = data.get("length", data.get("size", "?"))
        return f"\u2684 nonce ({length} bytes)"

    # --- meta ---
    if etype == "hook_status":
        status = data.get("status", "?")
        level = data.get("level", "")
        extra = f" [{level}]" if level else ""
        return f"\u2713 {module}{extra} {status}"

    if etype == "error":
        desc = _truncate(data.get("description", str(data)), 80)
        return f"\u2717 {desc}"

    # Fallback: show type and data summary
    summary = _truncate(str(data), 60) if data else ""
    return f"{etype}: {summary}" if summary else etype


def _truncate(s: str, maxlen: int) -> str:
    """Truncate string to maxlen, appending ellipsis if needed."""
    if len(s) <= maxlen:
        return s
    return s[: maxlen - 1] + "\u2026"


class LiveMonitor:
    """Interactive Frida event monitor with Rich live terminal display.

    Receives events from a Frida session and renders them in real-time
    with color-coded modules, a scrolling event log, and running counters.
    """

    MAX_VISIBLE_EVENTS = 25

    def __init__(
        self,
        package: str,
        console: Console | None = None,
    ):
        self.package = package
        self.console = console or Console()
        self._events: list[dict[str, Any]] = []
        self._visible: deque[tuple[str, str, str]] = deque(
            maxlen=self.MAX_VISIBLE_EVENTS
        )  # (timestamp, module, formatted)
        self._module_counts: dict[str, int] = {}
        self._started_at: float = 0.0
        self._running = False

    @property
    def events(self) -> list[dict[str, Any]]:
        return self._events

    @property
    def event_count(self) -> int:
        return len(self._events)

    @property
    def module_counts(self) -> dict[str, int]:
        return dict(self._module_counts)

    @property
    def elapsed(self) -> float:
        if self._started_at == 0:
            return 0.0
        return time.time() - self._started_at

    def add_event(self, event: dict[str, Any]) -> None:
        """Add an event and update internal state for display."""
        self._events.append(event)

        module = event.get("module", "?")
        self._module_counts[module] = self._module_counts.get(module, 0) + 1

        # Format for display
        ts = _event_time(event)
        formatted = format_event(event)
        self._visible.append((ts, module, formatted))

    def on_message(self, message: dict, data: Any = None) -> None:
        """Frida on('message') callback — same signature as Session.on_message.

        Parses the message and routes to add_event.
        """
        import json as _json

        if message.get("type") == "send":
            payload = message.get("payload")
            if payload is None:
                return

            if isinstance(payload, str):
                try:
                    event = _json.loads(payload)
                    if isinstance(event, dict):
                        self.add_event(event)
                        return
                except (ValueError, TypeError):
                    pass
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

    def build_display(self) -> Layout:
        """Build the Rich Layout for the current state."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="events", ratio=1),
            Layout(name="footer", size=3),
        )

        # --- Header: status bar ---
        elapsed_int = int(self.elapsed)
        mins, secs = divmod(elapsed_int, 60)
        time_str = f"{mins:02d}:{secs:02d}"

        header_text = Text()
        header_text.append("  MONITOR  ", style="bold white on blue")
        header_text.append(f"  {self.package}", style="bold cyan")
        header_text.append(f"  |  ", style="dim")
        header_text.append(f"\u23f1 {time_str}", style="bold white")
        header_text.append(f"  |  ", style="dim")
        header_text.append(f"Events: {self.event_count}", style="bold green")

        layout["header"].update(Panel(header_text, style="blue"))

        # --- Events: scrolling log ---
        event_text = Text()
        if not self._visible:
            event_text.append(
                "  \u23f3 Waiting for events... Interact with the app on the device.\n",
                style="dim italic",
            )
        else:
            for ts, module, formatted in self._visible:
                style = MODULE_STYLES.get(module, DEFAULT_STYLE)
                event_text.append(f"  {ts} ", style="dim")
                event_text.append(f"[{module}]", style=f"bold {style}")
                event_text.append(f" {formatted}\n", style=style)

        layout["events"].update(
            Panel(event_text, title="Events", border_style="dim", title_align="left")
        )

        # --- Footer: module counters ---
        footer_text = Text()
        footer_text.append("  ")
        if self._module_counts:
            for mod, count in sorted(self._module_counts.items()):
                style = MODULE_STYLES.get(mod, DEFAULT_STYLE)
                footer_text.append(f" {mod}", style=f"bold {style}")
                footer_text.append(f":{count} ", style=style)
        else:
            footer_text.append("No events yet", style="dim")

        footer_text.append("  |  ", style="dim")
        footer_text.append("Ctrl+C to stop", style="dim italic")

        layout["footer"].update(Panel(footer_text, style="dim"))

        return layout

    def run(
        self,
        engine: Any,
        script_source: str,
        session: Any,
    ) -> None:
        """Run the live monitor loop.

        Args:
            engine: FridaEngine instance (already set up)
            script_source: Composed Frida script to inject
            session: Session instance for event persistence
        """
        self._started_at = time.time()
        self._running = True

        # Dual callback: feed both monitor display and session storage
        def _on_message(message: dict, data: Any = None) -> None:
            self.on_message(message, data)
            session.on_message(message, data)

        # Spawn app
        self.console.print(f"[green]Spawning {self.package}...[/green]")
        pid = engine.spawn(
            self.package,
            script_source=script_source,
            on_message=_on_message,
        )
        self.console.print(f"  PID: {pid}")
        self.console.print()

        # Set up graceful Ctrl+C
        original_sigint = signal.getsignal(signal.SIGINT)

        def _handle_sigint(signum: int, frame: Any) -> None:
            self._running = False

        signal.signal(signal.SIGINT, _handle_sigint)

        try:
            with Live(
                self.build_display(),
                console=self.console,
                refresh_per_second=4,
                screen=False,
            ) as live:
                while self._running:
                    live.update(self.build_display())
                    time.sleep(0.25)
        finally:
            signal.signal(signal.SIGINT, original_sigint)

        # Cleanup
        self.console.print("\n[yellow]Stopping monitor...[/yellow]")
        engine.cleanup()

        # Save session
        path = session.save()
        self.console.print(f"[green]Session saved: {path}[/green]")

        # Print summary
        self._print_summary(session)

    def _print_summary(self, session: Any) -> None:
        """Print final summary table after monitoring ends."""
        stats = session.event_stats()
        elapsed_int = int(self.elapsed)
        mins, secs = divmod(elapsed_int, 60)

        self.console.print()

        summary = Table(title=f"Monitor Summary ({mins:02d}:{secs:02d})")
        summary.add_column("Module", style="cyan")
        summary.add_column("Events", justify="right", style="green")
        summary.add_column("Types", style="dim")

        for module, count in sorted(stats["by_module"].items()):
            types = stats["by_module_type"].get(module, {})
            types_str = ", ".join(f"{t}:{c}" for t, c in sorted(types.items()))
            summary.add_row(module, str(count), types_str)

        summary.add_row("", "", "")
        summary.add_row("[bold]TOTAL[/bold]", f"[bold]{stats['total']}[/bold]", "")

        self.console.print(summary)

        if stats["unique_endpoints"]:
            self.console.print(
                f"\n[cyan]Unique endpoints ({len(stats['unique_endpoints'])}):[/cyan]"
            )
            for ep in stats["unique_endpoints"][:20]:
                self.console.print(f"  {ep}")
            if len(stats["unique_endpoints"]) > 20:
                self.console.print(
                    f"  ... and {len(stats['unique_endpoints']) - 20} more"
                )


def _event_time(event: dict[str, Any]) -> str:
    """Extract or generate a display timestamp for an event."""
    ts = event.get("ts")
    if ts and isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts)
            return dt.strftime("%H:%M:%S")
        except (ValueError, TypeError):
            pass
    return datetime.now(timezone.utc).strftime("%H:%M:%S")
