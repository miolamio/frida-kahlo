"""FridaEngine — spawn/attach/inject wrapper using frida-python API.

In frida 17.x, the Java bridge is no longer automatically available.
This engine uses the loader's Java bridge preamble to ensure Java.perform() works.
"""
from __future__ import annotations

import time
from typing import Any, Callable

import frida

from kahlo.instrument.loader import _JAVA_BRIDGE_PREAMBLE
from kahlo.stealth.manager import StealthManager


class FridaEngineError(Exception):
    pass


class FridaEngine:
    """Manages Frida device connection, process spawning, and script injection."""

    def __init__(self, stealth: StealthManager):
        self.stealth = stealth
        self._device: frida.core.Device | None = None
        self._session: frida.core.Session | None = None
        self._script: frida.core.Script | None = None
        self._pid: int | None = None
        self._package: str | None = None

    @property
    def is_attached(self) -> bool:
        return self._session is not None

    def _get_device(self) -> frida.core.Device:
        """Get device handle.

        If stealth manager has a custom port with ADB forwarding active,
        use remote device via localhost:27042 (the forwarded port).
        Otherwise, use standard USB transport.
        """
        if self._device is None:
            if self.stealth.port and self.stealth._forwarded:
                # Connect via ADB-forwarded port
                mgr = frida.get_device_manager()
                self._device = mgr.add_remote_device("127.0.0.1:27042")
            else:
                self._device = frida.get_usb_device(timeout=5)
        return self._device

    def spawn(
        self,
        package: str,
        script_source: str | None = None,
        on_message: Callable[[dict, Any], None] | None = None,
    ) -> int:
        """Spawn a package, optionally inject a script before resume.

        Returns the PID of the spawned process.
        """
        self.cleanup()

        device = self._get_device()
        self._package = package

        try:
            self._pid = device.spawn([package])
        except Exception as e:
            raise FridaEngineError(f"Failed to spawn {package}: {e}") from e

        try:
            self._session = device.attach(self._pid)
            self._session.on("detached", self._on_detached)
        except Exception as e:
            try:
                device.kill(self._pid)
            except Exception:
                pass
            raise FridaEngineError(f"Failed to attach to {package} (pid={self._pid}): {e}") from e

        if script_source:
            self.inject(script_source, on_message=on_message)

        try:
            device.resume(self._pid)
        except Exception as e:
            raise FridaEngineError(f"Failed to resume {package}: {e}") from e

        return self._pid

    def attach(
        self,
        target: str | int,
        script_source: str | None = None,
        on_message: Callable[[dict, Any], None] | None = None,
    ) -> None:
        """Attach to a running process by name or PID."""
        self.cleanup()

        device = self._get_device()

        try:
            self._session = device.attach(target)
            self._session.on("detached", self._on_detached)
            if isinstance(target, int):
                self._pid = target
        except Exception as e:
            raise FridaEngineError(f"Failed to attach to {target}: {e}") from e

        if script_source:
            self.inject(script_source, on_message=on_message)

    def inject(
        self,
        script_source: str,
        on_message: Callable[[dict, Any], None] | None = None,
        include_java_bridge: bool = False,
    ) -> None:
        """Inject a script into the current session.

        Args:
            script_source: JavaScript source code to inject
            on_message: Callback for script messages
            include_java_bridge: Prepend Java bridge for frida 17.x compatibility.
                Defaults to False because ScriptLoader.compose() already prepends it.
        """
        if self._session is None:
            raise FridaEngineError("No active session — call spawn() or attach() first")

        # Prepend Java bridge preamble for frida 17.x compatibility
        if include_java_bridge and _JAVA_BRIDGE_PREAMBLE:
            script_source = _JAVA_BRIDGE_PREAMBLE + "\n" + script_source

        try:
            self._script = self._session.create_script(script_source)
            if on_message:
                self._script.on("message", on_message)
            self._script.load()
        except Exception as e:
            raise FridaEngineError(f"Failed to inject script: {e}") from e

    def cleanup(self) -> None:
        """Detach session and kill spawned process."""
        if self._script is not None:
            try:
                self._script.unload()
            except Exception:
                pass
            self._script = None

        if self._session is not None:
            try:
                self._session.detach()
            except Exception:
                pass
            self._session = None

        if self._pid is not None:
            try:
                device = self._get_device()
                device.kill(self._pid)
            except Exception:
                pass
            self._pid = None

        self._package = None

    def _on_detached(self, reason: str, crash: Any = None) -> None:
        """Handle session detach events."""
        self._session = None
        self._script = None
