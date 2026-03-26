"""Frida-server lifecycle management."""
from __future__ import annotations

import subprocess
import time

from kahlo.device.adb import ADB, ADBError

DEFAULT_PATH = "/data/local/tmp/frida-server"
STEALTH_PATH = "/dev/.fs"


class FridaServerError(Exception):
    pass


class FridaServer:
    def __init__(self, adb: ADB, path: str = DEFAULT_PATH):
        self._adb = adb
        self.server_path = path
        self._port: int | None = None

    def is_installed(self) -> bool:
        try:
            result = self._adb.shell(f"ls -la {self.server_path}", su=True)
            return self.server_path in result or "No such file" not in result
        except ADBError:
            return False

    def is_running(self) -> bool:
        try:
            # Check specifically for frida-server process, not helpers
            result = self._adb.shell("ps -A | grep frida-server", su=True)
            # Filter out the grep process itself
            for line in result.splitlines():
                if "grep" not in line and "frida-server" in line:
                    return True
            # Also check for stealth renamed binary
            result = self._adb.shell("ps -A | grep '\\.fs'", su=True)
            for line in result.splitlines():
                if "grep" not in line and ".fs" in line:
                    return True
            return False
        except ADBError:
            return False

    def start(self, port: int | None = None) -> None:
        if self.is_running():
            return

        if not self.is_installed():
            raise FridaServerError(
                f"frida-server not found at {self.server_path}. "
                "Push it first: adb push frida-server /data/local/tmp/"
            )

        cmd = self.server_path
        if port:
            cmd += f" -l 0.0.0.0:{port}"
            self._port = port

        self._adb.shell(f"chmod 755 {self.server_path}", su=True)

        # Use Popen to launch frida-server without waiting for it to exit.
        # The nohup + redirect + & approach inside su -c doesn't work
        # because adb shell blocks until the session closes.
        serial_args = ["-s", self._adb._serial] if self._adb._serial else []
        shell_cmd = f"su -c '{cmd} >/dev/null 2>&1 &'"
        subprocess.Popen(
            ["adb"] + serial_args + ["shell", shell_cmd],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )

        # Wait for startup
        for _ in range(10):
            time.sleep(0.5)
            if self.is_running():
                return

        raise FridaServerError("frida-server failed to start within 5 seconds")

    def stop(self) -> None:
        try:
            # Kill frida-server and any helper processes
            self._adb.shell(
                "pkill -9 -f frida-server; pkill -9 -f re.frida.helper; pkill -9 -f '\\.fs'",
                su=True,
            )
        except ADBError:
            pass  # already stopped
        # Wait for processes to die
        for _ in range(6):
            time.sleep(0.5)
            if not self.is_running():
                break
        self._port = None

    def ensure(self) -> None:
        if not self.is_running():
            self.start(port=self._port)

    @property
    def port(self) -> int | None:
        return self._port
