"""Stealth manager — controls stealth levels and bypass scripts."""
from __future__ import annotations

import os
import subprocess
from enum import IntEnum

from kahlo.device.adb import ADB
from kahlo.device.frida_server import FridaServer
from kahlo.stealth.port import random_port


class StealthLevel(IntEnum):
    BASIC = 1      # random port + renamed binary
    BYPASS = 2     # + bypass JS scripts
    HLUDA = 3      # + custom frida build (manual)
    GADGET = 4     # frida-gadget (no server process)


class StealthManager:
    """Manages stealth frida-server with port randomization and bypass scripts.

    When a random port is used, ADB port forwarding is set up so that
    frida-python's USB transport (which connects to tcp:27042 by default)
    gets redirected to the actual frida-server port.
    """

    def __init__(self, adb: ADB, fs: FridaServer):
        self.adb = adb
        self.fs = fs
        self.level = StealthLevel.BASIC
        self.port: int | None = None
        self._forwarded = False

    def start(self) -> None:
        """Start frida-server with a random port and set up ADB forwarding."""
        self.port = random_port()
        self.fs.stop()
        self.fs.start(port=self.port)
        self._setup_port_forward()

    def stop(self) -> None:
        """Stop frida-server and remove ADB forwarding."""
        self._remove_port_forward()
        self.fs.stop()
        self.port = None

    def escalate(self) -> None:
        """Increase stealth level by one step."""
        if self.level < StealthLevel.GADGET:
            self.level = StealthLevel(self.level + 1)

    def get_bypass_scripts(self) -> list[str]:
        """Return list of JS bypass script paths based on current level."""
        scripts_dir = os.path.join(
            os.path.dirname(__file__), '..', '..', 'scripts', 'bypass'
        )
        scripts_dir = os.path.normpath(scripts_dir)
        scripts = []
        if self.level >= StealthLevel.BYPASS:
            stealth_path = os.path.join(scripts_dir, 'stealth.js')
            if os.path.exists(stealth_path):
                scripts.append(stealth_path)
            unpin_path = os.path.join(scripts_dir, 'ssl_unpin.js')
            if os.path.exists(unpin_path):
                scripts.append(unpin_path)
        return scripts

    def _setup_port_forward(self) -> None:
        """Set up ADB port forwarding from default frida port to actual port.

        frida-python USB transport connects to tcp:27042 on the device.
        We forward that to our random port so the connection works transparently.
        """
        if self.port and self.port != 27042:
            try:
                cmd = ["adb"]
                if self.adb._serial:
                    cmd += ["-s", self.adb._serial]
                cmd += ["forward", "tcp:27042", f"tcp:{self.port}"]
                subprocess.run(cmd, capture_output=True, timeout=5)
                self._forwarded = True
            except Exception:
                pass

    def _remove_port_forward(self) -> None:
        """Remove ADB port forwarding."""
        if self._forwarded:
            try:
                cmd = ["adb"]
                if self.adb._serial:
                    cmd += ["-s", self.adb._serial]
                cmd += ["forward", "--remove", "tcp:27042"]
                subprocess.run(cmd, capture_output=True, timeout=5)
                self._forwarded = False
            except Exception:
                pass
