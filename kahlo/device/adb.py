"""ADB wrapper for device communication."""
from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import dataclass

from pydantic import BaseModel


# Regex for valid Android package names and ADB shell-safe identifiers
_SAFE_SHELL_ARG_RE = re.compile(r'^[a-zA-Z0-9._/:@\-]+$')


def validate_shell_arg(value: str, label: str = "argument") -> str:
    """Validate that a string is safe for ADB shell interpolation.

    Only allows alphanumeric characters, dots, underscores, slashes,
    colons, at-signs, and hyphens. Raises ValueError otherwise.
    """
    if not value or not _SAFE_SHELL_ARG_RE.match(value):
        raise ValueError(
            f"Недопустимый {label}: {value!r} — "
            "допускаются только буквы, цифры, точки, подчёркивания, слеши и дефисы"
        )
    return value


class DeviceInfo(BaseModel):
    serial: str
    model: str
    android_version: str
    sdk_version: str
    build_id: str
    rooted: bool
    abi: str


@dataclass
class ADBDevice:
    serial: str
    state: str  # "device", "offline", "unauthorized"


class ADBError(Exception):
    pass


class ADB:
    def __init__(self, serial: str | None = None):
        self._serial = serial

    def _cmd(self, args: list[str], timeout: int = 30) -> str:
        cmd = ["adb"]
        if self._serial:
            cmd += ["-s", self._serial]
        cmd += args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode != 0 and result.stderr.strip():
                raise ADBError(f"adb error: {result.stderr.strip()}")
            return result.stdout.strip()
        except FileNotFoundError:
            raise ADBError("adb not found in PATH")
        except subprocess.TimeoutExpired:
            raise ADBError(f"adb command timed out: {' '.join(args)}")

    def devices(self) -> list[ADBDevice]:
        output = self._cmd(["devices"])
        result = []
        for line in output.splitlines()[1:]:  # skip header
            parts = line.split("\t")
            if len(parts) == 2:
                result.append(ADBDevice(serial=parts[0], state=parts[1]))
        return result

    def shell(self, cmd: str, su: bool = False) -> str:
        if su:
            cmd = f"su -c {shlex.quote(cmd)}"
        return self._cmd(["shell", cmd])

    def push(self, local: str, remote: str) -> str:
        return self._cmd(["push", local, remote])

    def pull(self, remote: str, local: str) -> str:
        return self._cmd(["pull", remote, local])

    def install(self, apk_paths: list[str]) -> str:
        if len(apk_paths) == 1:
            return self._cmd(["install", "-r", apk_paths[0]], timeout=120)
        else:
            return self._cmd(["install-multiple", "-r"] + apk_paths, timeout=120)

    def uninstall(self, package: str) -> str:
        return self._cmd(["uninstall", package])

    def list_packages(self, third_party_only: bool = False) -> list[str]:
        args = ["shell", "pm", "list", "packages"]
        if third_party_only:
            args.append("-3")
        output = self._cmd(args)
        return [line.replace("package:", "") for line in output.splitlines() if line.startswith("package:")]

    def get_device_info(self) -> DeviceInfo:
        def prop(name: str) -> str:
            return self.shell(f"getprop {name}")

        # Check root
        try:
            root_check = self.shell("whoami", su=True)
            rooted = "root" in root_check
        except ADBError:
            rooted = False

        return DeviceInfo(
            serial=self._serial or self.devices()[0].serial,
            model=prop("ro.product.model"),
            android_version=prop("ro.build.version.release"),
            sdk_version=prop("ro.build.version.sdk"),
            build_id=prop("ro.build.display.id"),
            rooted=rooted,
            abi=prop("ro.product.cpu.abi"),
        )
