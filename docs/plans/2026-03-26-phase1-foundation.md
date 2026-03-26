# Phase 1: Foundation — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Bootstrap the frida-kahlo project with a working CLI that can talk to an Android device via ADB, manage frida-server lifecycle, and install APKs.

**Architecture:** Python CLI (typer + rich) wrapping ADB and frida-server operations. Device communication via subprocess calls to `adb`. Pydantic models for device info. Testable against real device `28e37107` (Redmi Note 5A, rooted, Android 15).

**Tech Stack:** Python 3.11+, typer, rich, pydantic, frida, frida-tools

**Test app:** 2GIS (`ru.dublgis.dgismobile`) — will be installed and used for validation in later phases.

---

### Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `kahlo/__init__.py`
- Create: `kahlo/cli.py`
- Create: `.gitignore`
- Create: `CLAUDE.md`

**Step 1: Create `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "frida-kahlo"
version = "0.1.0"
description = "CLI framework for automated Android app analysis via Frida"
requires-python = ">=3.11"
dependencies = [
    "frida>=17.0",
    "frida-tools>=14.0",
    "typer>=0.12",
    "rich>=13.0",
    "pydantic>=2.0",
]

[project.scripts]
kahlo = "kahlo.cli:app"

[project.optional-dependencies]
dev = ["pytest>=8.0", "pytest-timeout>=2.0"]
static = ["androguard>=4.0"]
acquire = ["playwright>=1.40"]
```

**Step 2: Create `kahlo/__init__.py`**

```python
"""Frida-Kahlo: CLI framework for automated Android app analysis."""

__version__ = "0.1.0"
```

**Step 3: Create minimal `kahlo/cli.py`**

```python
import typer

app = typer.Typer(
    name="kahlo",
    help="Frida-Kahlo: Android app analysis framework",
    no_args_is_help=True,
)


@app.command()
def version():
    """Show version."""
    from kahlo import __version__
    typer.echo(f"frida-kahlo v{__version__}")


if __name__ == "__main__":
    app()
```

**Step 4: Create `.gitignore`**

```
__pycache__/
*.pyc
*.egg-info/
dist/
build/
.venv/
sessions/
*.apk
*.xapk
*.apkm
.DS_Store
```

**Step 5: Create `CLAUDE.md`**

```markdown
# CLAUDE.md

## Project

Frida-Kahlo — CLI для автоматизированного анализа Android-приложений через Frida.
Язык общения: русский. Код и комменты: английский.

## Quick Start

```bash
pip install -e ".[dev]"
kahlo device          # статус устройства
kahlo install <apk>   # установка APK
```

## Architecture

- `kahlo/` — Python package (CLI + engine)
- `scripts/` — Frida JS modules (hooks, bypass, discovery)
- `sessions/` — analysis results (gitignored)
- `.development/` — design docs, checklist
- `.research/` — research findings

## Testing

```bash
pytest tests/ -v
kahlo device          # requires connected Android device
```

## Test Device

- Redmi Note 5A (28e37107), Android 15, root via Magisk
- frida-server at /data/local/tmp/frida-server
- Test app: 2GIS (ru.dublgis.dgismobile)

## Conventions

- Python: type hints, pydantic models for data
- Frida scripts: JS, send() for structured JSON events
- CLI output: rich for formatting, Russian UI messages
- Error handling: graceful — never crash on missing device/app
```

**Step 6: Install in dev mode and verify**

Run: `cd /Users/codegeek/src/frida-kahlo && pip install -e ".[dev]"`
Run: `kahlo version`
Expected: `frida-kahlo v0.1.0`

**Step 7: Init git and commit**

Run: `cd /Users/codegeek/src/frida-kahlo && git init && git add pyproject.toml kahlo/ .gitignore CLAUDE.md docs/ .development/ .research/ && git commit -m "feat: project scaffolding"`

---

### Task 2: ADB Wrapper

**Files:**
- Create: `kahlo/device/__init__.py`
- Create: `kahlo/device/adb.py`
- Create: `tests/__init__.py`
- Create: `tests/test_adb.py`

**Step 1: Write tests for ADB wrapper**

```python
# tests/test_adb.py
"""Tests for ADB wrapper. Requires connected Android device."""
import pytest
from kahlo.device.adb import ADB


@pytest.fixture
def adb():
    return ADB()


class TestADBDevices:
    def test_devices_returns_list(self, adb):
        devices = adb.devices()
        assert isinstance(devices, list)

    def test_at_least_one_device(self, adb):
        devices = adb.devices()
        assert len(devices) >= 1

    def test_device_has_serial(self, adb):
        devices = adb.devices()
        assert any(d.serial == "28e37107" for d in devices)


class TestADBShell:
    def test_shell_whoami(self, adb):
        result = adb.shell("whoami")
        assert "shell" in result or "root" in result

    def test_shell_su(self, adb):
        result = adb.shell("whoami", su=True)
        assert "root" in result

    def test_shell_getprop(self, adb):
        result = adb.shell("getprop ro.product.model")
        assert len(result) > 0


class TestADBDeviceInfo:
    def test_device_info_model(self, adb):
        info = adb.get_device_info()
        assert info.model == "Redmi Note 5A"

    def test_device_info_rooted(self, adb):
        info = adb.get_device_info()
        assert info.rooted is True

    def test_device_info_android_version(self, adb):
        info = adb.get_device_info()
        assert info.android_version  # non-empty


class TestADBPackages:
    def test_list_packages(self, adb):
        packages = adb.list_packages()
        assert isinstance(packages, list)
        assert len(packages) > 0

    def test_list_packages_contains_magisk(self, adb):
        packages = adb.list_packages()
        assert "com.topjohnwu.magisk" in packages
```

**Step 2: Run tests — verify they fail**

Run: `cd /Users/codegeek/src/frida-kahlo && pytest tests/test_adb.py -v`
Expected: FAIL (module not found)

**Step 3: Implement ADB wrapper**

```python
# kahlo/device/__init__.py
"""Device management: ADB + frida-server."""

# kahlo/device/adb.py
"""ADB wrapper for device communication."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass

from pydantic import BaseModel


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
            cmd = f"su -c '{cmd}'"
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
```

**Step 4: Run tests — verify they pass**

Run: `cd /Users/codegeek/src/frida-kahlo && pytest tests/test_adb.py -v`
Expected: all PASS

**Step 5: Commit**

Run: `git add kahlo/device/ tests/ && git commit -m "feat: ADB wrapper with device info, shell, packages"`

---

### Task 3: Frida Server Lifecycle

**Files:**
- Create: `kahlo/device/frida_server.py`
- Create: `tests/test_frida_server.py`

**Step 1: Write tests**

```python
# tests/test_frida_server.py
"""Tests for frida-server lifecycle. Requires connected rooted device."""
import pytest
from kahlo.device.adb import ADB
from kahlo.device.frida_server import FridaServer


@pytest.fixture
def fs():
    adb = ADB()
    return FridaServer(adb)


class TestFridaServerStatus:
    def test_server_exists_on_device(self, fs):
        assert fs.is_installed()

    def test_server_version(self, fs):
        # frida-server binary exists at expected path
        assert fs.server_path is not None


class TestFridaServerLifecycle:
    def test_ensure_starts_server(self, fs):
        fs.ensure()
        assert fs.is_running()

    def test_stop_server(self, fs):
        fs.ensure()
        assert fs.is_running()
        fs.stop()
        assert not fs.is_running()

    def test_ensure_is_idempotent(self, fs):
        fs.ensure()
        fs.ensure()  # second call should not fail
        assert fs.is_running()

    def test_start_on_custom_port(self, fs):
        fs.stop()
        fs.start(port=47293)
        assert fs.is_running()
        fs.stop()
```

**Step 2: Run tests — verify they fail**

Run: `pytest tests/test_frida_server.py -v`
Expected: FAIL

**Step 3: Implement FridaServer**

```python
# kahlo/device/frida_server.py
"""Frida-server lifecycle management."""
from __future__ import annotations

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
            result = self._adb.shell("ps -A | grep frida", su=True)
            return "frida" in result or ".fs" in result
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
        cmd += " &"

        self._adb.shell(f"chmod 755 {self.server_path}", su=True)
        self._adb.shell(cmd, su=True)

        # Wait for startup
        for _ in range(10):
            time.sleep(0.5)
            if self.is_running():
                return

        raise FridaServerError("frida-server failed to start within 5 seconds")

    def stop(self) -> None:
        try:
            self._adb.shell("pkill -f frida-server || pkill -f .fs", su=True)
            time.sleep(0.5)
        except ADBError:
            pass  # already stopped
        self._port = None

    def ensure(self) -> None:
        if not self.is_running():
            self.start(port=self._port)

    @property
    def port(self) -> int | None:
        return self._port
```

**Step 4: Run tests — verify they pass**

Run: `pytest tests/test_frida_server.py -v --timeout=30`
Expected: all PASS

**Step 5: Commit**

Run: `git add kahlo/device/frida_server.py tests/test_frida_server.py && git commit -m "feat: frida-server lifecycle (start/stop/ensure)"`

---

### Task 4: CLI Device Command

**Files:**
- Modify: `kahlo/cli.py`
- Create: `tests/test_cli.py`

**Step 1: Write CLI test**

```python
# tests/test_cli.py
"""Tests for CLI commands."""
from typer.testing import CliRunner
from kahlo.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "frida-kahlo" in result.output


def test_device():
    result = runner.invoke(app, ["device"])
    assert result.exit_code == 0
    assert "28e37107" in result.output or "Redmi" in result.output


def test_device_shows_root_status():
    result = runner.invoke(app, ["device"])
    assert result.exit_code == 0
    # Should mention root status
    assert "root" in result.output.lower() or "magisk" in result.output.lower()
```

**Step 2: Run — verify fail**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL (device command not found)

**Step 3: Implement device command**

```python
# kahlo/cli.py — full replacement
"""Frida-Kahlo CLI."""
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="kahlo",
    help="Frida-Kahlo: Android app analysis framework",
    no_args_is_help=True,
)
console = Console()


@app.command()
def version():
    """Show version."""
    from kahlo import __version__
    console.print(f"frida-kahlo v{__version__}")


@app.command()
def device():
    """Show connected device status."""
    from kahlo.device.adb import ADB, ADBError
    from kahlo.device.frida_server import FridaServer

    adb = ADB()

    try:
        devices = adb.devices()
    except ADBError as e:
        console.print(f"[red]Ошибка ADB: {e}[/red]")
        raise typer.Exit(1)

    if not devices:
        console.print("[red]Нет подключённых устройств[/red]")
        raise typer.Exit(1)

    # Use first device
    adb = ADB(serial=devices[0].serial)

    try:
        info = adb.get_device_info()
    except ADBError as e:
        console.print(f"[red]Не удалось получить информацию: {e}[/red]")
        raise typer.Exit(1)

    table = Table(title="Устройство")
    table.add_column("Параметр", style="cyan")
    table.add_column("Значение", style="green")

    table.add_row("Serial", info.serial)
    table.add_row("Модель", info.model)
    table.add_row("Android", info.android_version)
    table.add_row("SDK", info.sdk_version)
    table.add_row("Build", info.build_id)
    table.add_row("ABI", info.abi)
    table.add_row("Root", "✓ Magisk" if info.rooted else "✗")

    console.print(table)

    # Frida server status
    fs = FridaServer(adb)
    installed = fs.is_installed()
    running = fs.is_running()

    console.print()
    console.print(f"frida-server: {'[green]установлен[/green]' if installed else '[red]не найден[/red]'}")
    console.print(f"frida-server: {'[green]запущен[/green]' if running else '[yellow]остановлен[/yellow]'}")

    # Third-party apps
    apps = adb.list_packages(third_party_only=True)
    if apps:
        console.print(f"\nУстановленные приложения ({len(apps)}):")
        for pkg in sorted(apps):
            console.print(f"  {pkg}")


@app.command()
def install(
    path: str = typer.Argument(help="Path to APK, XAPK, or directory with split APKs"),
):
    """Install APK on device."""
    import os
    from kahlo.device.adb import ADB, ADBError

    adb = ADB()
    devices = adb.devices()
    if not devices:
        console.print("[red]Нет подключённых устройств[/red]")
        raise typer.Exit(1)

    adb = ADB(serial=devices[0].serial)

    # Collect APK files
    if os.path.isdir(path):
        apks = sorted([os.path.join(path, f) for f in os.listdir(path) if f.endswith(".apk")])
    else:
        apks = [path]

    if not apks:
        console.print(f"[red]APK не найдены в {path}[/red]")
        raise typer.Exit(1)

    console.print(f"Устанавливаю {len(apks)} APK на {devices[0].serial}...")
    for apk in apks:
        console.print(f"  {os.path.basename(apk)}")

    try:
        result = adb.install(apks)
        console.print(f"[green]Установлено: {result}[/green]")
    except ADBError as e:
        console.print(f"[red]Ошибка установки: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
```

**Step 4: Run tests — verify pass**

Run: `pytest tests/test_cli.py -v`
Expected: all PASS

**Step 5: Commit**

Run: `git add kahlo/cli.py tests/test_cli.py && git commit -m "feat: CLI device and install commands with rich output"`

---

### Task 5: Integration Test — Full Phase 1 Validation

**Step 1: Run all tests**

Run: `pytest tests/ -v --timeout=30`
Expected: all PASS

**Step 2: Manual CLI validation**

Run: `kahlo version`
Expected: `frida-kahlo v0.1.0`

Run: `kahlo device`
Expected: Rich table with device info, frida-server status, installed apps

Run: `kahlo --help`
Expected: Help text with available commands

**Step 3: Install 2GIS for future testing**

Download 2GIS APK and install:
Run: `kahlo install <path-to-2gis.apk>`
Expected: Successful installation

**Step 4: Final commit**

Run: `git add -A && git commit -m "feat: Phase 1 complete — foundation with ADB, frida-server, CLI"`
