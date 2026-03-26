# Фаза 1: Фундамент — Отчёт о выполнении

Дата: 2026-03-26
Коммит: 3001beb

## Результат

**20/20 тестов пройдено за 18 секунд.**

## Что реализовано

### 1. Структура проекта
- `pyproject.toml` — hatchling build, зависимости, pytest config
- `kahlo/__init__.py` — пакет v0.1.0
- `.gitignore` — sessions/, APK, __pycache__
- `CLAUDE.md` — инструкции для Claude Code

### 2. ADB Wrapper (`kahlo/device/adb.py`)
- `ADB.devices()` — список подключённых устройств
- `ADB.shell(cmd, su=False)` — выполнение команд (с поддержкой su)
- `ADB.push()` / `ADB.pull()` — передача файлов
- `ADB.install(apk_paths)` — установка APK (включая split APK через install-multiple)
- `ADB.uninstall(package)` — удаление
- `ADB.list_packages(third_party_only)` — список пакетов
- `ADB.get_device_info()` → Pydantic `DeviceInfo` модель
- 11 тестов

### 3. Frida Server Lifecycle (`kahlo/device/frida_server.py`)
- `FridaServer.is_installed()` — проверка наличия бинарника
- `FridaServer.is_running()` — проверка запущенности
- `FridaServer.start(port=None)` — запуск (с поддержкой кастомного порта)
- `FridaServer.stop()` — остановка (SIGKILL + cleanup helpers)
- `FridaServer.ensure()` — идемпотентный запуск
- 6 тестов

### 4. CLI (`kahlo/cli.py`)
- `kahlo version` — версия
- `kahlo device` — Rich-таблица с информацией об устройстве + frida-server + apps
- `kahlo install <path>` — установка APK/директории split-APK
- 3 теста

## Корректировки по ходу реализации

| # | Проблема | Решение |
|---|---------|---------|
| 1 | hatchling не находил пакет `kahlo` (имя проекта `frida-kahlo`) | Добавлен `[tool.hatch.build.targets.wheel] packages = ["kahlo"]` |
| 2 | typer сворачивал единственную команду в root | Добавлен `@app.callback()` + `invoke_without_command=True` |
| 3 | `adb shell "su -c 'frida-server &'"` блокировался | Переключено на `subprocess.Popen` для асинхронного запуска |
| 4 | `grep frida` ловил `re.frida.helper` после kill | Уточнён grep до `frida-server`, исключая grep itself |
| 5 | `pkill` недостаточно — процессы зависали | Добавлен `kill -9` + явный kill helpers + polling |
| 6 | Плагин `logfire` ломал pytest (protobuf import) | Добавлен `addopts = "-p no:logfire"` в pyproject.toml |
| 7 | План указывал Android 15, реально Android 16 (SDK 36) | Тесты написаны с assert non-empty, не привязаны к конкретной версии |

## Устройство

```
Serial:   28e37107
Модель:   Redmi Note 5A
Android:  16
SDK:      36
Build:    BP2A.250805.005
ABI:      arm64-v8a
Root:     ✓ Magisk
frida-server: установлен (/data/local/tmp/frida-server)
```

## Файлы

```
kahlo/__init__.py            — 52B
kahlo/cli.py                 — 3.2K
kahlo/device/__init__.py     — 45B
kahlo/device/adb.py          — 3.5K
kahlo/device/frida_server.py — 3.1K
tests/__init__.py            — 0B
tests/test_adb.py            — 1.5K
tests/test_cli.py            — 600B
tests/test_frida_server.py   — 1.2K
```

## Следующий шаг

Фаза 2: Stealth + Instrument
- `scripts/bypass/stealth.js` — anti-frida + anti-root bypass
- `scripts/bypass/ssl_unpin.js` — universal SSL unpinning
- `kahlo/stealth/` — manager, port randomization, detection check
- `kahlo/instrument/engine.py` — Frida spawn + inject + message handling
- `scripts/discovery.js` — class/method enumeration
- Тестирование на 2GIS (ru.dublgis.dgismobile)
