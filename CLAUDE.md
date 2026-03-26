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
