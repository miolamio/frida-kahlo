# CLAUDE.md

## Project

Frida-Kahlo — CLI for automated Android app analysis via Frida.
Language: Russian for UI, English for code and comments.

## Quick Start

```bash
pip install -e ".[dev]"
kahlo device                # device status
kahlo analyze com.example.app --skip-fetch --duration 60  # full pipeline
```

## Architecture

- `kahlo/` — Python package (CLI + engine + pipeline)
  - `acquire/` — APK download (Playwright), extraction, installation
  - `prepare/` — manifest parsing, jadx decompilation
  - `instrument/` — Frida engine, script loader, session management
  - `analyze/` — traffic, vault, recon, netmodel, patterns analysis
  - `report/` — markdown, api-spec.json, replay scripts
  - `stealth/` — anti-detection (port randomization, bypass scripts)
  - `device/` — ADB wrapper, frida-server management
  - `pipeline.py` — full orchestration (ACQUIRE -> PREPARE -> INSTRUMENT -> ANALYZE -> REPORT)
  - `cli.py` — typer CLI
- `scripts/` — Frida JS modules (hooks, bypass, discovery)
- `sessions/` — analysis results (gitignored)
- `skills/` — Claude Code skills (android-analysis, android-replay)

## CLI Commands

```bash
# Full pipeline
kahlo analyze <name_or_package> [--duration 60] [--skip-fetch] [--skip-static]

# Individual commands
kahlo fetch <app_name>              # download APK from mirrors
kahlo install <apk_path>            # install APK on device
kahlo manifest <apk_or_dir>         # parse AndroidManifest.xml
kahlo scan <package> [--duration N]  # instrument + collect events
kahlo report <session.json>         # generate analysis report
kahlo device                        # device status
kahlo stealth-check <package>       # check Frida detection
kahlo frida-start                   # start frida-server (stealth)
kahlo frida-stop                    # stop frida-server
kahlo version                       # show version
```

### `kahlo analyze` — Full Pipeline

The main command. Orchestrates: fetch APK -> install -> manifest analysis -> jadx (background) -> Frida instrumentation -> collect events -> analyze -> generate reports.

- If target contains dots (com.xxx.yyy): treated as package name, skips APK fetch
- If target is plain text: tries to download APK from APKPure/APKCombo
- `--skip-fetch`: assume app is already installed on device
- `--skip-static`: skip jadx decompilation
- Output: `sessions/<session_id>_report/` with report.md, api-spec.json, replay/

### `kahlo scan` — Instrumentation Only

Spawns the app with all Frida hooks, collects events for N seconds. Does not generate reports (use `kahlo report` after).

### `kahlo report` — Report Generation

Generates report.md, api-spec.json, and replay scripts from a session JSON file.

## Testing

```bash
pytest tests/ -v --timeout=120
kahlo device          # requires connected Android device
```

## Requirements

- Rooted Android device with USB debugging
- frida-server on device at /data/local/tmp/frida-server
- Python 3.11+, frida 17.x, playwright 1.50 (optional)

## Conventions

- Python: type hints, pydantic models for data
- Frida scripts: JS, send() for structured JSON events
- CLI output: rich for formatting, Russian UI messages
- Error handling: graceful — never crash on missing device/app
- Pipeline stages: ACQUIRE -> PREPARE -> INSTRUMENT -> ANALYZE -> REPORT
