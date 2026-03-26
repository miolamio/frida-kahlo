# Фаза 5+6: Acquire + Full Pipeline — Отчёт о выполнении

Дата: 2026-03-26

## Результат

**144 теста пройдено** (+32 новых). Полный пайплайн работает end-to-end.

## Что реализовано

### Acquire модуль (`kahlo/acquire/`)

| Компонент | Функция |
|-----------|---------|
| `extractor.py` | Определение формата (APK/XAPK/APKM/dir), распаковка split APK |
| `fetcher.py` | Playwright + stealth — скачивание с APKPure/APKCombo |
| `installer.py` | Extract + ADB install + определение package name |

### Prepare модуль (`kahlo/prepare/`)

| Компонент | Функция |
|-----------|---------|
| `manifest.py` | Парсинг AndroidManifest: permissions, activities, services, SDK versions |
| `decompiler.py` | jadx wrapper (фоновый subprocess) |

### Pipeline (`kahlo/pipeline.py`)

Полная оркестрация с Rich-прогрессом:

```
ACQUIRE  → скачивание APK (Playwright) или пропуск
PREPARE  → установка + manifest + jadx (фон)
INSTRUMENT → stealth frida + 4 хука + discovery
ANALYZE  → 5 анализаторов
REPORT   → markdown + api-spec + replay
```

### CLI — 11 команд

```
kahlo version         — версия
kahlo device          — статус устройства
kahlo install <apk>   — установка APK
kahlo frida-start     — stealth frida-server
kahlo frida-stop      — остановка frida
kahlo scan <pkg>      — сбор данных (4 столпа)
kahlo report <session>— генерация отчётов
kahlo analyze <name>  — ПОЛНЫЙ ПАЙПЛАЙН (от имени до отчёта)
kahlo fetch <name>    — скачать APK с зеркал
kahlo manifest <apk>  — информация из манифеста
kahlo stealth-check   — проверка детекта Frida
```

### Claude Code Skills

| Скилл | Триггер | Workflow |
|-------|---------|---------|
| `android-analysis` | "проанализируй приложение", "analyze app" | kahlo analyze → read report → interpret |
| `android-replay` | "создай клиент", "replay API" | load api-spec + replay → generate client |

### CLAUDE.md

Обновлён с полным справочником команд.

## Интеграционный тест

```bash
$ kahlo analyze com.voltmobi.yakitoriya --skip-fetch --duration 30

[1/5] ACQUIRE   Пропуск (--skip-fetch)
[2/5] PREPARE   Manifest: 23 permissions, 8 services
[3/5] INSTRUMENT 1,348 событий за 30 сек
[4/5] ANALYZE   6 серверов, 30 секретов, 11 SDK
[5/5] REPORT    report.md (65KB), api-spec.json, 15 replay файлов
```

**1,348 событий** (вдвое больше первого скана — больше активности).

## Прогресс проекта — ФИНАЛ

| Фаза | Тесты | Результат |
|------|-------|-----------|
| 1. Фундамент | 20 | ADB + frida-server + CLI |
| 2. Stealth + Instrument | 27 | Bypass + FridaEngine + Discovery |
| 3. Четыре столпа | 10 | 626→1348 событий за 30 сек |
| 4. Анализ + Отчёт | 55 | Автоотчёт + API spec + replay |
| 5. Acquire | 21 | APK fetch (Playwright) + extract + install |
| 6. Pipeline + Skills | 11 | `kahlo analyze` end-to-end |
| **Итого** | **144** | **Полная система** |

## Файлы проекта (итоговые)

```
kahlo/                    — Python пакет
  cli.py                  — 11 CLI команд
  pipeline.py             — полная оркестрация
  acquire/                — APK скачивание/распаковка/установка
  prepare/                — manifest парсинг, jadx
  device/                 — ADB, frida-server lifecycle
  stealth/                — антидетект (4 уровня)
  instrument/             — FridaEngine, ScriptLoader, Session
  analyze/                — 5 анализаторов (traffic, vault, recon, netmodel, patterns)
  report/                 — markdown, api_spec, replay генераторы

scripts/                  — Frida JS модули
  common.js               — shared utilities
  discovery.js            — class enumeration
  bypass/stealth.js       — антидетект (proc/maps, files, ports, ptrace, root)
  bypass/ssl_unpin.js     — universal SSL unpinning
  hooks/traffic.js        — 5-уровневый перехват трафика
  hooks/vault.js          — хранилище и секреты
  hooks/recon.js          — разведка окружения
  hooks/netmodel.js       — криптография и signing

skills/                   — Claude Code skills
  android-analysis/       — skill для анализа приложений
  android-replay/         — skill для воспроизведения API

tests/                    — 144 теста
```
