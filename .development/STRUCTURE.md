# Структура проекта

```
frida-kahlo/
├── kahlo/                        # Python-пакет (CLI + движок)
│   ├── __init__.py
│   ├── cli.py                    # typer CLI — точка входа
│   ├── pipeline.py               # оркестрация полного пайплайна
│   │
│   ├── acquire/                  # Получение APK
│   │   ├── __init__.py
│   │   ├── fetcher.py            # Playwright — APKMirror/APKPure
│   │   ├── extractor.py          # XAPK/APKM → split APK
│   │   └── installer.py          # adb install-multiple
│   │
│   ├── prepare/                  # Статический анализ
│   │   ├── __init__.py
│   │   ├── manifest.py           # AndroidManifest → permissions, services
│   │   ├── decompiler.py         # jadx wrapper (фоновый процесс)
│   │   └── strings.py            # извлечение URL, ключей, строк
│   │
│   ├── device/                   # Управление устройством
│   │   ├── __init__.py
│   │   ├── adb.py                # ADB обёртка
│   │   └── frida_server.py       # lifecycle: push, start, stop, health
│   │
│   ├── stealth/                  # Stealth Layer
│   │   ├── __init__.py
│   │   ├── manager.py            # выбор уровня, эскалация
│   │   ├── port.py               # рандомизация порта
│   │   └── checker.py            # проверка детекта
│   │
│   ├── instrument/               # Frida-оркестрация
│   │   ├── __init__.py
│   │   ├── engine.py             # spawn, inject, message handler
│   │   ├── loader.py             # загрузка и композиция JS-модулей
│   │   └── session.py            # Session — сбор событий в JSON
│   │
│   ├── analyze/                  # Анализ собранных данных
│   │   ├── __init__.py
│   │   ├── traffic.py            # карта API, endpoints, flows
│   │   ├── vault.py              # агрегация секретов
│   │   ├── recon.py              # fingerprint appetite
│   │   ├── netmodel.py           # protocol detection, signing analysis
│   │   └── patterns.py           # known services (Firebase, Adjust...)
│   │
│   ├── report/                   # Генерация отчётов
│   │   ├── __init__.py
│   │   ├── markdown.py           # человекочитаемый .md
│   │   ├── api_spec.py           # OpenAPI-подобная спецификация
│   │   └── replay.py             # генерация Python/curl replay
│   │
│   └── utils/                    # Общие утилиты
│       ├── __init__.py
│       ├── json_stream.py        # JSONL streaming
│       ├── colors.py             # терминальный вывод
│       └── config.py             # настройки (~/.kahlo/config.toml)
│
├── scripts/                      # Frida JS-модули
│   ├── bypass/
│   │   ├── stealth.js            # anti-frida + anti-root
│   │   └── ssl_unpin.js          # universal SSL unpinning
│   │
│   ├── hooks/
│   │   ├── traffic.js            # Столп 1: весь сетевой трафик
│   │   ├── vault.js              # Столп 2: хранилище и секреты
│   │   ├── recon.js              # Столп 3: разведка окружения
│   │   └── netmodel.js           # Столп 4: сетевая механика
│   │
│   ├── discovery.js              # class/method enumeration
│   └── common.js                 # shared utils (send, format)
│
├── sessions/                     # результаты анализов (gitignored)
│
├── skills/                       # Claude Code skills
│   ├── android-analysis/
│   │   └── SKILL.md
│   └── android-replay/
│       └── SKILL.md
│
├── .development/                 # документация разработки
│   ├── DESIGN.md
│   ├── STRUCTURE.md
│   ├── CHECKLIST.md
│   └── RESEARCH.md
│
├── pyproject.toml
├── CLAUDE.md
└── README.md
```
