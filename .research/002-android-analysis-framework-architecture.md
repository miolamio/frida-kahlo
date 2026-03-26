# Android Analysis Framework — Architecture Patterns

Дата исследования: 2026-03-26
Источник: Perplexity sonar-pro

## Рекомендуемая архитектура

**Модульный CLI-пайплайн с Clean Architecture** (domain-driven layers):
- Entities → Use Cases → Adapters (обёртки ADB/Frida/jadx) → CLI
- DAG стадий: device management → static → dynamic → LLM → reporting
- Unidirectional Data Flow: Input APK → stages → output JSON stream

## Слои

| Слой | Ответственность | Инструменты |
|------|----------------|-------------|
| Entities/Domain | Результаты анализа как immutable data classes | Pydantic |
| Use Cases | Бизнес-логика: `analyze_apk()`, `hook_crypto_apis()` | Dependency inversion |
| Adapters | Обёртки ADB, Frida, Androguard | Abstract base classes |
| Frameworks/Drivers | CLI entrypoint, ADB/Frida execution | Typer, asyncio |

## Статический анализ — инструменты

| Инструмент | Роль | Интеграция |
|-----------|------|-----------|
| apktool | Декомпиляция в smali/resources | `apktool d apk -o outdir` |
| jadx | Java декомпиляция | `jadx -d out apk` |
| Androguard | Manifest, permissions, strings, code patterns | Python API: `AnalyzeAPK(path)` |
| APKiD | Packer/обфускация detection | `apkid scan apk` → JSON |
| droidlysis | Comprehensive static | Python batch mode |
| quark-engine | ML-based code pattern detection | `quark -a apk --json` |

## Динамический анализ — паттерны

- **Hooking strategies**: Pre-defined scripts для crypto (javax.crypto.*), network (OkHttp), FS (java.io.*)
- **frida-dexdump**: Runtime DEX dumping
- **Coverage-guided**: Frida Stalker API + tracing
- **Script factory**: Генерация хуков динамически из static findings

## Report Generation

- **JSON-first**: Pydantic для structured schemas
- **Jinja2**: Markdown templates
- Schema: `{"static": {...}, "dynamic": {...}, "risks": [...]}`

## LLM Integration

- Pipe JSON → LiteLLM/Ollama
- Chain-of-analysis: static → LLM summarizes → dynamic targets → re-prompt

## MobSF как референс

MobSF — full-stack анализатор (ADB + apktool/jadx/Androguard + Frida + reports).
Наше отличие: фокус на **protocol RE и API recreation**, а не на vulnerability scanning.
