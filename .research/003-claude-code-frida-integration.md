# Claude Code + Frida Integration Patterns

Дата исследования: 2026-03-26
Источник: Perplexity sonar-pro

## Источники
- [Zane St. John — Reverse engineering Android malware with Claude Code (Feb 2026)](https://zanestjohn.com/blog/reing-with-claude-code)
- [Anthropic — Claude Code Security](https://www.anthropic.com/news/claude-code-security)
- [CSIS — AI-Driven Code Analysis](https://www.csis.org/blogs/strategic-technologies-blog/ai-driven-code-analysis-what-claude-code-security-can-and-cant-do)

## Кейс Zane St. John — RE малвари с Claude Code

### Workflow
1. Подключил проектор к Pi-hole → обнаружил подозрительные DNS-запросы
2. Root устройство через XDA tutorial
3. `adb pull` 5 APK → `jadx` декомпиляция
4. Дал Claude Code одну задачу с контекстом и подсказками
5. Claude Code автономно:
   - Нашёл XOR-шифрование строк
   - Написал Python-расшифровщик
   - Раскрыл C2-архитектуру (5 доменов, 3-stage payload)
   - Реверснул AES-128-CBC протокол
   - **Написал работающий C2-клиент**
   - Скачал Stage 2 payload (70KB JAR)

### Что работало
- Автономная декомпозиция задачи без микроменеджмента
- Быстрое определение паттернов обфускации
- Протокольный RE через trial-and-error реализации
- Часы вместо дней

### Что НЕ было
- Никаких MCP-серверов
- Никаких кастомных skills
- Никакой автоматизации — всё вручную через file system access
- **Это gap, который заполняет Frida-Kahlo**

## Claude Code Skill Design

Рекомендации для multi-step workflows:

```yaml
name: android_security_analysis
steps:
  - tool: adb_install
  - tool: jadx_decompile
  - tool: frida_dynamic_hooks
  - tool: traffic_analyzer
  - output: generate_report
```

## Agent Orchestration

Supervisor → параллельные subagents:
- **StaticAgent**: jadx decompile → reasoning on Java code → vuln patterns
- **DynamicAgent**: Frida hooks → traffic capture → runtime APIs
- Supervisor: combines outputs for unified reasoning

## Structured Output для Claude

Hooks → JSON schemas:
```json
{
    "timestamp": "...",
    "method": "...",
    "args": [...],
    "return": "...",
    "stack": [...]
}
```

Post-process → Pydantic models → Claude prompt: "Analyze this JSON for patterns."

## Существующие проекты

- Zane St. John — ручной workflow, нет автоматизации
- Claude Code Security — статический source-code reasoning, не мобильный RE
- Нет MCP-серверов для ADB/Frida в публичном доступе
- **Frida-Kahlo будет первым** комплексным CLI для AI-assisted mobile RE
