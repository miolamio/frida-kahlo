# .research — Исследования Frida-Kahlo

Все исследования проведены 2026-03-26 с использованием Perplexity (sonar-pro) и WebFetch.

## Индекс

| # | Файл | Тема |
|---|------|------|
| 001 | [frida-automation-state-of-art.md](001-frida-automation-state-of-art.md) | Состояние дел Frida-автоматизации: TypeScript, модульные хуки, инструменты-компаньоны |
| 002 | [android-analysis-framework-architecture.md](002-android-analysis-framework-architecture.md) | Архитектура фреймворка: Clean Architecture, инструменты статического/динамического анализа |
| 003 | [claude-code-frida-integration.md](003-claude-code-frida-integration.md) | Интеграция Claude Code + Frida: skills, agents, structured output |
| 004 | [frida-anti-detection.md](004-frida-anti-detection.md) | Антидетект Frida: все методы детекции, bypass-стратегии, сборка hluda, уровни эскалации |
| 005 | [api-recreation-from-frida.md](005-api-recreation-from-frida.md) | Воссоздание API: перехват OkHttp chain, signing, replay, бинарные протоколы, thin client |
| 006 | [claude-code-re-case-study.md](006-claude-code-re-case-study.md) | Кейс: реверс Android малвари с Claude Code (Zane St. John, Feb 2026) |
| 007 | [previous-experiments.md](007-previous-experiments.md) | Наши предыдущие эксперименты: 15 скриптов, Echo SDK, техники, уроки |

## NotebookLM

Все источники собраны в NotebookLM для дальнейшего изучения:
https://notebooklm.google.com/notebook/41001826-39af-488e-90b7-e7feef883208

## Ключевые выводы

1. **Python CLI + JS Frida scripts** — оптимальный стек (frida-python самый зрелый)
2. **Антидетект**: начинаем с random port + bypass.js, эскалируем до hluda/gadget
3. **API Recreation**: hook OkHttp interceptor chain → extract signing → replay из Python
4. **Claude Code**: лучше работает с "миссией" и structured data, не с пошаговыми инструкциями
5. **Нет аналогов**: Frida-Kahlo будет первым CLI для AI-assisted protocol RE
