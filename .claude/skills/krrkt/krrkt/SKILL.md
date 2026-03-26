---
name: krrkt
description: "Check Russian text quality using the krrkt CLI tool. Analyzes text for stop words, corporate stamps, bureaucratese, vague language, imposed assessments, cliches, passive voice, and other informational style issues. Scores text 0-10 (Glvrd-compatible scale). Use when: (1) user writes or edits Russian text and asks to check quality, (2) user says 'проверь текст', 'проверка качества', 'инфостиль', 'стоп-слова', 'krrkt', 'check text quality', (3) user asks to improve Russian writing style, (4) user opens a Russian .md/.txt file and asks for feedback. Requires krrkt CLI installed (pip install krrkt). NOT for English text, translation, or spelling/grammar proofreading."
---

# krrkt — Russian Text Quality Checker

## Prerequisites

Verify krrkt is installed: `krrkt --help`. If missing: `pip install krrkt`.

## Commands

Check text (instant, dictionary-only):

```bash
krrkt check --no-llm "Наша компания является лидером рынка."
```

Check file:

```bash
krrkt check --no-llm /path/to/file.txt
```

JSON output:

```bash
krrkt check --no-llm --format json "Text"
```

Score only:

```bash
krrkt score --no-llm "Text"
```

Deep analysis with LLM (requires Claude API key or subscription):

```bash
krrkt check "Text"
```

## Score Scale

| Score | Meaning |
|-------|---------|
| 7.5-10 | Clean text |
| 5-7.4 | Has issues |
| 0-4.9 | Serious problems |

## Finding Severity

- Weight 80-100 (`■`): fix required — stamps, evaluations, amplifiers
- Weight 1-79 (`▲`): worth considering — weak verbs, participles, introductory words
- Weight 0 (`○`): informational — pronouns

## Rule Categories

**Purity** — remove or replace with facts:

| Rule | Example |
|------|---------|
| Corporate stamp | широкий спектр, команда профессионалов |
| Assessment without proof | уникальный, инновационный, лучший |
| Amplifier | очень, абсолютно, невероятно |
| Time parasite | на сегодняшний день, в настоящее время |
| Newspaper stamp | ни для кого не секрет |
| Ad stamp | уникальное предложение |
| Bureaucratese | в связи с, данный, осуществлять |
| Pompous word | коммуникация (= общение), инициировать (= начинать) |
| Pleonasm | бесплатный подарок, главная суть |
| Vagueness | некоторые, многолетний опыт |
| Filler | просто, буквально, как бы |
| Verbal noun phrase | осуществлять поставку (= поставлять) |

**Readability** — simplify:

| Rule | Example |
|------|---------|
| Introductory construction | безусловно, конечно, казалось бы |
| Passive voice | было принято решение (= решили) |
| Complex syntax | для того чтобы, несмотря на то что |

## Suggesting Fixes

For each finding, suggest a concrete replacement:
- **Stamp** — replace with specific facts
- **Assessment** — provide evidence or delete
- **Amplifier** — delete ("абсолютно уникальный" → facts)
- **Bureaucratese** — plain Russian ("осуществлять поставку" → "поставлять")
- **Pompous word** — use simpler equivalent from the description field
- **Passive voice** — find the actor ("было решено" → "мы решили")
- **Verbal noun** — convert to verb ("проведение анализа" → "проанализировали")
- **Time parasite** — delete ("на сегодняшний день компания работает" → "компания работает")

## Markdown Files

When checking .md files, extract prose only. Skip: YAML frontmatter, code blocks, HTML, markdown formatting syntax.

## Batch Check

```bash
for f in *.md; do echo "=== $f ===" && krrkt score --no-llm "$f"; done
```
