# Case Study: RE Android Malware with Claude Code

Дата исследования: 2026-03-26
Источник: [zanestjohn.com](https://zanestjohn.com/blog/reing-with-claude-code) (Feb 2026)

## Контекст

Автор обнаружил малварь на бюджетном Android-проекторе через Pi-hole DNS.
Подозрительные домены: `o.fecebbbk.xyz`, `usmyip.kkoip.com`.

## Инструменты

- **ADB**: root shell, package management
  - `adb shell pm list packages`
  - `adb pull $(adb shell pm path com.hotack.silentsdk | cut -d: -f2)`
  - `adb shell pm disable-user --user 0 [package_name]`
- **JADX**: декомпиляция APK → Java source
- **Python**: кастомные скрипты расшифровки
- **Claude Code**: автономный анализ

## Workflow

### Phase 1 — Reconnaissance
1. Подключил проектор к Pi-hole
2. Обнаружил подозрительные DNS-запросы
3. Отключил подозрительные system packages → подтвердил source

### Phase 2 — Extraction
1. Root устройства (XDA tutorial)
2. Вытащил 5 APK через `adb pull`
3. Декомпилировал через JADX
4. Создал структурированную директорию для Claude Code

### Phase 3 — Claude Code Analysis
Дал Claude Code:
- "Clear mission" (не пошаговые инструкции)
- Правильные инструменты (file access, Python)
- Подсказки где начать

Claude Code **автономно**:
1. Нашёл XOR-шифрование строк по паттернам вроде `g({-99,127,58,...}, {-4,15,83,...})`
2. Написал Python-расшифровщик без явной инструкции
3. Расшифровал: `api.pixelpioneerss.com`
4. Маппировал C2-архитектуру через несколько APK
5. Реверснул AES-128-CBC протокол:
   ```
   Request: [Version(4)][Ciphertext(N)][IV(16)][Key(16)]
            int32 BE     AES-CBC       Random   Random
            (1003)       128-bit       128-bit
   ```
6. Обнаружил разницу request/response формата через trial-and-error
7. **Написал работающий C2-клиент**
8. Скачал Stage 2 payload (70KB JAR)
9. Связал residential proxy инфраструктуру (Kookeey/KKOIP)

## Ключевые находки

### Обфускация строк
- Rotating XOR ciphers для sensitive data
- "Textbook obfuscation — defeats static analysis but trivially reversible"

### Dynamic Code Loading
```java
Class<?> dexLoaderClass = Class.forName(
    "dalvik" + "." + "system" + "." + "Dex" + "ClassLoader"
);
```
DexClassLoader имя собрано из фрагментов для обхода static analysis.

### Malicious Init Script
```bash
# /system/bin/appsdisable — отключает Google Play Protect
pm query-receivers --components -a android.intent.action.BOOT_COMPLETED \
  | grep com.google.android \
  | busybox xargs -n 1 pm disable
```

## Результат
- 5 C2 доменов
- 3-stage payload chain
- Residential proxy infrastructure
- "Analysis that would normally take a skilled analyst days was done in hours"

## Уроки для Frida-Kahlo

1. **Давать Claude Code "миссию", а не пошаговые инструкции** — он лучше работает автономно
2. **Structured data критична** — Claude Code отлично работает с декомпилированным кодом в директориях
3. **Trial-and-error в реализации** — Claude Code может обнаружить тонкости протокола через попытки
4. **Нет автоматизации** — всё делалось вручную. Kahlo заполняет этот gap.
5. **Фокус на protocol RE** — именно построение клиента дало глубочайшее понимание малвари
