# Результаты исследований

NotebookLM: https://notebooklm.google.com/notebook/41001826-39af-488e-90b7-e7feef883208

## Источники

### Frida + автоматизация
- [OWASP MASTG — Frida](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/)
- [Intercepting OkHttp at Runtime (Doyensec, Jan 2026)](https://blog.doyensec.com/2026/01/22/frida-instrumentation.html) — OkHttp interceptor chain, request mutation tracing
- [httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning) — universal SSL unpin + MitM
- [Exploiting Mobile Apps Using Frida (Prism Infosec)](https://prisminfosec.com/exploiting-mobile-apps-using-frida/)

### Антидетект Frida
- [Frida Detection & Prevention (Approov)](https://approov.io/knowledge/frida-detection-prevention)
- [Root Detection Bypass (8kSec)](https://8ksec.io/advanced-root-detection-bypass-techniques/)
- [muellerberndt/frida-detection (GitHub)](https://github.com/muellerberndt/frida-detection) — reference detection methods
- [Defending Apps Against Frida (Stackademic)](https://blog.stackademic.com/defending-mobile-apps-against-frida-even-with-root-bypass-android-f26ae7df4e89)

### Claude Code + RE
- [Reverse engineering Android malware with Claude Code (Zane St. John, Feb 2026)](https://zanestjohn.com/blog/reing-with-claude-code) — workflow: jadx decompile → Claude Code autonomously analyzes, writes decryptors, builds C2 client

## Ключевые выводы

### Антидетект — стратегия по уровням надёжности

| Подход | vs SafetyNet | vs RootBeer | vs Anti-Frida | Комментарий |
|--------|-------------|-------------|---------------|-------------|
| frida-server (stock) | Low | Low | Very Low | Очевидные артефакты |
| renamed + MagiskHide | Medium | Medium | Low | MagiskHide deprecated |
| hluda + Shamiko | High | High | Medium | Строки/порты убраны |
| **frida-gadget + Zygisk** | **Very High** | **Very High** | **High** | Нет внешнего процесса |
| + Stalker hooks | Highest | Highest | Highest | Inline rewrite detection |

### Детекция Frida — что ищут приложения

1. **Файлы**: `/data/local/tmp/frida-server`, `/proc/self/maps` (frida-agent.so)
2. **Сеть**: порт 27042, D-Bus protocol на открытых TCP портах
3. **Память**: строки "frida", "gum", "frida-agent" в .text/.data
4. **Процесс**: ptrace (TracerPid != 0), /proc/self/fd (pipe к frida)
5. **Целостность**: CRC native-библиотек (Interceptor inline hooks)

### API Recreation — паттерн

1. Перехват OkHttp interceptor chain → полный request/response
2. Выявление signing: HMAC/nonce/timestamp в заголовках
3. Извлечение ключей из KeyStore/SharedPreferences/hardcoded
4. Реализация auth flow: login → token → refresh → retry
5. Формирование device fingerprint: User-Agent, X-Device-Id, ANDROID_ID
6. Thin client = requests.Session + signing + token refresh + fingerprint

### Предыдущий опыт (Lab/android)

15 Frida-скриптов с прогрессией от базовых URL-хуков до бинарного протокола.
Результат: Echo SDK — полный альтернативный клиент MAX/OneMe:
- Dual transport: TCP (msgpack + LZ4) и WebSocket (JSON)
- 150+ opcodes документировано
- Auth, messaging, media, contacts, reactions, stickers
- Zero telemetry
- Это proof-of-concept для одного приложения; Frida-Kahlo обобщает подход.
