# Frida Automation — State of the Art (2025-2026)

Дата исследования: 2026-03-26
Источник: Perplexity sonar-pro

## Источники
- [Prism Infosec — Exploiting Mobile Apps Using Frida](https://prisminfosec.com/exploiting-mobile-apps-using-frida/)
- [Stackademic — Defending Mobile Apps Against Frida](https://blog.stackademic.com/defending-mobile-apps-against-frida-even-with-root-bypass-android-f26ae7df4e89)
- [Vaadata — Frida, the Tool Dedicated to Mobile Application Security](https://www.vaadata.com/blog/frida-the-tool-dedicated-to-mobile-application-security/)
- [PTKD — Android App Dynamic Analysis](https://www.ptkd.com/mobile-security/android-app-security/android-app-dynamic-analysis)
- [OWASP MASTG — Frida](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0001/)
- [HackTheDome — Advanced Dynamic Analysis with Objection](https://hackthedome.com/module-7-advanced-dynamic-analysis-with-objection/)
- [Dark Wolf — Dynamic Analysis Playbook](https://asrp.darkwolf.io/ASRP-Plays/dynamic)

## Автоматизация пайплайнов

Ключевые практики:
- **Script templating**: Jinja2/Mustache для генерации скриптов из APK-метаданных (package name, target classes из jadx)
- **Python-оркестрация**: `frida-tools` + `python-frida` для spawn, inject, capture. Пайплайн: `apktool d` → static → hook generation → frida spawn → JSON export → LLM
- **Non-interactive**: `frida -U -f com.app -l script.js --no-pause`
- **Error handling**: `Process.enumerateModules()` для runtime-валидации; structured logs

## TypeScript + frida-compile

- Frida экосистема 2025-2026 предпочитает **TypeScript** для типизации и IDE
- Компиляция: `frida-compile script.ts -o script.js` (npm `@frida/frida-compile`)
- ES modules: `import { hookClass } from './hooks.js'`
- Hot-reload: `Script.reload()`

## Модульная библиотека хуков

Структура:
```
frida-lib/
├── hooks/
│   ├── index.ts          # Exports: hookSsl(), hookRootCheck()
│   └── composable.ts     # Factory: composeHooks([hookA, hookB])
├── utils/
│   └── jsonLogger.ts     # Structured output
└── package.json
```

Паттерн:
```typescript
export function composeHooks(hooks: HookCallback[]): HookCallback {
    return function (args: any[]) {
        hooks.forEach(h => h(args));
    };
}
```

## Инструменты-компаньоны

| Инструмент | Роль | Команда |
|-----------|------|---------|
| objection | High-level Frida wrapper для runtime exploration | `objection -g com.app explore` |
| r2frida | Radare2 + Frida для binary analysis + live hooking | `r2 frida://usb//com.app` |
| apktool | APK decoding → smali для static analysis | `apktool d app.apk` |
| jadx | Decompiler → Java source → определение hook targets | `jadx app.apk` |
| medusa | Frida-based SSL pinning bypass + MITM | Модуль для Frida |
| house | Full Frida runtime explorer, heap scanning | `house explore com.app` |

## Автоматическое обнаружение классов

- `Java.enumerateLoadedClasses()` — все загруженные классы
- `Process.enumerateModules()` — native-модули
- `Java.use('ClassName').class.getDeclaredMethods()` — методы класса
- `Java.enumerateClassLoaders()` — множественные classloader-ы
- `frida-trace -j '*!*Security*'` — автотрассировка по паттерну
- `Java.choose('ClassInstance', {...})` — heap scanning

## Structured Output для LLM

```python
import frida

def on_message(message, data):
    if message['type'] == 'send':
        with open('output.jsonl', 'a') as f:
            f.write(message['payload'] + '\n')

session = frida.attach('com.app')
script = session.create_script(script_source)
script.on('message', on_message)
script.load()
```

RPC exports:
```javascript
rpc.exports = {
    dumpHeap: function() { return JSON.stringify(heapScan()); }
};
// Python: session.rpc.dumpHeap()
```
