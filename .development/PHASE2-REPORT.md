# Фаза 2: Stealth + Instrument — Отчёт о выполнении

Дата: 2026-03-26

## Результат

**47/47 тестов пройдено за 63 секунды** (включая 20 из Фазы 1).

Новых тестов: 27 (stealth: 9, instrument: 17, discovery: 1)

## Что реализовано

### 1. JavaScript-скрипты

#### `scripts/common.js` — общие утилиты
- `sendEvent(module, type, data)` — единый формат событий
- `safeHook(className, callback)` — try/catch обёртка
- `stackTrace()` — Java stack trace
- `readableBytes(buf, off, len)` — buffer → string
- `detectFormat(bytes, len)` — определение JSON/protobuf/msgpack/gzip/binary

#### `scripts/bypass/stealth.js` — антидетект
- `/proc/self/maps` фильтрация (скрытие frida-agent строк)
- `libc.so: open/read` — перехват чтения maps
- `libc.so: access` — скрытие файлов (frida, magisk, su, busybox, supersu)
- `libc.so: connect` — блокировка port scan 27042/27043
- `libc.so: ptrace` → return 0 (PTRACE_TRACEME bypass)
- `/proc/self/status: TracerPid` — фильтрация
- Java: RootBeer bypass (все 12 методов)
- Java: `File.exists()` — скрытие root-путей
- Java: `PackageManager.getPackageInfo` — скрытие Magisk/SuperSU/KernelSU

#### `scripts/bypass/ssl_unpin.js` — SSL unpinning
- OkHttp3 CertificatePinner (2 overload)
- TrustManagerImpl.verifyChain
- Custom X509TrustManager через SSLContext.init override
- OkHostnameVerifier
- WebViewClient.onReceivedSslError
- HttpsURLConnection default verifier
- Conscrypt TrustManagerImpl
- NetworkSecurityConfig (Android 7+)
- Apache HTTP legacy

#### `scripts/discovery.js` — обнаружение классов
- Перечисление всех загруженных классов (фильтр system)
- Классификация: http, websocket, grpc, crypto, analytics, retrofit
- Поиск по методам: addNetworkInterceptor, newWebSocket, newCall
- Результат: JSON class_map через send()

### 2. Python Stealth Layer (`kahlo/stealth/`)

#### `port.py`
- `random_port(low, high, exclude)` — случайный порт (10000-60000), исключая 27042/27043

#### `manager.py` — StealthManager
- 4 уровня эскалации: BASIC → BYPASS → HLUDA → GADGET
- `start()` — запуск frida-server на random порту + ADB port forwarding
- `stop()` — остановка + cleanup forwarding
- `escalate()` — переход на следующий уровень
- `get_bypass_scripts()` — список JS bypass-скриптов для текущего уровня

#### `checker.py`
- `check_detection(package)` — spawn приложения, проверка crash за 3 секунды
- Поддержка stealth mode (remote device через port forward)

### 3. Python Instrument Engine (`kahlo/instrument/`)

#### `engine.py` — FridaEngine
- `spawn(package, script_source, on_message)` — запуск приложения с инъекцией
- `attach(package, script_source, on_message)` — подключение к запущенному
- `is_attached` — проверка состояния
- `cleanup()` — detach + kill
- Java bridge preamble (для совместимости с frida 17.x)

#### `loader.py` — ScriptLoader
- `load(modules)` — загрузка JS-файлов из scripts/
- `compose(bypass, hooks, extra)` — сборка: common + bypass + hooks + extra
- `list_scripts()` — доступные модули
- Java bridge inline из frida_tools

#### `session.py` — Session
- `add_event(event)` — добавление события с auto-timestamp
- `on_message(message, data)` — callback для frida send()
- `save()` → JSON с метаданными + events
- Session ID: `YYYYMMDD-HHMMSS-package`

### 4. CLI команды (добавлены в `kahlo/cli.py`)
- `kahlo frida-start` — запуск frida-server со stealth
- `kahlo frida-stop` — остановка
- `kahlo stealth-check <package>` — проверка детекта

## Интеграционное тестирование на устройстве

| Шаг | Команда | Результат |
|-----|---------|-----------|
| 1 | `kahlo device` | Устройство найдено, root ✓ |
| 2 | `kahlo frida-start` | frida-server на random порту + port forward |
| 3 | `kahlo stealth-check com.voltmobi.yakitoriya` | Детект не обнаружен ✓ |
| 4 | Discovery на yakitoriya | 38,185 классов, 2,779 классифицировано |
| 5 | `kahlo frida-stop` | Cleanup ✓ |

### Discovery результаты (yakitoriya)
- HTTP-классы: 187 (включая OkHttp, Retrofit)
- gRPC: 173
- Crypto: 21
- Analytics: 2,398 (Firebase, Google Analytics)
- WebSocket: найден

## Корректировки по ходу реализации

| # | Проблема | Решение |
|---|---------|---------|
| 1 | Java bridge недоступен в frida 17.x через create_script() | ScriptLoader инлайнит Java bridge из frida_tools/bridges/java.js |
| 2 | frida.get_usb_device() не работает со stealth-портом | ADB port forwarding: random → 27042 + remote device |
| 3 | Discovery занимает ~12 сек на 38K классов | Polling с таймаутом 30 сек вместо фиксированного sleep |
| 4 | Каскадные сбои тестов при остановленном frida-server | Fixtures проверяют is_running() и перезапускают |

## Файлы (новые)

```
scripts/common.js                    — 1.6K
scripts/bypass/stealth.js            — 6.1K
scripts/bypass/ssl_unpin.js          — 4.2K
scripts/discovery.js                 — 3.8K
kahlo/stealth/__init__.py            — 45B
kahlo/stealth/port.py                — 350B
kahlo/stealth/manager.py             — 2.8K
kahlo/stealth/checker.py             — 1.5K
kahlo/instrument/__init__.py         — 45B
kahlo/instrument/engine.py           — 3.9K
kahlo/instrument/loader.py           — 3.2K
kahlo/instrument/session.py          — 2.4K
tests/test_stealth.py                — 2.1K
tests/test_instrument.py             — 4.5K
tests/test_discovery.py              — 1.2K
```

## Следующий шаг

Фаза 3: Четыре столпа (хуки) — scripts/hooks/traffic.js, vault.js, recon.js, netmodel.js
Тестирование на yakitoriya с реальным перехватом трафика.
