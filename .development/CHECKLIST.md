# Чек-лист реализации Frida-Kahlo

## Фаза 1: Фундамент

- [ ] Инициализация проекта
  - [ ] `pyproject.toml` — зависимости (frida, typer, rich, pydantic)
  - [ ] Структура пакета `kahlo/` с `__init__.py`
  - [ ] `CLAUDE.md` — инструкции для Claude Code
  - [ ] `.gitignore` (sessions/, *.apk, __pycache__)
  - [ ] `git init` + первый коммит

- [ ] Device Manager (`kahlo/device/`)
  - [ ] `adb.py` — обёртка ADB
    - [ ] `devices()` — список подключённых устройств
    - [ ] `shell(cmd, su=False)` — выполнение команд
    - [ ] `push(local, remote)` / `pull(remote, local)`
    - [ ] `install(apk_paths: list)` — install-multiple для split APK
    - [ ] `uninstall(package)`
    - [ ] `list_packages()` — установленные приложения
    - [ ] `get_device_info()` — модель, Android version, root status
  - [ ] `frida_server.py` — lifecycle frida-server
    - [ ] `is_running()` — проверка через `frida-ps -U`
    - [ ] `start(port=None)` — запуск (push если нет, chmod, start)
    - [ ] `stop()` — kill
    - [ ] `ensure()` — start если не запущен

- [ ] CLI базовый (`kahlo/cli.py`)
  - [ ] `kahlo device` — статус: устройство, root, frida-server, apps
  - [ ] `kahlo install <path>` — установка APK/XAPK
  - [ ] Entry point в pyproject.toml: `[project.scripts] kahlo = "kahlo.cli:app"`

- [ ] Тесты фазы 1
  - [ ] `kahlo device` показывает 28e37107, root, frida-server status
  - [ ] `kahlo install` работает с обычным APK и split APK

## Фаза 2: Stealth + Instrument

- [ ] Stealth Layer (`kahlo/stealth/`)
  - [ ] `port.py` — рандомизация порта (10000-60000)
  - [ ] `manager.py` — StealthManager
    - [ ] Уровень 1: random port + renamed binary
    - [ ] Уровень 2: + bypass scripts
    - [ ] Уровень 3: hluda build (документация)
    - [ ] Уровень 4: frida-gadget (документация)
    - [ ] `escalate()` — переход на следующий уровень
  - [ ] `checker.py` — проверка детекта
    - [ ] Запуск приложения → проверка crash/exit в первые 5 сек
    - [ ] Проверка логов на "frida", "root", "tamper"

- [ ] Bypass Scripts (`scripts/bypass/`)
  - [ ] `stealth.js` — unified anti-detection
    - [ ] libc open/openat → фильтрация "frida"/"magisk" из /proc/self/maps
    - [ ] libc access/stat → скрытие /data/local/tmp/frida-server
    - [ ] libc connect → блокировка port scan 27042
    - [ ] libc ptrace → return -1
    - [ ] Java RootBeer bypass (все методы)
    - [ ] Java SafetyNet/PlayIntegrity bypass
  - [ ] `ssl_unpin.js` — universal SSL unpinning
    - [ ] OkHttp CertificatePinner
    - [ ] TrustManagerImpl
    - [ ] Conscrypt cert verification
    - [ ] Custom X509TrustManager
    - [ ] NetworkSecurityConfig

- [ ] Instrument Engine (`kahlo/instrument/`)
  - [ ] `engine.py` — FridaEngine
    - [ ] `spawn(package, scripts)` — запуск с инъекцией
    - [ ] `attach(package, scripts)` — подключение к запущенному
    - [ ] `on_message(callback)` — обработка send() из JS
    - [ ] `detach()` / `kill()`
  - [ ] `loader.py` — ScriptLoader
    - [ ] `load(module_names)` — загрузка и конкатенация JS-модулей
    - [ ] `compose(bypass + hooks)` — stealth первым, потом хуки
    - [ ] Подстановка переменных (package name, class map из discovery)
  - [ ] `session.py` — Session
    - [ ] `start(package)` — создание директории, метаданные
    - [ ] `add_event(event)` — append в JSONL
    - [ ] `save()` — финализация session.json
    - [ ] Session ID: timestamp-package (20260326-143015-com.app)

- [ ] Discovery (`scripts/discovery.js`)
  - [ ] Enumeration loaded classes с фильтрацией system
  - [ ] Поиск: OkHttp, Retrofit, WebSocket, gRPC, crypto, analytics
  - [ ] Поиск по методам: addNetworkInterceptor, newWebSocket, newCall
  - [ ] Результат: class_map JSON для настройки остальных хуков

- [ ] CLI команды
  - [ ] `kahlo stealth check <package>` — запуск + проверка
  - [ ] `kahlo stealth escalate` — повышение уровня

- [ ] Тесты фазы 2
  - [ ] Stealth bypass: приложение не крашится при spawn
  - [ ] SSL unpin: перехват HTTPS трафика
  - [ ] Discovery: находит классы на тестовом приложении (yakitoriya)

## Фаза 3: Четыре столпа (хуки)

- [ ] Traffic (`scripts/hooks/traffic.js`)
  - [ ] Уровень 1: OkHttp Interceptor (registerClass)
    - [ ] Полный request: method, url, headers, body
    - [ ] Полный response: status, headers, body, elapsed
    - [ ] Определение формата body (JSON/protobuf/msgpack/binary)
  - [ ] Уровень 2: WebSocket (OkHttp RealWebSocket)
    - [ ] send (text + binary)
    - [ ] onMessage (text + binary)
  - [ ] Уровень 3: Conscrypt SSLOutputStream.write / SSLInputStream.read
    - [ ] HTTP-парсинг из сырого потока
  - [ ] Уровень 4: Native ssl_write/ssl_read
    - [ ] libboringssl.so, libssl.so, libconscrypt_jni.so
  - [ ] Уровень 5: Socket.connect + raw I/O
  - [ ] Адаптация к class_map из discovery

- [ ] Vault (`scripts/hooks/vault.js`)
  - [ ] SharedPreferences.getString/putString (и другие типы)
  - [ ] SharedPreferences.Editor.apply/commit
  - [ ] SQLiteDatabase.query/insert/update/rawQuery
  - [ ] FileOutputStream.write / FileInputStream.read (internal storage)
  - [ ] KeyStore.getKey / KeyStore.setEntry
  - [ ] AccountManager.getAuthToken
  - [ ] Начальный дамп при подключении:
    - [ ] Все файлы SharedPreferences
    - [ ] Список SQLite + схема
    - [ ] ls internal storage

- [ ] Recon (`scripts/hooks/recon.js`)
  - [ ] Build.* (MODEL, MANUFACTURER, FINGERPRINT, VERSION)
  - [ ] Settings.Secure.getString (ANDROID_ID)
  - [ ] TelephonyManager (getDeviceId, getNetworkOperator, getSimOperator)
  - [ ] NetworkCapabilities.hasTransport (VPN detection)
  - [ ] ConnectivityManager.getActiveNetwork
  - [ ] LocationManager.getLastKnownLocation
  - [ ] WifiManager.getConnectionInfo
  - [ ] PackageManager.getInstalledPackages
  - [ ] URL.openConnection (фильтр IP-сервисов, конкурентов)
  - [ ] Socket.connect (подозрительные хосты)
  - [ ] InetAddress.isReachable (ping-пробы)

- [ ] Netmodel (`scripts/hooks/netmodel.js`)
  - [ ] Надстройка над traffic — анализ паттернов
  - [ ] Детекция формата: JSON vs protobuf vs msgpack
  - [ ] Извлечение auth headers (Authorization, X-Token, Cookie)
  - [ ] Детекция signing (X-Signature, X-Nonce, X-Timestamp)
  - [ ] javax.crypto.Mac.doFinal (HMAC extraction)
  - [ ] java.security.Signature.sign
  - [ ] MessageDigest.digest
  - [ ] TLS info: SSLSession.getCipherSuite, getPeerCertificates

- [ ] Common (`scripts/common.js`)
  - [ ] `sendEvent(module, type, data)` — unified format
  - [ ] `safeHook(className, callback)` — try/catch обёртка
  - [ ] `readableBytes(buf, off, len)` — buffer to string
  - [ ] `stackTrace()` — Java stack trace string
  - [ ] `detectFormat(bytes)` — JSON/protobuf/msgpack/binary

- [ ] Python Capture Engine обновление
  - [ ] `session.py` — фильтрация по модулю/типу
  - [ ] Дедупликация одинаковых событий
  - [ ] Лимит размера body (4KB preview + полный в отдельном файле)

- [ ] Тесты фазы 3
  - [ ] `kahlo scan com.voltmobi.yakitoriya --duration 60` → session.json
  - [ ] Traffic: перехвачены HTTP-запросы с полными body
  - [ ] Vault: извлечены SharedPreferences
  - [ ] Recon: пойманы device info запросы
  - [ ] Все события в едином JSON формате

## Фаза 4: Анализ + Отчёт

- [ ] Traffic Analyzer (`kahlo/analyze/traffic.py`)
  - [ ] Группировка по эндпоинтам (URL → method → count)
  - [ ] Выявление auth flow (login → token → refresh)
  - [ ] Цепочки зависимостей (запрос A даёт токен для запроса B)
  - [ ] Таймлайн запросов (waterfall)
  - [ ] Уникальные серверы/домены

- [ ] Vault Analyzer (`kahlo/analyze/vault.py`)
  - [ ] Классификация: tokens, keys, user_data, settings, cache
  - [ ] Связь с traffic: этот токен используется в этом header
  - [ ] Чувствительность: пароли, ключи, PII

- [ ] Recon Analyzer (`kahlo/analyze/recon.py`)
  - [ ] Fingerprint appetite score (0-100)
  - [ ] Категоризация по GDPR/privacy severity
  - [ ] Сравнение с declared permissions в manifest

- [ ] Netmodel Analyzer (`kahlo/analyze/netmodel.py`)
  - [ ] Protocol detection report
  - [ ] Auth model description
  - [ ] Signing algorithm extraction
  - [ ] Device fingerprint recipe
  - [ ] Server infrastructure map

- [ ] Pattern Detector (`kahlo/analyze/patterns.py`)
  - [ ] Known SDKs: Firebase, Google Analytics, Adjust, AppsFlyer, Sentry
  - [ ] Known trackers: Facebook SDK, VK Analytics, MyTracker
  - [ ] CDN detection: Cloudflare, Akamai, AWS CloudFront

- [ ] Report Generator (`kahlo/report/`)
  - [ ] `markdown.py` — структурированный отчёт
    - [ ] Executive summary
    - [ ] Traffic map (таблица эндпоинтов)
    - [ ] Auth flow diagram (текстовый)
    - [ ] Privacy report (fingerprint appetite)
    - [ ] Storage inventory
    - [ ] Network architecture
    - [ ] Recommendations / findings
  - [ ] `api_spec.py` — JSON спецификация API
    - [ ] Эндпоинты с параметрами
    - [ ] Auth requirements
    - [ ] Signing requirements
    - [ ] Example requests/responses
  - [ ] `replay.py` — генерация replay-скриптов
    - [ ] curl команды для каждого эндпоинта
    - [ ] Python requests для каждого эндпоинта
    - [ ] Thin client skeleton с auth + signing

- [ ] CLI команды
  - [ ] `kahlo report <session_id>` — генерация из существующей сессии
  - [ ] `kahlo replay <session_id> [endpoint]` — replay для конкретного URL

- [ ] Тесты фазы 4
  - [ ] Генерация отчёта из сессии yakitoriya
  - [ ] API spec содержит все найденные эндпоинты
  - [ ] Replay curl команды работают

## Фаза 5: Acquire (APK fetch)

- [ ] APK Fetcher (`kahlo/acquire/fetcher.py`)
  - [ ] Playwright setup (headless Chromium)
  - [ ] APKMirror search + download
  - [ ] APKPure search + download
  - [ ] APKCombo search + download
  - [ ] Fallback chain: APKMirror → APKPure → APKCombo
  - [ ] Выбор правильной архитектуры (arm64-v8a)
  - [ ] Верификация скачанного файла

- [ ] Extractor (`kahlo/acquire/extractor.py`)
  - [ ] XAPK → split APK (JSON manifest + zip)
  - [ ] APKM → split APK (JSON manifest + zip)
  - [ ] APK → as is

- [ ] Installer (`kahlo/acquire/installer.py`)
  - [ ] `install(apk_dir)` → adb install-multiple
  - [ ] Обработка ошибок (already installed, incompatible)

- [ ] CLI команды
  - [ ] `kahlo fetch <app_name>` — поиск + скачивание
  - [ ] `kahlo fetch --list <app_name>` — показать доступные версии

- [ ] Тесты фазы 5
  - [ ] `kahlo fetch "yakitoriya"` → скачивает APK
  - [ ] Установка скачанного на устройство

## Фаза 6: Полный пайплайн + Skills

- [ ] Pipeline (`kahlo/pipeline.py`)
  - [ ] `full_analyze(app_name_or_package, duration=120)`
  - [ ] Оркестрация: fetch → install → stealth → scan → analyze → report
  - [ ] Прогресс-бар (rich)
  - [ ] Параллельно: jadx декомпиляция в фоне
  - [ ] Graceful shutdown (Ctrl+C)

- [ ] CLI
  - [ ] `kahlo analyze <name>` — полный пайплайн
  - [ ] `kahlo analyze <name> --skip-fetch` — если APK уже есть
  - [ ] `kahlo analyze <name> --skip-static` — без jadx
  - [ ] `kahlo monitor <package>` — интерактивный режим (rich live)

- [ ] Claude Code Skills (`skills/`)
  - [ ] `android-analysis/SKILL.md`
    - [ ] Когда триггерить: "проанализируй", "что делает", "как работает API"
    - [ ] Workflow: kahlo analyze → прочитать report → интерпретировать
    - [ ] Предложить углубление: monitor для интересных находок
  - [ ] `android-replay/SKILL.md`
    - [ ] Когда триггерить: "создай клиент", "повтори API", "клон"
    - [ ] Workflow: загрузить api-spec.json + vault.json → сгенерировать код
    - [ ] Реализовать auth + signing + fingerprint

- [ ] CLAUDE.md — обновление
  - [ ] Описание проекта
  - [ ] Доступные команды kahlo
  - [ ] Как читать отчёты
  - [ ] Как запускать анализ

- [ ] Prepare / Static Analysis (`kahlo/prepare/`)
  - [ ] `manifest.py` — парсинг AndroidManifest.xml
    - [ ] Permissions (запрашиваемые)
    - [ ] Activities, Services, Receivers, Providers
    - [ ] Intent filters
    - [ ] минимальный/целевой SDK
  - [ ] `decompiler.py` — jadx wrapper
    - [ ] Запуск в фоне (subprocess)
    - [ ] Статус прогресса
    - [ ] Путь к результату
  - [ ] `strings.py` — извлечение из декомпилированного кода
    - [ ] URL / endpoints
    - [ ] API keys / tokens (regex patterns)
    - [ ] Подозрительные строки

- [ ] Тесты фазы 6
  - [ ] `kahlo analyze "yakitoriya"` — полный цикл от имени до отчёта
  - [ ] `kahlo analyze "MAX messenger"` — полный цикл (тяжёлое приложение)
  - [ ] Claude Code skill: "проанализируй якиторию" → автоматический запуск
