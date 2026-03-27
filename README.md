# Frida-Kahlo

CLI-фреймворк для автоматизированного анализа Android-приложений через Frida.

Даёшь имя приложения — получаешь полный отчёт: сетевой трафик, хранилище, секреты, телеметрия, криптография, SDK-трекеры, и готовый thin-client для воспроизведения API.

## Возможности

- **Полный пайплайн**: скачивание APK → установка → Frida-инструментация → анализ → отчёт
- **4 столпа анализа**: трафик (5 уровней перехвата), хранилище/секреты, разведка окружения, сетевая модель
- **Stealth**: антидетект Frida (рандомизация порта, bypass /proc/maps, ptrace, root detection)
- **SSL Unpinning**: универсальный обход cert pinning (OkHttp, TrustManager, Conscrypt, WebView)
- **Автоотчёт**: Markdown-отчёт + JSON API-спецификация + curl/Python replay-скрипты + thin client
- **Live monitor**: интерактивный мониторинг с Rich-интерфейсом в терминале
- **Auth capture**: перехват login-flow, расшифровка EncryptedSharedPreferences (Tink), JWT-декодинг
- **Статический анализ**: сканирование jadx-декомпиляции на URL, секреты, крипто-паттерны
- **Агрегация и diff**: объединение нескольких сканов, сравнение сессий
- **Postman/Insomnia экспорт**: готовая коллекция запросов

## Установка

```bash
git clone https://github.com/yourname/frida-kahlo.git
cd frida-kahlo
pip install -e ".[dev]"
```

### Требования

- Python 3.11+
- Frida 17.x (`pip install frida frida-tools`)
- Android-устройство с root (Magisk) и USB-отладкой
- frida-server на устройстве (`/data/local/tmp/frida-server`)

### Опциональные зависимости

```bash
pip install -e ".[acquire]"   # Playwright для скачивания APK
pip install -e ".[static]"    # Androguard для расширенного анализа
```

## Быстрый старт

```bash
# Проверить устройство
kahlo device

# Запустить stealth frida-server
kahlo frida-start

# Полный анализ установленного приложения (30 сек)
kahlo scan com.example.app --duration 30

# Сгенерировать отчёт
kahlo report sessions/session.json

# Или всё сразу — от имени до отчёта
kahlo analyze com.example.app --skip-fetch --duration 60
```

## Команды

| Команда | Описание |
|---------|----------|
| `kahlo analyze <app>` | Полный пайплайн: fetch → install → scan → analyze → report |
| `kahlo scan <package>` | Инструментация + сбор событий (4 столпа) |
| `kahlo monitor <package>` | Live-мониторинг с Rich-интерфейсом |
| `kahlo report <session>` | Генерация отчётов из сессии |
| `kahlo fetch <name>` | Скачать APK с зеркал (APKPure, APKCombo) |
| `kahlo install <apk>` | Установить APK на устройство |
| `kahlo device` | Статус устройства и frida-server |
| `kahlo frida-start` | Запуск frida-server (stealth) |
| `kahlo frida-stop` | Остановка frida-server |
| `kahlo stealth-check <pkg>` | Проверка детекта Frida |
| `kahlo manifest <apk>` | Парсинг AndroidManifest.xml |
| `kahlo static <jadx_dir>` | Статический анализ jadx-выхода |
| `kahlo aggregate <s1> <s2>` | Объединение нескольких сессий |
| `kahlo diff <old> <new>` | Сравнение двух сессий |
| `kahlo export-postman <s>` | Экспорт в Postman Collection |

## Архитектура

```
kahlo/
  cli.py                 15 CLI-команд (typer + rich)
  pipeline.py            Оркестрация полного пайплайна
  acquire/               Скачивание APK (Playwright), распаковка, установка
  prepare/               Парсинг манифеста, jadx-декомпиляция
  device/                ADB-обёртка, lifecycle frida-server
  stealth/               Антидетект (4 уровня эскалации)
  instrument/            FridaEngine, ScriptLoader, Session
  analyze/               12 анализаторов (traffic, vault, recon, netmodel,
                         patterns, auth, jwt, static, decoder, aggregate,
                         diff, flows)
  report/                Markdown, API spec, replay, Postman
  monitor.py             Live-мониторинг

scripts/
  common.js              Общие утилиты
  discovery.js           Обнаружение классов (OkHttp, Retrofit, WS, crypto)
  bypass/stealth.js      Антидетект (/proc/maps, ptrace, root, файлы)
  bypass/ssl_unpin.js    Универсальный SSL unpinning
  hooks/traffic.js       Перехват трафика (5 уровней: OkHttp3, system OkHttp,
                         HttpURLConnection, Conscrypt SSL, native SSL)
  hooks/vault.js         Хранилище (SharedPreferences, SQLite, KeyStore, Tink)
  hooks/recon.js         Разведка (device info, VPN, carrier, IP, apps)
  hooks/netmodel.js      Криптография (Cipher, HMAC, Signature, TLS, UUID)
```

## Четыре столпа анализа

### Traffic — Сетевой трафик
5 каскадных уровней перехвата: OkHttp3 Interceptor → system OkHttp v2 (HttpEngine) → HttpURLConnection → Conscrypt SSL stream → native SSL_write/SSL_read. Полные request/response с заголовками, телами, таймингами.

### Vault — Хранилище и секреты
SharedPreferences (включая EncryptedSharedPreferences с расшифровкой через Tink), SQLite, файловая система, KeyStore, AccountManager. Автоматическое извлечение токенов, API-ключей, device ID.

### Recon — Разведка окружения
Что приложение узнаёт о телефоне: Build.*, ANDROID_ID, оператор/PLMN, VPN-детекция, IP-сервисы, проверка установленных приложений, геолокация, сенсоры. Fingerprint appetite score (0-100).

### Netmodel — Сетевая модель
Криптографические операции: AES/RSA шифрование, HMAC-подписи, хеши, TLS-параметры, генерация nonce. Извлечение signing recipe для воспроизведения API.

## Результат анализа

После `kahlo scan` + `kahlo report` в папке сессии:

```
sessions/<session_id>_report/
  report.md                Markdown-отчёт (Infrastructure, API, Secrets,
                           Privacy, Crypto, SDKs, Auth Flow, Recreation)
  api-spec.json            JSON-спецификация API
  postman_collection.json  Postman Collection v2.1
  replay/
    client.py              Thin-client с per-host routing и signing
    curl/                  curl-команды для каждого эндпоинта
    python/                Python requests для каждого эндпоинта
```

## Stealth — Антидетект

4 уровня эскалации:

| Уровень | Техника | Покрытие |
|---------|---------|----------|
| 1. Basic | Random port + bypass.js | ~70% приложений |
| 2. Bypass | + /proc/maps фильтрация, ptrace, root-hide | ~85% |
| 3. hluda | Кастомный билд Frida без артефактов | ~95% |
| 4. Gadget | frida-gadget (нет внешнего процесса) | ~99% |

## Пример: результаты анализа Yakitoriya

За 30 секунд сканирования приложения доставки еды:

- **1,348 событий** перехвачено
- **6 серверов**: beacon2.yakitoriya.ru, api.wavesend.ru, sentry.inno.co, Firebase, Branch.io, AppsFlyer
- **30 секретов**: API-ключи (Branch.io, AppsFlyer), HMAC signing key, AES encryption key/IV, Pushwoosh device ID
- **11 SDK**: Firebase Crashlytics, Sentry 8.28.0, Pushwoosh 6.7.48, AppsFlyer 6.17.5, Branch.io, Yandex Metrica, и др.
- **Fingerprint appetite**: 55/100 (читает SIM-оператора, SDK версию)
- **Автогенерированный thin client** с per-host routing и HMAC-подписью

## Тестирование

```bash
# Все тесты (требуется устройство с frida-server)
pytest tests/ -v --timeout=120

# Только тесты без устройства
pytest tests/ -v --timeout=60 -k "not (test_discovery or test_spawn or test_scan or test_system_okhttp)"
```

405 тестов покрывают: ADB, frida-server lifecycle, stealth, instrument engine, все 4 хука, все 12 анализаторов, все 4 генератора отчётов, monitor, decoder, aggregate, diff, flows, postman.

## Лицензия

MIT
