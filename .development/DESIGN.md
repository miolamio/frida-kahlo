# Frida-Kahlo: Дизайн системы

## Концепция

Frida-Kahlo — Python CLI для автоматизированного анализа Android-приложений через Frida. Превращает ручной процесс реверс-инжиниринга в систему, которая автоматически перехватывает, анализирует и воспроизводит API любого приложения.

**Идеальный конечный результат (ТРИЗ):** пользователь говорит "проанализируй приложение X" → система скачивает APK, устанавливает, прогоняет через все анализаторы → выдаёт полный отчёт + готовый thin-client для воспроизведения API, неотличимый от оригинального приложения для сервера.

## Два режима работы

- **`kahlo analyze <app>`** — полный автоматический пайплайн: fetch → prepare → instrument → analyze → report
- **`kahlo monitor <package>`** — интерактивный live-мониторинг для углублённого исследования

## Стек

- **Python** — CLI, оркестрация, анализ, отчёты (frida-python, typer, rich, playwright)
- **JavaScript** — Frida-скрипты (хуки, bypass, discovery)
- **Устройство** — Android с root (Magisk), frida-server

## Архитектура

```
┌─────────────────────────────────────────┐
│  kahlo CLI  (Python, typer)             │
├─────────┬──────────┬────────────────────┤
│ Device  │ Script   │ Capture            │
│ Manager │ Engine   │ Engine             │
│ (ADB)   │ (frida-  │ (JSON collector,   │
│         │  python) │  session storage)  │
├─────────┴──────────┴────────────────────┤
│  Stealth Layer                          │
│  (anti-detect, port rando, proc filter, │
│   root-hide, hluda escalation)          │
├─────────────────────────────────────────┤
│  Frida Script Library  (JS modules)     │
│  hooks/ bypass/ discovery/              │
└─────────────────────────────────────────┘
        ↕ USB/ADB ↕
┌─────────────────────────────────────────┐
│  Android Device (rooted, frida-server)  │
└─────────────────────────────────────────┘
```

## Пайплайн

```
"Проанализируй Telegram"
         │
    ┌────▼────┐
    │ ACQUIRE │  APK Fetcher (Playwright) → APKMirror/APKPure
    └────┬────┘  Скачивание, распаковка split-APK
         │
    ┌────▼────┐
    │ PREPARE │  adb install + jadx декомпиляция (фон)
    └────┬────┘  Manifest: permissions, services, receivers
         │       Строки, URL, ключи из кода
         │
    ┌────▼──────┐
    │ INSTRUMENT│  Stealth Frida → spawn приложения
    └────┬──────┘  4 модуля хуков параллельно + discovery
         │         Сбор 60-120 сек + user interaction
         │
    ┌────▼────┐
    │ ANALYZE │  Структурирование: API map, auth flow,
    └────┬────┘  signing, protocol, telemetry, storage
         │
    ┌────▼────┐
    │ REPORT  │  report.md + session.json + api-spec.json
    └─────────┘  + vault.json + recon.json + replay/
```

## Четыре столпа анализа

### Столп 1: TRAFFIC — Весь трафик

Полный перехват всего, что уходит и приходит. Каскад уровней:

1. OkHttp Interceptor → чистый HTTP, headers, body, response
2. WebSocket send/receive → WS-фреймы
3. Conscrypt SSLOutputStream.write/read → сырой TLS-поток
4. Native ssl_write/ssl_read → libboringssl.so / libssl.so
5. Socket.connect + raw I/O → TCP без TLS

Что собираем по каждому запросу:
- URL, метод, заголовки, тело (полное), cookies
- Ответ: код, заголовки, тело, время
- Формат тела: JSON / protobuf / msgpack / form-data / binary
- TLS: SNI, версия, cipher suite
- Сервер: IP, порт, hostname, CDN-признаки
- Стектрейс: какой Java-класс инициировал запрос

Выход: полная карта API — все эндпоинты, частота, зависимости.

### Столп 2: VAULT — Хранилище и секреты

Всё, что приложение хранит на устройстве:

- SharedPreferences — read/write (файл, ключ, значение)
- SQLite — query/insert/update (БД, таблица, SQL, данные)
- File I/O — open/write/read (путь, содержимое)
- KeyStore — getKey/setEntry (алиас, тип, ключ)
- AccountManager — getAuthToken
- ContentProvider — query/insert

Дамп при подключении:
- Все SharedPreferences файлы целиком
- SQLite базы + схема + ключевые таблицы
- internal storage (`/data/data/<package>/`)
- KeyStore entries

Выход: JSON с полной картой хранилища + извлечённые токены/ключи.

### Столп 3: RECON — Разведка приложением окружения

Что приложение пытается узнать:

- Устройство: Build.*, ANDROID_ID, IMEI
- Сеть: оператор (PLMN), WiFi SSID/BSSID, тип соединения
- VPN-детекция: NetworkCapabilities.hasTransport(TRANSPORT_VPN)
- IP-разведка: ipify, ifconfig.me, ip.mail.ru
- Геолокация: GPS, Cell ID, WiFi-based
- Root-детекция: su, Magisk paths
- Frida-детекция: /proc/maps, port scan, ptrace
- Конкуренты: пробы к telegram.org, whatsapp.net
- Батарея/сенсоры: уровень заряда, акселерометр
- Установленные приложения: PackageManager.getInstalledPackages()

Каждое обращение: что запросило, какой метод, что получило, стектрейс.

Выход: fingerprint appetite — полный профиль приватности.

### Столп 4: NETMODEL — Механика сетевой модели

Как устроена сетевая архитектура приложения:

- Протокол: REST JSON / GraphQL / gRPC / WebSocket / бинарный
- Auth-модель: Bearer / cookie / API key / cert pinning / кастомная подпись
- Сессия: создание, обновление, TTL токенов
- Signing: какие поля подписываются, алгоритм, ключ, nonce/timestamp
- Device ID: формирование, состав, возможность генерации
- Серверы: основной API, CDN, аналитика, push, ads (IP/домен/гео)
- Cert pinning: какие сертификаты, как пинятся
- Anti-replay: timestamp validation, nonce uniqueness
- Fingerprint: User-Agent, X-App-Version, X-Device-* — что ожидает сервер

Выход: спецификация протокола для создания клона.

## Stealth Layer

Три уровня защиты:

### Уровень 1: Серверный
- Переименованный бинарник в tmpfs (`/dev/.fs`)
- Случайный порт (10000-60000) каждый раз
- Кастомный билд hluda (без строк frida/gum) — при эскалации

### Уровень 2: Инъекционный (bypass JS)
- Перехват libc: open/openat/access/stat — скрытие файлов с "frida"/"magisk"/"su"
- Перехват libc: connect — блокировка сканирования порта frida-server
- Перехват libc: ptrace — имитация "не трассируется"
- Java-хуки: RootBeer, SafetyNet, PlayIntegrity
- Фильтрация /proc/self/maps — удаление строк с frida-agent

### Уровень 3: Системный (Magisk)
- Zygisk — процесс-скрытие
- Shamiko — advanced hide

Стратегия эскалации: random port + bypass → hluda → frida-gadget (патч APK).

## Единый формат события

```json
{
  "ts": "2026-03-26T14:30:15.123Z",
  "module": "traffic",
  "type": "http_request",
  "data": { ... }
}
```

## CLI-интерфейс

```
kahlo analyze <name_or_package>       полный пайплайн
kahlo fetch <app_name>                скачать APK с зеркал
kahlo install <apk_path>              установить на устройство
kahlo scan <package> [--duration 120] автоматический сбор (4 столпа)
kahlo monitor <package>               live-мониторинг
kahlo report <session_id>             сгенерировать отчёт
kahlo replay <session_id> [endpoint]  воспроизвести запросы
kahlo device                          статус устройства
kahlo stealth check <package>         проверка детекта
kahlo stealth escalate                поднять уровень скрытности
```
