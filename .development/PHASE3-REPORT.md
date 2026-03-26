# Фаза 3: Четыре столпа (хуки) — Отчёт о выполнении

Дата: 2026-03-26

## Результат

**57/57 тестов пройдено** (47 из Фаз 1-2 + 10 новых).

**Первый реальный скан: 626 событий за 30 секунд** с yakitoriya.

## Что реализовано

### 1. Traffic Hook (`scripts/hooks/traffic.js`)

5 каскадных уровней перехвата:

| Уровень | Техника | Результат на yakitoriya |
|---------|---------|------------------------|
| 1 | OkHttp Interceptor (Java.registerClass) | Полные HTTP req/res |
| 2 | WebSocket (RealWebSocket) | WS фреймы |
| 3 | Conscrypt SSL streams | Сырой TLS → HTTP parse |
| 4 | Native SSL_write/SSL_read | Fallback для обфускации |
| 5 | Socket.connect | TCP соединения (IP, порт) |

Результат: 43 события — 9 TCP connections, 31 SSL raw, 3 hook status.

### 2. Vault Hook (`scripts/hooks/vault.js`)

| Метод | Что ловим |
|-------|-----------|
| SharedPreferences | getString/putString/getInt/putInt/getBoolean/putBoolean + apply/commit |
| SQLiteDatabase | query/rawQuery/insert/update/delete/execSQL |
| FileOutputStream | write (internal storage) |
| KeyStore | getKey/getEntry |
| Initial dump | Все prefs файлы + список БД при загрузке |

Результат: 395 событий — **самый активный модуль!**
- 299 pref reads, 41 pref writes
- 18 sqlite writes, 34 file writes
- 1 initial dump: 16 файлов prefs, 16 баз данных
- Найдено: Branch.io API key (`key_live_lb1cVtiq4sOUdOI3WMgyqfhoEEedz7Nc`), Pushwoosh device_id, Firebase/Crashlytics IDs, AppsFlyer tracking

### 3. Recon Hook (`scripts/hooks/recon.js`)

| Категория | Что перехватываем |
|-----------|-------------------|
| Устройство | Build.* reflection, Settings.Secure (ANDROID_ID) |
| Сеть | TelephonyManager (оператор, IMEI), NetworkCapabilities (VPN) |
| WiFi | WifiManager.getConnectionInfo |
| Геолокация | LocationManager |
| Приложения | PackageManager.getInstalledPackages |
| IP-разведка | URL.openConnection (ipify, ifconfig, checkip) |
| Конкуренты | Socket.connect (telegram, whatsapp, gosuslugi) |
| Сенсоры | SensorManager.registerListener |

Результат: 16 событий — SDK_INT=36, SIM оператор "MTS RUS" (25001), network queries.

### 4. Netmodel Hook (`scripts/hooks/netmodel.js`)

| Метод | Что ловим |
|-------|-----------|
| Cipher | init/doFinal — алгоритм, ключ, IV, input/output |
| Mac | init/doFinal — HMAC |
| Signature | sign/verify |
| MessageDigest | digest — хеши |
| SSLSocket | startHandshake — TLS info |
| UUID | randomUUID — nonce generation |

Результат: 171 событие — 154 SHA-1 хеша, 12 UUID nonces, 2 HmacSHA256 (ключ извлечён!), 1 AES/CBC/PKCS5Padding.

### 5. CLI `kahlo scan`

```bash
$ kahlo scan com.voltmobi.yakitoriya --duration 30

[*] Запуск анализа com.voltmobi.yakitoriya (30 сек)
[+] frida-server на порту 47293
[+] Загружены модули: stealth, ssl_unpin, discovery, traffic, vault, recon, netmodel
[+] Приложение запущено (PID: 12345)
Сбор данных... ████████████████████████████ 30/30 сек (626 событий)
[+] Сессия сохранена

┌─ Результаты ────────────────────────┐
│ Модуль     │ События │ Типы         │
├────────────┼─────────┼──────────────┤
│ vault      │ 395     │ pref, sqlite │
│ netmodel   │ 171     │ hash, hmac   │
│ traffic    │ 43      │ tcp, ssl_raw │
│ recon      │ 16      │ device, sim  │
│ discovery  │ 1       │ class_map    │
│ ИТОГО      │ 626     │              │
└────────────┴─────────┴──────────────┘
```

## Интересные находки (yakitoriya)

### Серверы
- `beacon2.yakitoriya.ru` — основной API
- `api.wavesend.ru` — push/notifications
- `sentry.inno.co` — error reporting
- `firebase-settings.crashlytics.com` — crash analytics
- `api2.branch.io` — deep linking
- `launches.appsflyersdk.com` — attribution tracking

### Секреты
- Branch.io API key: `key_live_lb1cVtiq4sOUdOI3WMgyqfhoEEedz7Nc`
- Pushwoosh device_id (extracted from prefs)
- HmacSHA256 signing key: `4a784b6f65776779465a5448396d4b3237635272`
- AES/CBC/PKCS5Padding encryption используется для каких-то данных
- 12 UUID nonces сгенерировано за 30 секунд

### Телеметрия
- SIM оператор: MTS RUS (MCC/MNC: 25001)
- SDK_INT: 36
- 6 разных аналитических сервисов активны одновременно

## Файлы (новые)

```
scripts/hooks/traffic.js     — сетевой трафик (5 уровней)
scripts/hooks/vault.js       — хранилище и секреты
scripts/hooks/recon.js       — разведка окружения
scripts/hooks/netmodel.js    — криптография и signing
tests/test_hooks.py          — 8 тестов (синтаксис, композиция, stats)
tests/test_scan.py           — 2 теста (интеграция, CLI)
```

## Корректировки

| # | Проблема | Решение |
|---|---------|---------|
| 1 | OkHttp interceptor нуждается в Java bridge | Уже решено в Фазе 2 (ScriptLoader preamble) |
| 2 | Body может быть огромным | Truncate до 4KB + field body_length |
| 3 | Initial dump vault нужна задержка | setTimeout(5000) для инициализации app context |
| 4 | Session stats нужны для CLI | Добавлен event_stats() в Session |

## Следующий шаг

Фаза 4: Анализ + Отчёт — Python-анализаторы для каждого столпа, генерация Markdown-отчёта, API spec, replay-скрипты.
