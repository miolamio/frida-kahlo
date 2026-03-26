# Предыдущие эксперименты — Lab/android

Путь: /Users/codegeek/Lab/android/

## Окружение

- Устройство: Redmi Note 5A (Mi8937), Android 15 (BP2A.250805.005)
- ROM: LineageOS 23.0
- Root: Magisk (su = root)
- Frida: 17.6.1 (ARM64 server, 52MB)
- Тестовые приложения:
  - Yakitoriya (com.voltmobi.yakitoriya) — доставка еды
  - MAX/OneMe (ru.oneme.app v26.9.1) — мессенджер

## Прогрессия скриптов

### Базовые (01-07) — универсальные

| # | Файл | Техника | Когда использовать |
|---|------|---------|-------------------|
| 01 | logger.js | `java.net.URL` + `okhttp3.HttpUrl.parse` | Быстрая проверка URL-классов |
| 02 | traffic-logger.js | OkHttp custom Interceptor через `Builder.build` | Полный HTTP лог если OkHttp не обфусцирован |
| 03 | hunter.js | Enumeration классов → ищем `addNetworkInterceptor` | Поиск обфусцированного OkHttp |
| 04 | native_logger.js | Native `SSL_write` в libssl/libboringssl | Обход Java-обфускации |
| 05 | conscrypt_logger.js | `SSL_write` через `libconscrypt_jni.so` exports | Android 10+ Conscrypt |
| 06 | universal_ssl.js | Java Conscrypt `SSLOutputStream.write` | Универсальный TLS перехват |
| 07 | master_logger.js | Улучшенный 06 + цвета + GZIP + JSON extraction | Production-quality лог |

### MAX-специфичные (08-15) — реверс-инжиниринг MAX/OneMe

| # | Файл | Техника | Результат |
|---|------|---------|-----------|
| 08 | max-full-capture.js | OkHttp Interceptor + WebSocket + SSL fallback | Полный HTTP + WS перехват |
| 09 | max-hunter.js | Расширенный class discovery (OkHttp, Retrofit, WS, gRPC) | Карта классов MAX |
| 10 | max-capture-v2.js | Улучшенный capture | Стабильная запись |
| 11 | max-capture-light.js | Lightweight версия | Без overhead |
| 12 | max-hexdump.js | Hex dump бинарного протокола | Raw bytes анализ |
| 13 | max-connection-info.js | Connection details extraction | Сервера, порты, TLS |
| 14 | max-full-landscape.js | Comprehensive capture всего | Полная картина |
| 15 | max-telemetry-spy.js | VPN, carrier, IP, ping probes, events | Профиль телеметрии |

## Ключевые техники из скриптов

### OkHttp Interceptor Injection (08)
```javascript
var FullInterceptor = Java.registerClass({
    name: 'com.research.FullCapture',
    implements: [Interceptor],
    methods: {
        intercept: function(chain) {
            var request = chain.request();
            // ... log request ...
            var response = chain.proceed(request);
            // ... log response ...
            return response;
        }
    }
});

OkHttpClientBuilder.build.implementation = function() {
    this.addNetworkInterceptor(FullInterceptor.$new());
    return this.build.call(this);
};
```

### Class Discovery (09)
```javascript
var targets = {
    "addNetworkInterceptor": [],
    "addInterceptor": [],
    "newWebSocket": [],
    "newCall": [],
    "enqueue": [],
    "execute": []
};

Java.enumerateLoadedClasses({
    onMatch: function(className) {
        // Фильтрация system classes
        // Поиск по имени: okhttp, retrofit, websocket, grpc
        // Поиск по методам: getDeclaredMethods()
    },
    onComplete: function() { /* report */ }
});
```

### Telemetry Spy (15) — паттерны
```javascript
// VPN detection
NetworkCapabilities.hasTransport.implementation // transport === 4 (TRANSPORT_VPN)

// Carrier info
TelephonyManager.getNetworkOperator      // PLMN MCC:MNC
TelephonyManager.getSimOperator
TelephonyManager.getNetworkOperatorName

// IP detection
URL.openConnection → фильтр: ipify, ifconfig, yandex.net, checkip.amazonaws, ip.mail.ru

// Competitor probes
Socket.connect → фильтр: gosuslugi, telegram, whatsapp, gstatic, mtalk.google

// Binary events decoding
// Opcode 0x0005 = EVENTS/LOG, msgpack strings extraction
```

## Echo Project — результат RE

Путь: /Users/codegeek/Lab/android/echo/

Полный альтернативный клиент MAX/OneMe, построенный из результатов Frida-анализа:

### Архитектура
```
echo-sdk/          SDK library (pip install echo-max)
  echo/
    client.py      EchoClient — single entry point
    transport/     TCP (binary) + WebSocket (JSON)
    protocol/      Opcodes, packet format, event dispatch
    models/        User, Chat, Message, typed events
    media.py       Photo/file upload and download
    session.py     Token persistence, seq counter
    reconnect.py   Exponential backoff
    errors.py      Error hierarchy
  tests/           54 unit tests

echo-cli/          Rich terminal client
echo-tui/          Textual TUI client
echo-server/       Mock server for testing (Docker)
```

### Что было реализовано
- Dual transport: TCP (msgpack + LZ4) и WebSocket (JSON)
- 150+ opcodes документировано
- Authentication: SMS code + token-based login
- Messaging: send, receive, edit, delete, reply, forward
- Chat history: cursor-based pagination
- Contacts: get, search, find by phone
- Reactions: add, remove, get (emoji)
- Stickers: send by ID
- Media: photo/file upload and download
- Events: typed async stream
- Reconnect: automatic with exponential backoff
- **Zero telemetry**

### Документация
- PROTOCOL.md — 47KB, 1200+ строк, 18 секций
- SOURCES.md — все references, decompiled classes, links

### Уроки для Kahlo
1. Прогрессия от простых хуков к сложным — правильный подход
2. Discovery (hunter) критичен для обфусцированных приложений
3. Бинарные протоколы можно декодировать из SSL intercepts
4. Telemetry analysis раскрывает скрытое поведение
5. Результат RE → полноценный SDK — это proof-of-concept для Kahlo
