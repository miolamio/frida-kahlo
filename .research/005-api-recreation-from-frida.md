# API Recreation from Frida Intercepts

Дата исследования: 2026-03-26
Источник: Perplexity sonar-pro

## Источники
- [Doyensec — Intercepting OkHttp at Runtime (Jan 2026)](https://blog.doyensec.com/2026/01/22/frida-instrumentation.html)
- [httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning)
- [HTTP Toolkit — Frida Scripts](https://httptoolkit.com/frida-scripts/)
- [AppSec Santa — Objection 2026](https://appsecsanta.com/objection)
- [Brown Fine Security — Intercepting Mobile Traffic with Caido and Frida](https://brownfinesecurity.com/blog/intercepting-mobile-traffic-with-caido-and-frida)

## 1. Полный перехват HTTP Request/Response

### OkHttp Interceptor Chain
Ключевой источник (Doyensec, Jan 2026): перехват на разных уровнях chain даёт разную видимость:
- `RealCall.execute()` / `enqueue()` — видим начальный запрос
- **Interceptor chain** — видим мутации (auth headers, signatures, encryption добавленные post-JSON serialization)
- Рекомендация: hook `OkHttpClient$Builder.build` → addNetworkInterceptor → custom interceptor ловит **финальный** запрос перед отправкой

### httptoolkit scripts
- Автоматический HTTPS MitM
- Bypass certificate pinning + transparency checks
- Полные request/response включая headers и body

### Комбинирование
- objection `android sslpinning disable` для proxy (mitmproxy/Burp)
- Frida hooks для in-process capture (без proxy)

## 2. Детекция API Signing Mechanisms

### Паттерн
1. Hook OkHttp interceptor chain
2. Логировать inputs/outputs каждого interceptor
3. Найти interceptor, который добавляет signing headers
4. Извлечь: алгоритм (HMAC-SHA256), ключ, nonce pattern

### Типичные признаки signing
- `X-Signature` / `X-Sign` header
- `X-Nonce` / `X-Timestamp` header
- `Authorization: HMAC ...`
- Body hash в header

### Frida hooks для crypto
```javascript
// javax.crypto.Mac — HMAC
Java.use("javax.crypto.Mac").doFinal.overload('[B').implementation = function(input) {
    var result = this.doFinal(input);
    send({module:"netmodel", type:"hmac", data:{
        algorithm: this.getAlgorithm(),
        input: arrayToHex(input),
        output: arrayToHex(result)
    }});
    return result;
};
```

## 3. Replay из Python

### Шаблон
```python
import requests
import hmac
import hashlib
import time

session = requests.Session()
session.headers.update({'Authorization': 'Bearer <extracted_token>'})

def sign_request(payload, secret):
    nonce = str(int(time.time()))
    msg = nonce + payload
    signature = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return {'X-Signature': signature, 'X-Nonce': nonce}

payload = '{"key": "value"}'
headers = sign_request(payload, 'extracted_secret')
response = session.post('https://api.example.com/endpoint', json=payload, headers=headers)
```

### Dynamic tokens
- Мониторить `onFailure`/`onResponse` для token expiry
- Реализовать refresh loop: 401 → refresh_token → retry

## 4. Детекция бинарных протоколов

### Из SSL intercepts
- Логировать `contentType` (application/octet-stream = бинарный)
- Логировать raw bytes первых 16 байт
- Паттерны:
  - **MsgPack**: compact structs, magic bytes 0x80-0x8f (fixmap), 0x90-0x9f (fixarray)
  - **Protobuf**: varint fields, tag 0x08 (field 1, varint type)
  - **Custom TLV**: [tag:1-2byte][length:2-4byte][value]
  - **JSON**: starts with `{` or `[`

### Frida hook для contentType
```javascript
// Hook RequestBody для определения формата
var RequestBody = Java.use("okhttp3.RequestBody");
// Hook contentType() → определяем формат
// Hook writeTo(BufferedSink) → raw bytes
```

## 5. Конвертация Frida Captures → Python/curl

### Инструменты
- **objection**: REPL → export to HAR/JSON → `har2curl`
- **HTTP Toolkit scripts**: MitM dumps → HAR → Python via `haralyzer`
- **Caido + Frida**: scope-filtered HTTP → cURL/Python snippets
- **Manual**: Frida `send()` → Python dicts → `requests` replay

### Наш подход (Kahlo)
Kahlo session.json → `kahlo replay` → генерация:
- curl команды для каждого эндпоинта
- Python requests с auth + signing
- Thin client skeleton

## 6. Anti-Replay Protections

### Timestamp-based
- Извлечь clock source (System.currentTimeMillis())
- Синхронизировать Python `time.time()` с ±5с tolerance
- Hook для определения серверного validation window

### Nonce-based
- Capture generation pattern (UUID + ts, random, counter)
- Stateful nonce counter в Python session
- Никогда не повторять nonce

### Device fingerprint-based
- Hook fingerprint builders (Build.FINGERPRINT + IMEI hash)
- Реплицировать в Python headers (X-Device-ID)
- Frida unpin + interceptor tracing для полного списка checks

## 7. Thin Client — паттерн

```python
class AppMimicClient:
    def __init__(self, secret, device_id):
        self.session = requests.Session()
        self.secret = secret
        self.device_id = device_id

    def _sign(self, method, path, body, nonce):
        msg = f"{method}{path}{body}{nonce}"
        return hmac.new(self.secret.encode(), msg.encode(), hashlib.sha256).hexdigest()

    def post(self, path, json_data):
        nonce = str(int(time.time_ns() // 1_000_000))
        body = json.dumps(json_data)
        sig = self._sign('POST', path, body, nonce)
        headers = {
            'X-Nonce': nonce,
            'X-Sig': sig,
            'X-Device': self.device_id,
            'Content-Type': 'application/json'
        }
        return self.session.post(f"https://api.example.com{path}",
                                  json=json_data, headers=headers)
```

Ключ: реверсить **полную interceptor chain** из Frida traces, включая encryption/auth stacking.
