# Stealth Reference — Антидетект Frida

## Что детектят приложения

### 1. Файловая система
```
/data/local/tmp/frida-server          — файл exists
/data/local/tmp/re.frida.server       — файл exists
/proc/self/maps                       — содержит "frida-agent", "frida-gadget", "gum"
/proc/self/fd/                        — symlinks на frida pipes
/system/app/Superuser.apk             — root indicator
/system/xbin/su, /sbin/su             — root indicator
/data/adb/magisk/                     — Magisk directory
```

### 2. Сетевая
```
TCP port 27042                        — default frida-server port
D-Bus AUTH message на открытых портах — frida protocol signature
localhost socket scan (1-65535)        — ищут любой frida listener
```

### 3. Память процесса
```
Строки: "frida", "gum-js-loop", "frida-agent", "gmain"
/proc/self/maps → любые .so с "frida" в имени
CRC/hash integrity check native libs  — Interceptor inline hooks меняют код
Thread names: "gmain", "gdbus"        — GLib main loop threads
```

### 4. Системная
```
ptrace(PTRACE_TRACEME)                — если вернул ошибку = кто-то трассирует
/proc/self/status: TracerPid != 0     — процесс под отладкой
getppid() → ppid frida-server         — parent process check
```

## Bypass-стратегия (stealth.js)

### Хук open/openat — фильтрация /proc/self/maps
```javascript
// Перехватываем чтение /proc/self/maps и фильтруем строки с "frida"
var openPtr = Module.findExportByName("libc.so", "open");
var readPtr = Module.findExportByName("libc.so", "read");

// Стратегия: при open("/proc/self/maps") запоминаем fd,
// при read(fd) фильтруем строки содержащие "frida"/"gum"
```

### Хук access/stat — скрытие файлов
```javascript
var accessPtr = Module.findExportByName("libc.so", "access");
Interceptor.attach(accessPtr, {
    onEnter: function(args) {
        var path = args[0].readCString();
        if (path && (path.indexOf("frida") !== -1 ||
                     path.indexOf("magisk") !== -1 ||
                     path.indexOf("/su") !== -1)) {
            // Подменяем путь на несуществующий
            args[0] = Memory.allocUtf8String("/nonexistent");
        }
    }
});
```

### Хук connect — блокировка port scan
```javascript
var connectPtr = Module.findExportByName("libc.so", "connect");
Interceptor.attach(connectPtr, {
    onEnter: function(args) {
        var sockaddr = args[1];
        var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
        if (port === 27042) {
            // Подменяем на невалидный адрес
            sockaddr.add(2).writeU8(0);
            sockaddr.add(3).writeU8(0);
        }
    }
});
```

### Хук ptrace
```javascript
var ptracePtr = Module.findExportByName("libc.so", "ptrace");
Interceptor.replace(ptracePtr, new NativeCallback(function(request, pid, addr, data) {
    if (request === 0) { // PTRACE_TRACEME
        return 0; // Успех — никто не трассирует
    }
    return -1;
}, 'long', ['int', 'int', 'pointer', 'pointer']));
```

### Java-level root detection bypass
```javascript
// RootBeer (самая популярная библиотека)
try {
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    var methods = ["isRooted", "isRootedWithoutBusyBoxCheck",
                   "checkForSuBinary", "checkForBusyBoxBinary",
                   "checkForRootManagementApps", "checkForDangerousProps",
                   "checkSuExists", "checkForMagiskBinary"];
    methods.forEach(function(m) {
        try {
            RootBeer[m].implementation = function() { return false; };
        } catch(e) {}
    });
} catch(e) {} // RootBeer не используется — ок
```

## SSL Unpinning стратегия

Порядок попыток (от частого к редкому):

1. **OkHttp CertificatePinner** — самый частый
2. **TrustManagerImpl.checkServerTrusted** — Android system
3. **X509TrustManager custom implementations** — часто в финтехе
4. **NetworkSecurityConfig** — Android 7+
5. **Conscrypt cert verification**
6. **WebViewClient.onReceivedSslError** — для WebView

Источник готовых скриптов: [httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning)

## Уровни эскалации

```
Уровень 0: Stock frida-server, port 27042
            → детектится всем

Уровень 1: Random port + /dev/.fs + bypass.js
            → проходит 70% приложений

Уровень 2: hluda build (без строк frida/gum) + Shamiko
            → проходит 90% приложений

Уровень 3: frida-gadget (patch APK, нет внешнего процесса)
            → проходит 95% приложений

Уровень 4: frida-gadget + Stalker (inline rewrite detection code)
            → проходит 99% приложений
```

## Сборка hluda (кастомный Frida без артефактов)

```bash
# Клонировать hluda fork
git clone https://github.com/xxr0ss/AntiFrida  # reference detection
# Или использовать автоматический пересборщик:
# https://github.com/aspect-build/aspect-workflows  (frida rebuild recipes)

# Ручная замена строк в исходниках Frida:
git clone --recurse-submodules https://github.com/frida/frida.git
cd frida

# Замена всех строк "frida" → "kahlo" в исходниках
find . -name "*.c" -o -name "*.h" -o -name "*.vala" | \
  xargs sed -i '' 's/frida/kahlo/g; s/FRIDA/KAHLO/g'

# Замена имён thread: "gmain" → рандомное
# Замена named pipe patterns
# Замена D-Bus signatures

# Сборка под Android arm64
make server-android-arm64

# Результат: build/frida-android-arm64/bin/frida-server
# Переименовать и push
```

Примечание: полная пересборка сложна и хрупка. Для MVP используем Уровень 1 (random port + bypass.js). Эскалация — по мере необходимости.
