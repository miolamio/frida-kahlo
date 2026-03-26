# Frida Anti-Detection — Полное руководство

Дата исследования: 2026-03-26
Источник: Perplexity sonar-pro

## Источники
- [Appdome — How to Detect Frida Server](https://www.appdome.com/how-to/mobile-malware-prevention/binary-instrumentation-detection/detecting-frida-and-frida-methods-in-android-ios-apps/)
- [Approov — Frida Detection & Prevention](https://approov.io/knowledge/frida-detection-prevention)
- [muellerberndt/frida-detection (GitHub)](https://github.com/muellerberndt/frida-detection)
- [Stackademic — Defending Against Frida](https://blog.stackademic.com/defending-mobile-apps-against-frida-even-with-root-bypass-android-f26ae7df4e89)
- [8kSec — Root Detection Bypass](https://8ksec.io/advanced-root-detection-bypass-techniques/)
- [OWASP MASTG — Dynamic Analysis on Non-Rooted Devices](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0026/)
- [NorthSec 2022 — Bypass Modern Android Runtime Protections](https://nsec.io/session/2022-reverse-and-bypass-of-modern-android-runtime-protections-fr.html)

## 1. Методы детекции Frida

### Файловая система
- `/proc/self/maps` — сканирование на `frida-agent.so`, `frida-gadget.so`
- `/proc/<pid>/maps` — то же для дочерних процессов
- `/data/local/tmp/frida-server` — file existence check
- `/proc/self/fd` — open file descriptors, ищут frida pipes/sockets

### Сеть
- TCP port 27042 — local port scan
- D-Bus AUTH messages — отправка на все открытые TCP порты
- Frida-specific protocol responses

### Память
- Строки `"frida-agent"`, `"Gum"`, `"frida-gadget"` в text/data секциях
- ASM-based file ops для обхода Java-level hooks при сканировании

### Процесс
- `ptrace(PTRACE_TRACEME)` — если ошибка, процесс трассируется
- `/proc/<pid>/status` → `TracerPid != 0`
- Native code integrity: CRC/hash проверка .so для детекции inline hooks (Interceptor)

### RASP-решения
- Appdome — коммерческий, детектит всё вышеперечисленное
- Approov — cloud attestation + RASP
- Обычно layered: root + frida + emulator detection одновременно

## 2. Anti-Detection Solutions

### Renamed binary + non-default port
```bash
cp frida-server /dev/.fs
chmod 755 /dev/.fs
/dev/.fs -l 0.0.0.0:47293 &
```
Клиент: `frida -H 127.0.0.1:47293 -f com.app`

### Magisk модули

| Модуль | Назначение | Статус 2026 |
|--------|-----------|-------------|
| MagiskHide | Скрытие root от приложений | Deprecated, заменён Shamiko |
| Shamiko | Advanced process hiding | Актуален, Zygisk-based |
| Zygisk | Инъекция в Zygote | Актуален, base для Shamiko |
| HideMyApplist | Скрытие установленных приложений | Актуален |

### hluda (кастомные билды Frida)
- Fork с заменёнными строками "frida"→random, "gum"→random
- Убраны D-Bus signatures
- Thread names замаскированы ("gmain"→random)
- Требует пересборки из исходников
- Эффективность: 90%+ приложений

### frida-gadget vs frida-server
- **frida-server**: отдельный процесс, порт, легко детектируется
- **frida-gadget**: .so загружается внутри целевого приложения
  - Нет внешнего процесса
  - Нет открытого порта
  - Сложнее детектировать
  - Требует патча APK (добавление gadget .so в lib/)
  - Или через Zygisk injection

### Stalker-based bypass
- Frida Stalker API для трассировки и inline rewrite
- Перезапись кода проверок прямо в памяти
- Обходит integrity checks (CRC native libs)
- Наиболее надёжный, но сложный метод

## 3. Сборка кастомного Frida Server

```bash
# Клонировать
git clone --recurse-submodules https://github.com/frida/frida.git
cd frida

# Массовая замена строк
find . -name "*.c" -o -name "*.h" -o -name "*.vala" | \
  xargs sed -i '' 's/frida/kahlo/g; s/FRIDA/KAHLO/g'

# Замена thread names
# gmain → рандом, gdbus → рандом

# Замена D-Bus signatures

# Сборка
export ANDROID_NDK=/path/to/ndk-r26
mkdir build && cd build
cmake .. \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-30 \
  -DCMAKE_BUILD_TYPE=Release
make -j$(nproc) frida-server

# Post-build
arm64-linux-android-strip --strip-all frida-server
mv frida-server kahlo-server

# Проверка
strings kahlo-server | grep -i frida  # должно быть пусто
```

## 4. Runtime Bypass Scripts

### Unified stealth.js (все bypass-ы в одном)

```javascript
// === /proc/self/maps фильтрация ===
var openPtr = Module.findExportByName("libc.so", "open");
Interceptor.attach(openPtr, {
    onEnter: function(args) {
        this.path = args[0].readCString();
    },
    onLeave: function(retval) {
        if (this.path && this.path.indexOf("/proc/self/maps") !== -1) {
            this.isMaps = true;
            this.fd = retval.toInt32();
        }
    }
});

// === File existence скрытие ===
var accessPtr = Module.findExportByName("libc.so", "access");
Interceptor.attach(accessPtr, {
    onEnter: function(args) {
        var path = args[0].readCString();
        if (path && (path.indexOf("frida") !== -1 ||
                     path.indexOf("magisk") !== -1 ||
                     path.indexOf("/su") !== -1)) {
            args[0] = Memory.allocUtf8String("/nonexistent");
        }
    }
});

// === Port scan блокировка ===
var connectPtr = Module.findExportByName("libc.so", "connect");
Interceptor.attach(connectPtr, {
    onEnter: function(args) {
        var sa = args[1];
        var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
        if (port === 27042) {
            sa.add(2).writeU8(0);
            sa.add(3).writeU8(0);
        }
    }
});

// === ptrace bypass ===
var ptracePtr = Module.findExportByName("libc.so", "ptrace");
Interceptor.replace(ptracePtr, new NativeCallback(function(req, pid, addr, data) {
    if (req === 0) return 0;  // PTRACE_TRACEME → success
    return -1;
}, 'long', ['int', 'int', 'pointer', 'pointer']));

// === Java root detection ===
Java.perform(function() {
    // RootBeer
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        ["isRooted","isRootedWithoutBusyBoxCheck","checkForSuBinary",
         "checkForBusyBoxBinary","checkForRootManagementApps",
         "checkForDangerousProps","checkSuExists","checkForMagiskBinary"
        ].forEach(function(m) {
            try { RootBeer[m].implementation = function() { return false; }; } catch(e) {}
        });
    } catch(e) {}
});
```

## 5. Надёжность по уровням

| Подход | vs SafetyNet | vs RootBeer | vs Anti-Frida (RASP) |
|--------|-------------|-------------|---------------------|
| Stock frida-server | Low | Low | Very Low |
| Renamed + MagiskHide | Medium | Medium | Low |
| hluda + Shamiko | High | High | Medium |
| **frida-gadget + Zygisk** | **Very High** | **Very High** | **High** |
| + Stalker hooks | Highest | Highest | Highest |

**Рекомендация для MVP**: random port + renamed binary + bypass.js (Уровень 1).
Эскалация по необходимости.
