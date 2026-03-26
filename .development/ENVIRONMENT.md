# Текущее окружение

## Хост (macOS)
- Platform: Darwin 25.2.0 (macOS)
- Python: miniconda3
- Frida: 17.6.1 (frida + frida-tools 14.4.5)
- ADB: установлен, daemon running
- jadx: проверить (`which jadx`)
- objection: не установлен

## Устройство
- ID: 28e37107
- Модель: Redmi Note 5A (Mi8937)
- ROM: LineageOS 23.0 (BP2A.250805.005, Android 15)
- Root: Magisk (su = root)
- frida-server: /data/local/tmp/frida-server (ARM64 ELF, 52MB)
- Архитектура: arm64-v8a

## Предыдущие эксперименты
- Путь: /Users/codegeek/Lab/android/
- 15 Frida JS-скриптов
- Echo SDK (Python) — альтернативный клиент MAX
- Тестовые APK: yakitoriya (com.voltmobi.yakitoriya), MAX (ru.oneme.app)

## Статус инструментов
- [x] jadx: /opt/homebrew/bin/jadx
- [x] frida 17.6.1 + frida-tools 14.4.5
- [x] playwright 1.50.0 (+ tf-playwright-stealth 1.1.0!)
- [x] typer 0.21.1
- [x] rich 14.2.0
- [x] pydantic 2.12.5
- [ ] apktool: не установлен (`brew install apktool`)
- [ ] androguard: не установлен (`pip install androguard`)
- [ ] apkid: не установлен (`pip install apkid`)

## ADB команды (quick reference)
```bash
adb devices                                    # список устройств
adb shell "su -c 'whoami'"                     # проверка root
adb shell pm list packages                     # все пакеты
adb push <local> /data/local/tmp/              # загрузка на устройство
adb shell "su -c '/data/local/tmp/frida-server &'"  # запуск frida
frida-ps -U                                    # процессы через frida
frida -U -f <package> -l <script.js>           # spawn + inject
```

## Frida порты и пути
- Default port: 27042 (TCP) — ДЕТЕКТИРУЕТСЯ, менять на random
- Server path: /data/local/tmp/frida-server — ДЕТЕКТИРУЕТСЯ, переносить
- Stealth path: /dev/.fs (tmpfs, не виден через обычный ls)
- Stealth port: random 10000-60000
