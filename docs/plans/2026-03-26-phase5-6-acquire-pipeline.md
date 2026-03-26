# Phase 5+6: Acquire + Full Pipeline — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the APK acquisition module (Playwright-based download from APK mirrors) and the full orchestration pipeline so that `kahlo analyze "yakitoriya"` goes from app name → download → install → scan → analyze → report, all automated.

**Architecture:** Fetcher uses Playwright (headless Chromium) with tf-playwright-stealth to search APKMirror/APKPure, download APK, extract split APKs if needed. Extractor handles XAPK/APKM/APK formats. Pipeline orchestrates the full flow with rich progress. Prepare module wraps jadx for static analysis (background).

**Tech Stack:** Playwright 1.50 + tf-playwright-stealth 1.1 (both already installed), jadx (at /opt/homebrew/bin/jadx)

**Test app:** Search for "yakitoriya" or "2GIS" — download and verify.

---

### Task 1: APK Extractor (`kahlo/acquire/extractor.py`)

Handles format detection and extraction of split APKs.

**Formats:**
- `.apk` — single APK, use as-is
- `.xapk` — ZIP containing manifest.json + multiple .apk files
- `.apkm` — ZIP containing info.json + multiple .apk files (APKMirror format)
- Directory with .apk files — use all .apk files

**Implementation:**
```python
class APKExtractor:
    def extract(self, path: str, output_dir: str) -> list[str]:
        """Extract APK(s) from any format. Returns list of APK paths."""
        if path.endswith('.xapk') or path.endswith('.apkm'):
            return self._extract_split(path, output_dir)
        elif path.endswith('.apk'):
            return [path]
        elif os.path.isdir(path):
            return sorted(glob.glob(os.path.join(path, '*.apk')))

    def _extract_split(self, archive: str, output_dir: str) -> list[str]:
        """Extract XAPK/APKM → individual APK files."""
        # Unzip, find all .apk files inside, return paths
```

Test with existing yakitoriya XAPK from Lab: `/Users/codegeek/Lab/android/apps/yakitoriya/`

---

### Task 2: APK Fetcher (`kahlo/acquire/fetcher.py`)

Downloads APK from mirror sites using Playwright.

**Strategy:** APKPure has simpler structure, try first. APKCombo as fallback. APKMirror as last resort (heavy JS).

**APKPure approach:**
1. Navigate to `https://apkpure.com/search?q={app_name}`
2. Click first result
3. Find download button → get APK/XAPK URL
4. Download file

**APKCombo approach:**
1. Navigate to `https://apkcombo.com/search/{app_name}`
2. Click first result
3. Find download → get direct link

**Implementation:**
```python
class APKFetcher:
    async def fetch(self, query: str, output_dir: str) -> str | None:
        """Search and download APK. Returns path to downloaded file."""
        # Try APKPure first, then APKCombo
        path = await self._try_apkpure(query, output_dir)
        if not path:
            path = await self._try_apkcombo(query, output_dir)
        return path
```

Use `playwright-stealth` to avoid bot detection. Headless mode.

---

### Task 3: Installer (`kahlo/acquire/installer.py`)

Simple wrapper combining extractor + ADB install.

```python
class APKInstaller:
    def install(self, apk_path: str, adb: ADB) -> str:
        """Extract if needed, install on device. Returns package name."""
        extractor = APKExtractor()
        apks = extractor.extract(apk_path, temp_dir)
        adb.install(apks)
        return self._detect_package_name(apks)
```

---

### Task 4: Prepare Module (`kahlo/prepare/`)

Static analysis preparation (runs in background).

**manifest.py:**
```python
class ManifestAnalyzer:
    def analyze(self, apk_path: str) -> ManifestInfo:
        """Extract AndroidManifest.xml info using aapt2 or androguard."""
        # Package name, permissions, activities, services, receivers
```

**decompiler.py:**
```python
class Decompiler:
    def decompile(self, apk_path: str, output_dir: str) -> subprocess.Popen:
        """Run jadx in background. Returns process handle."""
        return subprocess.Popen(["jadx", "-d", output_dir, apk_path])
```

---

### Task 5: Full Pipeline (`kahlo/pipeline.py`)

Orchestrates the entire flow.

```python
class Pipeline:
    async def analyze(self, query: str, duration: int = 60) -> str:
        """Full pipeline: fetch → install → scan → analyze → report."""
        # 1. ACQUIRE: fetch APK
        # 2. PREPARE: install + jadx (background)
        # 3. INSTRUMENT: stealth + scan
        # 4. ANALYZE: all analyzers
        # 5. REPORT: markdown + api_spec + replay
        return session_dir
```

Rich progress display for each stage.

---

### Task 6: CLI `kahlo analyze` Command

```
kahlo analyze <name_or_package> [--duration 60] [--skip-fetch] [--skip-static]
```

- If name looks like a package (contains dots): skip fetch, use directly
- If plain name: fetch APK first
- `--skip-fetch`: assume APK already installed
- `--skip-static`: skip jadx decompilation

---

### Task 7: Claude Code Skills

**skills/android-analysis/SKILL.md:**
- Triggers: "проанализируй приложение", "что делает приложение", "как работает API"
- Instructs Claude to run `kahlo analyze` or `kahlo scan` + `kahlo report`
- How to read and interpret results

**skills/android-replay/SKILL.md:**
- Triggers: "создай клиент", "повтори API", "клон"
- Instructs Claude to load api-spec.json + replay scripts
- Generate full thin client from captured data

---

### Task 8: CLAUDE.md Update

Update project CLAUDE.md with all available commands and workflows.

---

### Task 9: Integration Test

The ultimate test:
1. `kahlo analyze "yakitoriya" --duration 30` — full pipeline from name to report
   OR
2. `kahlo analyze com.voltmobi.yakitoriya --duration 30 --skip-fetch` — skip download, use installed app

Verify complete output: session.json + report.md + api-spec.json + replay/
