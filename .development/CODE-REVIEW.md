# Code Review: Frida-Kahlo

**Reviewer:** Claude Opus 4.6 (1M context)
**Date:** 2026-03-27
**Scope:** Full codebase review (Python + JavaScript + config + docs + tests)
**Codebase:** ~5,800 lines Python (kahlo/), ~3,800 lines JavaScript (scripts/), ~5,900 lines tests
**Test results:** 397 passed, 8 failed (device-dependent tests, expected without USB)

---

## Executive Summary

Frida-Kahlo is a well-structured, thoughtfully designed Android analysis framework. The architecture is clean, the module separation is clear, and the data flow from events through analyzers to reports is coherent. The code demonstrates strong domain knowledge of Frida internals, Android internals, and protocol reverse engineering.

That said, this was built in a single session (6 phases + 10 improvements), and it shows the marks of rapid development: there are security concerns in the ADB layer, several unused imports, duplicated code blocks, and a few subtle logic bugs. None of these are show-stoppers, but they should be addressed before sharing on GitHub.

---

## 1. Critical Issues (MUST fix)

### C-1. Command injection via `adb shell` with unsanitized package names

**Files:** `kahlo/device/adb.py:63-66`, `kahlo/cli.py:239`, `kahlo/pipeline.py:199`

The `ADB.shell()` method passes the `cmd` argument directly as a single string to `adb shell`. When callers interpolate user-controlled package names into this string, a malicious package name like `com.evil; rm -rf /` would execute arbitrary commands on the device.

```python
# adb.py:63
def shell(self, cmd: str, su: bool = False) -> str:
    if su:
        cmd = f"su -c '{cmd}'"     # no escaping of cmd contents
    return self._cmd(["shell", cmd])
```

Callers that interpolate user input:
- `cli.py:239`: `adb.shell(f"pm clear {package}")` -- `package` comes from CLI argument
- `pipeline.py:199`: `adb.shell(f"pm path {package_name}")` -- from user input
- `frida_server.py:25`: `self._adb.shell(f"ls -la {self.server_path}")` -- controlled by constructor

**Recommendation:** Add a `_validate_package_name()` helper that rejects names not matching `^[a-zA-Z0-9._]+$`, and call it before any shell interpolation. Alternatively, pass arguments as a list instead of a single string, or use `shlex.quote()`.

### C-2. The `frida_start` CLI command uses hardcoded English instead of Russian

**File:** `kahlo/cli.py:124-153`

The project convention (per CLAUDE.md) is "Russian for UI". The `frida_start`, `frida_stop`, `monitor`, and several other commands use English for user-facing messages ("Starting frida-server with stealth...", "No devices connected"). The `device` and `install` commands correctly use Russian. This inconsistency needs to be resolved.

**Affected commands:** `frida_start`, `frida_stop`, `scan`, `monitor`, `analyze_cmd`, `fetch_cmd`, `static_cmd`, `aggregate_cmd`, `diff_cmd`, `export_postman_cmd`.

### C-3. `mapsFdSet` in stealth.js grows unboundedly (memory leak)

**File:** `scripts/bypass/stealth.js:35`

The `mapsFdSet` object tracks file descriptors opened for `/proc/*/maps` but never removes them when the fd is closed. On long-running sessions, this grows with every `open`/`openat` call to maps files.

```javascript
var mapsFdSet = {};
// ...
mapsFdSet[fd] = true;   // line 51 and 106 — never deleted
```

**Recommendation:** Hook `close()` in libc and delete the fd from `mapsFdSet` when it is closed.

---

## 2. Important Issues (SHOULD fix)

### I-1. Unused imports across multiple modules

**File:** `kahlo/acquire/installer.py:6,7,8` -- `subprocess`, `tempfile`, `Any` are imported but never used at module level (`subprocess` and `re` are imported again inside methods).

**File:** `kahlo/pipeline.py:10` -- `Any` imported but never used.

**File:** `kahlo/prepare/strings.py:8` -- `Any` imported but never used.

**File:** `kahlo/device/adb.py:6` -- `dataclass` imported from `dataclasses` but `ADBDevice` uses `@dataclass` while `DeviceInfo` uses `BaseModel`. This is not an unused import, but a design inconsistency.

**Recommendation:** Clean up unused imports. Use `ruff check --select F401` to find all of them.

### I-2. `import re` inside functions in `patterns.py:_extract_version`

**File:** `kahlo/analyze/patterns.py:308,315,322,332`

The `re` module is imported four separate times inside the `_extract_version` function body. It should be imported once at the top of the module (it is not imported there currently).

### I-3. `pref_write` events in `vault.py` do not record the file name

**File:** `kahlo/cli.py` (vault.js hooks) and `kahlo/analyze/vault.py:320-324`

When a `pref_write` event is processed, the `file` field is not extracted from `data`:

```python
elif etype == "pref_write":
    total_writes += 1
    key = data.get("key", "")
    value = data.get("value")
    # BUG: 'file' is not extracted, nor is the event used to populate pref_files_map
```

And in `scripts/hooks/vault.js:112-119`, the `pref_write` events from `SharedPreferencesImpl$EditorImpl` do not include a `file` field at all -- the Editor does not have direct access to `mFile`. This means write counts in `pref_files_map` are always 0 for pref files that are only written to.

**Recommendation:** Either track the file in the editor hooks (e.g., by hooking `commit()`/`apply()` and reading the parent `SharedPreferencesImpl.mFile`), or acknowledge the limitation in the documentation.

### I-4. The `recon.py` analyzer does not populate `ip_lookups` and `competitor_probes` lists

**File:** `kahlo/analyze/recon.py:78-84`

The `ip_lookup` and `competitor_probe` events are processed for category scoring but the actual data (service name, package name) is never added to the report lists:

```python
elif etype == "ip_lookup":
    service = data.get("service", data.get("url", ""))
    categories.add("ip_lookup")
    # BUG: 'service' is extracted but never added to any list

elif etype == "competitor_probe":
    pkg = data.get("package", "")
    categories.add("competitor_probes")
    # BUG: 'pkg' is extracted but never added to any list
```

The returned `ReconReport` always has `ip_lookups=[]` and `competitor_probes=[]`.

**Recommendation:** Add `ip_lookups.append(service)` and `competitor_probes.append(pkg)` with deduplication.

### I-5. `DeviceInfo` uses Pydantic `BaseModel` while `ADBDevice` uses `@dataclass`

**File:** `kahlo/device/adb.py:10,21`

Mixing Pydantic models and dataclasses for similar data structures in the same module creates inconsistency. Both represent device data.

**Recommendation:** Use Pydantic `BaseModel` for both, or dataclasses for both. Since the project convention is Pydantic for data models, convert `ADBDevice` to a `BaseModel`.

### I-6. `_JAVA_BRIDGE_PREAMBLE` double-loading risk

**Files:** `kahlo/instrument/loader.py:98`, `kahlo/instrument/engine.py:131-132`

When `ScriptLoader.compose()` is called with `include_java_bridge=True` (the default), it prepends the bridge. Then `FridaEngine.inject()` also prepends it if `include_java_bridge=True` (the default). This means if you call `engine.spawn(package, script_source=loader.compose(...))`, the Java bridge is prepended **twice**.

Looking at the actual call path in `cli.py:261-279`: `loader.compose()` includes the bridge, then `engine.spawn()` calls `engine.inject()` which adds it again. The result is a script with the Java bridge defined twice.

In practice this works because JavaScript tolerates re-declaration, but it doubles the injected script size and could cause subtle issues.

**Recommendation:** Either have `compose()` default to `include_java_bridge=False` (let the engine handle it), or have `inject()` default to `include_java_bridge=False` (let the loader handle it). Pick one injection point.

### I-7. `generate_markdown` imports `json` inside function body

**File:** `kahlo/report/markdown.py:365`

```python
import json
lines.append(json.dumps(jwt.header, indent=2))
```

The `json` module is imported at line 365 inside the function instead of at the top of the module.

### I-8. Hardcoded jadx path `/opt/homebrew/bin/jadx`

**Files:** `kahlo/prepare/manifest.py:62`, `kahlo/prepare/decompiler.py:19`, `kahlo/acquire/installer.py:103`

The jadx path is hardcoded to a Homebrew location. This breaks on Linux, non-Homebrew macOS, or any system where jadx is installed elsewhere.

**Recommendation:** Use `shutil.which("jadx")` as the primary lookup, falling back to the hardcoded path. Or make it a configurable setting.

### I-9. `_detect_via_binary` in installer.py uses heuristic that only matches `com.*` packages

**File:** `kahlo/acquire/installer.py:140`

```python
matches = re.findall(r'(com\.[a-z][a-z0-9]*\.[a-z][a-z0-9.]*)', text)
```

This regex only matches packages starting with `com.`. Packages like `org.example.app`, `io.company.app`, `ru.yandex.app`, etc. would not be detected.

**Recommendation:** Broaden the regex to `((?:com|org|io|net|ru|me|de|uk|fr|eu|app)\.[a-z][a-z0-9]*\.[a-z][a-z0-9.]*)` or make it generic: `([a-z][a-z0-9]*\.[a-z][a-z0-9]*\.[a-z][a-z0-9.]*)`.

### I-10. The `report` command in CLI does not pass `auth` analysis to `generate_markdown`

**File:** `kahlo/cli.py:536`

The `report` command runs `analyze_auth(events, package)` at line 515, but at line 536 the call to `generate_markdown` does not pass the `auth` parameter when the function signature accepts it:

```python
md_content = generate_markdown(session, traffic, vault, recon, netmodel, patterns, auth, static=static_report)
```

Wait -- actually looking more carefully, line 536 does pass `auth` as a positional argument. This is correct. But the `pipeline.py` REPORT stage at line 394-397 does NOT pass `auth` at all:

```python
md_content = generate_markdown(
    session_data, traffic, vault, recon, netmodel, patterns,
    static=static_report,
)
```

The pipeline never runs `analyze_auth`, so auth flow data is missing from pipeline-generated reports.

**Recommendation:** Add auth analysis to the pipeline's ANALYZE stage and pass it to `generate_markdown`.

### I-11. `_multipart` body decoder can raise `ValueError` on missing closing quote

**File:** `kahlo/analyze/decoder.py:509`

```python
end = line.index('"', start)  # raises ValueError if no closing quote
```

If the multipart Content-Disposition header is malformed (no closing quote after `name="`), this line raises `ValueError` and the entire decode fails.

**Recommendation:** Wrap in try/except or use `line.find('"', start)` with a check for -1.

---

## 3. Minor Issues (NICE to fix)

### M-1. Duplicated `safeHook` function between `common.js` and `bypass/stealth.js`

**Files:** `scripts/common.js:13-21`, `scripts/bypass/stealth.js:9-13`

The `safeHook` function is defined in both files. Since stealth.js is loaded before common.js (it is in the bypass list), this works, but if loading order changes, the common.js version (which returns a boolean) would be overwritten by the stealth.js version (which returns void).

### M-2. `statusFiles` in stealth.js grows unboundedly

**File:** `scripts/bypass/stealth.js:189`

Same issue as `mapsFdSet` (C-3) but for status file tracking. Less critical since `/proc/*/status` is read less frequently.

### M-3. Inconsistent type annotation styles

Some modules use `dict[str, Any]` (Python 3.10+ style), while the `from __future__ import annotations` import is inconsistently applied. Files like `kahlo/analyze/recon.py` do not import `from __future__ import annotations` but use `dict[str, str]` which works in Python 3.9+ for variable annotations but not for older Python.

Since `pyproject.toml` requires `>=3.11`, this is fine, but the `from __future__ import annotations` usage should be consistent (either always or never).

### M-4. Missing `__all__` exports in `__init__.py` files

None of the `__init__.py` files define `__all__`, which means `from kahlo.analyze import *` would import nothing useful. Not critical for a CLI tool but good practice.

### M-5. `vault.js` KeyStore `aliases()` hook calls `this.aliases.call(this)` twice

**File:** `scripts/hooks/vault.js:654-658`

```javascript
var result = this.aliases();
// ...
var enumCopy = this.aliases.call(this);  // calls aliases() AGAIN
```

The Enumeration returned by `aliases()` is consumed once -- calling it again is wasteful. Also, `result` (the first call) is returned to the app, but the enumeration may already be partially consumed. This could cause subtle bugs if the Enumeration is stateful.

**Recommendation:** Clone the result before iterating, or iterate the original and construct a new Enumeration for the return value.

### M-6. `_categorize_known_key` has a redundant branch

**File:** `kahlo/analyze/vault.py:193-196`

```python
if _UUID_RE.match(value):
    return "device_id", "medium"
return "device_id", "medium"
```

Both branches return the same thing.

### M-7. Test file `test_scan.py` has `import time` but all time-dependent tests are mocked

**File:** `tests/test_scan.py`

Minor unused import in the test file.

### M-8. `_host_to_prefix` could be a dict lookup instead of a loop

**File:** `kahlo/report/replay.py:113-125`

The `_KNOWN` patterns list is iterated linearly for every endpoint. Converting to a more efficient lookup or caching would be cleaner.

### M-9. `markdown.py` hardcodes a specific package name

**File:** `kahlo/report/markdown.py:277`

```python
elif "/com.voltmobi.yakitoriya/" in fw.path:
    short_path = fw.path.split("/com.voltmobi.yakitoriya/")[-1]
```

This is a leftover from development with the test app. The first `if` branch handles the general case via the `package` variable, but this `elif` should be removed.

### M-10. `pyproject.toml` missing `playwright-stealth` in `[project.optional-dependencies]`

**File:** `pyproject.toml:24`

The `acquire` optional dependencies list `playwright>=1.40` but `fetcher.py:57` also imports `playwright_stealth`. This should be listed as a dependency.

---

## 4. Architecture and Design Assessment

### What is done well

1. **Clean module separation.** The `acquire -> prepare -> instrument -> analyze -> report` pipeline is well-defined and each module has clear responsibilities. No circular dependencies exist.

2. **Layered traffic capture.** The traffic.js hooks implement a multi-level capture strategy (OkHttp3 > System OkHttp v2 > HttpURLConnection > SSL parsed > Native SSL > Socket.connect) with proper deduplication logic using `_activeLevel`. This is sophisticated and correct.

3. **Pydantic models everywhere.** All analyzer outputs use Pydantic `BaseModel` for structured data, making serialization, validation, and type safety consistent.

4. **Graceful degradation.** Every hook in the JS files is wrapped in try/catch. The analyzers handle missing data gracefully. The CLI commands catch exceptions and provide human-readable error messages.

5. **Auth flow detection.** The auth flow detection system (detecting login URLs, auth headers, JWTs in traffic) is well-thought-out and covers many patterns.

6. **HTTP body decoding.** The `BodyDecoder` class handles JSON, protobuf, msgpack, form-urlencoded, gzip, multipart, and XML with proper content-type routing and content inspection fallback.

### Design concerns

1. **Event schema is implicit.** There is no formal schema for the event JSON objects passed between JS hooks and Python analyzers. A Pydantic model like `FridaEvent(module: str, type: str, data: dict, ts: str)` would catch mismatches early.

2. **No configuration file.** All settings (jadx path, scan duration, stealth level, scripts to load) are hardcoded or passed as CLI args. A `~/.kahlo.toml` or `kahlo.toml` config file would improve usability.

3. **Session JSON files can be very large.** With MAX_BODY=4096 per event and potentially thousands of events, sessions can reach tens of megabytes. Consider a streaming/incremental write approach for long scans.

---

## 5. Test Coverage Assessment

### Coverage overview

- **Strong coverage:** Analyzers (traffic, vault, recon, netmodel, patterns, auth, jwt, static, decoder, aggregate, diff, flows), report generators (markdown, api_spec, replay, postman), CLI commands, session management, ADB wrapper, pipeline.
- **397 of 405 tests pass** (8 device-dependent failures are expected).

### Gaps

1. **No tests for `monitor.py`** (`LiveMonitor.run` method is untested for the actual Frida spawn/display loop). The `test_monitor.py` file tests `format_event` and `LiveMonitor` state management but not the `run()` method.

2. **No tests for `fetcher.py`** (APK download from APKPure/APKCombo). This is understandable since it requires network access and a running Playwright browser, but at least mock tests for the download flow could be added.

3. **No integration test** for the full `kahlo analyze` pipeline end-to-end with a mock Frida device. The `test_pipeline.py` tests the Pipeline class but mocks out all Frida interaction.

4. **JavaScript hook tests are device-dependent.** The 8 failing tests all try to actually spawn an app on a device. These should be marked with `@pytest.mark.skipif` when no device is connected, or mocked.

5. **No test for `_multipart` body decoder edge case** (missing closing quote, malformed headers).

6. **No test for the `flows.py` analyzer** in isolation with crafted events that test the chain detection edge cases (e.g., chains longer than 2, circular dependencies, identical values across unrelated requests).

---

## 6. Documentation Assessment

### CLAUDE.md

Accurate and well-maintained. It correctly documents the CLI commands, architecture, conventions, and test setup. Minor issue: the `skills/` section references `android-analysis` and `android-replay` which exist and are correct.

### Skills

Both `skills/android-analysis/SKILL.md` and `skills/android-replay/SKILL.md` are well-written and provide actionable workflows. The `android-replay` skill references `replay_client.py` and `curl_commands.sh` which don't match the actual generated filenames (`client.py` and individual curl scripts in `curl/` subdirectory). Should be updated to match actual output.

### Phase reports

The `.development/` directory contains detailed phase reports that document the implementation history. These are valuable for understanding design decisions.

---

## 7. Deployment Readiness

### Can someone `pip install` and use it?

**Mostly yes**, with caveats:

1. `pip install -e ".[dev]"` works. The `kahlo` CLI entry point is configured.
2. `frida` and `frida-tools` are required and correctly declared.
3. `playwright` and `playwright-stealth` need to be installed for APK fetching but `playwright-stealth` is missing from the deps (see M-10).
4. `androguard` is correctly listed as optional under `[project.optional-dependencies].static`.
5. **No `requests` dependency** is declared, but `kahlo/report/replay.py` generates code that imports `requests` (for the thin client). This is correct -- the generated code is for the user, not for kahlo itself.
6. **No `README.md`** at the project root (only `CLAUDE.md`). A GitHub-facing README would help new users.

### Missing for public release

- LICENSE file
- README.md (GitHub-facing)
- `.gitignore` should verify `sessions/` directory is excluded (it is mentioned as gitignored in CLAUDE.md)
- GitHub Actions CI configuration for running tests
- Version pinning in `pyproject.toml` for reproducible builds (current ranges like `>=17.0` are fine for development but loose for release)

---

## 8. Recommendations (Future improvements)

### R-1. Add a `kahlo config` command for persistent settings

Store jadx path, default duration, stealth level, preferred scripts, etc. in `~/.config/kahlo/config.toml`.

### R-2. Add `@pytest.mark.device` decorator for device-dependent tests

Skip device tests automatically when no device is connected instead of letting them fail.

### R-3. Add HTTP/2 frame capture

The current traffic hooks capture HTTP/1.1 from SSL streams. Many modern apps use HTTP/2 which multiplexes frames and cannot be parsed with the current line-based HTTP parser. Consider hooking at the OkHttp3 internal HTTP/2 frame layer.

### R-4. Add a formal event schema

Define a Pydantic model for Frida events and validate incoming events in `Session.on_message()`. This catches JS-Python data format mismatches early.

### R-5. Consider adding `httpx` as an alternative to the generated `requests` client

The generated thin client uses `requests`. Since `httpx` supports HTTP/2, it might be more appropriate for modern APIs. This could be a template option.

### R-6. Add session compression

Large sessions (>10MB JSON) are common. Compressing with gzip on save and auto-detecting on load would reduce disk usage.

---

## Summary

| Category | Count |
|----------|-------|
| Critical | 3 |
| Important | 11 |
| Minor | 10 |
| Recommendations | 6 |

The project is in a solid state for a single-session build. The architecture is clean and the domain expertise is evident throughout. The critical issues (command injection, memory leak, language inconsistency) should be addressed before publishing. The important issues are quality-of-life improvements that would prevent subtle bugs and improve maintainability.

Overall assessment: **Good quality, ready for GitHub after addressing the 3 critical issues.**
