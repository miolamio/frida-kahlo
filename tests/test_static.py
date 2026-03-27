"""Tests for static code analyzer — regex patterns and jadx output scanning."""
import os
import tempfile

import pytest


# --- URL Pattern Tests ---


class TestURLPatterns:
    def test_standard_https_url(self):
        from kahlo.analyze.static import URL_PATTERNS
        line = 'String url = "https://api.example.com/v1/data";'
        matches = []
        for p in URL_PATTERNS:
            matches.extend(m.group(0) for m in p.finditer(line))
        assert any("api.example.com" in m for m in matches)

    def test_http_url(self):
        from kahlo.analyze.static import URL_PATTERNS
        line = 'return "http://beacon2.yakitoriya.ru/api/menu";'
        matches = []
        for p in URL_PATTERNS:
            matches.extend(m.group(0) for m in p.finditer(line))
        assert any("beacon2.yakitoriya.ru" in m for m in matches)

    def test_url_with_path_and_params(self):
        from kahlo.analyze.static import URL_PATTERNS
        line = '"https://api.example.com/v2/orders?page=1&limit=20"'
        matches = []
        for p in URL_PATTERNS:
            matches.extend(m.group(0) for m in p.finditer(line))
        assert any("page=1" in m for m in matches)

    def test_no_match_on_plain_text(self):
        from kahlo.analyze.static import URL_PATTERNS
        line = "String name = 'hello world';"
        matches = []
        for p in URL_PATTERNS:
            matches.extend(m.group(0) for m in p.finditer(line))
        assert len(matches) == 0

    def test_skip_w3_urls(self):
        from kahlo.analyze.static import _URL_SKIP_PREFIXES
        url = "http://www.w3.org/2001/XMLSchema"
        assert any(url.startswith(p) for p in _URL_SKIP_PREFIXES)

    def test_skip_android_schema_urls(self):
        from kahlo.analyze.static import _URL_SKIP_PREFIXES
        url = "http://schemas.android.com/apk/res/android"
        assert any(url.startswith(p) for p in _URL_SKIP_PREFIXES)


# --- Secret Pattern Tests ---


class TestSecretPatterns:
    def test_api_key_assignment(self):
        from kahlo.analyze.static import SECRET_PATTERNS
        line = 'static final String API_KEY = "sk_live_1234567890abcdef";'
        found = False
        for pattern, name, confidence in SECRET_PATTERNS:
            if pattern.search(line):
                found = True
                break
        assert found

    def test_google_api_key(self):
        from kahlo.analyze.static import SECRET_PATTERNS
        line = '"AIzaSyB1234567890abcdefghijklmnopqrstuvw"'
        found = False
        for pattern, name, confidence in SECRET_PATTERNS:
            m = pattern.search(line)
            if m and name == "google_api_key":
                found = True
                break
        assert found

    def test_stripe_key(self):
        from kahlo.analyze.static import SECRET_PATTERNS
        line = 'String key = "sk-1234567890abcdefghijklmnop";'
        found = False
        for pattern, name, confidence in SECRET_PATTERNS:
            m = pattern.search(line)
            if m and name == "stripe_key":
                found = True
                break
        assert found

    def test_bearer_token(self):
        from kahlo.analyze.static import SECRET_PATTERNS
        line = '"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"'
        found = False
        for pattern, name, confidence in SECRET_PATTERNS:
            m = pattern.search(line)
            if m and name == "bearer_token":
                found = True
                break
        assert found

    def test_hex_key_32_chars(self):
        from kahlo.analyze.static import SECRET_PATTERNS
        line = 'String key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";'
        found = False
        for pattern, name, confidence in SECRET_PATTERNS:
            m = pattern.search(line)
            if m and name == "hex_key":
                found = True
                break
        assert found

    def test_no_false_positive_short_string(self):
        from kahlo.analyze.static import _is_secret_false_positive
        assert _is_secret_false_positive("short")
        assert _is_secret_false_positive("1234567")  # < 8 chars

    def test_no_false_positive_placeholder(self):
        from kahlo.analyze.static import _is_secret_false_positive
        assert _is_secret_false_positive("YOUR_API_KEY_HERE")
        assert _is_secret_false_positive("xxxxxxxxyyyyyyyy")

    def test_real_key_not_false_positive(self):
        from kahlo.analyze.static import _is_secret_false_positive
        assert not _is_secret_false_positive("sk_live_1234567890abcdef")
        assert not _is_secret_false_positive("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")


# --- Crypto Pattern Tests ---


class TestCryptoPatterns:
    def test_cipher_get_instance(self):
        from kahlo.analyze.static import CRYPTO_PATTERNS
        line = 'Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");'
        found = False
        algo = None
        for pattern, api_type, usage in CRYPTO_PATTERNS:
            m = pattern.search(line)
            if m and api_type == "cipher":
                found = True
                algo = m.group(1)
                break
        assert found
        assert algo == "AES/CBC/PKCS5Padding"

    def test_mac_get_instance(self):
        from kahlo.analyze.static import CRYPTO_PATTERNS
        line = 'Mac mac = Mac.getInstance("HmacSHA256");'
        found = False
        for pattern, api_type, usage in CRYPTO_PATTERNS:
            m = pattern.search(line)
            if m and api_type == "mac":
                found = True
                assert m.group(1) == "HmacSHA256"
                break
        assert found

    def test_message_digest(self):
        from kahlo.analyze.static import CRYPTO_PATTERNS
        line = 'MessageDigest md = MessageDigest.getInstance("SHA-256");'
        found = False
        for pattern, api_type, usage in CRYPTO_PATTERNS:
            m = pattern.search(line)
            if m and api_type == "hash":
                found = True
                assert m.group(1) == "SHA-256"
                break
        assert found

    def test_key_generator(self):
        from kahlo.analyze.static import CRYPTO_PATTERNS
        line = 'KeyGenerator.getInstance("AES")'
        found = False
        for pattern, api_type, usage in CRYPTO_PATTERNS:
            m = pattern.search(line)
            if m and api_type == "keygen":
                found = True
                break
        assert found

    def test_signature_get_instance(self):
        from kahlo.analyze.static import CRYPTO_PATTERNS
        line = 'Signature.getInstance("SHA256withRSA")'
        found = False
        for pattern, api_type, usage in CRYPTO_PATTERNS:
            m = pattern.search(line)
            if m and api_type == "signature":
                found = True
                assert m.group(1) == "SHA256withRSA"
                break
        assert found

    def test_secret_key_spec(self):
        from kahlo.analyze.static import CRYPTO_PATTERNS
        line = 'new SecretKeySpec(keyBytes, "AES");'
        found = False
        for pattern, api_type, usage in CRYPTO_PATTERNS:
            m = pattern.search(line)
            if m and api_type == "secret_key_spec":
                found = True
                break
        assert found


# --- Obfuscation Tests ---


class TestObfuscation:
    def test_no_obfuscation(self):
        """Classes with normal package names should report no obfuscation."""
        from kahlo.analyze.static import _assess_obfuscation
        with tempfile.TemporaryDirectory() as tmpdir:
            sources = os.path.join(tmpdir, "sources")
            # Create normal package structure
            pkg = os.path.join(sources, "com", "example", "app")
            os.makedirs(pkg)
            for name in ["MainActivity.java", "ApiClient.java", "Utils.java"]:
                with open(os.path.join(pkg, name), "w") as f:
                    f.write("// class\n")

            files = [
                os.path.join(pkg, "MainActivity.java"),
                os.path.join(pkg, "ApiClient.java"),
                os.path.join(pkg, "Utils.java"),
            ]
            info = _assess_obfuscation(tmpdir, files)
            assert info.level == "none"

    def test_heavy_obfuscation(self):
        """Most classes with single-letter packages should report heavy."""
        from kahlo.analyze.static import _assess_obfuscation
        with tempfile.TemporaryDirectory() as tmpdir:
            sources = os.path.join(tmpdir, "sources")
            # Create obfuscated package structure
            for pkg_name in ["a/b", "c/d", "e/f", "g/h", "i/j"]:
                pkg = os.path.join(sources, pkg_name)
                os.makedirs(pkg, exist_ok=True)
                with open(os.path.join(pkg, "a.java"), "w") as f:
                    f.write("// class\n")

            # Add one normal class
            normal_pkg = os.path.join(sources, "com", "example")
            os.makedirs(normal_pkg, exist_ok=True)
            with open(os.path.join(normal_pkg, "App.java"), "w") as f:
                f.write("// class\n")

            files = []
            for root, _dirs, fnames in os.walk(sources):
                for fn in fnames:
                    if fn.endswith(".java"):
                        files.append(os.path.join(root, fn))

            info = _assess_obfuscation(tmpdir, files)
            assert info.level == "heavy"
            assert info.short_class_count >= 4

    def test_proguard_file_detected(self):
        """Presence of proguard-rules.txt should be detected."""
        from kahlo.analyze.static import _assess_obfuscation
        with tempfile.TemporaryDirectory() as tmpdir:
            sources = os.path.join(tmpdir, "sources", "com", "example")
            os.makedirs(sources)
            with open(os.path.join(sources, "App.java"), "w") as f:
                f.write("// class\n")
            with open(os.path.join(tmpdir, "proguard-rules.txt"), "w") as f:
                f.write("-keep class com.example.**\n")

            files = [os.path.join(sources, "App.java")]
            info = _assess_obfuscation(tmpdir, files)
            assert info.tool == "proguard"
            assert "Found proguard-rules.txt" in info.evidence


# --- Integration Tests (with mock files) ---


class TestStaticAnalyzerIntegration:
    def test_empty_directory(self):
        """Empty directory should return empty report."""
        from kahlo.analyze.static import analyze_static
        with tempfile.TemporaryDirectory() as tmpdir:
            report = analyze_static(tmpdir)
            assert report.files_scanned == 0
            assert len(report.urls) == 0

    def test_nonexistent_directory(self):
        """Nonexistent directory should return empty report."""
        from kahlo.analyze.static import analyze_static
        report = analyze_static("/nonexistent/path/to/jadx")
        assert report.files_scanned == 0

    def test_scan_mock_java_files(self):
        """Scan mock Java files with known patterns."""
        from kahlo.analyze.static import analyze_static
        with tempfile.TemporaryDirectory() as tmpdir:
            sources = os.path.join(tmpdir, "sources", "com", "example")
            os.makedirs(sources)

            # Create a Java file with URLs and crypto
            content = '''
package com.example;

public class ApiClient {
    private static final String BASE_URL = "https://api.example.com/v2";
    private static final String CDN_URL = "https://cdn.example.com/images";

    public byte[] encrypt(byte[] data, byte[] key) {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        return cipher.doFinal(data);
    }

    public String hash(String input) {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return hex(md.digest(input.getBytes()));
    }
}
'''
            with open(os.path.join(sources, "ApiClient.java"), "w") as f:
                f.write(content)

            # Create a file with secrets
            secrets_content = '''
package com.example;

public class Config {
    public static final String API_KEY = "AIzaSyB1234567890abcdefghijklmnopqrstuvw";
    public static final String SECRET = "sk-abcdefghijklmnopqrstuvwxyz1234";
    private String token = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
}
'''
            with open(os.path.join(sources, "Config.java"), "w") as f:
                f.write(secrets_content)

            report = analyze_static(tmpdir)

            # Should find URLs
            assert len(report.urls) >= 2
            url_values = {u.url for u in report.urls}
            assert any("api.example.com" in u for u in url_values)
            assert any("cdn.example.com" in u for u in url_values)

            # Should find crypto
            assert len(report.crypto_usage) >= 2
            algos = {c.algorithm for c in report.crypto_usage}
            assert "AES/CBC/PKCS5Padding" in algos
            assert "SHA-256" in algos

            # Should find secrets
            assert len(report.secrets) >= 1
            secret_names = {s.name for s in report.secrets}
            assert "google_api_key" in secret_names or "stripe_key" in secret_names

            # Should find interesting classes
            assert len(report.interesting_classes) >= 1
            assert any("ApiClient" in cls for cls in report.interesting_classes)

            # Files scanned
            assert report.files_scanned == 2

    def test_skip_large_files(self):
        """Files larger than _MAX_FILE_SIZE should be skipped."""
        from kahlo.analyze.static import analyze_static, _MAX_FILE_SIZE
        with tempfile.TemporaryDirectory() as tmpdir:
            sources = os.path.join(tmpdir, "sources", "com", "example")
            os.makedirs(sources)

            # Create a huge file
            with open(os.path.join(sources, "Huge.java"), "w") as f:
                f.write("// filler\n" * (_MAX_FILE_SIZE // 10 + 1))

            # Create a normal file
            with open(os.path.join(sources, "Normal.java"), "w") as f:
                f.write('String url = "https://api.example.com/v1";\n')

            report = analyze_static(tmpdir)
            assert report.files_scanned == 1
            assert report.files_skipped == 1

    def test_kotlin_files_scanned(self):
        """Kotlin .kt files should also be scanned."""
        from kahlo.analyze.static import analyze_static
        with tempfile.TemporaryDirectory() as tmpdir:
            sources = os.path.join(tmpdir, "sources", "com", "example")
            os.makedirs(sources)

            content = '''
package com.example

class AuthService {
    val apiUrl = "https://auth.example.com/login"

    fun sign(data: String): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        return mac.doFinal(data.toByteArray())
    }
}
'''
            with open(os.path.join(sources, "AuthService.kt"), "w") as f:
                f.write(content)

            report = analyze_static(tmpdir)
            assert report.files_scanned == 1
            assert len(report.urls) >= 1
            assert len(report.crypto_usage) >= 1
            assert any("HmacSHA256" in c.algorithm for c in report.crypto_usage)

    def test_url_deduplication(self):
        """Same URL in multiple files should only appear once."""
        from kahlo.analyze.static import analyze_static
        with tempfile.TemporaryDirectory() as tmpdir:
            sources = os.path.join(tmpdir, "sources", "com", "example")
            os.makedirs(sources)

            for i in range(3):
                with open(os.path.join(sources, f"File{i}.java"), "w") as f:
                    f.write(f'String url = "https://api.example.com/endpoint";\n')

            report = analyze_static(tmpdir)
            url_values = [u.url for u in report.urls]
            assert url_values.count("https://api.example.com/endpoint") == 1


# --- String Extraction Tests ---


class TestStringExtraction:
    def test_extract_from_nonexistent_file(self):
        from kahlo.prepare.strings import extract_strings
        result = extract_strings("/nonexistent/file.apk")
        assert result.total_count == 0
        assert len(result.urls) == 0

    def test_extract_from_real_apk(self):
        """Extract strings from real APK if available."""
        apk_path = os.environ.get("KAHLO_TEST_APK_FILE", "")
        if not apk_path or not os.path.isfile(apk_path):
            pytest.skip("KAHLO_TEST_APK_FILE not set")

        from kahlo.prepare.strings import extract_strings
        result = extract_strings(apk_path)
        assert result.total_count > 0
        assert len(result.urls) > 0
        # Should find at least some URLs from the binary
        url_text = " ".join(result.urls)
        # The APK likely contains some URLs
        assert "http" in url_text.lower()


# --- Real jadx Output Test ---


class TestRealJadxOutput:
    """Integration tests with real jadx output (skipped if not available)."""

    JADX_DIR = "/tmp/yakitoriya-jadx"

    @pytest.fixture(autouse=True)
    def check_jadx_output(self):
        if not os.path.isdir(self.JADX_DIR):
            pytest.skip("jadx output not available at /tmp/yakitoriya-jadx")

    def test_real_jadx_scan(self):
        from kahlo.analyze.static import analyze_static
        report = analyze_static(self.JADX_DIR)
        assert report.files_scanned > 0
        # Real app should have URLs
        assert len(report.urls) > 0

    def test_real_jadx_crypto(self):
        from kahlo.analyze.static import analyze_static
        report = analyze_static(self.JADX_DIR)
        # Real app uses crypto (AES, HMAC, etc.)
        assert len(report.crypto_usage) > 0

    def test_real_jadx_obfuscation(self):
        from kahlo.analyze.static import analyze_static
        report = analyze_static(self.JADX_DIR)
        # Should determine some obfuscation level
        assert report.obfuscation.total_class_count > 0

    def test_real_jadx_interesting_classes(self):
        from kahlo.analyze.static import analyze_static
        report = analyze_static(self.JADX_DIR)
        # Real app should have some interesting classes
        assert len(report.interesting_classes) > 0


# --- Markdown Integration Test ---


class TestMarkdownStaticSection:
    def test_markdown_without_static(self):
        """generate_markdown should work without static report (backward compat)."""
        from kahlo.analyze.auth import AuthFlowReport
        from kahlo.analyze.netmodel import NetmodelReport
        from kahlo.analyze.patterns import PatternsReport
        from kahlo.analyze.recon import ReconReport
        from kahlo.analyze.traffic import TrafficReport
        from kahlo.analyze.vault import VaultReport
        from kahlo.report.markdown import generate_markdown

        session = {
            "package": "com.test.app",
            "session_id": "test_123",
            "started_at": "2026-01-01T00:00:00",
            "ended_at": "2026-01-01T00:01:00",
            "event_count": 0,
            "stats": {"by_module": {}, "by_type": {}},
        }
        md = generate_markdown(
            session,
            TrafficReport(),
            VaultReport(),
            ReconReport(),
            NetmodelReport(),
            PatternsReport(),
        )
        assert "## 7. SDK Inventory" in md
        assert "## 6b. Static Code Analysis" not in md

    def test_markdown_with_static(self):
        """generate_markdown should include static section when provided."""
        from kahlo.analyze.auth import AuthFlowReport
        from kahlo.analyze.netmodel import NetmodelReport
        from kahlo.analyze.patterns import PatternsReport
        from kahlo.analyze.recon import ReconReport
        from kahlo.analyze.static import (
            CryptoFinding,
            ObfuscationInfo,
            SecretFinding,
            StaticReport,
            URLFinding,
        )
        from kahlo.analyze.traffic import TrafficReport
        from kahlo.analyze.vault import VaultReport
        from kahlo.report.markdown import generate_markdown

        session = {
            "package": "com.test.app",
            "session_id": "test_123",
            "started_at": "2026-01-01T00:00:00",
            "ended_at": "2026-01-01T00:01:00",
            "event_count": 0,
            "stats": {"by_module": {}, "by_type": {}},
        }
        static = StaticReport(
            urls=[URLFinding(url="https://api.test.com", file="Test.java", line=10)],
            secrets=[SecretFinding(
                name="api_key", value="AIzaTest1234567890", file="Config.java",
                line=5, pattern="google_api_key", confidence="high",
            )],
            crypto_usage=[CryptoFinding(
                algorithm="AES/CBC/PKCS5Padding", file="Crypto.java",
                line=20, context="Cipher.getInstance(\"AES/CBC/PKCS5Padding\")", usage="encrypt/decrypt",
            )],
            obfuscation=ObfuscationInfo(level="light", tool="proguard", evidence=["test"]),
            files_scanned=100,
        )
        md = generate_markdown(
            session,
            TrafficReport(),
            VaultReport(),
            ReconReport(),
            NetmodelReport(),
            PatternsReport(),
            static=static,
        )
        assert "## 6b. Static Code Analysis" in md
        assert "https://api.test.com" in md
        assert "AES/CBC/PKCS5Padding" in md
        assert "api_key" in md
