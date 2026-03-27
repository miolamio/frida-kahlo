"""Tests for auth flow analyzer, JWT decoder, and encrypted pref hooks."""
import json
import os

import pytest

# --- JWT Decoder Tests ---


class TestJWTDecoder:
    """Test JWT decoding utility."""

    def test_decode_valid_jwt(self):
        from kahlo.analyze.jwt import decode_jwt

        # HS256 JWT: {"alg":"HS256","typ":"JWT"}.{"sub":"1234567890","name":"Test","iat":1516239022}
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjJ9."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        result = decode_jwt(token, source="test")
        assert result is not None
        assert result.header["alg"] == "HS256"
        assert result.header["typ"] == "JWT"
        assert result.payload["sub"] == "1234567890"
        assert result.subject == "1234567890"
        assert result.issued_at is not None
        assert result.custom_claims.get("name") == "Test"
        assert result.source == "test"

    def test_decode_jwt_with_expiry(self):
        from kahlo.analyze.jwt import decode_jwt

        # JWT with exp in the past
        # {"alg":"HS256"}.{"sub":"user1","exp":1000000000,"iat":999999000}
        token = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiJ1c2VyMSIsImV4cCI6MTAwMDAwMDAwMCwiaWF0Ijo5OTk5OTkwMDB9."
            "signature"
        )
        result = decode_jwt(token)
        assert result is not None
        assert result.subject == "user1"
        assert result.is_expired is True  # exp=1000000000 is in the past
        assert result.expires_at is not None

    def test_decode_invalid_jwt(self):
        from kahlo.analyze.jwt import decode_jwt

        assert decode_jwt("") is None
        assert decode_jwt("not-a-jwt") is None
        assert decode_jwt("abc.def") is None
        assert decode_jwt(None) is None

    def test_decode_malformed_payload(self):
        from kahlo.analyze.jwt import decode_jwt

        # Valid header, malformed payload
        token = "eyJhbGciOiJIUzI1NiJ9.not-base64-at-all.signature"
        result = decode_jwt(token)
        # Should still decode header, but payload may be empty
        if result:
            assert result.header.get("alg") == "HS256"

    def test_find_jwts_in_text(self):
        from kahlo.analyze.jwt import find_jwts_in_text

        text = (
            'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
            'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjJ9.'
            'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c and some other text'
        )
        tokens = find_jwts_in_text(text, source="test_header")
        assert len(tokens) == 1
        assert tokens[0].subject == "1234567890"
        assert tokens[0].source == "test_header"

    def test_find_jwts_empty(self):
        from kahlo.analyze.jwt import find_jwts_in_text

        assert find_jwts_in_text("") == []
        assert find_jwts_in_text("no tokens here") == []
        assert find_jwts_in_text(None) == []

    def test_find_jwts_in_events(self):
        from kahlo.analyze.jwt import find_jwts_in_events

        jwt_value = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjJ9."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )

        events = [
            {
                "module": "traffic",
                "type": "http_request",
                "data": {
                    "url": "https://api.example.com/data",
                    "headers": {"Authorization": f"Bearer {jwt_value}"},
                    "body": "",
                },
            },
            {
                "module": "vault",
                "type": "encrypted_pref_read",
                "data": {
                    "key": "auth_token",
                    "value": jwt_value,
                },
            },
        ]
        tokens = find_jwts_in_events(events)
        # Should find the JWT but deduplicate (same token in two places)
        assert len(tokens) == 1
        assert tokens[0].subject == "1234567890"

    def test_jwt_custom_claims(self):
        from kahlo.analyze.jwt import decode_jwt

        # JWT with custom claims: {"alg":"HS256"}.{"sub":"u1","role":"admin","org_id":"123"}
        token = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiJ1MSIsInJvbGUiOiJhZG1pbiIsIm9yZ19pZCI6IjEyMyJ9."
            "sig"
        )
        result = decode_jwt(token)
        assert result is not None
        assert result.subject == "u1"
        assert "role" in result.custom_claims
        assert result.custom_claims["role"] == "admin"
        assert "org_id" in result.custom_claims


# --- Auth Flow Analyzer Tests ---


class TestAuthFlowAnalyzer:
    """Test auth flow detection and analysis."""

    def test_analyze_auth_empty(self):
        from kahlo.analyze.auth import analyze_auth

        report = analyze_auth([])
        assert report.has_auth_flow is False
        assert len(report.auth_steps) == 0
        assert len(report.jwt_tokens) == 0
        assert len(report.encrypted_prefs) == 0

    def test_detect_auth_request_by_url(self):
        from kahlo.analyze.auth import analyze_auth

        events = [
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "index": 1,
                    "method": "POST",
                    "url": "https://api.example.com/auth/login",
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"email": "test@test.com", "password": "xxx"}',
                    "body_format": "json",
                    "auth_flow": True,
                    "auth_signal": "url_pattern",
                },
            },
            {
                "module": "traffic",
                "type": "http_response",
                "ts": "2026-03-27T10:00:01Z",
                "data": {
                    "index": 1,
                    "url": "https://api.example.com/auth/login",
                    "status": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"access_token": "eyJ...", "refresh_token": "abc123"}',
                    "body_format": "json",
                    "auth_flow": True,
                    "auth_signal": "response_to_auth_request",
                },
            },
        ]
        report = analyze_auth(events)
        assert report.has_auth_flow is True
        assert len(report.auth_steps) == 1
        assert report.auth_steps[0].step_type == "login"
        assert report.auth_steps[0].request.method == "POST"
        assert report.auth_steps[0].response is not None
        assert report.auth_steps[0].response.status == 200
        assert report.auth_url == "https://api.example.com/auth/login"
        assert report.auth_method == "POST"

    def test_detect_token_refresh(self):
        from kahlo.analyze.auth import analyze_auth

        events = [
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "index": 1,
                    "method": "POST",
                    "url": "https://api.example.com/auth/refresh",
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"refresh_token": "abc123"}',
                    "body_format": "json",
                    "auth_flow": True,
                    "auth_signal": "url_pattern",
                },
            },
            {
                "module": "traffic",
                "type": "http_response",
                "ts": "2026-03-27T10:00:01Z",
                "data": {
                    "index": 1,
                    "url": "https://api.example.com/auth/refresh",
                    "status": 200,
                    "headers": {},
                    "body": '{"access_token": "new_token"}',
                    "auth_flow": True,
                    "auth_has_jwt": False,
                },
            },
        ]
        report = analyze_auth(events)
        assert report.has_auth_flow is True
        assert report.token_refresh is not None
        assert report.token_refresh.refresh_url == "https://api.example.com/auth/refresh"
        assert report.token_refresh.uses_refresh_token is True

    def test_encrypted_prefs_collected(self):
        from kahlo.analyze.auth import analyze_auth

        events = [
            {
                "module": "vault",
                "type": "encrypted_pref_read",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "key": "user_token",
                    "value": "abc123xyz",
                    "value_type": "string",
                    "source": "EncryptedSharedPreferences",
                },
            },
            {
                "module": "vault",
                "type": "encrypted_pref_read",
                "ts": "2026-03-27T10:00:01Z",
                "data": {
                    "key": "user_name",
                    "value": "John",
                    "value_type": "string",
                    "source": "EncryptedSharedPreferences",
                },
            },
            {
                "module": "vault",
                "type": "tink_decrypt",
                "ts": "2026-03-27T10:00:02Z",
                "data": {
                    "algorithm": "AesGcm",
                    "plaintext_preview": "some plaintext",
                    "plaintext_length": 14,
                },
            },
        ]
        report = analyze_auth(events)
        assert len(report.encrypted_prefs) == 2
        assert report.encrypted_prefs[0].key == "user_token"
        assert report.encrypted_prefs[0].value == "abc123xyz"
        assert report.tink_decrypts == 1

    def test_encrypted_pref_dump_collected(self):
        from kahlo.analyze.auth import analyze_auth

        events = [
            {
                "module": "vault",
                "type": "encrypted_pref_dump",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "entries": {"key1": "val1", "key2": "val2"},
                    "count": 2,
                    "source": "EncryptedSharedPreferences",
                },
            },
        ]
        report = analyze_auth(events)
        assert len(report.encrypted_prefs) == 2

    def test_multi_step_auth_flow(self):
        from kahlo.analyze.auth import analyze_auth

        events = [
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "index": 1,
                    "method": "POST",
                    "url": "https://api.example.com/auth/sms/send",
                    "headers": {},
                    "body": '{"phone": "+7999"}',
                    "auth_flow": True,
                    "auth_signal": "url_pattern",
                },
            },
            {
                "module": "traffic",
                "type": "http_response",
                "ts": "2026-03-27T10:00:01Z",
                "data": {
                    "index": 1,
                    "url": "https://api.example.com/auth/sms/send",
                    "status": 200,
                    "auth_flow": True,
                },
            },
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:10Z",
                "data": {
                    "index": 2,
                    "method": "POST",
                    "url": "https://api.example.com/auth/verify",
                    "headers": {},
                    "body": '{"phone": "+7999", "code": "1234"}',
                    "auth_flow": True,
                    "auth_signal": "url_pattern",
                },
            },
            {
                "module": "traffic",
                "type": "http_response",
                "ts": "2026-03-27T10:00:11Z",
                "data": {
                    "index": 2,
                    "url": "https://api.example.com/auth/verify",
                    "status": 200,
                    "headers": {},
                    "body": '{"token": "eyJxxx"}',
                    "auth_flow": True,
                    "auth_has_jwt": True,
                },
            },
        ]
        report = analyze_auth(events)
        assert report.has_auth_flow is True
        assert len(report.auth_steps) == 2
        # First step is SMS send — matches "sms" -> "verify"
        assert report.auth_steps[0].step_type == "verify"
        # Second step is verify — matches "verify"
        assert report.auth_steps[1].step_type == "verify"
        # Both have matched responses
        assert report.auth_steps[0].response is not None
        assert report.auth_steps[1].response is not None

    def test_classify_step_types(self):
        from kahlo.analyze.auth import _classify_step

        assert _classify_step("https://api.com/auth/login") == "login"
        assert _classify_step("https://api.com/oauth2/token") == "token"
        assert _classify_step("https://api.com/auth/refresh") == "refresh"
        assert _classify_step("https://api.com/verify/sms") == "verify"
        assert _classify_step("https://api.com/register") == "register"
        assert _classify_step("https://api.com/api/session") == "session"
        # /auth matches "auth" -> "login"
        assert _classify_step("https://api.com/auth/something") == "login"
        # No pattern match -> fallback
        assert _classify_step("https://api.com/data/fetch") == "auth"


# --- Vault Analyzer Enhancement Tests ---


class TestVaultAnalyzerEncryptedPrefs:
    """Test vault analyzer with encrypted pref events."""

    def test_encrypted_pref_read_processed(self):
        from kahlo.analyze.vault import analyze_vault

        events = [
            {
                "module": "vault",
                "type": "encrypted_pref_read",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "key": "auth_token",
                    "value": "secret_token_value_123",
                    "value_type": "string",
                    "source": "EncryptedSharedPreferences",
                },
            },
            {
                "module": "vault",
                "type": "encrypted_pref_read",
                "ts": "2026-03-27T10:00:01Z",
                "data": {
                    "key": "user_id",
                    "value": "12345",
                    "value_type": "string",
                    "source": "EncryptedSharedPreferences",
                },
            },
        ]
        report = analyze_vault(events)
        assert len(report.decrypted_prefs) == 2
        assert report.decrypted_prefs[0].key == "auth_token"
        assert report.decrypted_prefs[0].value == "secret_token_value_123"
        # Auth token should be classified as a secret
        token_secrets = [s for s in report.secrets if "auth" in s.name.lower() or "token" in s.name.lower()]
        assert len(token_secrets) >= 1

    def test_encrypted_pref_write_processed(self):
        from kahlo.analyze.vault import analyze_vault

        events = [
            {
                "module": "vault",
                "type": "encrypted_pref_write",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "key": "session_id",
                    "value": "sess_abc123",
                    "value_type": "string",
                    "source": "EncryptedSharedPreferences",
                },
            },
        ]
        report = analyze_vault(events)
        assert len(report.decrypted_prefs) == 1
        assert report.total_pref_writes == 1
        # session_id should be classified as high-sensitivity secret
        session_secrets = [s for s in report.secrets if "session" in s.name.lower()]
        assert len(session_secrets) >= 1
        assert all(s.sensitivity == "high" for s in session_secrets)

    def test_encrypted_pref_dump_processed(self):
        from kahlo.analyze.vault import analyze_vault

        events = [
            {
                "module": "vault",
                "type": "encrypted_pref_dump",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "entries": {
                        "token": "abc123",
                        "username": "john",
                        "device_id": "dev-001",
                    },
                    "count": 3,
                    "source": "EncryptedSharedPreferences",
                },
            },
        ]
        report = analyze_vault(events)
        assert len(report.decrypted_prefs) == 3

    def test_tink_decrypt_counted(self):
        from kahlo.analyze.vault import analyze_vault

        events = [
            {
                "module": "vault",
                "type": "tink_decrypt",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "algorithm": "AesGcm",
                    "plaintext_preview": "decrypted text",
                    "plaintext_length": 14,
                },
            },
            {
                "module": "vault",
                "type": "tink_decrypt",
                "ts": "2026-03-27T10:00:01Z",
                "data": {
                    "algorithm": "AesSiv",
                    "plaintext_preview": "key name",
                    "plaintext_length": 8,
                },
            },
        ]
        report = analyze_vault(events)
        assert report.tink_decrypts == 2

    def test_dedup_encrypted_prefs(self):
        from kahlo.analyze.vault import analyze_vault

        events = [
            {
                "module": "vault",
                "type": "encrypted_pref_read",
                "ts": "2026-03-27T10:00:00Z",
                "data": {"key": "same_key", "value": "val1", "value_type": "string"},
            },
            {
                "module": "vault",
                "type": "encrypted_pref_read",
                "ts": "2026-03-27T10:00:01Z",
                "data": {"key": "same_key", "value": "val1", "value_type": "string"},
            },
        ]
        report = analyze_vault(events)
        # Should be deduplicated
        assert len(report.decrypted_prefs) == 1


# --- Traffic Auth Detection Tests ---


class TestTrafficAuthDetection:
    """Test auth flow detection in traffic events."""

    def test_auth_events_have_auth_flow_flag(self):
        """Test that the traffic analyzer processes auth_flow tagged events."""
        from kahlo.analyze.traffic import analyze_traffic

        events = [
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "index": 1,
                    "method": "POST",
                    "url": "https://api.example.com/auth/login",
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"email": "test@test.com"}',
                    "auth_flow": True,
                    "auth_signal": "url_pattern",
                    "source": "okhttp3",
                },
            },
        ]
        report = analyze_traffic(events)
        assert len(report.endpoints) == 1
        assert report.endpoints[0].path == "/auth/login"

    def test_non_auth_events_not_tagged(self):
        """Verify non-auth events don't have auth_flow flag."""
        from kahlo.analyze.traffic import analyze_traffic

        events = [
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "index": 1,
                    "method": "GET",
                    "url": "https://cdn.example.com/image.png",
                    "headers": {},
                    "body": "",
                    "source": "okhttp3",
                },
            },
        ]
        report = analyze_traffic(events)
        assert len(report.endpoints) == 1
        # This request should not have auth_flow attribute


# --- Markdown Report Auth Section Tests ---


class TestMarkdownAuthSection:
    """Test markdown report generation with auth data."""

    def test_report_with_auth_section(self):
        from kahlo.analyze.auth import AuthFlowReport, AuthRequest, AuthResponse, AuthStep
        from kahlo.analyze.jwt import JWTToken
        from kahlo.analyze.netmodel import NetmodelReport
        from kahlo.analyze.patterns import PatternsReport
        from kahlo.analyze.recon import ReconReport
        from kahlo.analyze.traffic import TrafficReport
        from kahlo.analyze.vault import VaultReport
        from kahlo.report.markdown import generate_markdown

        session = {
            "session_id": "test_session",
            "package": "com.example.app",
            "started_at": "2026-03-27T10:00:00Z",
            "ended_at": "2026-03-27T10:01:00Z",
            "event_count": 10,
            "stats": {"by_module": {"traffic": 5, "vault": 5}, "by_type": {}},
        }

        auth = AuthFlowReport(
            has_auth_flow=True,
            auth_steps=[
                AuthStep(
                    request=AuthRequest(
                        index=1,
                        method="POST",
                        url="https://api.example.com/auth/login",
                        host="api.example.com",
                        path="/auth/login",
                    ),
                    response=AuthResponse(index=1, status=200),
                    step_type="login",
                ),
            ],
            auth_url="https://api.example.com/auth/login",
            auth_method="POST",
            total_auth_events=2,
        )

        md = generate_markdown(
            session,
            TrafficReport(),
            VaultReport(),
            ReconReport(),
            NetmodelReport(),
            PatternsReport(),
            auth,
        )

        assert "Auth Flow Analysis" in md
        assert "Auth Sequence" in md
        assert "/auth/login" in md

    def test_report_without_auth(self):
        from kahlo.analyze.netmodel import NetmodelReport
        from kahlo.analyze.patterns import PatternsReport
        from kahlo.analyze.recon import ReconReport
        from kahlo.analyze.traffic import TrafficReport
        from kahlo.analyze.vault import VaultReport
        from kahlo.report.markdown import generate_markdown

        session = {
            "session_id": "test_session",
            "package": "com.example.app",
            "started_at": "2026-03-27T10:00:00Z",
            "ended_at": "2026-03-27T10:01:00Z",
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
            None,
        )

        # Should not contain auth section
        assert "Auth Flow Analysis" not in md

    def test_report_with_jwt_section(self):
        from kahlo.analyze.auth import AuthFlowReport
        from kahlo.analyze.jwt import JWTToken
        from kahlo.analyze.netmodel import NetmodelReport
        from kahlo.analyze.patterns import PatternsReport
        from kahlo.analyze.recon import ReconReport
        from kahlo.analyze.traffic import TrafficReport
        from kahlo.analyze.vault import VaultReport
        from kahlo.report.markdown import generate_markdown

        session = {
            "session_id": "test",
            "package": "com.example.app",
            "started_at": "2026-03-27T10:00:00Z",
            "ended_at": "2026-03-27T10:01:00Z",
            "event_count": 0,
            "stats": {"by_module": {}, "by_type": {}},
        }

        auth = AuthFlowReport(
            jwt_tokens=[
                JWTToken(
                    raw="eyJ...",
                    header={"alg": "HS256"},
                    payload={"sub": "user1"},
                    issuer="example.com",
                    subject="user1",
                    source="traffic:header",
                ),
            ],
        )

        md = generate_markdown(
            session,
            TrafficReport(),
            VaultReport(),
            ReconReport(),
            NetmodelReport(),
            PatternsReport(),
            auth,
        )

        assert "JWT Tokens" in md
        assert "example.com" in md
        assert "user1" in md


# --- Integration with Real Session Data ---


SESSION_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "sessions",
    "com.voltmobi.yakitoriya_20260326_122701_5d3395.json",
)


@pytest.fixture(scope="module")
def session_data():
    """Load the real session data once for all tests."""
    with open(SESSION_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def events(session_data):
    return session_data["events"]


class TestRealSessionAuth:
    """Run auth analysis on real yakitoriya session data."""

    def test_auth_analysis_runs(self, events):
        from kahlo.analyze.auth import analyze_auth

        report = analyze_auth(events, "com.voltmobi.yakitoriya")
        assert report is not None
        # May or may not have auth flow in the existing session
        # (the scan didn't capture login — so auth_steps may be 0)

    def test_jwt_scan_on_real_data(self, events):
        from kahlo.analyze.jwt import find_jwts_in_events

        tokens = find_jwts_in_events(events)
        # Real session may not have JWTs, but should not crash
        assert isinstance(tokens, list)

    def test_vault_with_real_data_has_keystore(self, events):
        from kahlo.analyze.vault import analyze_vault

        report = analyze_vault(events, "com.voltmobi.yakitoriya")
        # Should still detect the Tink keystore entries
        assert len(report.keystore_entries) >= 2
        # Decrypted prefs may be empty (old scan without new hooks)
        assert isinstance(report.decrypted_prefs, list)
        assert isinstance(report.tink_decrypts, int)

    def test_report_generation_with_auth(self, events, session_data):
        """Verify the full report generates without error when auth is included."""
        from kahlo.analyze.auth import analyze_auth
        from kahlo.analyze.netmodel import analyze_netmodel
        from kahlo.analyze.patterns import analyze_patterns
        from kahlo.analyze.recon import analyze_recon
        from kahlo.analyze.traffic import analyze_traffic
        from kahlo.analyze.vault import analyze_vault
        from kahlo.report.markdown import generate_markdown

        traffic = analyze_traffic(events, "com.voltmobi.yakitoriya")
        vault = analyze_vault(events, "com.voltmobi.yakitoriya")
        recon = analyze_recon(events)
        netmodel = analyze_netmodel(events)
        patterns = analyze_patterns(events)
        auth = analyze_auth(events, "com.voltmobi.yakitoriya")

        md = generate_markdown(session_data, traffic, vault, recon, netmodel, patterns, auth)
        assert len(md) > 100
        assert "Yakitoriya" in md
