"""Tests for analyzers — run against real yakitoriya session data."""
import json
import os

import pytest

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
    """Extract events from session data."""
    return session_data["events"]


# --- Traffic Analyzer Tests ---

class TestTrafficAnalyzer:
    def test_analyze_traffic_returns_report(self, events):
        from kahlo.analyze.traffic import analyze_traffic
        report = analyze_traffic(events, package="com.voltmobi.yakitoriya")
        assert report is not None

    def test_servers_found(self, events):
        from kahlo.analyze.traffic import analyze_traffic
        report = analyze_traffic(events, package="com.voltmobi.yakitoriya")
        assert len(report.servers) >= 5  # At least 5 unique servers
        hosts = {s.host for s in report.servers}
        assert "firebase-settings.crashlytics.com" in hosts
        assert "sentry.inno.co" in hosts
        assert "api.wavesend.ru" in hosts
        assert "beacon2.yakitoriya.ru" in hosts
        assert "api2.branch.io" in hosts

    def test_server_ips(self, events):
        from kahlo.analyze.traffic import analyze_traffic
        report = analyze_traffic(events, package="com.voltmobi.yakitoriya")
        server_map = {s.host: s for s in report.servers}
        assert server_map["sentry.inno.co"].ip == "84.201.136.35"
        assert server_map["api.wavesend.ru"].ip == "82.147.67.99"
        assert server_map["beacon2.yakitoriya.ru"].ip == "178.248.232.193"

    def test_role_detection(self, events):
        from kahlo.analyze.traffic import analyze_traffic
        report = analyze_traffic(events, package="com.voltmobi.yakitoriya")
        server_map = {s.host: s for s in report.servers}
        assert server_map["firebase-settings.crashlytics.com"].role == "crash_analytics"
        assert server_map["sentry.inno.co"].role == "error_reporting"
        assert server_map["api.wavesend.ru"].role == "push_notifications"
        assert server_map["beacon2.yakitoriya.ru"].role == "core_api"
        assert server_map["api2.branch.io"].role == "attribution"

    def test_endpoints_extracted(self, events):
        from kahlo.analyze.traffic import analyze_traffic
        report = analyze_traffic(events, package="com.voltmobi.yakitoriya")
        assert len(report.endpoints) >= 4
        paths = {ep.path for ep in report.endpoints}
        assert "/api/13/envelope/" in paths
        assert "/json/1.3/postEvent" in paths
        assert "/json/1.3/getInApps" in paths

    def test_total_connections(self, events):
        from kahlo.analyze.traffic import analyze_traffic
        report = analyze_traffic(events, package="com.voltmobi.yakitoriya")
        assert report.total_connections == 9  # 9 tcp_connect events

    def test_ssl_sessions_captured(self, events):
        from kahlo.analyze.traffic import analyze_traffic
        report = analyze_traffic(events, package="com.voltmobi.yakitoriya")
        assert len(report.ssl_sessions) == 31  # 31 ssl_raw events

    def test_endpoint_auth_detection(self, events):
        from kahlo.analyze.traffic import analyze_traffic
        report = analyze_traffic(events, package="com.voltmobi.yakitoriya")
        # Pushwoosh endpoints use "Token null" — not real auth
        pushwoosh_eps = [ep for ep in report.endpoints if "wavesend" in (ep.host or "")]
        for ep in pushwoosh_eps:
            assert ep.has_auth is False  # "Token null" should not count as real auth

    def test_empty_events(self):
        from kahlo.analyze.traffic import analyze_traffic
        report = analyze_traffic([])
        assert len(report.servers) == 0
        assert len(report.endpoints) == 0

    def test_http_request_events_processed(self):
        """Test that structured http_request events are processed into endpoints."""
        from kahlo.analyze.traffic import analyze_traffic
        events = [
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "index": 1,
                    "method": "POST",
                    "url": "https://api.example.com/v1/data",
                    "headers": {"Content-Type": "application/json", "Authorization": "Bearer token123"},
                    "body": '{"key": "value"}',
                    "body_length": 16,
                    "body_format": "json",
                    "source": "system_okhttp",
                },
            },
            {
                "module": "traffic",
                "type": "http_response",
                "ts": "2026-03-27T10:00:01Z",
                "data": {
                    "index": 1,
                    "url": "https://api.example.com/v1/data",
                    "status": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"result": "ok"}',
                    "body_length": 16,
                    "body_format": "json",
                    "source": "system_okhttp",
                },
            },
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:02Z",
                "data": {
                    "index": 2,
                    "method": "GET",
                    "url": "https://cdn.example.com/image.png",
                    "headers": {},
                    "body": "",
                    "body_length": 0,
                    "body_format": "empty",
                    "source": "system_okhttp",
                },
            },
        ]
        report = analyze_traffic(events, package="com.example.app")
        assert report.total_requests == 2
        assert len(report.endpoints) == 2
        methods = {ep.method for ep in report.endpoints}
        assert "POST" in methods
        assert "GET" in methods
        # Check endpoint details
        post_ep = next(ep for ep in report.endpoints if ep.method == "POST")
        assert post_ep.host == "api.example.com"
        assert post_ep.path == "/v1/data"
        assert post_ep.has_auth is True
        assert post_ep.content_type == "application/json"

    def test_mixed_http_request_and_ssl_raw(self):
        """Test that both structured and raw events create endpoints without duplication."""
        from kahlo.analyze.traffic import analyze_traffic
        events = [
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "index": 1,
                    "method": "POST",
                    "url": "https://sentry.example.com/api/1/envelope/",
                    "headers": {"Content-Type": "application/json"},
                    "body": "{}",
                    "body_length": 2,
                    "source": "system_okhttp",
                },
            },
            {
                "module": "traffic",
                "type": "tcp_connect",
                "ts": "2026-03-27T10:00:00Z",
                "data": {"host": "sentry.example.com", "ip": "1.2.3.4", "port": 443},
            },
        ]
        report = analyze_traffic(events, package="com.example.app")
        assert report.total_requests == 1
        assert report.total_connections == 1
        assert len(report.endpoints) == 1
        assert report.endpoints[0].method == "POST"


# --- Vault Analyzer Tests ---

class TestVaultAnalyzer:
    def test_analyze_vault_returns_report(self, events):
        from kahlo.analyze.vault import analyze_vault
        report = analyze_vault(events, package="com.voltmobi.yakitoriya")
        assert report is not None

    def test_prefs_files_found(self, events):
        from kahlo.analyze.vault import analyze_vault
        report = analyze_vault(events, package="com.voltmobi.yakitoriya")
        assert len(report.prefs_files) >= 10
        file_names = {pf.file for pf in report.prefs_files}
        assert "com.google.firebase.crashlytics.xml" in file_names
        assert "com.pushwoosh.pushnotifications.xml" in file_names

    def test_secrets_extracted(self, events):
        from kahlo.analyze.vault import analyze_vault
        report = analyze_vault(events, package="com.voltmobi.yakitoriya")
        assert len(report.secrets) >= 5
        # Check specific secrets
        secret_values = {s.value for s in report.secrets}
        assert "2ed17728-7d78-4ca1-a2f3-7fa4eab342d1" in secret_values  # Pushwoosh HWID

    def test_databases_found(self, events):
        from kahlo.analyze.vault import analyze_vault
        report = analyze_vault(events, package="com.voltmobi.yakitoriya")
        assert len(report.databases) >= 2
        db_names = {db.name for db in report.databases}
        assert "google_app_measurement.db" in db_names

    def test_file_writes_found(self, events):
        from kahlo.analyze.vault import analyze_vault
        report = analyze_vault(events, package="com.voltmobi.yakitoriya")
        assert len(report.file_writes) >= 10

    def test_keystore_entries_found(self, events):
        from kahlo.analyze.vault import analyze_vault
        report = analyze_vault(events, package="com.voltmobi.yakitoriya")
        assert len(report.keystore_entries) >= 2  # At least 2 encrypted pref stores

    def test_sensitivity_classification(self, events):
        from kahlo.analyze.vault import analyze_vault
        report = analyze_vault(events, package="com.voltmobi.yakitoriya")
        sensitivities = {s.sensitivity for s in report.secrets}
        assert "medium" in sensitivities  # SDK keys, device IDs

    def test_total_reads_writes(self, events):
        from kahlo.analyze.vault import analyze_vault
        report = analyze_vault(events, package="com.voltmobi.yakitoriya")
        assert report.total_pref_reads == 299
        assert report.total_pref_writes == 41

    def test_empty_events(self):
        from kahlo.analyze.vault import analyze_vault
        report = analyze_vault([])
        assert len(report.secrets) == 0
        assert len(report.prefs_files) == 0


# --- Recon Analyzer Tests ---

class TestReconAnalyzer:
    def test_analyze_recon_returns_report(self, events):
        from kahlo.analyze.recon import analyze_recon
        report = analyze_recon(events)
        assert report is not None

    def test_device_info_collected(self, events):
        from kahlo.analyze.recon import analyze_recon
        report = analyze_recon(events)
        assert "SDK_INT" in report.device_info
        assert report.device_info["SDK_INT"] == "36"

    def test_telecom_collected(self, events):
        from kahlo.analyze.recon import analyze_recon
        report = analyze_recon(events)
        assert "getSimOperator" in report.telecom
        assert report.telecom["getSimOperator"] == "25001"
        assert "getNetworkOperatorName" in report.telecom
        assert report.telecom["getNetworkOperatorName"] == "MTS RUS"

    def test_network_info_collected(self, events):
        from kahlo.analyze.recon import analyze_recon
        report = analyze_recon(events)
        assert len(report.network_info) >= 1
        assert report.network_queries == 8

    def test_fingerprint_appetite(self, events):
        from kahlo.analyze.recon import analyze_recon
        report = analyze_recon(events)
        # Should have device + network + telecom = 15 + 15 + 15 + bonus = at least 45
        assert report.fingerprint_appetite >= 40

    def test_categories(self, events):
        from kahlo.analyze.recon import analyze_recon
        report = analyze_recon(events)
        assert "device" in report.categories
        assert "telecom" in report.categories
        assert "network" in report.categories

    def test_empty_events(self):
        from kahlo.analyze.recon import analyze_recon
        report = analyze_recon([])
        assert report.fingerprint_appetite == 0
        assert len(report.categories) == 0


# --- Netmodel Analyzer Tests ---

class TestNetmodelAnalyzer:
    def test_analyze_netmodel_returns_report(self, events):
        from kahlo.analyze.netmodel import analyze_netmodel
        report = analyze_netmodel(events)
        assert report is not None

    def test_hash_counts(self, events):
        from kahlo.analyze.netmodel import analyze_netmodel
        report = analyze_netmodel(events)
        assert report.total_hash_ops == 154  # All hash events
        assert "MD5" in report.hash_algorithm_counts
        assert "SHA-1" in report.hash_algorithm_counts
        assert "SHA-256" in report.hash_algorithm_counts

    def test_hmac_keys_found(self, events):
        from kahlo.analyze.netmodel import analyze_netmodel
        report = analyze_netmodel(events)
        assert len(report.hmac_keys) >= 1
        hmac = report.hmac_keys[0]
        assert hmac.algorithm == "HmacSHA256"
        assert hmac.key_hex == "4a784b6f65776779465a5448396d4b32376352726334"
        assert hmac.key_ascii == "JxKoewgyFZTH9mK27cRrc4"

    def test_crypto_operations(self, events):
        from kahlo.analyze.netmodel import analyze_netmodel
        report = analyze_netmodel(events)
        assert len(report.crypto_operations) >= 1
        op = report.crypto_operations[0]
        assert op.algorithm == "AES/CBC/PKCS5Padding"
        assert op.op == "encrypt"
        assert op.key_hex == "f00ac59eedbf80cd8eaf853cae119b42"

    def test_nonces_found(self, events):
        from kahlo.analyze.netmodel import analyze_netmodel
        report = analyze_netmodel(events)
        assert len(report.nonces) == 12

    def test_signing_recipe(self, events):
        from kahlo.analyze.netmodel import analyze_netmodel
        report = analyze_netmodel(events)
        assert report.signing_recipe is not None
        assert report.signing_recipe.algorithm == "HmacSHA256"
        assert report.signing_recipe.nonce_method == "UUID.randomUUID"

    def test_empty_events(self):
        from kahlo.analyze.netmodel import analyze_netmodel
        report = analyze_netmodel([])
        assert report.total_hash_ops == 0
        assert report.signing_recipe is None


# --- Patterns Analyzer Tests ---

class TestPatternsAnalyzer:
    def test_analyze_patterns_returns_report(self, events):
        from kahlo.analyze.patterns import analyze_patterns
        report = analyze_patterns(events)
        assert report is not None

    def test_sdks_detected(self, events):
        from kahlo.analyze.patterns import analyze_patterns
        report = analyze_patterns(events, traffic_hosts=[
            "firebase-settings.crashlytics.com",
            "sentry.inno.co",
            "api.wavesend.ru",
            "beacon2.yakitoriya.ru",
            "api2.branch.io",
            "launches.appsflyersdk.com",
        ])
        sdk_names = {sdk.name for sdk in report.sdks}
        assert "Firebase Crashlytics" in sdk_names
        assert "Sentry" in sdk_names
        assert "Pushwoosh" in sdk_names
        assert "AppsFlyer" in sdk_names
        assert "Branch.io" in sdk_names

    def test_sdk_versions_extracted(self, events):
        from kahlo.analyze.patterns import analyze_patterns
        report = analyze_patterns(events, traffic_hosts=[
            "sentry.inno.co", "api.wavesend.ru", "launches.appsflyersdk.com",
        ])
        sdk_map = {sdk.name: sdk for sdk in report.sdks}
        # Sentry should have version from SSL preview
        if "Sentry" in sdk_map:
            assert sdk_map["Sentry"].version == "8.28.0"
        # Pushwoosh should have version from SSL preview
        if "Pushwoosh" in sdk_map:
            assert sdk_map["Pushwoosh"].version == "6.7.48"

    def test_sdk_categories(self, events):
        from kahlo.analyze.patterns import analyze_patterns
        report = analyze_patterns(events)
        categories = {sdk.category for sdk in report.sdks}
        assert "crash_reporting" in categories or "error_reporting" in categories

    def test_tune_legacy_detected(self, events):
        from kahlo.analyze.patterns import analyze_patterns
        report = analyze_patterns(events)
        sdk_names = {sdk.name for sdk in report.sdks}
        assert "TUNE/HasOffers" in sdk_names

    def test_empty_events(self):
        from kahlo.analyze.patterns import analyze_patterns
        report = analyze_patterns([])
        assert len(report.sdks) == 0
