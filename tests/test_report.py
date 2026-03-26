"""Tests for report generators — verify output files are created with meaningful content."""
import json
import os
import tempfile

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
def analysis_results(session_data):
    """Run all analyzers once and return results."""
    from kahlo.analyze.netmodel import analyze_netmodel
    from kahlo.analyze.patterns import analyze_patterns
    from kahlo.analyze.recon import analyze_recon
    from kahlo.analyze.traffic import analyze_traffic
    from kahlo.analyze.vault import analyze_vault

    events = session_data["events"]
    package = session_data["package"]

    traffic = analyze_traffic(events, package)
    vault = analyze_vault(events, package)
    recon = analyze_recon(events)
    netmodel = analyze_netmodel(events)
    hosts = [s.host for s in traffic.servers]
    patterns = analyze_patterns(events, hosts)

    return {
        "session": session_data,
        "traffic": traffic,
        "vault": vault,
        "recon": recon,
        "netmodel": netmodel,
        "patterns": patterns,
    }


# --- Markdown Report Tests ---

class TestMarkdownReport:
    def test_generates_markdown(self, analysis_results):
        from kahlo.report.markdown import generate_markdown

        md = generate_markdown(
            analysis_results["session"],
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["recon"],
            analysis_results["netmodel"],
            analysis_results["patterns"],
        )
        assert isinstance(md, str)
        assert len(md) > 1000  # Should be substantial

    def test_contains_all_sections(self, analysis_results):
        from kahlo.report.markdown import generate_markdown

        md = generate_markdown(
            analysis_results["session"],
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["recon"],
            analysis_results["netmodel"],
            analysis_results["patterns"],
        )

        assert "## 1. Executive Summary" in md
        assert "## 2. Network Infrastructure" in md
        assert "## 3. API Endpoints" in md
        assert "## 4. Storage & Secrets" in md
        assert "## 5. Privacy Profile" in md
        assert "## 6. Cryptographic Operations" in md
        assert "## 7. SDK Inventory" in md
        assert "## 8. API Recreation Assessment" in md

    def test_contains_server_info(self, analysis_results):
        from kahlo.report.markdown import generate_markdown

        md = generate_markdown(
            analysis_results["session"],
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["recon"],
            analysis_results["netmodel"],
            analysis_results["patterns"],
        )

        assert "beacon2.yakitoriya.ru" in md
        assert "sentry.inno.co" in md
        assert "api.wavesend.ru" in md

    def test_secrets_masked(self, analysis_results):
        from kahlo.report.markdown import generate_markdown

        md = generate_markdown(
            analysis_results["session"],
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["recon"],
            analysis_results["netmodel"],
            analysis_results["patterns"],
        )

        # Secrets should be partially masked — full values should NOT appear in most cases
        # But short values may be shown in full
        assert "..." in md  # Should have masked values

    def test_contains_package_name(self, analysis_results):
        from kahlo.report.markdown import generate_markdown

        md = generate_markdown(
            analysis_results["session"],
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["recon"],
            analysis_results["netmodel"],
            analysis_results["patterns"],
        )

        assert "com.voltmobi.yakitoriya" in md

    def test_contains_sdk_names(self, analysis_results):
        from kahlo.report.markdown import generate_markdown

        md = generate_markdown(
            analysis_results["session"],
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["recon"],
            analysis_results["netmodel"],
            analysis_results["patterns"],
        )

        assert "Firebase Crashlytics" in md or "Sentry" in md
        assert "Pushwoosh" in md


# --- API Spec Tests ---

class TestAPISpec:
    def test_generates_valid_json(self, analysis_results):
        from kahlo.report.api_spec import generate_api_spec

        spec_json = generate_api_spec(
            analysis_results["session"],
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["netmodel"],
        )
        spec = json.loads(spec_json)
        assert isinstance(spec, dict)

    def test_has_required_fields(self, analysis_results):
        from kahlo.report.api_spec import generate_api_spec

        spec_json = generate_api_spec(
            analysis_results["session"],
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["netmodel"],
        )
        spec = json.loads(spec_json)

        assert "app" in spec
        assert spec["app"] == "com.voltmobi.yakitoriya"
        assert "base_urls" in spec
        assert "endpoints" in spec
        assert "servers" in spec
        assert len(spec["base_urls"]) >= 5
        assert len(spec["endpoints"]) >= 4

    def test_has_servers(self, analysis_results):
        from kahlo.report.api_spec import generate_api_spec

        spec_json = generate_api_spec(
            analysis_results["session"],
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["netmodel"],
        )
        spec = json.loads(spec_json)

        server_hosts = {s["host"] for s in spec["servers"]}
        assert "beacon2.yakitoriya.ru" in server_hosts

    def test_has_signing_info(self, analysis_results):
        from kahlo.report.api_spec import generate_api_spec

        spec_json = generate_api_spec(
            analysis_results["session"],
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["netmodel"],
        )
        spec = json.loads(spec_json)

        assert spec.get("signing") is not None
        assert spec["signing"]["algorithm"] == "HmacSHA256"

    def test_has_encryption_info(self, analysis_results):
        from kahlo.report.api_spec import generate_api_spec

        spec_json = generate_api_spec(
            analysis_results["session"],
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["netmodel"],
        )
        spec = json.loads(spec_json)

        assert spec.get("encryption") is not None
        assert "AES" in spec["encryption"]["algorithm"]


# --- Replay Script Tests ---

class TestReplayScripts:
    def test_generates_files(self, analysis_results):
        from kahlo.report.replay import generate_replay

        with tempfile.TemporaryDirectory() as tmpdir:
            files = generate_replay(
                tmpdir,
                analysis_results["traffic"],
                analysis_results["vault"],
                analysis_results["netmodel"],
                "com.voltmobi.yakitoriya",
            )
            assert len(files) >= 5  # curl + python + client

    def test_curl_scripts_created(self, analysis_results):
        from kahlo.report.replay import generate_replay

        with tempfile.TemporaryDirectory() as tmpdir:
            generate_replay(
                tmpdir,
                analysis_results["traffic"],
                analysis_results["vault"],
                analysis_results["netmodel"],
                "com.voltmobi.yakitoriya",
            )
            curl_dir = os.path.join(tmpdir, "curl")
            assert os.path.isdir(curl_dir)
            curl_files = os.listdir(curl_dir)
            assert len(curl_files) >= 4

            # Check content of first curl script
            first_file = sorted(curl_files)[0]
            with open(os.path.join(curl_dir, first_file)) as f:
                content = f.read()
            assert "curl" in content

    def test_python_scripts_created(self, analysis_results):
        from kahlo.report.replay import generate_replay

        with tempfile.TemporaryDirectory() as tmpdir:
            generate_replay(
                tmpdir,
                analysis_results["traffic"],
                analysis_results["vault"],
                analysis_results["netmodel"],
                "com.voltmobi.yakitoriya",
            )
            python_dir = os.path.join(tmpdir, "python")
            assert os.path.isdir(python_dir)
            py_files = [f for f in os.listdir(python_dir) if f.endswith(".py")]
            assert len(py_files) >= 4

    def test_signing_code_generated(self, analysis_results):
        from kahlo.report.replay import generate_replay

        with tempfile.TemporaryDirectory() as tmpdir:
            generate_replay(
                tmpdir,
                analysis_results["traffic"],
                analysis_results["vault"],
                analysis_results["netmodel"],
                "com.voltmobi.yakitoriya",
            )
            signing_path = os.path.join(tmpdir, "python", "signing.py")
            assert os.path.exists(signing_path)
            with open(signing_path) as f:
                content = f.read()
            assert "hmac" in content
            assert "HmacSHA256" in content

    def test_thin_client_generated(self, analysis_results):
        from kahlo.report.replay import generate_replay

        with tempfile.TemporaryDirectory() as tmpdir:
            generate_replay(
                tmpdir,
                analysis_results["traffic"],
                analysis_results["vault"],
                analysis_results["netmodel"],
                "com.voltmobi.yakitoriya",
            )
            client_path = os.path.join(tmpdir, "client.py")
            assert os.path.exists(client_path)
            with open(client_path) as f:
                content = f.read()
            assert "class" in content
            assert "requests" in content
            assert "YakitoriyaClient" in content

    def test_encryption_code_generated(self, analysis_results):
        from kahlo.report.replay import generate_replay

        with tempfile.TemporaryDirectory() as tmpdir:
            generate_replay(
                tmpdir,
                analysis_results["traffic"],
                analysis_results["vault"],
                analysis_results["netmodel"],
                "com.voltmobi.yakitoriya",
            )
            crypto_path = os.path.join(tmpdir, "python", "encryption.py")
            assert os.path.exists(crypto_path)
            with open(crypto_path) as f:
                content = f.read()
            assert "AES" in content
