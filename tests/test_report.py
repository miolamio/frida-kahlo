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


# --- Method Name Normalization Tests ---

class TestMethodNameNormalization:
    """Test that URL-to-method-name conversion produces valid, readable Python identifiers."""

    def test_pushwoosh_post_event(self):
        from kahlo.report.replay import _url_to_method_name

        name = _url_to_method_name("https://api.wavesend.ru/json/1.3/postEvent")
        assert name == "pushwoosh_post_event"
        assert name.isidentifier()

    def test_sentry_envelope(self):
        from kahlo.report.replay import _url_to_method_name

        name = _url_to_method_name("https://sentry.inno.co/api/13/envelope/")
        assert name == "sentry_envelope"
        assert name.isidentifier()

    def test_appsflyer_androidevent_strips_query(self):
        from kahlo.report.replay import _url_to_method_name

        name = _url_to_method_name(
            "https://launches.appsflyersdk.com/api/v6.17/androidevent?app_id=com.voltmobi.yakitoriya&buildnumber=6.17.5"
        )
        assert name == "appsflyer_androidevent"
        assert name.isidentifier()
        # Must NOT contain '=' or dots
        assert "=" not in name
        assert "." not in name

    def test_branch_install(self):
        from kahlo.report.replay import _url_to_method_name

        name = _url_to_method_name("https://api2.branch.io/v1/install")
        assert name == "branch_install"
        assert name.isidentifier()

    def test_wavesend_get_in_apps(self):
        from kahlo.report.replay import _url_to_method_name

        name = _url_to_method_name("https://api.wavesend.ru/json/1.3/getInApps")
        assert name == "pushwoosh_get_in_apps"
        assert name.isidentifier()

    def test_all_names_are_valid_identifiers(self, analysis_results):
        """Every endpoint from the real session must produce a valid Python identifier."""
        from kahlo.report.replay import _url_to_method_name

        for ep in analysis_results["traffic"].endpoints:
            name = _url_to_method_name(ep.url, ep.host)
            assert name.isidentifier(), f"Invalid identifier: {name!r} from {ep.url}"

    def test_no_python_keywords(self, analysis_results):
        """Method names must not be Python keywords."""
        import keyword as kw

        from kahlo.report.replay import _url_to_method_name

        for ep in analysis_results["traffic"].endpoints:
            name = _url_to_method_name(ep.url, ep.host)
            assert not kw.iskeyword(name), f"Keyword collision: {name!r}"


# --- Per-Host Routing Tests ---

class TestPerHostRouting:
    """Test that the generated thin client routes each endpoint to its correct server."""

    def test_client_has_host_constants(self, analysis_results):
        from kahlo.report.replay import generate_replay

        with tempfile.TemporaryDirectory() as tmpdir:
            generate_replay(
                tmpdir,
                analysis_results["traffic"],
                analysis_results["vault"],
                analysis_results["netmodel"],
                "com.voltmobi.yakitoriya",
            )
            with open(os.path.join(tmpdir, "client.py")) as f:
                content = f.read()

            # Must have per-host constants
            assert "HOST_PUSHWOOSH" in content
            assert "HOST_SENTRY" in content
            assert "HOST_BRANCH" in content
            assert "HOST_APPSFLYER" in content
            assert "HOST_YAKITORIYA" in content

    def test_pushwoosh_methods_use_pushwoosh_host(self, analysis_results):
        from kahlo.report.replay import generate_replay

        with tempfile.TemporaryDirectory() as tmpdir:
            generate_replay(
                tmpdir,
                analysis_results["traffic"],
                analysis_results["vault"],
                analysis_results["netmodel"],
                "com.voltmobi.yakitoriya",
            )
            with open(os.path.join(tmpdir, "client.py")) as f:
                content = f.read()

            # Pushwoosh methods must route to HOST_PUSHWOOSH, not BASE_URL
            assert "HOST_PUSHWOOSH}/json/1.3/postEvent" in content
            assert "HOST_PUSHWOOSH}/json/1.3/getInApps" in content

    def test_sentry_method_uses_sentry_host(self, analysis_results):
        from kahlo.report.replay import generate_replay

        with tempfile.TemporaryDirectory() as tmpdir:
            generate_replay(
                tmpdir,
                analysis_results["traffic"],
                analysis_results["vault"],
                analysis_results["netmodel"],
                "com.voltmobi.yakitoriya",
            )
            with open(os.path.join(tmpdir, "client.py")) as f:
                content = f.read()

            assert "HOST_SENTRY}/api/13/envelope/" in content

    def test_no_method_uses_base_url_for_routing(self, analysis_results):
        """No endpoint method should route via BASE_URL — all should use HOST_* constants."""
        from kahlo.report.replay import generate_replay

        with tempfile.TemporaryDirectory() as tmpdir:
            generate_replay(
                tmpdir,
                analysis_results["traffic"],
                analysis_results["vault"],
                analysis_results["netmodel"],
                "com.voltmobi.yakitoriya",
            )
            with open(os.path.join(tmpdir, "client.py")) as f:
                content = f.read()

            # Methods should never use {self.BASE_URL} for actual routing
            # (BASE_URL is kept for backward compatibility only)
            assert "self.BASE_URL}/" not in content

    def test_client_is_valid_python(self, analysis_results):
        """The generated client.py must parse as valid Python."""
        import ast

        from kahlo.report.replay import generate_replay

        with tempfile.TemporaryDirectory() as tmpdir:
            generate_replay(
                tmpdir,
                analysis_results["traffic"],
                analysis_results["vault"],
                analysis_results["netmodel"],
                "com.voltmobi.yakitoriya",
            )
            with open(os.path.join(tmpdir, "client.py")) as f:
                content = f.read()

            # Must not raise SyntaxError
            ast.parse(content)


# --- Per-Endpoint Auth Tests ---

class TestPerEndpointAuth:
    """Test that the generated client applies correct auth per endpoint."""

    def test_pushwoosh_has_token_null(self, analysis_results):
        from kahlo.report.replay import generate_replay

        with tempfile.TemporaryDirectory() as tmpdir:
            generate_replay(
                tmpdir,
                analysis_results["traffic"],
                analysis_results["vault"],
                analysis_results["netmodel"],
                "com.voltmobi.yakitoriya",
            )
            with open(os.path.join(tmpdir, "client.py")) as f:
                content = f.read()

            # Pushwoosh methods should set "Token null" auth
            assert '"Token null"' in content

    def test_branch_has_no_auth(self, analysis_results):
        """Branch endpoints should NOT have Authorization header."""
        from kahlo.report.replay import generate_replay

        with tempfile.TemporaryDirectory() as tmpdir:
            generate_replay(
                tmpdir,
                analysis_results["traffic"],
                analysis_results["vault"],
                analysis_results["netmodel"],
                "com.voltmobi.yakitoriya",
            )
            with open(os.path.join(tmpdir, "client.py")) as f:
                content = f.read()

            # Find the branch_install method and check it has no auth
            lines = content.split("\n")
            in_branch = False
            branch_lines = []
            for line in lines:
                if "def branch_install" in line:
                    in_branch = True
                elif in_branch and line.strip().startswith("def "):
                    break
                if in_branch:
                    branch_lines.append(line)

            branch_code = "\n".join(branch_lines)
            assert "Authorization" not in branch_code


# --- Curl Scripts Full Headers Tests ---

class TestCurlFullHeaders:
    """Test that curl scripts include all captured headers."""

    def test_sentry_curl_has_x_sentry_auth(self, analysis_results):
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
            # Find the sentry envelope script
            found = False
            for fname in os.listdir(curl_dir):
                if "envelope" in fname:
                    with open(os.path.join(curl_dir, fname)) as f:
                        content = f.read()
                    assert "X-Sentry-Auth" in content
                    found = True
                    break
            assert found, "Sentry envelope curl script not found"

    def test_curl_includes_connection_header(self, analysis_results):
        """Curl scripts should include Connection header (previously filtered)."""
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
            first_file = sorted(os.listdir(curl_dir))[0]
            with open(os.path.join(curl_dir, first_file)) as f:
                content = f.read()
            # Connection header should now be present
            assert "Connection:" in content

    def test_curl_includes_accept_encoding(self, analysis_results):
        """Curl scripts should include Accept-Encoding header (previously filtered)."""
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
            first_file = sorted(os.listdir(curl_dir))[0]
            with open(os.path.join(curl_dir, first_file)) as f:
                content = f.read()
            assert "Accept-Encoding:" in content


# --- API Spec Per-Host Base URL Tests ---

class TestAPISpecPerHostBaseURL:
    """Test that the API spec includes per-endpoint base_url."""

    def test_endpoints_have_base_url(self, analysis_results):
        from kahlo.report.api_spec import generate_api_spec

        spec_json = generate_api_spec(
            analysis_results["session"],
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["netmodel"],
        )
        spec = json.loads(spec_json)

        for ep in spec["endpoints"]:
            assert "base_url" in ep, f"Endpoint {ep['url']} missing base_url"

    def test_base_url_matches_host(self, analysis_results):
        from kahlo.report.api_spec import generate_api_spec

        spec_json = generate_api_spec(
            analysis_results["session"],
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["netmodel"],
        )
        spec = json.loads(spec_json)

        for ep in spec["endpoints"]:
            # base_url should contain the endpoint's host
            assert ep["host"] in ep["base_url"], (
                f"base_url {ep['base_url']} does not contain host {ep['host']}"
            )

    def test_endpoints_have_auth_value(self, analysis_results):
        """Each endpoint should expose its auth_value for per-endpoint auth inspection."""
        from kahlo.report.api_spec import generate_api_spec

        spec_json = generate_api_spec(
            analysis_results["session"],
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["netmodel"],
        )
        spec = json.loads(spec_json)

        for ep in spec["endpoints"]:
            assert "auth_value" in ep, f"Endpoint {ep['url']} missing auth_value"
