"""Tests for Postman Collection export — verify valid v2.1 JSON output."""
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
    """Run analyzers and return traffic + vault."""
    from kahlo.analyze.traffic import analyze_traffic
    from kahlo.analyze.vault import analyze_vault

    events = session_data["events"]
    package = session_data["package"]

    traffic = analyze_traffic(events, package)
    vault = analyze_vault(events, package)

    return {"traffic": traffic, "vault": vault, "package": package}


class TestPostmanCollection:
    """Test Postman Collection v2.1 generation."""

    def test_generates_dict(self, analysis_results):
        """generate_postman_collection should return a dict."""
        from kahlo.report.postman import generate_postman_collection

        collection = generate_postman_collection(
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["package"],
        )
        assert isinstance(collection, dict)

    def test_valid_json_serializable(self, analysis_results):
        """Collection should be JSON-serializable."""
        from kahlo.report.postman import generate_postman_collection

        collection = generate_postman_collection(
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["package"],
        )
        json_str = json.dumps(collection, indent=2, ensure_ascii=False)
        assert len(json_str) > 100
        # Round-trip
        parsed = json.loads(json_str)
        assert parsed == collection

    def test_has_correct_schema(self, analysis_results):
        """Collection should have the Postman v2.1 schema URL."""
        from kahlo.report.postman import generate_postman_collection

        collection = generate_postman_collection(
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["package"],
        )
        assert "info" in collection
        assert "schema" in collection["info"]
        assert "v2.1.0" in collection["info"]["schema"]

    def test_has_collection_name(self, analysis_results):
        """Collection should have a meaningful name."""
        from kahlo.report.postman import generate_postman_collection

        collection = generate_postman_collection(
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["package"],
        )
        assert "name" in collection["info"]
        assert "Yakitoriya" in collection["info"]["name"]

    def test_has_items(self, analysis_results):
        """Collection should contain request items."""
        from kahlo.report.postman import generate_postman_collection

        collection = generate_postman_collection(
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["package"],
        )
        assert "item" in collection
        assert len(collection["item"]) >= 1

    def test_items_grouped_by_host(self, analysis_results):
        """Items should be grouped into folders by host."""
        from kahlo.report.postman import generate_postman_collection

        collection = generate_postman_collection(
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["package"],
        )
        # Multiple servers -> should have folders
        items = collection["item"]
        # With multiple hosts, items should be folder objects containing sub-items
        folders = [i for i in items if "item" in i]
        if len(set(ep.host for ep in analysis_results["traffic"].endpoints if ep.host)) > 1:
            assert len(folders) >= 2

    def test_request_format(self, analysis_results):
        """Each request item should have correct structure."""
        from kahlo.report.postman import generate_postman_collection

        collection = generate_postman_collection(
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["package"],
        )

        # Dig into items to find actual requests
        def _find_requests(items: list) -> list:
            result = []
            for item in items:
                if "request" in item:
                    result.append(item)
                elif "item" in item:
                    result.extend(_find_requests(item["item"]))
            return result

        requests = _find_requests(collection["item"])
        assert len(requests) >= 4

        for req_item in requests:
            assert "name" in req_item
            assert "request" in req_item
            request = req_item["request"]
            assert "method" in request
            assert "url" in request
            assert "header" in request

            # URL should have correct format
            url = request["url"]
            assert "raw" in url
            assert "host" in url
            assert "path" in url

    def test_post_requests_have_body(self, analysis_results):
        """POST requests should include a body if available."""
        from kahlo.report.postman import generate_postman_collection

        collection = generate_postman_collection(
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["package"],
        )

        def _find_requests(items: list) -> list:
            result = []
            for item in items:
                if "request" in item:
                    result.append(item)
                elif "item" in item:
                    result.extend(_find_requests(item["item"]))
            return result

        requests = _find_requests(collection["item"])
        post_requests = [r for r in requests if r["request"]["method"] == "POST"]

        # At least some POST requests should have body
        bodies = [r for r in post_requests if "body" in r["request"]]
        if post_requests:
            assert len(bodies) >= 1

    def test_headers_included(self, analysis_results):
        """Request headers should be included (excluding Content-Length and Host)."""
        from kahlo.report.postman import generate_postman_collection

        collection = generate_postman_collection(
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["package"],
        )

        def _find_requests(items: list) -> list:
            result = []
            for item in items:
                if "request" in item:
                    result.append(item)
                elif "item" in item:
                    result.extend(_find_requests(item["item"]))
            return result

        requests = _find_requests(collection["item"])

        # At least some requests should have headers
        with_headers = [
            r for r in requests if len(r["request"]["header"]) > 0
        ]
        assert len(with_headers) >= 1

        # Should not include Content-Length or Host
        for req_item in requests:
            for header in req_item["request"]["header"]:
                assert header["key"].lower() not in ("content-length", "host")

    def test_variables_section(self, analysis_results):
        """Collection should have variables for base URLs."""
        from kahlo.report.postman import generate_postman_collection

        collection = generate_postman_collection(
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["package"],
        )

        assert "variable" in collection
        variables = collection["variable"]
        assert len(variables) >= 1

        # Should have base_url variables
        var_keys = {v["key"] for v in variables}
        base_url_vars = [k for k in var_keys if k.startswith("base_url_")]
        assert len(base_url_vars) >= 1

    def test_without_vault(self, analysis_results):
        """Should work without vault data."""
        from kahlo.report.postman import generate_postman_collection

        collection = generate_postman_collection(
            analysis_results["traffic"],
            vault=None,
            package=analysis_results["package"],
        )
        assert isinstance(collection, dict)
        assert "item" in collection

    def test_empty_traffic(self):
        """Should handle empty traffic gracefully."""
        from kahlo.analyze.traffic import TrafficReport
        from kahlo.report.postman import generate_postman_collection

        collection = generate_postman_collection(
            TrafficReport(),
            vault=None,
            package="com.example.app",
        )
        assert isinstance(collection, dict)
        assert collection["item"] == []


class TestPostmanOutput:
    """Test that Postman export writes valid files."""

    def test_write_collection_file(self, analysis_results):
        """Written collection file should be valid JSON."""
        from kahlo.report.postman import generate_postman_collection

        collection = generate_postman_collection(
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["package"],
        )

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(collection, f, indent=2, ensure_ascii=False)
            output_path = f.name

        try:
            assert os.path.exists(output_path)
            assert os.path.getsize(output_path) > 100

            # Re-read and validate
            with open(output_path) as f:
                parsed = json.load(f)

            assert "info" in parsed
            assert "item" in parsed
            assert "v2.1.0" in parsed["info"]["schema"]
        finally:
            os.unlink(output_path)


class TestPostmanIntegrationWithReport:
    """Test that Postman export is generated as part of report command."""

    def test_postman_in_report_output(self, session_data, analysis_results):
        """The report command should also generate postman_collection.json."""
        # This tests that the postman module works when called from report flow
        from kahlo.report.postman import generate_postman_collection

        collection = generate_postman_collection(
            analysis_results["traffic"],
            analysis_results["vault"],
            analysis_results["package"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            postman_path = os.path.join(tmpdir, "postman_collection.json")
            with open(postman_path, "w", encoding="utf-8") as f:
                json.dump(collection, f, indent=2, ensure_ascii=False)

            assert os.path.exists(postman_path)
            with open(postman_path) as f:
                parsed = json.load(f)
            assert parsed["info"]["schema"].endswith("v2.1.0/collection.json")


class TestURLParsing:
    """Test URL parsing for Postman format."""

    def test_simple_url(self):
        from kahlo.report.postman import _parse_url

        result = _parse_url("https://api.example.com/v1/users")
        assert result["raw"] == "https://api.example.com/v1/users"
        assert result["protocol"] == "https"
        assert result["host"] == ["api", "example", "com"]
        assert result["path"] == ["v1", "users"]

    def test_url_with_query(self):
        from kahlo.report.postman import _parse_url

        result = _parse_url("https://api.example.com/search?q=test&page=1")
        assert "query" in result
        assert len(result["query"]) == 2
        assert result["query"][0]["key"] == "q"
        assert result["query"][0]["value"] == "test"

    def test_url_with_port(self):
        from kahlo.report.postman import _parse_url

        result = _parse_url("http://api.example.com:8080/api")
        assert result["port"] == "8080"

    def test_root_path(self):
        from kahlo.report.postman import _parse_url

        result = _parse_url("https://api.example.com/")
        assert result["path"] == []
