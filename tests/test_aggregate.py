"""Tests for session aggregation — merge multiple sessions into unified API map."""
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


class TestSessionAggregator:
    """Test the SessionAggregator with real session data."""

    def test_aggregate_single_session(self):
        """Aggregating one session should work and contain all data."""
        from kahlo.analyze.aggregate import SessionAggregator

        agg = SessionAggregator()
        report = agg.aggregate([SESSION_PATH])

        assert len(report.sessions) == 1
        assert report.sessions[0].package == "com.voltmobi.yakitoriya"
        assert len(report.all_endpoints) >= 4
        assert len(report.all_servers) >= 5
        assert len(report.all_secrets) >= 5

    def test_aggregate_same_session_twice(self):
        """Merging the same session with itself simulates 2 scans.

        Endpoints should be deduplicated but with doubled counts.
        Secrets/SDKs should be deduplicated (same values).
        """
        from kahlo.analyze.aggregate import SessionAggregator

        agg = SessionAggregator()
        report = agg.aggregate([SESSION_PATH, SESSION_PATH])

        assert len(report.sessions) == 2
        # Endpoints should be deduplicated (same host/path/method)
        # but counts should be doubled
        for ep in report.all_endpoints:
            assert ep.count >= 2  # Each endpoint seen at least once per session

        # Secrets should be deduplicated by value
        # Count should be same as single session (values don't change)
        single_report = agg.aggregate([SESSION_PATH])
        assert len(report.all_secrets) == len(single_report.all_secrets)

        # SDKs should be deduplicated by name
        assert len(report.all_sdks) == len(single_report.all_sdks)

    def test_aggregate_frequency_tracking(self):
        """endpoint_frequency should track how many sessions each endpoint appears in."""
        from kahlo.analyze.aggregate import SessionAggregator

        agg = SessionAggregator()
        report = agg.aggregate([SESSION_PATH, SESSION_PATH])

        # Each endpoint should appear in 2 sessions
        for key, freq in report.endpoint_frequency.items():
            assert freq == 2

    def test_aggregate_first_seen(self):
        """endpoint_first_seen should map each endpoint to the first session that saw it."""
        from kahlo.analyze.aggregate import SessionAggregator

        agg = SessionAggregator()
        report = agg.aggregate([SESSION_PATH])

        session_id = report.sessions[0].session_id
        for key, first in report.endpoint_first_seen.items():
            assert first == session_id

    def test_session_summary_counts(self):
        """SessionSummary should contain accurate counts."""
        from kahlo.analyze.aggregate import SessionAggregator

        agg = SessionAggregator()
        report = agg.aggregate([SESSION_PATH])

        summary = report.sessions[0]
        assert summary.event_count > 0
        assert summary.server_count >= 5
        assert summary.endpoint_count >= 4
        assert summary.secret_count >= 5

    def test_servers_deduplicated(self):
        """Servers from the same session merged twice should be deduplicated."""
        from kahlo.analyze.aggregate import SessionAggregator

        agg = SessionAggregator()
        single = agg.aggregate([SESSION_PATH])
        double = agg.aggregate([SESSION_PATH, SESSION_PATH])

        # Same number of unique servers
        assert len(double.all_servers) == len(single.all_servers)

        # But connection counts should be doubled
        single_map = {s.host: s.connection_count for s in single.all_servers}
        double_map = {s.host: s.connection_count for s in double.all_servers}
        for host in single_map:
            assert double_map[host] == single_map[host] * 2


class TestAggregatedMarkdown:
    """Test the aggregated markdown report generation."""

    def test_generates_markdown(self):
        from kahlo.analyze.aggregate import (
            SessionAggregator,
            generate_aggregated_markdown,
        )

        agg = SessionAggregator()
        report = agg.aggregate([SESSION_PATH, SESSION_PATH])
        md = generate_aggregated_markdown(report)

        assert isinstance(md, str)
        assert len(md) > 500
        assert "Aggregated Analysis Report" in md
        assert "Sessions merged" in md
        assert "2" in md  # 2 sessions

    def test_contains_all_sections(self):
        from kahlo.analyze.aggregate import (
            SessionAggregator,
            generate_aggregated_markdown,
        )

        agg = SessionAggregator()
        report = agg.aggregate([SESSION_PATH])
        md = generate_aggregated_markdown(report)

        assert "## Sessions" in md
        assert "## Servers" in md
        assert "## Endpoints" in md
        assert "## Secrets" in md
        assert "## SDKs" in md


class TestAggregatedAPISpec:
    """Test the aggregated API spec generation."""

    def test_generates_valid_json(self):
        from kahlo.analyze.aggregate import (
            SessionAggregator,
            generate_aggregated_api_spec,
        )

        agg = SessionAggregator()
        report = agg.aggregate([SESSION_PATH])
        spec_json = generate_aggregated_api_spec(report, "com.voltmobi.yakitoriya")
        spec = json.loads(spec_json)

        assert isinstance(spec, dict)
        assert spec["aggregated"] is True
        assert spec["sessions_count"] == 1
        assert len(spec["endpoints"]) >= 4
        assert len(spec["servers"]) >= 5

    def test_frequency_in_spec(self):
        from kahlo.analyze.aggregate import (
            SessionAggregator,
            generate_aggregated_api_spec,
        )

        agg = SessionAggregator()
        report = agg.aggregate([SESSION_PATH, SESSION_PATH])
        spec_json = generate_aggregated_api_spec(report, "com.voltmobi.yakitoriya")
        spec = json.loads(spec_json)

        assert spec["sessions_count"] == 2
        for ep in spec["endpoints"]:
            assert ep["sessions_seen"] == 2


class TestAggregateOutput:
    """Test that aggregate produces output files."""

    def test_full_output(self):
        from kahlo.analyze.aggregate import (
            SessionAggregator,
            generate_aggregated_api_spec,
            generate_aggregated_markdown,
        )

        agg = SessionAggregator()
        report = agg.aggregate([SESSION_PATH, SESSION_PATH])

        with tempfile.TemporaryDirectory() as tmpdir:
            md = generate_aggregated_markdown(report)
            md_path = os.path.join(tmpdir, "aggregated_report.md")
            with open(md_path, "w") as f:
                f.write(md)
            assert os.path.exists(md_path)
            assert os.path.getsize(md_path) > 0

            spec = generate_aggregated_api_spec(report, "com.voltmobi.yakitoriya")
            spec_path = os.path.join(tmpdir, "aggregated_api_spec.json")
            with open(spec_path, "w") as f:
                f.write(spec)
            assert os.path.exists(spec_path)
            # Validate JSON
            with open(spec_path) as f:
                parsed = json.load(f)
            assert parsed["aggregated"] is True
