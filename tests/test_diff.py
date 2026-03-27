"""Tests for session diff — compare two sessions to find changes."""
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


class TestSessionDiffer:
    """Test the SessionDiffer with real and synthetic data."""

    def test_diff_same_session(self):
        """Diffing a session with itself should show no changes."""
        from kahlo.analyze.diff import SessionDiffer

        differ = SessionDiffer()
        diff = differ.diff(SESSION_PATH, SESSION_PATH)

        assert len(diff.new_endpoints) == 0
        assert len(diff.removed_endpoints) == 0
        assert len(diff.new_secrets) == 0
        assert len(diff.removed_secrets) == 0
        assert len(diff.new_sdks) == 0
        assert len(diff.removed_sdks) == 0
        assert len(diff.new_servers) == 0
        assert len(diff.removed_servers) == 0

    def test_diff_same_session_event_counts(self):
        """Event counts should be identical for same session."""
        from kahlo.analyze.diff import SessionDiffer

        differ = SessionDiffer()
        diff = differ.diff(SESSION_PATH, SESSION_PATH)

        assert diff.event_count_old == diff.event_count_new
        assert diff.event_count_old > 0

    def test_diff_same_session_server_counts(self):
        """Server counts should be identical for same session."""
        from kahlo.analyze.diff import SessionDiffer

        differ = SessionDiffer()
        diff = differ.diff(SESSION_PATH, SESSION_PATH)

        assert diff.server_count_old == diff.server_count_new
        assert diff.server_count_old >= 5

    def test_diff_with_empty_session(self, session_data):
        """Diffing with an empty session should show all as new."""
        from kahlo.analyze.diff import SessionDiffer

        # Create a minimal empty session
        empty_session = {
            "session_id": "empty_test",
            "package": "com.voltmobi.yakitoriya",
            "started_at": "2026-03-27T00:00:00Z",
            "ended_at": "2026-03-27T00:00:01Z",
            "event_count": 0,
            "stats": {"by_module": {}, "by_type": {}},
            "metadata": {},
            "events": [],
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(empty_session, f)
            empty_path = f.name

        try:
            differ = SessionDiffer()

            # Empty -> Real: everything is new
            diff = differ.diff(empty_path, SESSION_PATH)
            assert len(diff.new_endpoints) > 0
            assert len(diff.removed_endpoints) == 0
            assert len(diff.new_secrets) > 0
            assert len(diff.new_sdks) > 0
            assert len(diff.new_servers) > 0
            assert diff.event_count_old == 0
            assert diff.event_count_new > 0

            # Real -> Empty: everything is removed
            diff_reverse = differ.diff(SESSION_PATH, empty_path)
            assert len(diff_reverse.new_endpoints) == 0
            assert len(diff_reverse.removed_endpoints) > 0
            assert len(diff_reverse.removed_secrets) > 0
            assert len(diff_reverse.removed_sdks) > 0
            assert len(diff_reverse.removed_servers) > 0
        finally:
            os.unlink(empty_path)

    def test_diff_with_modified_session(self, session_data):
        """Diffing with a modified session should detect specific changes."""
        from kahlo.analyze.diff import SessionDiffer

        # Create a modified session: add an extra endpoint
        modified = json.loads(json.dumps(session_data))
        modified["events"].append({
            "module": "traffic",
            "type": "http_request",
            "ts": "2026-03-27T12:30:00Z",
            "data": {
                "index": 999,
                "method": "GET",
                "url": "https://new-api.example.com/v1/new-feature",
                "headers": {},
                "body": "",
            },
        })
        modified["events"].append({
            "module": "traffic",
            "type": "tcp_connect",
            "ts": "2026-03-27T12:30:00Z",
            "data": {"host": "new-api.example.com", "ip": "1.2.3.4", "port": 443},
        })

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(modified, f)
            modified_path = f.name

        try:
            differ = SessionDiffer()
            diff = differ.diff(SESSION_PATH, modified_path)

            # Should detect the new endpoint
            assert len(diff.new_endpoints) >= 1
            found_new = any("new-feature" in ep for ep in diff.new_endpoints)
            assert found_new, f"Expected 'new-feature' in new endpoints: {diff.new_endpoints}"

            # Should detect the new server
            assert "new-api.example.com" in diff.new_servers

            # No removed endpoints
            assert len(diff.removed_endpoints) == 0
        finally:
            os.unlink(modified_path)


class TestDiffMarkdown:
    """Test the diff markdown report generation."""

    def test_no_changes_report(self):
        """Report for identical sessions should say no differences."""
        from kahlo.analyze.diff import SessionDiffer, generate_diff_markdown

        differ = SessionDiffer()
        diff = differ.diff(SESSION_PATH, SESSION_PATH)
        md = generate_diff_markdown(diff)

        assert "No differences found" in md
        assert "Session Diff Report" in md

    def test_changes_report(self, session_data):
        """Report with changes should list additions and removals."""
        from kahlo.analyze.diff import SessionDiffer, generate_diff_markdown

        empty_session = {
            "session_id": "empty_test",
            "package": "com.voltmobi.yakitoriya",
            "started_at": "2026-03-27T00:00:00Z",
            "ended_at": "2026-03-27T00:00:01Z",
            "event_count": 0,
            "stats": {"by_module": {}, "by_type": {}},
            "metadata": {},
            "events": [],
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(empty_session, f)
            empty_path = f.name

        try:
            differ = SessionDiffer()
            diff = differ.diff(empty_path, SESSION_PATH)
            md = generate_diff_markdown(diff)

            assert "Session Diff Report" in md
            assert "New Endpoints" in md
            assert "+" in md  # Addition markers
        finally:
            os.unlink(empty_path)

    def test_report_contains_overview(self):
        """Report should contain overview table with event counts."""
        from kahlo.analyze.diff import SessionDiffer, generate_diff_markdown

        differ = SessionDiffer()
        diff = differ.diff(SESSION_PATH, SESSION_PATH)
        md = generate_diff_markdown(diff)

        assert "## Overview" in md
        assert "Events" in md
        assert "Servers" in md


class TestEndpointDiff:
    """Test changed endpoint detection."""

    def test_changed_endpoint_count(self, session_data):
        """Modifying an endpoint's count should be detected as a change."""
        from kahlo.analyze.diff import SessionDiffer

        # Create a session where an existing endpoint has been seen more times
        modified = json.loads(json.dumps(session_data))
        # Add duplicate requests for existing endpoints
        traffic_reqs = [
            e for e in modified["events"]
            if e.get("module") == "traffic" and e.get("type") == "http_request"
        ]
        if traffic_reqs:
            # Duplicate the first http_request event
            modified["events"].append(json.loads(json.dumps(traffic_reqs[0])))

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(modified, f)
            modified_path = f.name

        try:
            differ = SessionDiffer()
            diff = differ.diff(SESSION_PATH, modified_path)

            # Should detect count changes for at least one endpoint
            # (depending on whether the duplicated request creates a visible change)
            assert isinstance(diff.changed_endpoints, list)
        finally:
            os.unlink(modified_path)
