"""Tests for request flow chain analysis — detect dependencies between requests."""
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
    return session_data["events"]


class TestFlowAnalyzer:
    """Test the flow analyzer with synthetic and real data."""

    def test_empty_events(self):
        """Empty events should produce empty report."""
        from kahlo.analyze.flows import analyze_flows

        report = analyze_flows([])
        assert len(report.chains) == 0
        assert report.total_links == 0

    def test_no_traffic_events(self):
        """Non-traffic events should produce empty report."""
        from kahlo.analyze.flows import analyze_flows

        events = [
            {"module": "recon", "type": "device_info", "data": {}},
        ]
        report = analyze_flows(events)
        assert len(report.chains) == 0

    def test_simple_auth_chain(self):
        """Detect a simple auth flow: login returns token, next request uses it."""
        from kahlo.analyze.flows import analyze_flows

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
                    "body": '{"username": "test", "password": "pass"}',
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
                    "body": '{"access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig", "refresh_token": "rf_abc123def456"}',
                },
            },
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:02Z",
                "data": {
                    "index": 2,
                    "method": "GET",
                    "url": "https://api.example.com/api/user/profile",
                    "headers": {
                        "Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
                    },
                    "body": "",
                },
            },
        ]

        report = analyze_flows(events)
        assert len(report.chains) >= 1
        assert report.total_links >= 1

        # The chain should link the token from login response to the auth header
        chain = report.chains[0]
        assert len(chain.steps) >= 1
        step = chain.steps[0]
        assert "access_token" in (step.response_field or "")
        assert chain.chain_type == "auth" or "header" in (step.next_request_field or "").lower()

    def test_cookie_chain(self):
        """Detect cookie flow: Set-Cookie in response -> Cookie in next request."""
        from kahlo.analyze.flows import analyze_flows

        events = [
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "index": 1,
                    "method": "GET",
                    "url": "https://app.example.com/init",
                    "headers": {},
                    "body": "",
                },
            },
            {
                "module": "traffic",
                "type": "http_response",
                "ts": "2026-03-27T10:00:01Z",
                "data": {
                    "index": 1,
                    "url": "https://app.example.com/init",
                    "status": 200,
                    "headers": {
                        "Set-Cookie": "session_id=abc123def456xyz789; Path=/; HttpOnly",
                    },
                    "body": "{}",
                },
            },
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:02Z",
                "data": {
                    "index": 2,
                    "method": "GET",
                    "url": "https://app.example.com/api/data",
                    "headers": {
                        "Cookie": "session_id=abc123def456xyz789; Path=/; HttpOnly",
                    },
                    "body": "",
                },
            },
        ]

        report = analyze_flows(events)
        assert len(report.chains) >= 1
        # Should detect Set-Cookie -> Cookie link
        found_cookie = False
        for chain in report.chains:
            for step in chain.steps:
                if "cookie" in (step.response_field or "").lower() or "cookie" in (step.next_request_field or "").lower():
                    found_cookie = True
        assert found_cookie

    def test_data_fetch_chain(self):
        """Detect data dependency: response body field used in next request body."""
        from kahlo.analyze.flows import analyze_flows

        events = [
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "index": 1,
                    "method": "GET",
                    "url": "https://api.example.com/config",
                    "headers": {},
                    "body": "",
                },
            },
            {
                "module": "traffic",
                "type": "http_response",
                "ts": "2026-03-27T10:00:01Z",
                "data": {
                    "index": 1,
                    "url": "https://api.example.com/config",
                    "status": 200,
                    "headers": {},
                    "body": '{"api_endpoint": "https://backend.example.com/v2/process", "config_key": "cfg_9f8a7b6c5d4e3f2a1b"}',
                },
            },
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:02Z",
                "data": {
                    "index": 2,
                    "method": "POST",
                    "url": "https://backend.example.com/v2/process",
                    "headers": {},
                    "body": '{"key": "cfg_9f8a7b6c5d4e3f2a1b", "data": "test"}',
                },
            },
        ]

        report = analyze_flows(events)
        assert len(report.chains) >= 1

    def test_no_chain_for_unrelated_requests(self):
        """Unrelated requests should not produce chains."""
        from kahlo.analyze.flows import analyze_flows

        events = [
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "index": 1,
                    "method": "GET",
                    "url": "https://api.example.com/foo",
                    "headers": {},
                    "body": "",
                },
            },
            {
                "module": "traffic",
                "type": "http_response",
                "ts": "2026-03-27T10:00:01Z",
                "data": {
                    "index": 1,
                    "url": "https://api.example.com/foo",
                    "status": 200,
                    "headers": {},
                    "body": '{"result": "ok"}',
                },
            },
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:02Z",
                "data": {
                    "index": 2,
                    "method": "GET",
                    "url": "https://api.example.com/bar",
                    "headers": {},
                    "body": "",
                },
            },
        ]

        report = analyze_flows(events)
        # "ok" is too short to be a link, so no chains
        assert len(report.chains) == 0

    def test_real_session_flow(self, events):
        """Run flow analysis on real yakitoriya session — should not crash."""
        from kahlo.analyze.flows import analyze_flows

        report = analyze_flows(events)
        # Real session may or may not have chains, but should not error
        assert isinstance(report.chains, list)
        assert report.total_links >= 0


class TestFlowVisualization:
    """Test the text-based flow visualization."""

    def test_format_empty(self):
        from kahlo.analyze.flows import FlowReport, format_flow_text

        report = FlowReport()
        text = format_flow_text(report)
        assert "No request flow chains detected" in text

    def test_format_with_chains(self):
        from kahlo.analyze.flows import (
            FlowReport,
            FlowStep,
            RequestChain,
            format_flow_text,
        )

        chain = RequestChain(
            steps=[
                FlowStep(
                    request_url="https://api.example.com/auth/login",
                    request_method="POST",
                    response_field="access_token",
                    next_request_url="https://api.example.com/api/user",
                    next_request_field="header:Authorization",
                    link_value_preview="eyJhbGciOiJ...",
                ),
            ],
            chain_type="auth",
        )
        report = FlowReport(chains=[chain], total_links=1)
        text = format_flow_text(report)

        assert "Chain 1 (auth)" in text
        assert "access_token" in text
        assert "login" in text

    def test_format_real_session(self, events):
        """Format should not crash on real session data."""
        from kahlo.analyze.flows import analyze_flows, format_flow_text

        report = analyze_flows(events)
        text = format_flow_text(report)
        assert isinstance(text, str)
        assert len(text) > 0


class TestFlowClassification:
    """Test chain type classification."""

    def test_auth_chain_classification(self):
        from kahlo.analyze.flows import FlowStep, _classify_chain

        steps = [
            FlowStep(
                request_url="https://api.example.com/login",
                request_method="POST",
                response_field="access_token",
                next_request_url="https://api.example.com/data",
                next_request_field="header:Authorization",
                link_value_preview="eyJ...",
            ),
        ]
        assert _classify_chain(steps) == "auth"

    def test_pagination_chain_classification(self):
        from kahlo.analyze.flows import FlowStep, _classify_chain

        steps = [
            FlowStep(
                request_url="https://api.example.com/list",
                request_method="GET",
                response_field="next_cursor",
                next_request_url="https://api.example.com/list?cursor=abc",
                next_request_field="body",
                link_value_preview="cursor_abc...",
            ),
        ]
        assert _classify_chain(steps) == "pagination"

    def test_data_fetch_classification(self):
        from kahlo.analyze.flows import FlowStep, _classify_chain

        steps = [
            FlowStep(
                request_url="https://api.example.com/config",
                request_method="GET",
                response_field="endpoint_url",
                next_request_url="https://other.example.com/process",
                next_request_field="body",
                link_value_preview="https://other...",
            ),
        ]
        assert _classify_chain(steps) == "data_fetch"
