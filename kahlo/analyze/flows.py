"""Request Flow Chain Analyzer — detect dependencies between HTTP requests."""
from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field


class FlowStep(BaseModel):
    """A single step in a request chain."""
    request_url: str
    request_method: str = "GET"
    response_field: str | None = None       # field from response used in next request
    next_request_url: str | None = None
    next_request_field: str | None = None   # where the value is placed (header, body, query)
    link_value_preview: str | None = None   # preview of the linking value


class RequestChain(BaseModel):
    """A chain of requests linked by data dependencies."""
    steps: list[FlowStep] = Field(default_factory=list)
    chain_type: str = "data_fetch"  # "auth", "pagination", "data_fetch"


class FlowReport(BaseModel):
    """Complete flow analysis results."""
    chains: list[RequestChain] = Field(default_factory=list)
    total_links: int = 0


# Minimum value length to consider as a potential link (avoid matching "ok", "1", etc.)
_MIN_LINK_VALUE_LEN = 8
# Maximum value length to consider (avoid matching huge blobs)
_MAX_LINK_VALUE_LEN = 2048
# Values to ignore (too common)
_IGNORE_VALUES = {
    "true", "false", "null", "ok", "success", "error",
    "application/json", "text/html", "text/plain",
    "gzip", "close", "keep-alive", "0", "1",
}


def _extract_values_from_json(body: str) -> dict[str, str]:
    """Extract string values from a JSON body. Returns {field_path: value}."""
    result: dict[str, str] = {}
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return result

    def _walk(obj: Any, prefix: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                path = f"{prefix}.{k}" if prefix else k
                if isinstance(v, str) and _MIN_LINK_VALUE_LEN <= len(v) <= _MAX_LINK_VALUE_LEN:
                    if v.lower() not in _IGNORE_VALUES:
                        result[path] = v
                elif isinstance(v, (dict, list)):
                    _walk(v, path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _walk(item, f"{prefix}[{i}]")

    _walk(data)
    return result


def _extract_header_values(headers: dict[str, str]) -> dict[str, str]:
    """Extract meaningful values from headers."""
    result: dict[str, str] = {}
    for key, value in headers.items():
        if (
            _MIN_LINK_VALUE_LEN <= len(value) <= _MAX_LINK_VALUE_LEN
            and value.lower() not in _IGNORE_VALUES
        ):
            result[f"header:{key}"] = value
    return result


def _classify_chain(steps: list[FlowStep]) -> str:
    """Classify a chain type based on its steps."""
    for step in steps:
        # Auth patterns: token, bearer, authorization
        if step.next_request_field and any(
            kw in (step.next_request_field or "").lower()
            for kw in ("auth", "bearer", "token", "cookie", "session")
        ):
            return "auth"
        if step.response_field and any(
            kw in (step.response_field or "").lower()
            for kw in ("token", "access_token", "auth", "session", "jwt")
        ):
            return "auth"

        # Pagination patterns
        if step.response_field and any(
            kw in (step.response_field or "").lower()
            for kw in ("next", "cursor", "offset", "page")
        ):
            return "pagination"

    return "data_fetch"


def _preview_value(value: str, max_len: int = 40) -> str:
    """Create a preview of a value, truncated if needed."""
    if len(value) <= max_len:
        return value
    return value[:max_len] + "..."


def analyze_flows(events: list[dict[str, Any]]) -> FlowReport:
    """Find request chains: request A returns value -> request B uses that value.

    Detection logic:
    1. Extract all string values from response bodies and headers.
    2. Check if any of those values appear in subsequent request headers or bodies.
    3. Build chains from these links.

    Args:
        events: All session events (will be filtered to traffic module).

    Returns:
        FlowReport with detected chains.
    """
    # Collect structured HTTP request/response pairs
    traffic_events = [e for e in events if e.get("module") == "traffic"]

    # Build ordered list of requests and responses
    requests: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = []

    for event in traffic_events:
        etype = event.get("type", "")
        data = event.get("data", {})

        if etype == "http_request":
            requests.append({
                "index": data.get("index", 0),
                "method": data.get("method", "GET"),
                "url": data.get("url", ""),
                "headers": data.get("headers", {}),
                "body": data.get("body", ""),
                "ts": event.get("ts", ""),
            })
        elif etype == "http_response":
            responses.append({
                "index": data.get("index", 0),
                "url": data.get("url", ""),
                "status": data.get("status", 0),
                "headers": data.get("headers", {}),
                "body": data.get("body", ""),
                "ts": event.get("ts", ""),
            })

    # Also extract from ssl_raw events
    for event in traffic_events:
        if event.get("type") != "ssl_raw":
            continue
        data = event.get("data", {})
        direction = data.get("direction", "")
        preview = data.get("preview", "")
        if not preview:
            continue

        # Parse basic HTTP from preview
        lines = preview.split("..")
        if direction == "out":
            # Outgoing request
            method_match = re.match(r'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/', lines[0] if lines else "")
            if method_match:
                method = method_match.group(1)
                path = method_match.group(2)
                headers: dict[str, str] = {}
                body_parts: list[str] = []
                in_body = False
                for line in lines[1:]:
                    line = line.strip()
                    if not line and not in_body:
                        in_body = True
                        continue
                    if in_body:
                        body_parts.append(line)
                    else:
                        hm = re.match(r'^([A-Za-z][\w-]+):\s*(.+)', line)
                        if hm:
                            headers[hm.group(1)] = hm.group(2).strip()

                host = headers.get("Host", "")
                url = f"https://{host}{path}" if host else path
                body = "..".join(body_parts).strip()

                requests.append({
                    "index": -1,  # No index for ssl_raw
                    "method": method,
                    "url": url,
                    "headers": headers,
                    "body": body,
                    "ts": event.get("ts", ""),
                })

        elif direction == "in":
            # Incoming response
            body_parts_resp: list[str] = []
            in_body_resp = False
            resp_headers: dict[str, str] = {}
            for line in lines[1:]:
                line = line.strip()
                if not line and not in_body_resp:
                    in_body_resp = True
                    continue
                if in_body_resp:
                    body_parts_resp.append(line)
                else:
                    hm = re.match(r'^([A-Za-z][\w-]+):\s*(.+)', line)
                    if hm:
                        resp_headers[hm.group(1)] = hm.group(2).strip()

            body_resp = "..".join(body_parts_resp).strip()
            responses.append({
                "index": -1,
                "url": "",
                "status": 0,
                "headers": resp_headers,
                "body": body_resp,
                "ts": event.get("ts", ""),
            })

    if not requests or not responses:
        return FlowReport()

    # Build response value map: for each response, extract all string values
    # response_values[i] = {field_path: value}
    response_values: list[dict[str, str]] = []
    for resp in responses:
        values: dict[str, str] = {}
        # From body
        if resp["body"]:
            values.update(_extract_values_from_json(resp["body"]))
        # From headers (Set-Cookie, Location, etc.)
        values.update(_extract_header_values(resp["headers"]))
        response_values.append(values)

    # Find links: for each response value, check if it appears in any subsequent request
    links: list[tuple[int, str, str, int, str]] = []  # (resp_idx, field, value, req_idx, where_used)

    for resp_idx, resp_vals in enumerate(response_values):
        if not resp_vals:
            continue
        # Only look at requests that come after this response
        for req_idx, req in enumerate(requests):
            if req_idx <= resp_idx:
                continue  # Only subsequent requests

            req_headers_str = json.dumps(req["headers"])
            req_body = req.get("body", "")

            for field, value in resp_vals.items():
                # Check in request headers
                if value in req_headers_str:
                    # Find which header contains it
                    for hk, hv in req["headers"].items():
                        if value in hv:
                            links.append((resp_idx, field, value, req_idx, f"header:{hk}"))
                            break
                    break  # One link per response-request pair is enough

                # Check in request body
                if req_body and value in req_body:
                    links.append((resp_idx, field, value, req_idx, "body"))
                    break

    # Build chains from links
    # Group connected links into chains
    chains: list[RequestChain] = []
    used_links: set[int] = set()

    for i, (resp_idx, resp_field, value, req_idx, where_used) in enumerate(links):
        if i in used_links:
            continue

        steps: list[FlowStep] = []

        # The response came from a request at approximately resp_idx
        source_req = requests[min(resp_idx, len(requests) - 1)] if requests else None
        target_req = requests[req_idx] if req_idx < len(requests) else None

        if source_req and target_req:
            steps.append(FlowStep(
                request_url=source_req["url"],
                request_method=source_req["method"],
                response_field=resp_field,
                next_request_url=target_req["url"],
                next_request_field=where_used,
                link_value_preview=_preview_value(value),
            ))
            used_links.add(i)

            # Try to extend the chain: does the target request's response link to another request?
            current_req_idx = req_idx
            for j, (r_idx2, r_field2, val2, rq_idx2, where2) in enumerate(links):
                if j in used_links:
                    continue
                if r_idx2 == current_req_idx or (r_idx2 > resp_idx and rq_idx2 > current_req_idx):
                    next_target = requests[rq_idx2] if rq_idx2 < len(requests) else None
                    if next_target:
                        steps.append(FlowStep(
                            request_url=target_req["url"],
                            request_method=target_req["method"],
                            response_field=r_field2,
                            next_request_url=next_target["url"],
                            next_request_field=where2,
                            link_value_preview=_preview_value(val2),
                        ))
                        used_links.add(j)
                        target_req = next_target
                        current_req_idx = rq_idx2

        if steps:
            chain_type = _classify_chain(steps)
            chains.append(RequestChain(steps=steps, chain_type=chain_type))

    total_links = sum(len(c.steps) for c in chains)

    return FlowReport(chains=chains, total_links=total_links)


def format_flow_text(report: FlowReport) -> str:
    """Generate a text-based visualization of request flow chains.

    Example output:
        Login POST /auth -> token="eyJ..."
          |-> GET /api/user [Authorization: Bearer eyJ...]
               |-> POST /api/orders [Authorization: Bearer eyJ...]
    """
    if not report.chains:
        return "No request flow chains detected.\n"

    lines: list[str] = []
    lines.append(f"## Request Flow Chains ({len(report.chains)} chains, {report.total_links} links)")
    lines.append("")

    for i, chain in enumerate(report.chains, 1):
        lines.append(f"### Chain {i} ({chain.chain_type})")
        lines.append("")
        lines.append("```")

        for j, step in enumerate(chain.steps):
            # Extract short path from URL
            url = step.request_url
            path = url.split("://", 1)[1] if "://" in url else url
            if "/" in path:
                path = "/" + path.split("/", 1)[1]
            else:
                path = "/"

            value_preview = step.link_value_preview or "?"

            if j == 0:
                lines.append(f"{step.request_method} {path} -> {step.response_field}=\"{value_preview}\"")
            else:
                indent = "  " * j
                field_info = f"[{step.next_request_field}]" if step.next_request_field else ""
                lines.append(f"{indent}|-> {step.request_method} {path} {field_info}")
                if step.response_field:
                    lines.append(f"{indent}    -> {step.response_field}=\"{value_preview}\"")

            # Show next request
            if step.next_request_url:
                next_path = step.next_request_url
                if "://" in next_path:
                    next_path = "/" + next_path.split("://", 1)[1].split("/", 1)[1] if "/" in next_path.split("://", 1)[1] else "/"
                indent = "  " * (j + 1)
                field_info = f"[{step.next_request_field}]" if step.next_request_field else ""
                if j == 0:
                    lines.append(f"  |-> {next_path} {field_info}")

        lines.append("```")
        lines.append("")

    return "\n".join(lines)
