"""Auth Flow Analyzer — detect login/auth sequences from traffic and vault events."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from kahlo.analyze.jwt import JWTToken, find_jwts_in_events


class AuthRequest(BaseModel):
    """A single request in an auth flow sequence."""
    index: int = 0
    timestamp: str | None = None
    method: str = ""
    url: str = ""
    host: str = ""
    path: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    body_preview: str = ""
    body_format: str = ""
    auth_signal: str = ""
    auth_pattern: str = ""
    has_jwt: bool = False


class AuthResponse(BaseModel):
    """A response in an auth flow sequence."""
    index: int = 0
    timestamp: str | None = None
    status: int = 0
    url: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    body_preview: str = ""
    body_format: str = ""
    auth_signal: str = ""
    has_jwt: bool = False
    has_set_cookie: bool = False


class AuthStep(BaseModel):
    """A request-response pair in an auth flow."""
    request: AuthRequest
    response: AuthResponse | None = None
    step_type: str = ""  # "login", "token", "refresh", "verify", "register", "session"


class TokenRefreshPattern(BaseModel):
    """Detected token refresh pattern."""
    refresh_url: str = ""
    refresh_method: str = ""
    uses_refresh_token: bool = False
    response_has_new_token: bool = False
    token_field: str = ""


class EncryptedPrefEntry(BaseModel):
    """A decrypted entry from EncryptedSharedPreferences."""
    key: str
    value: str | None = None
    value_type: str = ""
    source: str = ""


class AuthFlowReport(BaseModel):
    """Complete auth flow analysis from a session."""
    auth_steps: list[AuthStep] = Field(default_factory=list)
    jwt_tokens: list[JWTToken] = Field(default_factory=list)
    encrypted_prefs: list[EncryptedPrefEntry] = Field(default_factory=list)
    token_refresh: TokenRefreshPattern | None = None
    auth_url: str = ""
    auth_method: str = ""
    auth_host: str = ""
    required_headers: dict[str, str] = Field(default_factory=dict)
    body_format: str = ""
    has_auth_flow: bool = False
    total_auth_events: int = 0
    tink_decrypts: int = 0


# Step type classification from URL patterns
# Order matters: more specific patterns first
_STEP_TYPE_PATTERNS: list[tuple[str, str]] = [
    ("refresh", "refresh"),
    ("renew", "refresh"),
    ("login", "login"),
    ("signin", "login"),
    ("sign_in", "login"),
    ("sign-in", "login"),
    ("authenticate", "login"),
    ("password", "login"),
    ("oauth2", "token"),
    ("oauth", "token"),
    ("/token", "token"),
    ("verification", "verify"),
    ("verify", "verify"),
    ("confirm", "verify"),
    ("otp", "verify"),
    ("sms", "verify"),
    ("code", "verify"),
    ("register", "register"),
    ("signup", "register"),
    ("sign_up", "register"),
    ("session", "session"),
    ("user/me", "session"),
    ("profile", "session"),
    ("account", "session"),
    ("auth", "login"),
]


def _classify_step(url: str) -> str:
    """Classify an auth step by URL pattern."""
    url_lower = url.lower()
    for pattern, step_type in _STEP_TYPE_PATTERNS:
        if pattern in url_lower:
            return step_type
    return "auth"


def analyze_auth(events: list[dict[str, Any]], package: str | None = None) -> AuthFlowReport:
    """Analyze auth flow from session events.

    Args:
        events: All session events.
        package: Package name for context.

    Returns:
        AuthFlowReport with auth steps, JWT tokens, encrypted prefs.
    """
    auth_requests: list[dict[str, Any]] = []
    auth_responses: list[dict[str, Any]] = []
    encrypted_prefs: list[EncryptedPrefEntry] = []
    tink_decrypts = 0

    for event in events:
        module = event.get("module", "")
        etype = event.get("type", "")
        data = event.get("data", {})
        ts = event.get("ts")

        # Collect auth-tagged traffic events
        if module == "traffic":
            if etype == "http_request" and data.get("auth_flow"):
                data["_ts"] = ts
                auth_requests.append(data)
            elif etype == "http_response" and data.get("auth_flow"):
                data["_ts"] = ts
                auth_responses.append(data)

        # Collect decrypted encrypted prefs
        elif module == "vault":
            if etype == "encrypted_pref_read":
                encrypted_prefs.append(EncryptedPrefEntry(
                    key=data.get("key", ""),
                    value=str(data.get("value")) if data.get("value") is not None else None,
                    value_type=data.get("value_type", ""),
                    source=data.get("source", "EncryptedSharedPreferences"),
                ))
            elif etype == "encrypted_pref_dump":
                entries = data.get("entries", {})
                for k, v in entries.items():
                    encrypted_prefs.append(EncryptedPrefEntry(
                        key=k,
                        value=str(v) if v is not None else None,
                        value_type="string",
                        source=data.get("source", "EncryptedSharedPreferences"),
                    ))
            elif etype == "encrypted_pref_write":
                encrypted_prefs.append(EncryptedPrefEntry(
                    key=data.get("key", ""),
                    value=str(data.get("value")) if data.get("value") is not None else None,
                    value_type=data.get("value_type", ""),
                    source="EncryptedSharedPreferences:write",
                ))
            elif etype == "tink_decrypt":
                tink_decrypts += 1

    # Match requests to responses by index
    response_by_index: dict[int, dict[str, Any]] = {}
    for res in auth_responses:
        idx = res.get("index", 0)
        if idx > 0:
            response_by_index[idx] = res

    # Build auth steps
    auth_steps: list[AuthStep] = []
    for req in auth_requests:
        idx = req.get("index", 0)
        url = req.get("url", "")

        # Parse host and path from URL
        host = ""
        path = ""
        if "://" in url:
            after_scheme = url.split("://", 1)[1]
            slash_idx = after_scheme.find("/")
            if slash_idx >= 0:
                host = after_scheme[:slash_idx]
                path = after_scheme[slash_idx:]
            else:
                host = after_scheme
                path = "/"
        else:
            path = url
            host = req.get("headers", {}).get("Host", "")

        ar = AuthRequest(
            index=idx,
            timestamp=req.get("_ts"),
            method=req.get("method", ""),
            url=url,
            host=host,
            path=path,
            headers=req.get("headers", {}),
            body_preview=req.get("body", "")[:500] if req.get("body") else "",
            body_format=req.get("body_format", ""),
            auth_signal=req.get("auth_signal", ""),
            auth_pattern=req.get("auth_pattern", ""),
            has_jwt=bool(req.get("auth_has_jwt")),
        )

        # Match response
        resp_data = response_by_index.get(idx)
        resp = None
        if resp_data:
            resp = AuthResponse(
                index=idx,
                timestamp=resp_data.get("_ts"),
                status=resp_data.get("status", 0),
                url=resp_data.get("url", ""),
                headers=resp_data.get("headers", {}),
                body_preview=resp_data.get("body", "")[:500] if resp_data.get("body") else "",
                body_format=resp_data.get("body_format", ""),
                auth_signal=resp_data.get("auth_signal", ""),
                has_jwt=bool(resp_data.get("auth_has_jwt")),
                has_set_cookie=bool(resp_data.get("auth_set_cookie")),
            )

        step_type = _classify_step(url)
        auth_steps.append(AuthStep(
            request=ar,
            response=resp,
            step_type=step_type,
        ))

    # Sort by index
    auth_steps.sort(key=lambda s: s.request.index)

    # Detect token refresh pattern
    token_refresh = None
    for step in auth_steps:
        if step.step_type == "refresh":
            refresh = TokenRefreshPattern(
                refresh_url=step.request.url,
                refresh_method=step.request.method,
                uses_refresh_token="refresh_token" in step.request.body_preview.lower(),
                response_has_new_token=step.response.has_jwt if step.response else False,
                token_field="access_token" if step.response and "access_token" in (step.response.body_preview or "").lower() else "",
            )
            token_refresh = refresh
            break

    # Find JWTs across all events
    jwt_tokens = find_jwts_in_events(events)

    # Determine primary auth endpoint
    auth_url = ""
    auth_method = ""
    auth_host = ""
    required_headers: dict[str, str] = {}
    body_format = ""

    login_steps = [s for s in auth_steps if s.step_type in ("login", "token", "auth")]
    if login_steps:
        first_login = login_steps[0]
        auth_url = first_login.request.url
        auth_method = first_login.request.method
        auth_host = first_login.request.host
        body_format = first_login.request.body_format

        # Extract required headers (skip standard ones)
        skip_headers = {"host", "content-length", "accept-encoding", "connection", "user-agent"}
        for hk, hv in first_login.request.headers.items():
            if hk.lower() not in skip_headers:
                required_headers[hk] = hv

    total_auth_events = len(auth_requests) + len(auth_responses)

    return AuthFlowReport(
        auth_steps=auth_steps,
        jwt_tokens=jwt_tokens,
        encrypted_prefs=encrypted_prefs,
        token_refresh=token_refresh,
        auth_url=auth_url,
        auth_method=auth_method,
        auth_host=auth_host,
        required_headers=required_headers,
        body_format=body_format,
        has_auth_flow=len(auth_steps) > 0,
        total_auth_events=total_auth_events,
        tink_decrypts=tink_decrypts,
    )
