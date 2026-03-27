"""JWT Decoder — best-effort decode of JWT tokens found in traffic and vault events."""
from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class JWTToken(BaseModel):
    """Decoded JWT token."""
    raw: str
    header: dict[str, Any] = Field(default_factory=dict)
    payload: dict[str, Any] = Field(default_factory=dict)
    issuer: str | None = None
    subject: str | None = None
    expires_at: str | None = None
    issued_at: str | None = None
    custom_claims: dict[str, Any] = Field(default_factory=dict)
    source: str = ""  # where this JWT was found
    is_expired: bool = False


# Standard JWT claims to exclude from custom_claims
_STANDARD_CLAIMS = {
    "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
    "typ", "alg", "kid",
}

# Regex to find JWT-like strings (three base64url parts separated by dots)
JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*')


def _base64url_decode(s: str) -> bytes:
    """Decode base64url string with padding fix."""
    # Add padding if needed
    remainder = len(s) % 4
    if remainder == 2:
        s += "=="
    elif remainder == 3:
        s += "="
    # Replace URL-safe chars
    s = s.replace("-", "+").replace("_", "/")
    return base64.b64decode(s)


def decode_jwt(token: str, source: str = "") -> JWTToken | None:
    """Decode a JWT token string (best-effort, no signature verification).

    Args:
        token: The JWT string (e.g., "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xxx")
        source: Where this token was found (for reporting).

    Returns:
        JWTToken with decoded header and payload, or None on failure.
    """
    if not token or not token.startswith("eyJ"):
        return None

    parts = token.split(".")
    if len(parts) < 2:
        return None

    try:
        header_bytes = _base64url_decode(parts[0])
        header = json.loads(header_bytes)
    except Exception:
        return None

    try:
        payload_bytes = _base64url_decode(parts[1])
        payload = json.loads(payload_bytes)
    except Exception:
        payload = {}

    # Extract standard claims
    issuer = payload.get("iss")
    subject = payload.get("sub")

    expires_at = None
    is_expired = False
    if "exp" in payload:
        try:
            exp_ts = int(payload["exp"])
            exp_dt = datetime.fromtimestamp(exp_ts, tz=timezone.utc)
            expires_at = exp_dt.isoformat()
            is_expired = exp_dt < datetime.now(timezone.utc)
        except (ValueError, TypeError, OSError):
            expires_at = str(payload["exp"])

    issued_at = None
    if "iat" in payload:
        try:
            iat_ts = int(payload["iat"])
            iat_dt = datetime.fromtimestamp(iat_ts, tz=timezone.utc)
            issued_at = iat_dt.isoformat()
        except (ValueError, TypeError, OSError):
            issued_at = str(payload["iat"])

    # Collect custom claims (everything not in standard set)
    custom_claims = {
        k: v for k, v in payload.items()
        if k not in _STANDARD_CLAIMS
    }

    return JWTToken(
        raw=token,
        header=header,
        payload=payload,
        issuer=str(issuer) if issuer is not None else None,
        subject=str(subject) if subject is not None else None,
        expires_at=expires_at,
        issued_at=issued_at,
        custom_claims=custom_claims,
        source=source,
        is_expired=is_expired,
    )


def find_jwts_in_text(text: str, source: str = "") -> list[JWTToken]:
    """Find and decode all JWT-like strings in a text blob.

    Args:
        text: Text to search (URL, header value, body, etc.)
        source: Context label for where the text came from.

    Returns:
        List of decoded JWTToken objects.
    """
    if not text:
        return []

    tokens = []
    seen = set()

    for match in JWT_PATTERN.finditer(text):
        raw = match.group(0)
        if raw in seen:
            continue
        seen.add(raw)

        decoded = decode_jwt(raw, source=source)
        if decoded is not None:
            tokens.append(decoded)

    return tokens


def find_jwts_in_events(events: list[dict[str, Any]]) -> list[JWTToken]:
    """Scan all session events for JWT tokens.

    Looks in:
    - traffic http_request/http_response: URL, headers (Authorization, Cookie), body
    - vault pref_read/encrypted_pref_read: values
    - vault tink_decrypt: plaintext_preview

    Returns:
        Deduplicated list of JWTToken objects.
    """
    seen_raws: set[str] = set()
    tokens: list[JWTToken] = []

    def _add(token: JWTToken | None) -> None:
        if token and token.raw not in seen_raws:
            seen_raws.add(token.raw)
            tokens.append(token)

    for event in events:
        module = event.get("module", "")
        etype = event.get("type", "")
        data = event.get("data", {})

        if module == "traffic" and etype in ("http_request", "http_response"):
            # Check URL
            url = data.get("url", "")
            for t in find_jwts_in_text(url, source=f"traffic:{etype}:url"):
                _add(t)

            # Check headers
            headers = data.get("headers", {})
            for hk, hv in headers.items():
                if isinstance(hv, str):
                    for t in find_jwts_in_text(hv, source=f"traffic:{etype}:header:{hk}"):
                        _add(t)

            # Check body
            body = data.get("body", "")
            if body:
                for t in find_jwts_in_text(body, source=f"traffic:{etype}:body"):
                    _add(t)

        elif module == "vault":
            if etype in ("pref_read", "encrypted_pref_read"):
                value = data.get("value", "")
                if isinstance(value, str) and value.startswith("eyJ"):
                    _add(decode_jwt(value, source=f"vault:{etype}:{data.get('key', '?')}"))

            elif etype == "encrypted_pref_dump":
                entries = data.get("entries", {})
                for k, v in entries.items():
                    if isinstance(v, str) and v.startswith("eyJ"):
                        _add(decode_jwt(v, source=f"vault:encrypted_pref_dump:{k}"))

            elif etype == "tink_decrypt":
                preview = data.get("plaintext_preview", "")
                for t in find_jwts_in_text(preview, source="vault:tink_decrypt"):
                    _add(t)

    return tokens
