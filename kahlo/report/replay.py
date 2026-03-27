"""Replay Script Generator — produce curl commands, Python scripts, and thin client."""
from __future__ import annotations

import json
import keyword
import os
import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

from kahlo.analyze.netmodel import NetmodelReport
from kahlo.analyze.traffic import EndpointInfo, TrafficReport
from kahlo.analyze.vault import VaultReport


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize_filename(name: str) -> str:
    """Convert a URL path into a safe filename."""
    safe = name.replace("/", "_").replace(".", "_").replace("?", "_").replace("&", "_")
    safe = safe.strip("_")
    if not safe:
        safe = "root"
    return safe[:60]


def _url_to_method_name(url: str, host: str | None = None) -> str:
    """Derive a clean Python method name from a URL.

    Strategy:
    1. Parse the URL to extract host and path.
    2. Use the *service* part of the host (e.g. "appsflyer" from
       "launches.appsflyersdk.com") as a prefix.
    3. Take the meaningful path segments (skip version numbers like v1, v6.17).
    4. Strip query parameters entirely.
    5. Collapse into a valid Python identifier.

    Examples:
        https://api.wavesend.ru/json/1.3/postEvent        -> pushwoosh_post_event
        https://sentry.inno.co/api/13/envelope/            -> sentry_envelope
        https://launches.appsflyersdk.com/api/v6.17/androidevent?app_id=... -> appsflyer_androidevent
        https://api2.branch.io/v1/install                  -> branch_install
    """
    parsed = urlparse(url)
    hostname = host or parsed.hostname or ""
    path = parsed.path or "/"

    # --- Derive service prefix from host ---
    prefix = _host_to_prefix(hostname)

    # --- Extract meaningful path segments ---
    segments = [s for s in path.split("/") if s]
    # Filter out noise: version segments (v1, v6.17, 1.3), "json", "api", numeric
    meaningful: list[str] = []
    for seg in segments:
        lower = seg.lower()
        # Skip pure version patterns: v1, v6.17, 1.3, 13 (purely numeric)
        if re.match(r'^v?\d+(\.\d+)*$', lower):
            continue
        # Skip common boilerplate path prefixes
        if lower in ("json", "api"):
            continue
        meaningful.append(seg)

    # Build method body from meaningful segments
    if meaningful:
        body = "_".join(meaningful)
    else:
        body = "root"

    # CamelCase -> snake_case (e.g. postEvent -> post_event)
    body = re.sub(r'([a-z])([A-Z])', r'\1_\2', body)
    body = body.lower()

    # Replace any non-alphanumeric with underscore
    body = re.sub(r'[^a-z0-9]', '_', body)
    # Collapse multiple underscores
    body = re.sub(r'_+', '_', body).strip('_')

    raw = f"{prefix}_{body}" if prefix else body
    # Collapse again after join
    raw = re.sub(r'_+', '_', raw).strip('_')

    if not raw:
        raw = "request"

    # Ensure it's a valid identifier (not a keyword, starts with letter/underscore)
    if raw[0].isdigit():
        raw = f"ep_{raw}"
    if keyword.iskeyword(raw):
        raw = f"{raw}_"

    return raw


def _host_to_prefix(hostname: str) -> str:
    """Extract a short service prefix from a hostname.

    Examples:
        api.wavesend.ru          -> pushwoosh  (known alias)
        sentry.inno.co           -> sentry
        launches.appsflyersdk.com -> appsflyer
        api2.branch.io           -> branch
        beacon2.yakitoriya.ru    -> yakitoriya
        firebase-settings.crashlytics.com -> crashlytics
    """
    hostname = hostname.lower()

    # Known aliases: map hostname patterns to canonical short names
    _KNOWN = [
        ("wavesend", "pushwoosh"),
        ("appsflyersdk", "appsflyer"),
        ("appsflyer", "appsflyer"),
        ("crashlytics", "crashlytics"),
        ("firebase", "firebase"),
        ("branch", "branch"),
        ("sentry", "sentry"),
        ("amplitude", "amplitude"),
        ("mixpanel", "mixpanel"),
        ("adjust", "adjust"),
        ("appmetrica", "appmetrica"),
    ]

    for pattern, name in _KNOWN:
        if pattern in hostname:
            return name

    # Fallback: take the most specific non-generic domain part
    parts = hostname.replace("-", ".").split(".")
    # Filter out generic parts
    generic = {"com", "ru", "io", "co", "net", "org", "api", "api2", "www",
               "app", "sdk", "cdn", "v1", "v2"}
    meaningful = [p for p in parts if p not in generic and len(p) > 1 and not p.isdigit()]
    if meaningful:
        # Pick the longest / most specific part
        return max(meaningful, key=len)
    return ""


def _host_base_url(endpoint: EndpointInfo) -> str:
    """Build the base URL (scheme + host) for an endpoint."""
    parsed = urlparse(endpoint.url)
    scheme = parsed.scheme or "https"
    host = parsed.hostname or endpoint.host or ""
    port = parsed.port
    if port and port not in (443, 80):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def _endpoint_auth_header(endpoint: EndpointInfo) -> str | None:
    """Return the correct Authorization header value for an endpoint, or None."""
    if endpoint.auth_value:
        return endpoint.auth_value
    return None


# ---------------------------------------------------------------------------
# Curl builder
# ---------------------------------------------------------------------------

def _build_curl(endpoint: EndpointInfo) -> str:
    """Build a curl command for an endpoint — includes ALL captured headers."""
    lines = [f"curl -X {endpoint.method or 'GET'} \\"]
    lines.append(f"  '{endpoint.url}' \\")

    for key, value in (endpoint.sample_headers or {}).items():
        # Skip headers that curl adds automatically
        if key.lower() in ("content-length", "host"):
            continue
        # Escape single quotes in header value
        escaped = value.replace("'", "'\\''")
        lines.append(f"  -H '{key}: {escaped}' \\")

    if endpoint.sample_body_preview and (endpoint.method or "").upper() in ("POST", "PUT", "PATCH"):
        body = endpoint.sample_body_preview
        # Try to clean up the body for curl
        if body.startswith("{"):
            try:
                parsed = json.loads(body)
                body = json.dumps(parsed, ensure_ascii=False)
            except json.JSONDecodeError:
                pass
        # Escape single quotes in the body
        body = body.replace("'", "'\\''")
        lines.append(f"  -d '{body}'")
    else:
        # Remove trailing backslash from last header
        if lines and lines[-1].endswith(" \\"):
            lines[-1] = lines[-1][:-2]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Python snippet builder
# ---------------------------------------------------------------------------

def _build_python(endpoint: EndpointInfo) -> str:
    """Build a Python requests snippet for an endpoint."""
    lines = ["import requests", ""]

    # Headers — include all captured headers
    headers: dict[str, str] = {}
    for key, value in (endpoint.sample_headers or {}).items():
        if key.lower() not in ("content-length", "host"):
            headers[key] = value

    if headers:
        lines.append(f"headers = {json.dumps(headers, indent=4, ensure_ascii=False)}")
        lines.append("")

    method = (endpoint.method or "GET").lower()

    if endpoint.sample_body_preview and method in ("post", "put", "patch"):
        body = endpoint.sample_body_preview
        if body.startswith("{"):
            try:
                parsed = json.loads(body)
                lines.append(f"data = {json.dumps(parsed, indent=4, ensure_ascii=False)}")
                lines.append("")
                lines.append(f"response = requests.{method}(")
                lines.append(f"    '{endpoint.url}',")
                lines.append(f"    headers=headers,")
                lines.append(f"    json=data,")
                lines.append(f")")
            except json.JSONDecodeError:
                lines.append(f"data = '''{body}'''")
                lines.append("")
                lines.append(f"response = requests.{method}(")
                lines.append(f"    '{endpoint.url}',")
                lines.append(f"    headers=headers,")
                lines.append(f"    data=data,")
                lines.append(f")")
        else:
            lines.append(f"data = '''{body}'''")
            lines.append("")
            lines.append(f"response = requests.{method}(")
            lines.append(f"    '{endpoint.url}',")
            lines.append(f"    headers=headers,")
            lines.append(f"    data=data,")
            lines.append(f")")
    else:
        lines.append(f"response = requests.{method}(")
        lines.append(f"    '{endpoint.url}',")
        if headers:
            lines.append(f"    headers=headers,")
        lines.append(f")")

    lines.append("")
    lines.append("print(f'Status: {response.status_code}')")
    lines.append("print(response.text[:500])")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Crypto helpers (unchanged logic)
# ---------------------------------------------------------------------------

def _build_signing_code(netmodel: NetmodelReport) -> str:
    """Build Python signing code if HMAC signing detected."""
    if not netmodel.signing_recipe:
        return ""

    sr = netmodel.signing_recipe
    lines = [
        "import hmac",
        "import hashlib",
        "",
        "",
        "def sign_request(data: bytes) -> str:",
        f"    \"\"\"Sign request data using {sr.algorithm}.\"\"\"",
        f"    key = bytes.fromhex('{sr.key_hex}')",
        f"    # Key ASCII: '{sr.key_ascii}'",
    ]

    algo = sr.algorithm.lower()
    if "sha256" in algo:
        lines.append("    return hmac.new(key, data, hashlib.sha256).hexdigest()")
    elif "sha1" in algo:
        lines.append("    return hmac.new(key, data, hashlib.sha1).hexdigest()")
    else:
        lines.append(f"    # Algorithm: {sr.algorithm}")
        lines.append("    return hmac.new(key, data, hashlib.sha256).hexdigest()")

    return "\n".join(lines)


def _build_encryption_code(netmodel: NetmodelReport) -> str:
    """Build Python encryption code if AES encryption detected."""
    if not netmodel.crypto_operations:
        return ""

    op = netmodel.crypto_operations[0]
    lines = [
        "from Crypto.Cipher import AES",
        "from Crypto.Util.Padding import pad, unpad",
        "",
        "",
        f"def encrypt_payload(plaintext: bytes) -> bytes:",
        f"    \"\"\"Encrypt payload using {op.algorithm}.\"\"\"",
        f"    key = bytes.fromhex('{op.key_hex}')",
        f"    iv = bytes.fromhex('{op.iv_hex}')",
        f"    cipher = AES.new(key, AES.MODE_CBC, iv)",
        f"    return cipher.encrypt(pad(plaintext, AES.block_size))",
        "",
        "",
        f"def decrypt_payload(ciphertext: bytes) -> bytes:",
        f"    \"\"\"Decrypt payload using {op.algorithm}.\"\"\"",
        f"    key = bytes.fromhex('{op.key_hex}')",
        f"    iv = bytes.fromhex('{op.iv_hex}')",
        f"    cipher = AES.new(key, AES.MODE_CBC, iv)",
        f"    return unpad(cipher.decrypt(ciphertext), AES.block_size)",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Thin client builder (rewritten)
# ---------------------------------------------------------------------------

def _build_thin_client(
    traffic: TrafficReport,
    vault: VaultReport,
    netmodel: NetmodelReport,
    package: str,
) -> str:
    """Build a thin client skeleton class with per-host routing and clean method names."""
    app_name = package.split(".")[-1].title() if "." in package else package

    # Find user-agent from endpoints
    user_agent = "Dalvik/2.1.0"
    for ep in traffic.endpoints:
        ua = ep.sample_headers.get("User-Agent", "")
        if ua:
            user_agent = ua
            break

    # Group endpoints by host
    host_groups: dict[str, list[EndpointInfo]] = defaultdict(list)
    for ep in traffic.endpoints:
        host = ep.host or urlparse(ep.url).hostname or "unknown"
        host_groups[host].append(ep)

    # Build host URL map — include ALL servers (even those without captured endpoints)
    host_urls: dict[str, str] = {}
    for s in traffic.servers:
        scheme = "https" if s.tls else "http"
        if s.port not in (443, 80):
            host_urls[s.host] = f"{scheme}://{s.host}:{s.port}"
        else:
            host_urls[s.host] = f"{scheme}://{s.host}"
    # Overlay with endpoint-derived URLs (more accurate — includes scheme from actual URL)
    for ep in traffic.endpoints:
        host = ep.host or urlparse(ep.url).hostname or "unknown"
        if host not in host_urls:
            host_urls[host] = _host_base_url(ep)

    # Find core API server
    core_host = ""
    for s in traffic.servers:
        if s.role == "core_api":
            core_host = s.host
            break

    lines = [
        '"""',
        f"Thin client for {package} API.",
        f"Auto-generated by Frida-Kahlo from session analysis.",
        '"""',
        "import requests",
        "import json",
    ]

    # Add signing import if needed
    if netmodel.signing_recipe:
        lines.extend(["import hmac", "import hashlib"])

    lines.extend([
        "",
        "",
        f"class {app_name}Client:",
        f'    """API client for {package}.',
        f"",
        f"    Servers discovered during analysis:",
    ])

    # Document all hosts and their roles in the class docstring
    for s in traffic.servers:
        prefix = _host_to_prefix(s.host)
        lines.append(f"        {s.host} ({s.role}) — prefix: {prefix}")

    lines.extend([
        '    """',
        "",
        "    # Per-host base URLs",
    ])

    # Emit host URL constants
    for host, url in sorted(host_urls.items()):
        const_name = _host_to_prefix(host).upper() or host.split(".")[0].upper()
        # Ensure constant name is a valid identifier
        const_name = re.sub(r'[^A-Z0-9]', '_', const_name)
        const_name = re.sub(r'_+', '_', const_name).strip('_')
        lines.append(f'    HOST_{const_name} = "{url}"')

    # Default BASE_URL for backward compatibility
    if core_host:
        core_const = _host_to_prefix(core_host).upper() or core_host.split(".")[0].upper()
        core_const = re.sub(r'[^A-Z0-9]', '_', core_const)
        core_const = re.sub(r'_+', '_', core_const).strip('_')
        lines.append(f"    BASE_URL = HOST_{core_const}")
    else:
        lines.append('    BASE_URL = ""')

    lines.extend([
        "",
        "    def __init__(self, token: str | None = None):",
        "        self.session = requests.Session()",
        "        self.session.headers.update({",
        f'            "User-Agent": "{user_agent}",',
        '            "Accept-Encoding": "gzip",',
        "        })",
        "        if token:",
        '            self.session.headers["Authorization"] = f"Bearer {token}"',
    ])

    # Add signing key if present
    if netmodel.signing_recipe:
        sr = netmodel.signing_recipe
        lines.append(f'        self._signing_key = bytes.fromhex("{sr.key_hex}")')

    lines.append("")

    # Add signing method if present
    if netmodel.signing_recipe:
        sr = netmodel.signing_recipe
        lines.extend([
            "    def _sign(self, data: bytes) -> str:",
            f'        """Sign data with {sr.algorithm}."""',
            "        return hmac.new(self._signing_key, data, hashlib.sha256).hexdigest()",
            "",
        ])

    # Generate methods grouped by host
    seen_methods: set[str] = set()
    first_group = True

    for host in sorted(host_groups.keys()):
        eps = host_groups[host]
        prefix = _host_to_prefix(host)
        host_const = (prefix.upper() or host.split(".")[0].upper())
        host_const = re.sub(r'[^A-Z0-9]', '_', host_const)
        host_const = re.sub(r'_+', '_', host_const).strip('_')

        if not first_group:
            lines.append("")
        first_group = False

        lines.append(f"    # --- {host} ({prefix or 'unknown'}) ---")
        lines.append("")

        for ep in eps:
            method_name = _url_to_method_name(ep.url, ep.host)
            http_method = (ep.method or "GET").lower()

            # De-duplicate method names
            if method_name in seen_methods:
                method_name += f"_{http_method}"
            if method_name in seen_methods:
                method_name += f"_{ep.count}"
            seen_methods.add(method_name)

            # Determine per-endpoint auth
            auth_value = _endpoint_auth_header(ep)

            # Build docstring with sample body
            doc_lines = [
                f"    def {method_name}(self, **kwargs):",
                f'        """',
                f"        {http_method.upper()} {ep.url}",
            ]

            if auth_value:
                doc_lines.append(f"        Auth: {auth_value}")

            if ep.content_type:
                doc_lines.append(f"        Content-Type: {ep.content_type}")

            doc_lines.append(f"        Observed: {ep.count} time(s)")

            # Include sample body in docstring if available and parseable
            if ep.sample_body_preview and ep.sample_body_preview.startswith("{"):
                try:
                    parsed_body = json.loads(ep.sample_body_preview)
                    body_str = json.dumps(parsed_body, indent=8, ensure_ascii=False)
                    doc_lines.append("")
                    doc_lines.append("        Sample body:")
                    for bline in body_str.split("\n"):
                        doc_lines.append(f"            {bline}")
                except json.JSONDecodeError:
                    pass

            doc_lines.append(f'        """')
            lines.extend(doc_lines)

            # Set per-endpoint auth if it differs from session default
            if auth_value:
                lines.append(f"        headers = {{}}")
                lines.append(f'        headers["Authorization"] = "{auth_value}"')
            else:
                lines.append(f"        headers = {{}}")

            path = urlparse(ep.url).path or "/"
            query = urlparse(ep.url).query
            if query:
                full_path = f"{path}?{query}"
            else:
                full_path = path

            if http_method in ("post", "put", "patch"):
                lines.extend([
                    f'        return self.session.{http_method}(',
                    f'            f"{{self.HOST_{host_const}}}{full_path}",',
                    f"            headers=headers,",
                    f"            json=kwargs,",
                    f"        )",
                ])
            else:
                lines.extend([
                    f'        return self.session.{http_method}(',
                    f'            f"{{self.HOST_{host_const}}}{full_path}",',
                    f"            headers=headers,",
                    f"            params=kwargs,",
                    f"        )",
                ])

            lines.append("")

    # Add usage example
    lines.extend([
        "",
        'if __name__ == "__main__":',
        f"    client = {app_name}Client()",
        '    # Example usage:',
    ])

    for ep in traffic.endpoints[:3]:
        method_name = _url_to_method_name(ep.url, ep.host)
        lines.append(f"    # response = client.{method_name}()")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_replay(
    output_dir: str,
    traffic: TrafficReport,
    vault: VaultReport,
    netmodel: NetmodelReport,
    package: str,
) -> list[str]:
    """Generate replay scripts for discovered endpoints.

    Args:
        output_dir: Directory to write replay scripts.
        traffic: Traffic analysis results.
        vault: Vault analysis results.
        netmodel: Netmodel analysis results.
        package: App package name.

    Returns:
        List of generated file paths.
    """
    os.makedirs(output_dir, exist_ok=True)
    generated: list[str] = []

    # Generate curl commands
    curl_dir = os.path.join(output_dir, "curl")
    os.makedirs(curl_dir, exist_ok=True)

    for i, ep in enumerate(traffic.endpoints):
        filename = f"{i+1:02d}_{_sanitize_filename(ep.path or 'root')}.sh"
        filepath = os.path.join(curl_dir, filename)
        content = f"#!/bin/bash\n# {ep.method} {ep.url}\n# Captured {ep.count} time(s)\n\n"
        content += _build_curl(ep) + "\n"
        with open(filepath, "w") as f:
            f.write(content)
        os.chmod(filepath, 0o755)
        generated.append(filepath)

    # Generate Python request scripts
    python_dir = os.path.join(output_dir, "python")
    os.makedirs(python_dir, exist_ok=True)

    for i, ep in enumerate(traffic.endpoints):
        filename = f"{i+1:02d}_{_sanitize_filename(ep.path or 'root')}.py"
        filepath = os.path.join(python_dir, filename)
        content = f'"""Replay: {ep.method} {ep.url}"""\n\n'
        content += _build_python(ep) + "\n"
        with open(filepath, "w") as f:
            f.write(content)
        generated.append(filepath)

    # Generate signing code if present
    if netmodel.signing_recipe:
        signing_path = os.path.join(python_dir, "signing.py")
        content = '"""HMAC signing code extracted from session."""\n\n'
        content += _build_signing_code(netmodel) + "\n"
        with open(signing_path, "w") as f:
            f.write(content)
        generated.append(signing_path)

    # Generate encryption code if present
    if netmodel.crypto_operations:
        crypto_path = os.path.join(python_dir, "encryption.py")
        content = '"""AES encryption code extracted from session."""\n\n'
        content += _build_encryption_code(netmodel) + "\n"
        with open(crypto_path, "w") as f:
            f.write(content)
        generated.append(crypto_path)

    # Generate thin client
    client_path = os.path.join(output_dir, "client.py")
    content = _build_thin_client(traffic, vault, netmodel, package) + "\n"
    with open(client_path, "w") as f:
        f.write(content)
    generated.append(client_path)

    return generated
