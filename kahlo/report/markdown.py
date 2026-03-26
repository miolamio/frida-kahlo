"""Markdown Report Generator — produce comprehensive analysis report."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kahlo.analyze.netmodel import NetmodelReport
from kahlo.analyze.patterns import PatternsReport
from kahlo.analyze.recon import ReconReport
from kahlo.analyze.traffic import TrafficReport
from kahlo.analyze.vault import VaultReport


def _mask_secret(value: str, show_chars: int = 8) -> str:
    """Partially mask a secret value: show first N chars + '...'."""
    if not value:
        return ""
    if len(value) <= show_chars + 3:
        return value
    return value[:show_chars] + "..."


def generate_markdown(
    session: dict[str, Any],
    traffic: TrafficReport,
    vault: VaultReport,
    recon: ReconReport,
    netmodel: NetmodelReport,
    patterns: PatternsReport,
) -> str:
    """Generate a comprehensive Markdown analysis report.

    Args:
        session: Raw session data dict (with session_id, package, etc.)
        traffic: Traffic analysis results.
        vault: Vault analysis results.
        recon: Recon analysis results.
        netmodel: Netmodel analysis results.
        patterns: Pattern detection results.

    Returns:
        Complete Markdown report string.
    """
    package = session.get("package", "unknown")
    session_id = session.get("session_id", "unknown")
    started_at = session.get("started_at", "")
    ended_at = session.get("ended_at", "")
    event_count = session.get("event_count", 0)
    stats = session.get("stats", {})

    # Calculate duration
    duration_str = "unknown"
    try:
        start = datetime.fromisoformat(started_at)
        end = datetime.fromisoformat(ended_at)
        duration = (end - start).total_seconds()
        duration_str = f"~{int(duration)} seconds"
    except (ValueError, TypeError):
        pass

    lines: list[str] = []

    # --- Header ---
    app_name = package.split(".")[-1].title() if "." in package else package
    lines.append(f"# {app_name} App ({package}) - Automated Analysis Report")
    lines.append("")
    lines.append(f"**Session:** `{session_id}`")
    lines.append(f"**Date:** {started_at[:19] if started_at else 'N/A'} UTC")
    lines.append(f"**Duration:** {duration_str}")
    lines.append(f"**Events Captured:** {event_count}")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC (automated)")
    lines.append("")
    lines.append("---")
    lines.append("")

    # --- 1. Executive Summary ---
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append(f"Automated Frida-Kahlo scan of **{package}** captured **{event_count} events** "
                 f"over {duration_str}.")
    lines.append("")

    by_module = stats.get("by_module", {})
    lines.append("| Module | Events |")
    lines.append("|--------|--------|")
    for mod, count in sorted(by_module.items(), key=lambda x: x[1], reverse=True):
        lines.append(f"| {mod} | {count} |")
    lines.append(f"| **Total** | **{event_count}** |")
    lines.append("")

    # Key findings summary
    lines.append("**Key Findings:**")
    lines.append(f"- **{len(traffic.servers)} servers** contacted across "
                 f"{len(set(s.role for s in traffic.servers))} categories")
    lines.append(f"- **{len(traffic.endpoints)} unique endpoints** detected from SSL captures")
    lines.append(f"- **{len(vault.secrets)} secrets/tokens** extracted from storage")
    lines.append(f"- **{len(vault.prefs_files)} SharedPreferences files** accessed ({vault.total_pref_reads} reads)")
    lines.append(f"- **{len(patterns.sdks)} SDKs** identified")
    if netmodel.signing_recipe:
        lines.append(f"- **Signing recipe** extracted: {netmodel.signing_recipe.algorithm}")
    lines.append(f"- **Fingerprint appetite:** {recon.fingerprint_appetite}/100")
    lines.append("")
    lines.append("---")
    lines.append("")

    # --- 2. Network Infrastructure ---
    lines.append("## 2. Network Infrastructure")
    lines.append("")

    if traffic.servers:
        lines.append("### 2.1 Servers & Domains")
        lines.append("")
        lines.append("| Domain | IP Address | Port | Role | Connections |")
        lines.append("|--------|-----------|------|------|-------------|")
        for s in traffic.servers:
            lines.append(f"| `{s.host}` | {s.ip or 'N/A'} | {s.port} | {s.role} | {s.connection_count} |")
        lines.append("")

    lines.append("### 2.2 Infrastructure Notes")
    lines.append("")
    lines.append(f"- All connections are TLS {traffic.servers[0].port if traffic.servers else 443} "
                 "-- no plaintext traffic observed" if all(s.tls for s in traffic.servers) else
                 "- Mixed TLS and plaintext connections detected")
    lines.append(f"- Total TCP connections: {traffic.total_connections}")
    lines.append(f"- Total HTTP requests captured: {traffic.total_requests}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # --- 3. API Endpoints ---
    lines.append("## 3. API Endpoints")
    lines.append("")

    if traffic.endpoints:
        lines.append("### 3.1 HTTP Endpoints")
        lines.append("")
        lines.append("| Method | Host | Path | Auth | Content-Type |")
        lines.append("|--------|------|------|------|--------------|")
        for ep in traffic.endpoints:
            auth_str = "Yes" if ep.has_auth else "No"
            if ep.auth_value:
                auth_str = f"`{_mask_secret(ep.auth_value, 15)}`"
            ct = ep.content_type or "N/A"
            lines.append(f"| {ep.method or 'N/A'} | `{ep.host or 'N/A'}` | `{ep.path or 'N/A'}` | {auth_str} | {ct} |")
        lines.append("")

        # Detailed endpoint info
        lines.append("### 3.2 Endpoint Details")
        lines.append("")
        for ep in traffic.endpoints:
            lines.append(f"**{ep.method} {ep.url}** (seen {ep.count}x)")
            lines.append("")
            if ep.sample_headers:
                lines.append("```")
                for k, v in ep.sample_headers.items():
                    lines.append(f"{k}: {v}")
                lines.append("```")
                lines.append("")
            if ep.sample_body_preview:
                lines.append("Body preview:")
                lines.append("```")
                lines.append(ep.sample_body_preview[:500])
                lines.append("```")
                lines.append("")
    else:
        lines.append("*No HTTP endpoints extracted from SSL captures.*")
        lines.append("")

    lines.append("---")
    lines.append("")

    # --- 4. Storage & Secrets ---
    lines.append("## 4. Storage & Secrets")
    lines.append("")

    lines.append("### 4.1 SharedPreferences Files")
    lines.append("")
    if vault.prefs_files:
        lines.append(f"**{len(vault.prefs_files)} files** accessed "
                     f"({vault.total_pref_reads} reads, {vault.total_pref_writes} writes)")
        lines.append("")
        lines.append("| File | Reads | Encrypted | Sample Keys |")
        lines.append("|------|-------|-----------|-------------|")
        for pf in sorted(vault.prefs_files, key=lambda p: p.keys_read, reverse=True):
            enc = "Yes" if pf.is_encrypted else "No"
            sample = ", ".join(pf.sample_keys[:3])
            if len(pf.sample_keys) > 3:
                sample += f" (+{len(pf.sample_keys) - 3} more)"
            lines.append(f"| `{pf.file}` | {pf.keys_read} | {enc} | {sample} |")
        lines.append("")

    if vault.databases:
        lines.append("### 4.2 SQLite Databases")
        lines.append("")
        lines.append("| Database | Tables | Writes |")
        lines.append("|----------|--------|--------|")
        for db in vault.databases:
            tables = ", ".join(db.tables) if db.tables else "N/A"
            lines.append(f"| `{db.name}` | {tables} | {db.write_count} |")
        lines.append("")

    if vault.secrets:
        lines.append("### 4.3 Extracted Secrets & Tokens")
        lines.append("")
        lines.append("| Name | Value | Source | Sensitivity |")
        lines.append("|------|-------|--------|-------------|")
        for secret in vault.secrets:
            masked = _mask_secret(secret.value, 12)
            lines.append(f"| {secret.name} | `{masked}` | {secret.category} | **{secret.sensitivity}** |")
        lines.append("")

    if vault.keystore_entries:
        lines.append("### 4.4 Encrypted Storage (Tink/AndroidX Security)")
        lines.append("")
        for entry in vault.keystore_entries:
            lines.append(f"- **{entry.store}**: {entry.key_type} ({entry.role})")
        lines.append("")

    if vault.file_writes:
        lines.append("### 4.5 File System Writes")
        lines.append("")
        for fw in vault.file_writes[:20]:
            short_path = fw.path.split("/com.voltmobi.yakitoriya/")[-1] if "/com.voltmobi.yakitoriya/" in fw.path else fw.path
            lines.append(f"- `{short_path}` ({fw.size} bytes)")
        if len(vault.file_writes) > 20:
            lines.append(f"- ... and {len(vault.file_writes) - 20} more")
        lines.append("")

    lines.append("---")
    lines.append("")

    # --- 5. Privacy Profile ---
    lines.append("## 5. Privacy Profile")
    lines.append("")
    lines.append(f"**Fingerprint Appetite Score: {recon.fingerprint_appetite}/100**")
    lines.append("")

    if recon.categories:
        lines.append(f"Data categories collected: {', '.join(recon.categories)}")
        lines.append("")

    if recon.device_info:
        lines.append("### 5.1 Device Information")
        lines.append("")
        lines.append("| Field | Value | Method |")
        lines.append("|-------|-------|--------|")
        for field, value in recon.device_info.items():
            if field.endswith("_access") or field.endswith("_source"):
                continue
            access = recon.device_info.get(f"{field}_access", "")
            source = recon.device_info.get(f"{field}_source", "")
            method = f"{source} ({access})" if access else source
            lines.append(f"| {field} | {value} | {method} |")
        lines.append("")

    if recon.telecom:
        lines.append("### 5.2 Telecom Information")
        lines.append("")
        lines.append("| Method | Value |")
        lines.append("|--------|-------|")
        for method, value in recon.telecom.items():
            lines.append(f"| `{method}` | {value} |")
        lines.append(f"\nTotal telecom queries: {recon.telecom_queries}")
        lines.append("")

    if recon.network_info:
        lines.append("### 5.3 Network Information")
        lines.append("")
        lines.append(f"Network queries: {recon.network_queries}")
        for info in recon.network_info:
            lines.append(f"- `{info['method']}` = {info['value']}")
        lines.append("")

    lines.append("---")
    lines.append("")

    # --- 6. Cryptography ---
    lines.append("## 6. Cryptographic Operations")
    lines.append("")

    if netmodel.hashes:
        lines.append("### 6.1 Hash Algorithm Usage")
        lines.append("")
        lines.append("| Algorithm | Count | Cert Hashing | Data Hashing |")
        lines.append("|-----------|-------|--------------|--------------|")
        for h in netmodel.hashes:
            cert = "Yes" if h.has_cert_hashing else "No"
            data = "Yes" if h.has_data_hashing else "No"
            lines.append(f"| {h.algorithm} | {h.count} | {cert} | {data} |")
        lines.append(f"\nTotal hash operations: {netmodel.total_hash_ops}")
        lines.append("")

    if netmodel.hmac_keys:
        lines.append("### 6.2 HMAC Operations")
        lines.append("")
        for hmac in netmodel.hmac_keys:
            lines.append(f"**Algorithm:** {hmac.algorithm}")
            lines.append(f"**Key (hex):** `{_mask_secret(hmac.key_hex, 16)}`")
            if hmac.key_ascii:
                lines.append(f"**Key (ASCII):** `{_mask_secret(hmac.key_ascii, 12)}`")
            lines.append(f"**Init count:** {hmac.count}")
            lines.append("")

    if netmodel.crypto_operations:
        lines.append("### 6.3 Encryption Operations")
        lines.append("")
        for op in netmodel.crypto_operations:
            lines.append(f"**{op.op.upper()}:** {op.algorithm}")
            lines.append(f"- Key: `{_mask_secret(op.key_hex, 16)}`")
            if op.iv_hex:
                lines.append(f"- IV: `{_mask_secret(op.iv_hex, 16)}`")
            lines.append(f"- Input: {op.input_length} bytes, Output: {op.output_length} bytes")
            if op.input_preview:
                lines.append(f"- Preview: `{op.input_preview[:200]}`")
            lines.append("")

    if netmodel.signing_recipe:
        lines.append("### 6.4 Signing Recipe")
        lines.append("")
        sr = netmodel.signing_recipe
        lines.append(f"- **Algorithm:** {sr.algorithm}")
        lines.append(f"- **Key:** `{_mask_secret(sr.key_hex, 16)}`")
        if sr.key_ascii:
            lines.append(f"- **Key (ASCII):** `{_mask_secret(sr.key_ascii, 12)}`")
        lines.append(f"- **Input pattern:** {sr.input_pattern}")
        lines.append(f"- **Nonce method:** {sr.nonce_method}")
        lines.append("")

    if netmodel.nonces:
        lines.append("### 6.5 Nonce/UUID Generation")
        lines.append("")
        lines.append(f"{len(netmodel.nonces)} nonces generated:")
        for n in netmodel.nonces[:10]:
            summary = f" ({n.stack_summary})" if n.stack_summary else ""
            lines.append(f"- `{n.value}` [{n.nonce_type}]{summary}")
        if len(netmodel.nonces) > 10:
            lines.append(f"- ... and {len(netmodel.nonces) - 10} more")
        lines.append("")

    lines.append("---")
    lines.append("")

    # --- 7. SDK Inventory ---
    lines.append("## 7. SDK Inventory")
    lines.append("")

    if patterns.sdks:
        lines.append("| SDK | Version | Category | Data Collected |")
        lines.append("|-----|---------|----------|----------------|")
        for sdk in patterns.sdks:
            version = sdk.version or "N/A"
            data = ", ".join(sdk.data_collected[:3])
            if len(sdk.data_collected) > 3:
                data += "..."
            lines.append(f"| **{sdk.name}** | {version} | {sdk.category} | {data} |")
        lines.append("")

        lines.append("### 7.1 SDK Evidence Details")
        lines.append("")
        for sdk in patterns.sdks:
            lines.append(f"**{sdk.name}** ({sdk.category})")
            for ev in sdk.evidence:
                lines.append(f"- {ev}")
            lines.append("")
    else:
        lines.append("*No known SDKs detected.*")
        lines.append("")

    lines.append("---")
    lines.append("")

    # --- 8. API Recreation Assessment ---
    lines.append("## 8. API Recreation Assessment")
    lines.append("")

    # Assess feasibility
    has_core_api = any(s.role == "core_api" for s in traffic.servers)
    has_signing = netmodel.signing_recipe is not None
    has_encryption = len(netmodel.crypto_operations) > 0
    has_auth_endpoints = any(ep.has_auth for ep in traffic.endpoints)

    if has_core_api:
        core_servers = [s for s in traffic.servers if s.role == "core_api"]
        lines.append(f"### Core API: `{core_servers[0].host}`")
        lines.append("")

    # Feasibility assessment
    feasibility = "HIGH"
    blockers: list[str] = []
    if has_encryption:
        blockers.append("Encrypted request bodies (AES-CBC) for some endpoints")
    if has_auth_endpoints:
        blockers.append("Authentication required for some endpoints")
    if vault.keystore_entries:
        blockers.append("EncryptedSharedPreferences may contain auth tokens")

    if len(blockers) > 2:
        feasibility = "MEDIUM"
    if len(blockers) > 3:
        feasibility = "LOW"

    lines.append(f"**Feasibility: {feasibility}**")
    lines.append("")

    if blockers:
        lines.append("**Blockers:**")
        for b in blockers:
            lines.append(f"- {b}")
        lines.append("")

    # What we have
    lines.append("**Available for recreation:**")
    for ep in traffic.endpoints:
        if not ep.has_auth or ep.auth_value == "Token null":
            lines.append(f"- {ep.method} {ep.url} (no auth required)")
    if netmodel.signing_recipe:
        lines.append(f"- Signing key: {netmodel.signing_recipe.algorithm} with known key")
    for secret in vault.secrets:
        if secret.category == "api_key":
            lines.append(f"- {secret.name}: `{_mask_secret(secret.value, 12)}`")
    lines.append("")

    lines.append("**Recommended next steps:**")
    lines.append("1. Extended scan during login flow to capture auth token exchange")
    lines.append("2. Extended scan during full app usage to map all API endpoints")
    lines.append("3. Hook Tink decrypt methods to reveal encrypted preference values")
    lines.append("4. Monitor HTTP/2 frames for full request/response bodies")
    lines.append("")

    lines.append("---")
    lines.append("")

    # --- Appendix: Event Summary ---
    lines.append("## Appendix: Event Count Summary")
    lines.append("")
    by_type = stats.get("by_type", {})
    if by_type:
        lines.append("| Module.Type | Count |")
        lines.append("|-------------|-------|")
        for key, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"| {key} | {count} |")
        lines.append(f"| **Total** | **{event_count}** |")
        lines.append("")

    return "\n".join(lines)
