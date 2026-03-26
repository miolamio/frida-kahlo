"""Netmodel Analyzer — parse netmodel events into crypto inventory and signing recipe."""
from __future__ import annotations

from collections import Counter
from typing import Any

from pydantic import BaseModel, Field


class CryptoOp(BaseModel):
    """A cryptographic operation (encrypt/decrypt)."""
    op: str  # "encrypt" or "decrypt"
    algorithm: str
    key_hex: str = ""
    iv_hex: str = ""
    input_preview: str = ""
    input_length: int = 0
    output_length: int = 0


class HMACKey(BaseModel):
    """An HMAC key initialization."""
    algorithm: str
    key_hex: str
    key_ascii: str = ""
    count: int = 1


class HashInfo(BaseModel):
    """Summary of hash algorithm usage."""
    algorithm: str
    count: int
    sample_outputs: list[str] = Field(default_factory=list)
    has_cert_hashing: bool = False
    has_data_hashing: bool = False


class TLSInfo(BaseModel):
    """TLS session information (from cert hashing patterns)."""
    cert_subject: str = ""
    md5: str = ""
    sha1: str = ""
    sha256: str = ""


class NonceInfo(BaseModel):
    """A nonce/UUID generation event."""
    nonce_type: str  # "uuid", "timestamp", etc.
    value: str
    stack_summary: str = ""  # extracted class/method from stack


class SigningRecipe(BaseModel):
    """Extracted signing pattern (e.g. HMAC signing of API requests)."""
    algorithm: str
    key_hex: str
    key_ascii: str = ""
    input_pattern: str = ""
    nonce_method: str = ""


class NetmodelReport(BaseModel):
    """Complete crypto/netmodel analysis from a session."""
    crypto_operations: list[CryptoOp] = Field(default_factory=list)
    hmac_keys: list[HMACKey] = Field(default_factory=list)
    hashes: list[HashInfo] = Field(default_factory=list)
    tls_sessions: list[TLSInfo] = Field(default_factory=list)
    nonces: list[NonceInfo] = Field(default_factory=list)
    signing_recipe: SigningRecipe | None = None
    total_hash_ops: int = 0
    hash_algorithm_counts: dict[str, int] = Field(default_factory=dict)


def _hex_to_ascii(hex_str: str) -> str:
    """Try to convert hex string to ASCII."""
    try:
        return bytes.fromhex(hex_str).decode("ascii", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return ""


def _extract_stack_summary(stack: str) -> str:
    """Extract the most relevant class/method from a Java stack trace."""
    if not stack:
        return ""
    lines = stack.strip().split("\n")
    # Skip the exception line, find first meaningful frame
    for line in lines[1:]:
        line = line.strip()
        if line.startswith("at "):
            # Extract class.method
            parts = line[3:].split("(")[0]
            # Skip standard library frames
            if parts.startswith("java.") or parts.startswith("javax."):
                continue
            return parts
    return ""


def analyze_netmodel(events: list[dict[str, Any]]) -> NetmodelReport:
    """Analyze netmodel events from a session.

    Args:
        events: All session events (will be filtered to module=="netmodel").

    Returns:
        NetmodelReport with crypto operations, HMAC keys, hashes, nonces.
    """
    netmodel_events = [e for e in events if e.get("module") == "netmodel"]

    crypto_ops: list[CryptoOp] = []
    hmac_map: dict[str, HMACKey] = {}  # key_hex → HMACKey
    hash_counter: Counter[str] = Counter()
    hash_samples: dict[str, list[str]] = {}
    hash_has_cert: dict[str, bool] = {}
    hash_has_data: dict[str, bool] = {}
    nonces: list[NonceInfo] = []
    tls_certs: list[TLSInfo] = []

    # Track cert subject extraction from hash input_preview
    cert_md5_map: dict[str, str] = {}  # output_hex → subject (from MD5 with input_preview)
    cert_sha1_map: dict[str, str] = {}
    cert_sha256_map: dict[str, str] = {}

    for event in netmodel_events:
        etype = event.get("type", "")
        data = event.get("data", {})

        if etype == "hash":
            algorithm = data.get("algorithm", "unknown")
            output_hex = data.get("output_hex", "")
            input_preview = data.get("input_preview", "")
            input_hex = data.get("input_hex", "")
            input_length = data.get("input_length", 0)

            hash_counter[algorithm] += 1

            if algorithm not in hash_samples:
                hash_samples[algorithm] = []
            if len(hash_samples[algorithm]) < 5 and output_hex:
                hash_samples[algorithm].append(output_hex)

            # Detect cert hashing (DER-encoded cert starts with 3082)
            is_cert = input_hex.startswith("3082") or (
                input_preview and any(marker in input_preview for marker in [
                    "U....", "*.H.", "GlobalSign", "DigiCert", "Amazon",
                    "Let's Encrypt", "ISRG", "wavesend", "yakitoriya",
                    "branch.io", "appsflyersdk", "conversions.",
                ])
            )

            if is_cert:
                hash_has_cert[algorithm] = True
                # Extract cert subject from input_preview if it has readable content
                subject = ""
                if input_preview and not input_preview.startswith("(streaming)"):
                    # Try to extract subject from the preview
                    for marker in ["*.", "CN=", "O=", "OU="]:
                        if marker in input_preview:
                            subject = input_preview
                            break
                elif input_preview == "(streaming)" and input_length and input_length < 600:
                    subject = f"cert ({input_length} bytes)"

                if algorithm == "MD5" and input_preview and "0" in input_preview[:5]:
                    # This is a cert with readable subject
                    if input_preview.startswith("0") and not input_preview.startswith("(streaming)"):
                        cert_md5_map[output_hex] = input_preview
            else:
                hash_has_data[algorithm] = True

        elif etype == "hmac_init":
            algorithm = data.get("algorithm", "unknown")
            key_hex = data.get("key_hex", "")
            key_ascii = _hex_to_ascii(key_hex)

            if key_hex in hmac_map:
                hmac_map[key_hex].count += 1
            else:
                hmac_map[key_hex] = HMACKey(
                    algorithm=algorithm,
                    key_hex=key_hex,
                    key_ascii=key_ascii,
                    count=1,
                )

        elif etype == "crypto_init":
            # Store for pairing with crypto_op
            pass

        elif etype == "crypto_op":
            op = data.get("op", "unknown")
            algorithm = data.get("algorithm", "unknown")
            key_hex = data.get("key_hex", "")
            iv_hex = data.get("iv_hex", "")
            input_preview = data.get("input_preview", "")
            input_length = data.get("input_length", 0)
            output_length = data.get("output_length", 0)

            crypto_ops.append(CryptoOp(
                op=op,
                algorithm=algorithm,
                key_hex=key_hex,
                iv_hex=iv_hex,
                input_preview=input_preview[:300] if input_preview else "",
                input_length=input_length,
                output_length=output_length,
            ))

        elif etype == "nonce":
            nonce_type = data.get("type", "unknown")
            value = data.get("value", "")
            stack = data.get("stack", "")
            stack_summary = _extract_stack_summary(stack)

            nonces.append(NonceInfo(
                nonce_type=nonce_type,
                value=value,
                stack_summary=stack_summary,
            ))

    # Build hash summaries
    hashes: list[HashInfo] = []
    for algo, count in hash_counter.most_common():
        hashes.append(HashInfo(
            algorithm=algo,
            count=count,
            sample_outputs=hash_samples.get(algo, []),
            has_cert_hashing=hash_has_cert.get(algo, False),
            has_data_hashing=hash_has_data.get(algo, False),
        ))

    # Build signing recipe from HMAC + nonce data
    signing_recipe = None
    if hmac_map:
        # Use the first (most common) HMAC key
        primary_hmac = next(iter(hmac_map.values()))
        nonce_method = "unknown"
        for n in nonces:
            if n.nonce_type == "uuid":
                nonce_method = "UUID.randomUUID"
                break
            elif n.nonce_type == "timestamp":
                nonce_method = "timestamp"
                break

        signing_recipe = SigningRecipe(
            algorithm=primary_hmac.algorithm,
            key_hex=primary_hmac.key_hex,
            key_ascii=primary_hmac.key_ascii,
            input_pattern="request body or attribution data",
            nonce_method=nonce_method,
        )

    return NetmodelReport(
        crypto_operations=crypto_ops,
        hmac_keys=list(hmac_map.values()),
        hashes=hashes,
        tls_sessions=tls_certs,
        nonces=nonces,
        signing_recipe=signing_recipe,
        total_hash_ops=sum(hash_counter.values()),
        hash_algorithm_counts=dict(hash_counter),
    )
