"""HTTP Body Decoder — decode, decompress, and detect protocols in HTTP bodies."""
from __future__ import annotations

import base64
import gzip
import json
import struct
import zlib
from typing import Any
from urllib.parse import parse_qs, unquote_plus

from pydantic import BaseModel, Field


class DecodedBody(BaseModel):
    """Result of decoding an HTTP body."""

    format: str  # json, protobuf, msgpack, gzip, form, xml, multipart, text, binary, empty
    raw_preview: str = ""  # first 200 chars of raw body
    parsed: dict | list | None = None  # structured data if parseable
    fields: list[str] | None = None  # top-level field names for JSON/form
    size: int = 0  # original body size
    compressed: bool = False  # was it gzip compressed?
    protobuf_fields: list[dict[str, Any]] | None = None  # protobuf field hints


# --- Protobuf wire format constants ---
_WIRE_VARINT = 0
_WIRE_64BIT = 1
_WIRE_LENGTH_DELIMITED = 2
_WIRE_32BIT = 5


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read a protobuf varint starting at offset. Return (value, new_offset)."""
    result = 0
    shift = 0
    pos = offset
    while pos < len(data):
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if (b & 0x80) == 0:
            return result, pos
        shift += 7
        if shift > 63:
            break
    raise ValueError("varint overflow or truncated")


class BodyDecoder:
    """Decode HTTP bodies based on content type and content inspection."""

    @staticmethod
    def decode(
        body: str | bytes,
        content_type: str | None = None,
    ) -> DecodedBody:
        """Decode HTTP body based on content type and content inspection.

        Args:
            body: Raw body as string or bytes.
            content_type: Content-Type header value if available.

        Returns:
            DecodedBody with format, parsed data, and field names.
        """
        if not body:
            return DecodedBody(format="empty", size=0)

        # Convert to bytes for binary inspection
        raw_bytes: bytes
        if isinstance(body, str):
            try:
                raw_bytes = body.encode("utf-8", errors="replace")
            except Exception:
                raw_bytes = body.encode("latin-1", errors="replace")
        else:
            raw_bytes = body

        original_size = len(raw_bytes)
        compressed = False

        # Step 1: Check for gzip and decompress
        if BodyDecoder._is_gzip(raw_bytes):
            try:
                decompressed = BodyDecoder.decompress_gzip(raw_bytes)
                raw_bytes = decompressed
                compressed = True
            except Exception:
                # Cannot decompress — return as gzip
                return DecodedBody(
                    format="gzip",
                    raw_preview=repr(raw_bytes[:200]),
                    size=original_size,
                    compressed=True,
                )

        # Step 2: Route by content type if available
        if content_type:
            ct_lower = content_type.lower()
            if "application/json" in ct_lower or "text/json" in ct_lower:
                return BodyDecoder._decode_as_json(raw_bytes, original_size, compressed)
            if "application/x-www-form-urlencoded" in ct_lower:
                return BodyDecoder._decode_as_form(raw_bytes, original_size, compressed)
            if "application/x-protobuf" in ct_lower or "application/protobuf" in ct_lower:
                return BodyDecoder._decode_as_protobuf(raw_bytes, original_size, compressed)
            if "application/msgpack" in ct_lower or "application/x-msgpack" in ct_lower:
                return BodyDecoder._decode_as_msgpack(raw_bytes, original_size, compressed)
            if "text/xml" in ct_lower or "application/xml" in ct_lower:
                return BodyDecoder._decode_as_xml(raw_bytes, original_size, compressed)
            if "multipart/" in ct_lower:
                return BodyDecoder._decode_as_multipart(raw_bytes, original_size, compressed)

        # Step 3: Content inspection (auto-detect)
        detected = BodyDecoder.detect_protocol(raw_bytes)

        if detected == "json":
            return BodyDecoder._decode_as_json(raw_bytes, original_size, compressed)
        if detected == "form_urlencoded":
            return BodyDecoder._decode_as_form(raw_bytes, original_size, compressed)
        if detected == "protobuf":
            return BodyDecoder._decode_as_protobuf(raw_bytes, original_size, compressed)
        if detected == "msgpack":
            return BodyDecoder._decode_as_msgpack(raw_bytes, original_size, compressed)
        if detected == "xml":
            return BodyDecoder._decode_as_xml(raw_bytes, original_size, compressed)
        if detected == "multipart":
            return BodyDecoder._decode_as_multipart(raw_bytes, original_size, compressed)

        # Fallback: text or binary
        try:
            text = raw_bytes.decode("utf-8")
            return DecodedBody(
                format="text",
                raw_preview=text[:200],
                size=original_size,
                compressed=compressed,
            )
        except UnicodeDecodeError:
            return DecodedBody(
                format="binary",
                raw_preview=repr(raw_bytes[:200]),
                size=original_size,
                compressed=compressed,
            )

    @staticmethod
    def detect_protocol(body: bytes) -> str:
        """Detect protocol from raw bytes: json, protobuf, msgpack, gzip,
        form_urlencoded, multipart, xml, text, binary.
        """
        if not body:
            return "empty"

        # Gzip magic bytes
        if BodyDecoder._is_gzip(body):
            return "gzip"

        first = body[0]

        # JSON: starts with { or [
        if first in (0x7B, 0x5B):  # { or [
            try:
                json.loads(body)
                return "json"
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Might be truncated JSON — still call it json if it looks like it
                try:
                    text = body.decode("utf-8", errors="replace")
                    if text.lstrip().startswith(("{", "[")):
                        return "json"
                except Exception:
                    pass

        # XML: starts with <? or <
        if first == 0x3C:  # <
            try:
                text = body.decode("utf-8", errors="replace").lstrip()
                if text.startswith("<?xml") or text.startswith("<"):
                    return "xml"
            except Exception:
                pass

        # Multipart: starts with --
        if body[:2] == b"--":
            return "multipart"

        # Msgpack: map (0x80-0x8f) or array (0x90-0x9f) or specific msgpack types
        if 0x80 <= first <= 0x8F or 0x90 <= first <= 0x9F:
            return "msgpack"
        if first in (0xDE, 0xDF, 0xDC, 0xDD):
            # msgpack map16/map32/array16/array32
            return "msgpack"

        # Protobuf: common varint field tags (field 1-15 with wire type 0 or 2)
        if first in (0x08, 0x0A, 0x10, 0x12, 0x18, 0x1A, 0x20, 0x22):
            # Attempt to parse as protobuf
            try:
                fields = BodyDecoder.decode_protobuf_fields(body)
                if fields and len(fields) >= 1:
                    return "protobuf"
            except Exception:
                pass

        # Form URL-encoded: key=value&key2=value2 (ASCII, contains = and &)
        try:
            text = body.decode("ascii")
            if "=" in text and all(
                c.isalnum() or c in "=&+%_.-[]" for c in text
            ):
                return "form_urlencoded"
        except (UnicodeDecodeError, ValueError):
            pass

        # Check if it's readable text
        try:
            body.decode("utf-8")
            return "text"
        except UnicodeDecodeError:
            return "binary"

    @staticmethod
    def decode_json(body: str | bytes) -> dict | list | None:
        """Parse JSON, return structured data or None on failure."""
        if not body:
            return None
        try:
            text = body if isinstance(body, str) else body.decode("utf-8", errors="replace")
            return json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    @staticmethod
    def decode_form(body: str | bytes) -> dict:
        """Parse application/x-www-form-urlencoded body into dict."""
        if not body:
            return {}
        try:
            text = body if isinstance(body, str) else body.decode("utf-8", errors="replace")
            parsed = parse_qs(text, keep_blank_values=True)
            # Flatten single-value lists
            result: dict[str, str | list[str]] = {}
            for k, v in parsed.items():
                result[k] = v[0] if len(v) == 1 else v
            return result
        except Exception:
            return {}

    @staticmethod
    def decode_protobuf_fields(body: bytes) -> list[dict[str, Any]]:
        """Best-effort protobuf field extraction without a .proto file.

        Parses wire format to extract field numbers, wire types, and values.
        Returns list of dicts with keys: field_number, wire_type, wire_type_name, value.
        """
        if not body or len(body) < 2:
            return []

        fields: list[dict[str, Any]] = []
        offset = 0

        try:
            while offset < len(body):
                if offset >= len(body):
                    break

                # Read tag (varint)
                tag, offset = _read_varint(body, offset)
                field_number = tag >> 3
                wire_type = tag & 0x07

                # Sanity check: field number should be reasonable
                if field_number < 1 or field_number > 536870911:
                    break

                wire_type_name = {
                    _WIRE_VARINT: "varint",
                    _WIRE_64BIT: "fixed64",
                    _WIRE_LENGTH_DELIMITED: "length_delimited",
                    _WIRE_32BIT: "fixed32",
                }.get(wire_type, f"unknown({wire_type})")

                if wire_type == _WIRE_VARINT:
                    value, offset = _read_varint(body, offset)
                    fields.append({
                        "field_number": field_number,
                        "wire_type": wire_type,
                        "wire_type_name": wire_type_name,
                        "value": value,
                    })

                elif wire_type == _WIRE_64BIT:
                    if offset + 8 > len(body):
                        break
                    value = struct.unpack_from("<Q", body, offset)[0]
                    offset += 8
                    fields.append({
                        "field_number": field_number,
                        "wire_type": wire_type,
                        "wire_type_name": wire_type_name,
                        "value": value,
                    })

                elif wire_type == _WIRE_LENGTH_DELIMITED:
                    length, offset = _read_varint(body, offset)
                    if length < 0 or offset + length > len(body):
                        break
                    data = body[offset : offset + length]
                    offset += length

                    # Try to decode as UTF-8 string
                    try:
                        str_value = data.decode("utf-8")
                        fields.append({
                            "field_number": field_number,
                            "wire_type": wire_type,
                            "wire_type_name": wire_type_name,
                            "value": str_value,
                            "value_type": "string",
                        })
                    except UnicodeDecodeError:
                        # Could be nested message or raw bytes
                        fields.append({
                            "field_number": field_number,
                            "wire_type": wire_type,
                            "wire_type_name": wire_type_name,
                            "value": data.hex(),
                            "value_type": "bytes",
                            "length": length,
                        })

                elif wire_type == _WIRE_32BIT:
                    if offset + 4 > len(body):
                        break
                    value = struct.unpack_from("<I", body, offset)[0]
                    offset += 4
                    fields.append({
                        "field_number": field_number,
                        "wire_type": wire_type,
                        "wire_type_name": wire_type_name,
                        "value": value,
                    })

                else:
                    # Unknown wire type — stop parsing
                    break

        except (ValueError, struct.error, IndexError):
            pass

        return fields

    @staticmethod
    def decode_msgpack(body: bytes) -> Any:
        """Decode msgpack to Python object. Returns None if msgpack is not available."""
        if not body:
            return None
        try:
            import msgpack  # type: ignore[import-untyped]

            return msgpack.unpackb(body, raw=False)
        except ImportError:
            # msgpack not installed — try basic decode for simple cases
            return BodyDecoder._decode_msgpack_basic(body)
        except Exception:
            return None

    @staticmethod
    def decompress_gzip(body: bytes) -> bytes:
        """Decompress gzip/deflate body."""
        if not body:
            return b""
        try:
            return gzip.decompress(body)
        except gzip.BadGzipFile:
            # Try raw deflate
            try:
                return zlib.decompress(body, -zlib.MAX_WBITS)
            except zlib.error:
                raise
        except Exception:
            # Try zlib with auto header detection
            return zlib.decompress(body, zlib.MAX_WBITS | 32)

    # --- Internal helpers ---

    @staticmethod
    def _is_gzip(data: bytes) -> bool:
        """Check for gzip magic bytes (1f 8b)."""
        return len(data) >= 2 and data[0] == 0x1F and data[1] == 0x8B

    @staticmethod
    def _decode_as_json(
        raw_bytes: bytes, original_size: int, compressed: bool
    ) -> DecodedBody:
        """Attempt JSON decode."""
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            text = repr(raw_bytes[:200])

        parsed = BodyDecoder.decode_json(text)
        fields: list[str] | None = None

        if isinstance(parsed, dict):
            fields = list(parsed.keys())
        elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            fields = list(parsed[0].keys())

        return DecodedBody(
            format="json",
            raw_preview=text[:200],
            parsed=parsed,
            fields=fields,
            size=original_size,
            compressed=compressed,
        )

    @staticmethod
    def _decode_as_form(
        raw_bytes: bytes, original_size: int, compressed: bool
    ) -> DecodedBody:
        """Decode form-urlencoded body."""
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            text = repr(raw_bytes[:200])

        parsed_form = BodyDecoder.decode_form(text)
        fields = list(parsed_form.keys()) if parsed_form else None

        return DecodedBody(
            format="form",
            raw_preview=text[:200],
            parsed=parsed_form if parsed_form else None,
            fields=fields,
            size=original_size,
            compressed=compressed,
        )

    @staticmethod
    def _decode_as_protobuf(
        raw_bytes: bytes, original_size: int, compressed: bool
    ) -> DecodedBody:
        """Decode protobuf body."""
        pb_fields = BodyDecoder.decode_protobuf_fields(raw_bytes)

        return DecodedBody(
            format="protobuf",
            raw_preview=repr(raw_bytes[:200]),
            size=original_size,
            compressed=compressed,
            protobuf_fields=pb_fields if pb_fields else None,
        )

    @staticmethod
    def _decode_as_msgpack(
        raw_bytes: bytes, original_size: int, compressed: bool
    ) -> DecodedBody:
        """Decode msgpack body."""
        decoded = BodyDecoder.decode_msgpack(raw_bytes)
        fields: list[str] | None = None

        if isinstance(decoded, dict):
            fields = [str(k) for k in decoded.keys()]

        return DecodedBody(
            format="msgpack",
            raw_preview=repr(raw_bytes[:200]),
            parsed=decoded,
            fields=fields,
            size=original_size,
            compressed=compressed,
        )

    @staticmethod
    def _decode_as_xml(
        raw_bytes: bytes, original_size: int, compressed: bool
    ) -> DecodedBody:
        """Return XML body info (no deep parsing)."""
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            text = repr(raw_bytes[:200])

        return DecodedBody(
            format="xml",
            raw_preview=text[:200],
            size=original_size,
            compressed=compressed,
        )

    @staticmethod
    def _decode_as_multipart(
        raw_bytes: bytes, original_size: int, compressed: bool
    ) -> DecodedBody:
        """Parse multipart body to extract field names."""
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            text = repr(raw_bytes[:200])

        # Extract field names from Content-Disposition headers
        fields: list[str] = []
        for line in text.split("\n"):
            line = line.strip()
            if 'name="' in line:
                start = line.index('name="') + 6
                end = line.index('"', start)
                fields.append(line[start:end])

        return DecodedBody(
            format="multipart",
            raw_preview=text[:200],
            fields=fields if fields else None,
            size=original_size,
            compressed=compressed,
        )

    @staticmethod
    def _decode_msgpack_basic(body: bytes) -> Any:
        """Basic msgpack decoder for simple fixmap/fixarray without library."""
        if not body:
            return None

        first = body[0]

        # Fixmap: 0x80 - 0x8f
        if 0x80 <= first <= 0x8F:
            n_entries = first & 0x0F
            result: dict[str, Any] = {}
            offset = 1
            for _ in range(n_entries):
                if offset >= len(body):
                    break
                key, offset = BodyDecoder._msgpack_read_value(body, offset)
                if offset >= len(body):
                    break
                val, offset = BodyDecoder._msgpack_read_value(body, offset)
                if key is not None:
                    result[str(key)] = val
            return result

        # Fixarray: 0x90 - 0x9f
        if 0x90 <= first <= 0x9F:
            n_items = first & 0x0F
            result_list: list[Any] = []
            offset = 1
            for _ in range(n_items):
                if offset >= len(body):
                    break
                val, offset = BodyDecoder._msgpack_read_value(body, offset)
                result_list.append(val)
            return result_list

        return None

    @staticmethod
    def _msgpack_read_value(data: bytes, offset: int) -> tuple[Any, int]:
        """Read a single msgpack value. Basic types only."""
        if offset >= len(data):
            return None, offset

        b = data[offset]

        # Positive fixint: 0x00 - 0x7f
        if b <= 0x7F:
            return b, offset + 1

        # Negative fixint: 0xe0 - 0xff
        if b >= 0xE0:
            return b - 256, offset + 1

        # Fixstr: 0xa0 - 0xbf
        if 0xA0 <= b <= 0xBF:
            length = b & 0x1F
            end = offset + 1 + length
            if end > len(data):
                return None, len(data)
            try:
                return data[offset + 1 : end].decode("utf-8"), end
            except UnicodeDecodeError:
                return data[offset + 1 : end].hex(), end

        # Nil
        if b == 0xC0:
            return None, offset + 1

        # Bool
        if b == 0xC2:
            return False, offset + 1
        if b == 0xC3:
            return True, offset + 1

        # str8
        if b == 0xD9:
            if offset + 1 >= len(data):
                return None, len(data)
            length = data[offset + 1]
            end = offset + 2 + length
            if end > len(data):
                return None, len(data)
            try:
                return data[offset + 2 : end].decode("utf-8"), end
            except UnicodeDecodeError:
                return data[offset + 2 : end].hex(), end

        # uint8
        if b == 0xCC:
            if offset + 1 >= len(data):
                return None, len(data)
            return data[offset + 1], offset + 2

        # uint16
        if b == 0xCD:
            if offset + 2 >= len(data):
                return None, len(data)
            return struct.unpack_from(">H", data, offset + 1)[0], offset + 3

        # Skip unknown types
        return None, offset + 1
