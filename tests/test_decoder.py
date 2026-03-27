"""Tests for HTTP body decoder — JSON, form, gzip, protobuf, msgpack detection."""
from __future__ import annotations

import gzip
import json
import os
import struct

import pytest

from kahlo.analyze.decoder import BodyDecoder, DecodedBody


# ============================================================================
# JSON parsing
# ============================================================================

class TestJsonDecoding:
    def test_simple_json_object(self):
        body = '{"name": "test", "value": 42}'
        result = BodyDecoder.decode(body)
        assert result.format == "json"
        assert result.parsed == {"name": "test", "value": 42}
        assert result.fields == ["name", "value"]
        assert result.size > 0

    def test_json_array(self):
        body = '[{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]'
        result = BodyDecoder.decode(body)
        assert result.format == "json"
        assert isinstance(result.parsed, list)
        assert len(result.parsed) == 2
        # Fields from first element
        assert result.fields == ["id", "name"]

    def test_json_with_content_type(self):
        body = '{"key": "value"}'
        result = BodyDecoder.decode(body, content_type="application/json; charset=utf-8")
        assert result.format == "json"
        assert result.parsed == {"key": "value"}

    def test_json_bytes(self):
        body = b'{"status": "ok"}'
        result = BodyDecoder.decode(body)
        assert result.format == "json"
        assert result.parsed == {"status": "ok"}

    def test_nested_json(self):
        body = '{"data": {"items": [1, 2, 3], "count": 3}, "success": true}'
        result = BodyDecoder.decode(body)
        assert result.format == "json"
        assert "data" in result.fields
        assert "success" in result.fields

    def test_truncated_json(self):
        """Truncated JSON should still be detected as json format."""
        body = '{"name": "test", "value": '
        result = BodyDecoder.decode(body)
        assert result.format == "json"
        assert result.parsed is None  # parse fails

    def test_empty_json_object(self):
        body = "{}"
        result = BodyDecoder.decode(body)
        assert result.format == "json"
        assert result.parsed == {}
        assert result.fields == []

    def test_decode_json_static_method(self):
        assert BodyDecoder.decode_json('{"a": 1}') == {"a": 1}
        assert BodyDecoder.decode_json("not json") is None
        assert BodyDecoder.decode_json("") is None
        assert BodyDecoder.decode_json(b'{"b": 2}') == {"b": 2}


# ============================================================================
# Form URL-encoded parsing
# ============================================================================

class TestFormDecoding:
    def test_simple_form(self):
        body = "username=admin&password=secret&remember=true"
        result = BodyDecoder.decode(body, content_type="application/x-www-form-urlencoded")
        assert result.format == "form"
        assert result.parsed is not None
        assert result.parsed["username"] == "admin"
        assert result.parsed["password"] == "secret"
        assert result.fields is not None
        assert "username" in result.fields
        assert "password" in result.fields
        assert "remember" in result.fields

    def test_form_with_encoded_values(self):
        body = "q=hello+world&lang=en"
        result = BodyDecoder.decode(body, content_type="application/x-www-form-urlencoded")
        assert result.format == "form"
        assert result.parsed is not None
        assert "q" in result.parsed

    def test_form_auto_detect(self):
        """Form data should be detected even without content-type."""
        body = "key1=val1&key2=val2&key3=val3"
        result = BodyDecoder.decode(body)
        assert result.format == "form"
        assert result.fields is not None
        assert "key1" in result.fields

    def test_decode_form_static_method(self):
        result = BodyDecoder.decode_form("a=1&b=2&c=3")
        assert result == {"a": "1", "b": "2", "c": "3"}

    def test_decode_form_empty(self):
        result = BodyDecoder.decode_form("")
        assert result == {}


# ============================================================================
# Gzip decompression
# ============================================================================

class TestGzipDecompression:
    def test_gzip_json(self):
        original = b'{"compressed": true, "data": [1, 2, 3]}'
        compressed = gzip.compress(original)
        result = BodyDecoder.decode(compressed)
        assert result.format == "json"
        assert result.compressed is True
        assert result.parsed == {"compressed": True, "data": [1, 2, 3]}
        assert result.fields is not None
        assert "compressed" in result.fields

    def test_gzip_text(self):
        original = b"Hello, this is plain text content"
        compressed = gzip.compress(original)
        result = BodyDecoder.decode(compressed)
        assert result.compressed is True
        assert result.format == "text"

    def test_gzip_detection(self):
        compressed = gzip.compress(b"test data")
        assert BodyDecoder.detect_protocol(compressed) == "gzip"

    def test_decompress_gzip_static(self):
        original = b"test decompression"
        compressed = gzip.compress(original)
        decompressed = BodyDecoder.decompress_gzip(compressed)
        assert decompressed == original

    def test_gzip_bad_data(self):
        """Non-gzip data with gzip magic should handle gracefully."""
        bad = b"\x1f\x8b" + b"\x00" * 10
        result = BodyDecoder.decode(bad)
        assert result.format == "gzip"
        assert result.compressed is True

    def test_decompress_empty(self):
        assert BodyDecoder.decompress_gzip(b"") == b""


# ============================================================================
# Protobuf field detection
# ============================================================================

class TestProtobufDetection:
    def test_simple_varint(self):
        """Field 1, wire type 0 (varint), value 150."""
        # Tag: (1 << 3) | 0 = 0x08, value: 150 = 0x96 0x01
        data = bytes([0x08, 0x96, 0x01])
        fields = BodyDecoder.decode_protobuf_fields(data)
        assert len(fields) == 1
        assert fields[0]["field_number"] == 1
        assert fields[0]["wire_type_name"] == "varint"
        assert fields[0]["value"] == 150

    def test_length_delimited_string(self):
        """Field 2, wire type 2 (length delimited), value 'testing'."""
        # Tag: (2 << 3) | 2 = 0x12, length: 7, then "testing"
        data = bytes([0x12, 0x07]) + b"testing"
        fields = BodyDecoder.decode_protobuf_fields(data)
        assert len(fields) == 1
        assert fields[0]["field_number"] == 2
        assert fields[0]["wire_type_name"] == "length_delimited"
        assert fields[0]["value"] == "testing"
        assert fields[0]["value_type"] == "string"

    def test_multiple_fields(self):
        """Multiple protobuf fields."""
        # Field 1 varint = 1, Field 2 string = "hi"
        data = bytes([0x08, 0x01, 0x12, 0x02]) + b"hi"
        fields = BodyDecoder.decode_protobuf_fields(data)
        assert len(fields) == 2
        assert fields[0]["field_number"] == 1
        assert fields[0]["value"] == 1
        assert fields[1]["field_number"] == 2
        assert fields[1]["value"] == "hi"

    def test_fixed32(self):
        """Field 1, wire type 5 (fixed32)."""
        # Tag: (1 << 3) | 5 = 0x0D, then 4 bytes little-endian
        data = bytes([0x0D]) + struct.pack("<I", 42)
        fields = BodyDecoder.decode_protobuf_fields(data)
        assert len(fields) == 1
        assert fields[0]["wire_type_name"] == "fixed32"
        assert fields[0]["value"] == 42

    def test_fixed64(self):
        """Field 1, wire type 1 (fixed64)."""
        # Tag: (1 << 3) | 1 = 0x09, then 8 bytes little-endian
        data = bytes([0x09]) + struct.pack("<Q", 123456789)
        fields = BodyDecoder.decode_protobuf_fields(data)
        assert len(fields) == 1
        assert fields[0]["wire_type_name"] == "fixed64"
        assert fields[0]["value"] == 123456789

    def test_protobuf_detection(self):
        """Protobuf-like data should be detected."""
        data = bytes([0x08, 0x96, 0x01, 0x12, 0x03]) + b"abc"
        assert BodyDecoder.detect_protocol(data) == "protobuf"

    def test_protobuf_full_decode(self):
        """Full decode pipeline for protobuf."""
        data = bytes([0x08, 0x01, 0x12, 0x05]) + b"hello"
        result = BodyDecoder.decode(data, content_type="application/x-protobuf")
        assert result.format == "protobuf"
        assert result.protobuf_fields is not None
        assert len(result.protobuf_fields) == 2

    def test_empty_protobuf(self):
        assert BodyDecoder.decode_protobuf_fields(b"") == []
        assert BodyDecoder.decode_protobuf_fields(b"\x00") == []

    def test_bytes_field(self):
        """Non-UTF8 length-delimited field should show as bytes."""
        # Field 1, wire type 2, 3 bytes of binary data
        data = bytes([0x0A, 0x03, 0xFF, 0xFE, 0xFD])
        fields = BodyDecoder.decode_protobuf_fields(data)
        assert len(fields) == 1
        assert fields[0]["value_type"] == "bytes"


# ============================================================================
# Msgpack detection
# ============================================================================

class TestMsgpackDetection:
    def test_detect_msgpack_fixmap(self):
        """Fixmap (0x80-0x8f) should be detected as msgpack."""
        # Fixmap with 1 entry
        data = bytes([0x81, 0xA3]) + b"key" + bytes([0xA5]) + b"value"
        assert BodyDecoder.detect_protocol(data) == "msgpack"

    def test_detect_msgpack_fixarray(self):
        """Fixarray (0x90-0x9f) should be detected as msgpack."""
        data = bytes([0x92, 0x01, 0x02])  # [1, 2]
        assert BodyDecoder.detect_protocol(data) == "msgpack"

    def test_msgpack_basic_decode(self):
        """Basic msgpack decode without library."""
        # Fixmap with 1 entry: {"key": "value"}
        data = bytes([0x81, 0xA3]) + b"key" + bytes([0xA5]) + b"value"
        result = BodyDecoder.decode(data, content_type="application/msgpack")
        assert result.format == "msgpack"
        # Basic decoder should handle this
        if result.parsed is not None:
            assert result.parsed.get("key") == "value"

    def test_msgpack_fixarray_decode(self):
        """Basic decode of a fixarray."""
        # [1, 2, 3]
        data = bytes([0x93, 0x01, 0x02, 0x03])
        decoded = BodyDecoder._decode_msgpack_basic(data)
        assert decoded == [1, 2, 3]

    def test_msgpack_fixmap_decode(self):
        """Basic decode of a fixmap with int values."""
        # {"a": 1}
        data = bytes([0x81, 0xA1]) + b"a" + bytes([0x01])
        decoded = BodyDecoder._decode_msgpack_basic(data)
        assert decoded == {"a": 1}

    def test_msgpack_nil_and_bool(self):
        """Msgpack nil and bool values."""
        # [nil, false, true]
        data = bytes([0x93, 0xC0, 0xC2, 0xC3])
        decoded = BodyDecoder._decode_msgpack_basic(data)
        assert decoded == [None, False, True]


# ============================================================================
# Content-type based routing
# ============================================================================

class TestContentTypeRouting:
    def test_json_content_type(self):
        body = '{"test": true}'
        result = BodyDecoder.decode(body, content_type="application/json")
        assert result.format == "json"

    def test_form_content_type(self):
        body = "a=1&b=2"
        result = BodyDecoder.decode(body, content_type="application/x-www-form-urlencoded")
        assert result.format == "form"

    def test_protobuf_content_type(self):
        body = bytes([0x08, 0x01])
        result = BodyDecoder.decode(body, content_type="application/x-protobuf")
        assert result.format == "protobuf"

    def test_xml_content_type(self):
        body = '<?xml version="1.0"?><root><item>test</item></root>'
        result = BodyDecoder.decode(body, content_type="text/xml")
        assert result.format == "xml"

    def test_multipart_content_type(self):
        body = '--boundary\r\nContent-Disposition: form-data; name="file"\r\n\r\ndata\r\n--boundary--'
        result = BodyDecoder.decode(body, content_type="multipart/form-data; boundary=boundary")
        assert result.format == "multipart"
        assert result.fields is not None
        assert "file" in result.fields

    def test_xml_auto_detect(self):
        body = '<?xml version="1.0"?><root/>'
        result = BodyDecoder.decode(body)
        assert result.format == "xml"

    def test_multipart_auto_detect(self):
        body = '--boundary\r\nContent-Disposition: form-data; name="field1"\r\n\r\nvalue1'
        result = BodyDecoder.decode(body)
        assert result.format == "multipart"


# ============================================================================
# Protocol detection
# ============================================================================

class TestProtocolDetection:
    def test_detect_empty(self):
        assert BodyDecoder.detect_protocol(b"") == "empty"

    def test_detect_json(self):
        assert BodyDecoder.detect_protocol(b'{"key": "value"}') == "json"
        assert BodyDecoder.detect_protocol(b'[1, 2, 3]') == "json"

    def test_detect_xml(self):
        assert BodyDecoder.detect_protocol(b'<?xml version="1.0"?>') == "xml"
        assert BodyDecoder.detect_protocol(b'<root/>') == "xml"

    def test_detect_multipart(self):
        assert BodyDecoder.detect_protocol(b'--boundary') == "multipart"

    def test_detect_gzip(self):
        data = gzip.compress(b"test")
        assert BodyDecoder.detect_protocol(data) == "gzip"

    def test_detect_text(self):
        assert BodyDecoder.detect_protocol(b"Hello, world!") == "text"

    def test_detect_binary(self):
        # Use bytes that don't match any known magic (0xF0+ avoids msgpack fixmap/fixarray)
        assert BodyDecoder.detect_protocol(bytes([0xFE, 0xFE, 0x00, 0x01, 0x02])) == "binary"


# ============================================================================
# Edge cases
# ============================================================================

class TestEdgeCases:
    def test_empty_string(self):
        result = BodyDecoder.decode("")
        assert result.format == "empty"
        assert result.size == 0

    def test_empty_bytes(self):
        result = BodyDecoder.decode(b"")
        assert result.format == "empty"
        assert result.size == 0

    def test_none_body(self):
        # None is falsy — should produce empty
        result = BodyDecoder.decode(None)
        assert result.format == "empty"

    def test_raw_preview_truncation(self):
        body = "x" * 1000
        result = BodyDecoder.decode(body)
        assert len(result.raw_preview) <= 200

    def test_decoded_body_model(self):
        db = DecodedBody(format="json", size=100)
        assert db.format == "json"
        assert db.raw_preview == ""
        assert db.parsed is None
        assert db.fields is None
        assert db.compressed is False

    def test_large_json_body(self):
        """Large JSON body should work and extract fields."""
        data = {"field_" + str(i): i for i in range(100)}
        body = json.dumps(data)
        result = BodyDecoder.decode(body)
        assert result.format == "json"
        assert result.fields is not None
        assert len(result.fields) == 100

    def test_binary_body(self):
        body = bytes(range(256))
        result = BodyDecoder.decode(body)
        # High bytes make it non-text
        assert result.format in ("binary", "protobuf", "msgpack")


# ============================================================================
# Integration: decode real bodies from yakitoriya session
# ============================================================================

SESSION_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "sessions",
    "com.voltmobi.yakitoriya_20260326_122701_5d3395.json",
)


@pytest.fixture(scope="module")
def session_events():
    """Load real session events."""
    with open(SESSION_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["events"]


class TestIntegrationYakitoriya:
    def test_traffic_analyzer_with_decoder(self, session_events):
        """Traffic analyzer should populate body format fields."""
        from kahlo.analyze.traffic import analyze_traffic

        report = analyze_traffic(session_events, package="com.voltmobi.yakitoriya")
        assert report is not None

        # At least some endpoints should have body format info
        has_body_format = any(
            ep.request_body_format is not None or ep.response_body_format is not None
            for ep in report.endpoints
        )
        assert has_body_format, "Expected at least one endpoint with body format info"

    def test_endpoint_body_schemas(self, session_events):
        """Endpoints with JSON bodies should have body_schema."""
        from kahlo.analyze.traffic import analyze_traffic

        report = analyze_traffic(session_events, package="com.voltmobi.yakitoriya")

        # Check that endpoints with JSON bodies get field names
        json_endpoints = [
            ep for ep in report.endpoints
            if ep.request_body_format == "json"
        ]
        for ep in json_endpoints:
            if ep.request_body_fields:
                assert isinstance(ep.request_body_fields, list)
                assert all(isinstance(f, str) for f in ep.request_body_fields)

    def test_decode_real_bodies(self, session_events):
        """Decode body previews from real SSL raw traffic events."""
        traffic_events = [
            e for e in session_events
            if e.get("module") == "traffic"
        ]

        decoded_count = 0
        for ev in traffic_events:
            # Try body from http_request/http_response
            body = ev.get("data", {}).get("body", "")
            if body:
                result = BodyDecoder.decode(body)
                assert result.format != "empty"
                assert result.size > 0
                decoded_count += 1
                continue
            # Try preview from ssl_raw
            preview = ev.get("data", {}).get("preview", "")
            if preview and len(preview) > 20:
                result = BodyDecoder.decode(preview)
                assert result.format is not None
                decoded_count += 1

        assert decoded_count > 0, "Expected at least one body/preview to decode"

    def test_ssl_raw_body_decode(self, session_events):
        """SSL raw captures with body previews should be decodable."""
        ssl_events = [
            e for e in session_events
            if e.get("module") == "traffic" and e.get("type") == "ssl_raw"
        ]

        for ev in ssl_events:
            preview = ev.get("data", {}).get("preview", "")
            if preview and len(preview) > 10:
                # Just ensure decode does not crash
                result = BodyDecoder.decode(preview)
                assert result.format is not None


# ============================================================================
# Structured http_request events with body decoding
# ============================================================================

class TestHttpRequestBodyDecoding:
    def test_json_request_body_decoded(self):
        """http_request with JSON body should have fields extracted."""
        from kahlo.analyze.traffic import analyze_traffic

        events = [
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "index": 1,
                    "method": "POST",
                    "url": "https://api.example.com/data",
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"user_id": 123, "action": "click", "ts": 1234567890}',
                    "body_length": 51,
                    "body_format": "json",
                    "source": "okhttp3",
                },
            },
            {
                "module": "traffic",
                "type": "http_response",
                "ts": "2026-03-27T10:00:01Z",
                "data": {
                    "index": 1,
                    "url": "https://api.example.com/data",
                    "status": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"status": "ok", "id": 456}',
                    "body_length": 27,
                    "body_format": "json",
                    "source": "okhttp3",
                },
            },
        ]

        report = analyze_traffic(events)
        assert len(report.endpoints) == 1
        ep = report.endpoints[0]

        # Request body fields
        assert ep.request_body_format == "json"
        assert ep.request_body_fields is not None
        assert "user_id" in ep.request_body_fields
        assert "action" in ep.request_body_fields

        # Response body fields
        assert ep.response_body_format == "json"
        assert ep.response_body_fields is not None
        assert "status" in ep.response_body_fields
        assert "id" in ep.response_body_fields

        # Body schema (merged)
        assert ep.body_schema is not None
        assert "user_id" in ep.body_schema
        assert "status" in ep.body_schema

    def test_form_request_body_decoded(self):
        """http_request with form body should have fields extracted."""
        from kahlo.analyze.traffic import analyze_traffic

        events = [
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "index": 1,
                    "method": "POST",
                    "url": "https://api.example.com/login",
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "body": "username=admin&password=secret",
                    "body_length": 30,
                    "body_format": "form",
                    "source": "okhttp3",
                },
            },
        ]

        report = analyze_traffic(events)
        assert len(report.endpoints) == 1
        ep = report.endpoints[0]

        assert ep.request_body_format == "form"
        assert ep.request_body_fields is not None
        assert "username" in ep.request_body_fields
        assert "password" in ep.request_body_fields

    def test_empty_body_no_schema(self):
        """Endpoint with empty body should not have body_schema."""
        from kahlo.analyze.traffic import analyze_traffic

        events = [
            {
                "module": "traffic",
                "type": "http_request",
                "ts": "2026-03-27T10:00:00Z",
                "data": {
                    "index": 1,
                    "method": "GET",
                    "url": "https://api.example.com/status",
                    "headers": {},
                    "body": "",
                    "body_length": 0,
                    "body_format": "empty",
                    "source": "okhttp3",
                },
            },
        ]

        report = analyze_traffic(events)
        assert len(report.endpoints) == 1
        ep = report.endpoints[0]
        assert ep.body_schema is None
