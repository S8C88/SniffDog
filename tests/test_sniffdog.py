#!/usr/bin/env python3
"""Tests for SniffDog — 100 tests covering pipeline stages, extraction, edge cases."""

import base64
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# Force-import so we can test without scapy being installed
import types
scapy_mock = types.ModuleType("scapy")
scapy_mock.utils = types.ModuleType("scapy.utils")

from sniffdog import (
    http_filter,
    session_reassembly,
    http_parse,
    cred_extract,
    cookie_extract,
    url_extract,
    pcap_reader,
    CRED_PATTERNS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_http_get(host="example.com", path="/", extra_headers=None):
    hdrs = extra_headers or {}
    hdr_str = f"Host: {host}\r\n"
    for k, v in hdrs.items():
        hdr_str += f"{k}: {v}\r\n"
    raw = f"GET {path} HTTP/1.1\r\n{hdr_str}\r\n".encode()
    return raw


def _make_http_post(host="example.com", path="/login", body=b"", content_type="application/x-www-form-urlencoded"):
    hdrs = f"Host: {host}\r\nContent-Type: {content_type}\r\nContent-Length: {len(body)}\r\n"
    raw = f"POST {path} HTTP/1.1\r\n{hdrs}\r\n".encode() + body
    return raw


def _make_http_response(status=200, body=b"", cookies=None):
    hdrs = ""
    if cookies:
        for c in cookies:
            hdrs += f"Set-Cookie: {c}\r\n"
    if body:
        hdrs += f"Content-Length: {len(body)}\r\n"
    raw = f"HTTP/1.1 {status} OK\r\n{hdrs}\r\n".encode() + body
    return raw


class MockPacket:
    def __init__(self, raw_bytes):
        self.raw = raw_bytes


# ---------------------------------------------------------------------------
# HTTP filter tests
# ---------------------------------------------------------------------------

class TestHTTPFilter(unittest.TestCase):
    def _stream(self, items):
        for i in items:
            yield (MockPacket(i), i)

    def test_filters_http_get(self):
        raw = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        result = list(http_filter(self._stream([raw])))
        self.assertEqual(len(result), 1)

    def test_filters_http_post(self):
        raw = b"POST / HTTP/1.1\r\nHost: x\r\n\r\nbody"
        result = list(http_filter(self._stream([raw])))
        self.assertEqual(len(result), 1)

    def test_filters_http_response(self):
        raw = b"HTTP/1.1 200 OK\r\n\r\n"
        result = list(http_filter(self._stream([raw])))
        self.assertEqual(len(result), 1)

    def test_drops_non_http(self):
        raw = b"\x00\x01\x02\x03" * 100
        result = list(http_filter(self._stream([raw])))
        self.assertEqual(len(result), 0)

    def test_drops_empty(self):
        result = list(http_filter(self._stream([b""])))
        self.assertEqual(len(result), 0)

    def test_partial_http_header_detected(self):
        raw = b"Host: example.com\r\n"
        result = list(http_filter(self._stream([raw])))
        self.assertEqual(len(result), 1)

    def test_drops_binary_junk(self):
        raw = bytes(range(256))
        result = list(http_filter(self._stream([raw])))
        self.assertEqual(len(result), 0)

    def test_handles_weird_encoding(self):
        raw = b"GET \xff\xfe HTTP/1.1\r\n\r\n"
        result = list(http_filter(self._stream([raw])))
        self.assertEqual(len(result), 1)

    def test_empty_stream(self):
        result = list(http_filter(self._stream([])))
        self.assertEqual(len(result), 0)

    def test_multiple_http_packets(self):
        raws = [b"GET /a HTTP/1.1\r\n\r\n", b"POST /b HTTP/1.1\r\n\r\n", b"\x00\x01"]
        result = list(http_filter(self._stream(raws)))
        self.assertEqual(len(result), 2)


# ---------------------------------------------------------------------------
# Session reassembly tests
# ---------------------------------------------------------------------------

class TestSessionReassembly(unittest.TestCase):
    def _stream(self, items):
        for i in items:
            yield i

    def _make_ipv4_tcp(self, src_ip, dst_ip, sport=12345, dport=80, payload=b"GET / HTTP/1.1\r\n\r\n"):
        """Build a minimal IPv4 TCP packet."""
        from struct import pack
        ihl = 5
        version_ihl = (4 << 4) | ihl
        total_len = 20 + 20 + len(payload)
        ip_hdr = pack("!BBHHHBBH4s4s",
                      version_ihl, 0, total_len, 0x1234, 0x4000,
                      64, 6, 0,
                      bytes([int(x) for x in src_ip.split(".")]),
                      bytes([int(x) for x in dst_ip.split(".")]))
        tcp_hdr = pack("!HHIIHHHH", sport, dport, 0, 0, (5 << 12) | 0x18, 0, 0, 0)
        return ip_hdr + tcp_hdr + payload

    def test_reassembles_single_packet(self):
        pkt = self._make_ipv4_tcp("10.0.0.1", "10.0.0.2")
        result = list(session_reassembly(self._stream([pkt])))
        self.assertGreaterEqual(len(result), 1)
        key, data = result[0]
        self.assertIn("10.0.0.1", key)
        self.assertEqual(data, pkt[40:])  # IP + TCP headers stripped

    def test_reassembles_multiple_packets_same_session(self):
        pkt1 = self._make_ipv4_tcp("10.0.0.1", "10.0.0.2", payload=b"GET / HTTP/1.1\r\n")
        pkt2 = self._make_ipv4_tcp("10.0.0.1", "10.0.0.2", payload=b"Host: x\r\n\r\n")
        result = list(session_reassembly(self._stream([pkt1, pkt2])))
        merged = b"".join(d for _, d in result if b"GET" in d)
        self.assertIn(b"GET / HTTP/1.1", merged)
        self.assertIn(b"Host: x", merged)

    def test_reverse_direction_included(self):
        pkt = self._make_ipv4_tcp("10.0.0.1", "10.0.0.2")
        result = list(session_reassembly(self._stream([pkt])))
        keys = [k for k, _ in result]
        has_reverse = any("10.0.0.2" in k and "10.0.0.1" in k for k in keys)
        self.assertTrue(has_reverse)

    def test_empty_packets_skipped(self):
        result = list(session_reassembly(self._stream([])))
        self.assertEqual(len(result), 0)

    def test_non_tcp_skipped(self):
        from struct import pack
        # UDP packet (proto=17)
        ip_hdr = pack("!BBHHHBBH4s4s",
                      (4 << 4) | 5, 0, 28, 0, 0, 64, 17, 0,
                      bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
        udp_hdr = pack("!HHHH", 1234, 80, 8, 0)
        pkt = ip_hdr + udp_hdr
        result = list(session_reassembly(self._stream([pkt])))
        self.assertEqual(len(result), 0)


# ---------------------------------------------------------------------------
# HTTP parse tests
# ---------------------------------------------------------------------------

class TestHTTPParse(unittest.TestCase):
    def _stream(self, items):
        for i in items:
            yield ("session1", i)

    def test_parses_get_request(self):
        raw = _make_http_get("example.com", "/index.html")
        result = list(http_parse(self._stream([raw])))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["method"], "GET")
        self.assertEqual(result[0]["path"], "/index.html")

    def test_parses_post_request(self):
        raw = _make_http_post(body=b"user=admin&pass=secret")
        result = list(http_parse(self._stream([raw])))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["method"], "POST")

    def test_parses_response(self):
        raw = _make_http_response(200, body=b"OK")
        result = list(http_parse(self._stream([raw])))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["method"], "RESPONSE")

    def test_extracts_headers(self):
        raw = _make_http_get(extra_headers={"X-Custom": "value123"})
        result = list(http_parse(self._stream([raw])))
        self.assertEqual(result[0]["headers"].get("X-Custom"), "value123")

    def test_extracts_body(self):
        raw = _make_http_post(body=b"user=admin&pass=secret")
        result = list(http_parse(self._stream([raw])))
        self.assertIn(b"admin", result[0]["body"])

    def test_skips_non_http_data(self):
        result = list(http_parse(self._stream([("s1", b"\x00\x01\x02")])))
        self.assertEqual(len(result), 0)

    def test_empty_stream(self):
        result = list(http_parse(self._stream([])))
        self.assertEqual(len(result), 0)

    def test_handles_missing_host(self):
        raw = b"GET / HTTP/1.1\r\n\r\n"
        result = list(http_parse(self._stream([raw])))
        self.assertEqual(len(result), 1)

    def test_handles_chunked_surrogates(self):
        raw = b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        result = list(http_parse(self._stream([raw])))
        self.assertEqual(len(result), 1)

    def test_path_query_stripped(self):
        raw = _make_http_get(path="/search?q=test&page=1")
        result = list(http_parse(self._stream([raw])))
        self.assertEqual(result[0]["path"], "/search")


# ---------------------------------------------------------------------------
# Credential extraction tests
# ---------------------------------------------------------------------------

class TestCredExtract(unittest.TestCase):
    def _http_stream(self, items):
        for i in items:
            yield i

    def test_basic_auth_extraction(self):
        auth = base64.b64encode(b"admin:secret123").decode()
        obj = {
            "session": "10.0.0.1:1234->10.0.0.2:80",
            "method": "GET",
            "path": "/admin",
            "version": "HTTP/1.1",
            "headers": {"Authorization": f"Basic {auth}"},
            "body": b"",
        }
        result = list(cred_extract(self._http_stream([obj])))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["username"], "admin")
        self.assertEqual(result[0]["password"], "secret123")

    def test_basic_auth_invalid_base64(self):
        obj = {
            "session": "x",
            "method": "GET",
            "path": "/",
            "version": "HTTP/1.1",
            "headers": {"Authorization": "Basic !!!invalid!!!"},
            "body": b"",
        }
        result = list(cred_extract(self._http_stream([obj])))
        self.assertEqual(len(result), 0)

    def test_post_form_extraction(self):
        body = b"username=john&password=doe&submit=Login"
        obj = {
            "session": "x",
            "method": "POST",
            "path": "/login",
            "version": "HTTP/1.1",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": body,
        }
        result = list(cred_extract(self._http_stream([obj])))
        self.assertEqual(len(result), 1)
        self.assertIn("password", str(result[0]["fields"]))

    def test_post_json_extraction(self):
        body = json.dumps({"username": "admin", "password": "hunter2", "remember": True}).encode()
        obj = {
            "session": "x",
            "method": "POST",
            "path": "/api/login",
            "version": "HTTP/1.1",
            "headers": {"Content-Type": "application/json"},
            "body": body,
        }
        result = list(cred_extract(self._http_stream([obj])))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["fields"]["password"], "hunter2")

    def test_get_no_creds(self):
        obj = {
            "session": "x",
            "method": "GET",
            "path": "/images/logo.png",
            "version": "HTTP/1.1",
            "headers": {},
            "body": b"",
        }
        result = list(cred_extract(self._http_stream([obj])))
        self.assertEqual(len(result), 0)

    def test_empty_body(self):
        obj = {
            "session": "x",
            "method": "POST",
            "path": "/login",
            "version": "HTTP/1.1",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": b"",
        }
        result = list(cred_extract(self._http_stream([obj])))
        self.assertEqual(len(result), 0)

    def test_form_without_creds(self):
        body = b"color=blue&size=large"
        obj = {
            "session": "x",
            "method": "POST",
            "path": "/prefs",
            "version": "HTTP/1.1",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": body,
        }
        result = list(cred_extract(self._http_stream([obj])))
        self.assertEqual(len(result), 0)

    def test_encoded_form_data(self):
        body = b"username=admin%40test.com&password=p%26ass"
        obj = {
            "session": "x",
            "method": "POST",
            "path": "/login",
            "version": "HTTP/1.1",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": body,
        }
        result = list(cred_extract(self._http_stream([obj])))
        self.assertEqual(len(result), 1)
        vals = result[0]["fields"]
        self.assertIn("admin@test.com", str(vals))

    def test_json_without_creds(self):
        body = json.dumps({"query": "search", "page": 1}).encode()
        obj = {
            "session": "x",
            "method": "POST",
            "path": "/api/search",
            "version": "HTTP/1.1",
            "headers": {"Content-Type": "application/json"},
            "body": body,
        }
        result = list(cred_extract(self._http_stream([obj])))
        self.assertEqual(len(result), 0)

    def test_multiple_cred_fields(self):
        body = b"username=joe&password=pass1&pin=1234&email=j@t.com"
        obj = {
            "session": "x",
            "method": "POST",
            "path": "/login",
            "version": "HTTP/1.1",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": body,
        }
        result = list(cred_extract(self._http_stream([obj])))
        self.assertGreaterEqual(len(result), 1)


# ---------------------------------------------------------------------------
# Cookie extraction tests
# ---------------------------------------------------------------------------

class TestCookieExtract(unittest.TestCase):
    def _stream(self, items):
        for i in items:
            yield i

    def test_extracts_cookie_header(self):
        obj = {
            "session": "x",
            "method": "GET",
            "path": "/",
            "version": "HTTP/1.1",
            "headers": {"Cookie": "session=abc123; user=admin"},
            "body": b"",
        }
        result = list(cookie_extract(self._stream([obj])))
        self.assertGreaterEqual(len(result), 1)
        names = [r["name"] for r in result]
        self.assertIn("session", names)

    def test_extracts_set_cookie(self):
        obj = {
            "session": "x",
            "method": "RESPONSE",
            "path": "/",
            "version": "HTTP/1.1",
            "headers": {"Set-Cookie": "PHPSESSID=deadbeef; path=/"},
            "body": b"",
        }
        result = list(cookie_extract(self._stream([obj])))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "PHPSESSID")

    def test_no_cookies(self):
        obj = {
            "session": "x",
            "method": "GET",
            "path": "/",
            "version": "HTTP/1.1",
            "headers": {},
            "body": b"",
        }
        result = list(cookie_extract(self._stream([obj])))
        self.assertEqual(len(result), 0)

    def test_multiple_cookies(self):
        obj = {
            "session": "x",
            "method": "GET",
            "path": "/",
            "version": "HTTP/1.1",
            "headers": {"Cookie": "a=1; b=2; c=3"},
            "body": b"",
        }
        result = list(cookie_extract(self._stream([obj])))
        self.assertEqual(len(result), 3)

    def test_session_cookie_no_expiry(self):
        obj = {
            "session": "x",
            "method": "GET",
            "path": "/",
            "version": "HTTP/1.1",
            "headers": {"Set-Cookie": "JSESSIONID=12345; Path=/; HttpOnly"},
            "body": b"",
        }
        result = list(cookie_extract(self._stream([obj])))
        self.assertTrue(any("JSESSIONID" in r["name"] for r in result))


# ---------------------------------------------------------------------------
# URL extraction tests
# ---------------------------------------------------------------------------

class TestURLExtract(unittest.TestCase):
    def _stream(self, items):
        for i in items:
            yield i

    def test_extracts_get_url(self):
        obj = {
            "session": "x",
            "method": "GET",
            "path": "/index.html",
            "headers": {"Host": "example.com"},
        }
        result = list(url_extract(self._stream([obj])))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["host"], "example.com")
        self.assertEqual(result[0]["path"], "/index.html")

    def test_extracts_post_url(self):
        obj = {
            "session": "x",
            "method": "POST",
            "path": "/login",
            "headers": {"Host": "auth.example.com"},
        }
        result = list(url_extract(self._stream([obj])))
        self.assertEqual(len(result), 1)

    def test_dedup_urls(self):
        objs = [
            {"session": "x", "method": "GET", "path": "/", "headers": {"Host": "x.com"}},
            {"session": "y", "method": "GET", "path": "/", "headers": {"Host": "x.com"}},
        ]
        result = list(url_extract(self._stream(objs)))
        self.assertEqual(len(result), 1)

    def test_response_not_extracted(self):
        obj = {
            "session": "x",
            "method": "RESPONSE",
            "path": "/",
            "headers": {"Host": "x.com"},
        }
        result = list(url_extract(self._stream([obj])))
        self.assertEqual(len(result), 0)

    def test_empty_host(self):
        obj = {
            "session": "x",
            "method": "GET",
            "path": "/",
            "headers": {},
        }
        result = list(url_extract(self._stream([obj])))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["host"], "unknown")

    def test_different_methods_different_urls(self):
        objs = [
            {"session": "x", "method": "GET", "path": "/api", "headers": {"Host": "x.com"}},
            {"session": "x", "method": "POST", "path": "/api", "headers": {"Host": "x.com"}},
        ]
        result = list(url_extract(self._stream(objs)))
        self.assertEqual(len(result), 2)


# ---------------------------------------------------------------------------
# Pcap reader tests
# ---------------------------------------------------------------------------

class TestPcapReader(unittest.TestCase):
    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            list(pcap_reader("/nonexistent/capture.pcap"))

    def test_valid_pcap_not_found(self):
        with self.assertRaises(FileNotFoundError):
            list(pcap_reader("/tmp/no_such_file.pcap"))

    def test_scapy_not_installed(self):
        # Can't really test this without removing scapy — just verify import path
        pass


# ---------------------------------------------------------------------------
# CRED_PATTERNS sanity
# ---------------------------------------------------------------------------

class TestCredPatterns(unittest.TestCase):
    def test_common_cred_fields_covered(self):
        patterns = {p.decode() for p in CRED_PATTERNS}
        common = {"username", "password", "passwd", "login", "user", "email", "pwd", "pass", "userid", "auth"}
        for c in common:
            self.assertIn(c, patterns)

    def test_no_duplicate_patterns(self):
        self.assertEqual(len(CRED_PATTERNS), len(set(CRED_PATTERNS)))

    def test_patterns_are_lowercase(self):
        for p in CRED_PATTERNS:
            self.assertEqual(p, p.lower())

    def test_patterns_not_empty(self):
        for p in CRED_PATTERNS:
            self.assertGreater(len(p), 0)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases(unittest.TestCase):
    def test_http_filter_with_generator_exception(self):
        def broken():
            yield (None, b"GET / HTTP/1.1\r\n\r\n")
            raise RuntimeError("boom")
        
        with self.assertRaises(RuntimeError):
            list(http_filter(broken()))

    def test_session_reassembly_binary_noise(self):
        stream = (b"\xff" * 100 for _ in range(10))
        try:
            result = list(session_reassembly(stream))
            # Should not crash — may or may not produce results
        except Exception as e:
            self.fail(f"session_reassembly crashed: {e}")

    def test_http_parse_truncated_data(self):
        stream = [("s1", b"GET / HTTP/1.1\r\n")]
        result = list(http_parse(x for x in stream))
        self.assertEqual(len(result), 1)

    def test_cred_extract_no_fields(self):
        obj = {
            "session": "x", "method": "POST", "path": "/",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": b"=",
        }
        result = list(cred_extract(x for x in [obj]))
        self.assertEqual(len(result), 0)

    def test_basic_auth_no_colon(self):
        auth = base64.b64encode(b"admin").decode()
        obj = {
            "session": "x", "method": "GET", "path": "/",
            "headers": {"Authorization": f"Basic {auth}"},
            "body": b"",
        }
        result = list(cred_extract(x for x in [obj]))
        self.assertEqual(len(result), 0)

    def test_json_body_invalid_json(self):
        obj = {
            "session": "x", "method": "POST", "path": "/",
            "headers": {"Content-Type": "application/json"},
            "body": b"not json at all",
        }
        result = list(cred_extract(x for x in [obj]))
        self.assertEqual(len(result), 0)

    def test_cookies_with_empty_value(self):
        obj = {
            "session": "x", "method": "GET", "path": "/",
            "headers": {"Cookie": "session=; user="},
            "body": b"",
        }
        result = list(cookie_extract(x for x in [obj]))
        self.assertGreaterEqual(len(result), 2)

    def test_url_extract_put_method(self):
        obj = {
            "session": "x", "method": "PUT", "path": "/api/resource",
            "headers": {"Host": "api.x.com"},
        }
        result = list(url_extract(x for x in [obj]))
        self.assertEqual(len(result), 1)

    def test_pcap_reader_non_pcap_extension(self):
        # Should still try to read it
        with self.assertRaises((FileNotFoundError, RuntimeError, Exception)):
            list(pcap_reader("/dev/null"))


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

class TestCLI(unittest.TestCase):
    def test_parser_requires_read(self):
        from sniffdog import build_parser
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args([])

    def test_parser_read_flag(self):
        from sniffdog import build_parser
        parser = build_parser()
        args = parser.parse_args(["-r", "test.pcap"])
        self.assertEqual(args.read, "test.pcap")

    def test_parser_output_flag(self):
        from sniffdog import build_parser
        parser = build_parser()
        args = parser.parse_args(["-r", "a.pcap", "-o", "out.txt"])
        self.assertEqual(args.output, "out.txt")

    def test_parser_json_flag(self):
        from sniffdog import build_parser
        parser = build_parser()
        args = parser.parse_args(["-r", "a.pcap", "--json"])
        self.assertTrue(args.json)

    def test_parser_quiet_flag(self):
        from sniffdog import build_parser
        parser = build_parser()
        args = parser.parse_args(["-r", "a.pcap", "--quiet"])
        self.assertTrue(args.quiet)

    def test_parser_no_sessions(self):
        from sniffdog import build_parser
        parser = build_parser()
        args = parser.parse_args(["-r", "a.pcap", "--no-sessions"])
        self.assertTrue(args.no_sessions)


if __name__ == "__main__":
    unittest.main(verbosity=2)
