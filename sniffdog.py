#!/usr/bin/env python3
"""
SniffDog — Streaming pcap analyzer. Generator pipeline. Feed it a pcap, get creds.
"""

import argparse
import base64
import json
import os
import sys
from collections import defaultdict
from typing import Any, Dict, Generator, List, Optional, Tuple

# Maximum file size: 1GB for pcap files (CWE-770)
MAX_PCAP_SIZE = 1 * 1024 * 1024 * 1024
MAX_OUTPUT_SIZE = 100 * 1024 * 1024  # 100MB for output


def _validate_path(path: str, purpose: str = "file") -> str:
    """Validate file path — canonicalize and check exists (CWE-20/CWE-22)."""
    # CWE-22: Canonicalize path and prevent traversal
    resolved = os.path.realpath(path)
    if purpose == "input" and not os.path.isfile(resolved):
        raise FileNotFoundError(f"Input file not found: {resolved}")
    if purpose == "output":
        parent = os.path.dirname(resolved)
        if parent and not os.path.isdir(parent):
            raise FileNotFoundError(f"Output directory does not exist: {parent}")
    return resolved


# Pipeline stage 1: pcap reader

def pcap_reader(path: str) -> Generator[Tuple[Any, bytes], None, None]:
    """Yield (scapy_packet, raw_bytes) from a pcap file.
    
    Falls back to raw byte reading if scapy chokes on the file.
    """
    # CWE-20/CWE-22: Validate input path
    resolved = _validate_path(path, "input")
    # CWE-770: Check file size before reading
    file_size = os.path.getsize(resolved)
    if file_size > MAX_PCAP_SIZE:
        raise RuntimeError(f"Pcap file too large ({file_size} bytes > {MAX_PCAP_SIZE} max)")

    try:
        from scapy.utils import RawPcapReader
    except ImportError:
        raise RuntimeError("scapy not installed. Try: pip install scapy")

    try:
        for pkt, raw in RawPcapReader(resolved):
            if raw:
                yield pkt, raw
    except Exception as e:
        raise RuntimeError(f"Failed to read pcap: {e}") from e


# Pipeline stage 2: HTTP filter

def http_filter(
    stream: Generator[Tuple[Any, bytes], None, None]
) -> Generator[bytes, None, None]:
    """Filter raw packets, yielding only ones that look like HTTP."""
    for pkt, raw in stream:
        try:
            if raw and (b"HTTP/" in raw or b"GET " in raw or b"POST " in raw
                        or b"HTTP/1." in raw or b"Host:" in raw):
                yield raw
        except Exception:  # CWE-703: skip on malformed packets
            continue


# ---------------------------------------------------------------------------
# Pipeline stage 3: Session reassembly
# ---------------------------------------------------------------------------

def _parse_ip(raw: bytes) -> Optional[Tuple[str, str, str, str]]:
    """Quick-and-dirty IP/tuple extraction from raw bytes."""
    try:
        if len(raw) < 20:
            return None
        version = (raw[0] >> 4) & 0xF
        if version == 4:
            if len(raw) < 20:
                return None
            ihl = (raw[0] & 0xF) * 4
            if len(raw) < ihl + 12:
                return None
            src = ".".join(str(b) for b in raw[12:16])
            dst = ".".join(str(b) for b in raw[16:20])
            proto = raw[9]
            if proto != 6:  # TCP
                return None
            if len(raw) < ihl + 20:
                return None
            sport = (raw[ihl] << 8) | raw[ihl + 1]
            dport = (raw[ihl + 2] << 8) | raw[ihl + 3]
            return (src, str(sport), dst, str(dport))
        elif version == 6:
            # IPv6 — TODO: implement properly
            return None
        return None
    except Exception:  # CWE-703: return None on parse failure
        return None


def _payload_from_raw(raw: bytes) -> bytes:
    """Extract TCP payload from raw IP packet, stripping both IP and TCP headers."""
    try:
        if len(raw) < 20:
            return b""
        version = (raw[0] >> 4) & 0xF
        if version == 4:
            ihl = (raw[0] & 0xF) * 4
            if len(raw) <= ihl:
                return b""
            total_len = (raw[2] << 8) | raw[3]
            if total_len > len(raw):
                total_len = len(raw)
            # TCP data offset (upper 4 bits of byte 12 in TCP header)
            tcp_hdr_len = ((raw[ihl + 12] >> 4) & 0xF) * 4
            data_start = ihl + tcp_hdr_len
            if data_start > total_len:
                return b""
            return raw[data_start:total_len]
        return b""
    except Exception:  # CWE-703: return empty on parse failure
        return b""


def session_reassembly(
    packets: Generator[bytes, None, None]
) -> Generator[Tuple[str, bytes], None, None]:
    """Group raw packets into TCP sessions, yield reassembled byte streams."""
    sessions: Dict[str, List[bytes]] = defaultdict(list)
    session_keys: List[str] = []

    for raw in packets:
        tuple_key = _parse_ip(raw)
        if tuple_key is None:
            continue
        key = ":".join(tuple_key)
        rev_key = ":".join([tuple_key[2], tuple_key[3], tuple_key[0], tuple_key[1]])

        payload = _payload_from_raw(raw)
        if not payload:
            continue

        sessions[key].append(payload)
        if key not in session_keys:
            session_keys.append(key)

        # Also store reverse direction for same conversation
        sessions[rev_key].append(payload)
        if rev_key not in session_keys:
            session_keys.append(rev_key)

    for key in session_keys:
        merged = b"".join(sessions[key])
        if merged:
            yield key, merged


# ---------------------------------------------------------------------------
# Pipeline stage 4: HTTP parse
# ---------------------------------------------------------------------------

def http_parse(
    sessions: Generator[Tuple[str, bytes], None, None]
) -> Generator[Dict[str, Any], None, None]:
    """Parse HTTP requests/responses from raw byte streams."""
    for session_key, data in sessions:
        try:
            if b"HTTP/1." not in data and b"GET " not in data and b"POST " not in data:
                continue
            
            lines = data.split(b"\r\n")
            if not lines:
                continue

            first = lines[0].decode("utf-8", errors="replace")
            method = ""
            path = ""
            version = ""

            if first.startswith("HTTP/"):
                # Response
                parts = first.split(" ", 2)
                version = parts[0] if len(parts) > 0 else ""
                status = parts[1] if len(parts) > 1 else ""
                method = "RESPONSE"
                path = status
            elif " " in first:
                parts = first.split(" ", 2)
                method = parts[0]
                raw_path = parts[1] if len(parts) > 1 else "/"
                path = raw_path.split("?")[0]
                version = parts[2] if len(parts) > 2 else ""

            headers = {}
            body_start = data.find(b"\r\n\r\n")
            header_lines = data[:body_start].split(b"\r\n")[1:] if body_start > 0 else []

            for hdr in header_lines:
                if b":" in hdr:
                    k, v = hdr.split(b":", 1)
                    headers[k.decode("utf-8", errors="replace").strip()] = (
                        v.decode("utf-8", errors="replace").strip()
                    )

            body = b""
            if body_start > 0:
                body = data[body_start + 4:]
                cl = headers.get("Content-Length")
                if cl:
                    try:
                        body = body[: int(cl)]
                    except ValueError:
                        pass

            yield {
                "session": session_key,
                "method": method,
                "path": path,
                "version": version,
                "headers": headers,
                "body": body,
            }
        except Exception:  # CWE-703: skip on malformed packets
            continue


# ---------------------------------------------------------------------------
# Pipeline stage 5: Credential extraction
# ---------------------------------------------------------------------------

CRED_PATTERNS = [
    b"username", b"password", b"passwd", b"login", b"user",
    b"email", b"pwd", b"pass", b"userid", b"auth",
]


def cred_extract(
    http_objects: Generator[Dict[str, Any], None, None]
) -> Generator[Dict[str, Any], None, None]:
    """Extract credentials from HTTP objects. Yields dicts of found creds."""
    for http_obj in http_objects:
        # Check Basic Auth
        auth_hdr = http_obj["headers"].get("Authorization", "")
        if auth_hdr.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_hdr[6:]).decode("utf-8", errors="replace")
                if ":" in decoded:
                    user, passwd = decoded.split(":", 1)
                    yield {
                        "type": "basic_auth",
                        "source": http_obj["session"],
                        "url": http_obj["path"],
                        "username": user,
                        "password": passwd,
                    }
            except Exception:  # CWE-703: skip unparseable auth headers
                pass

        # Check POST body for credentials
        if http_obj["method"] == "POST" and http_obj["body"]:
            body = http_obj["body"]

            # URL-encoded form data
            if http_obj["headers"].get("Content-Type", "").startswith(
                "application/x-www-form-urlencoded"
            ) or b"=" in body[:200]:
                try:
                    decoded_body = body.decode("utf-8", errors="replace")
                    pairs = decoded_body.split("&")
                    from urllib.parse import unquote_plus

                    params = {}
                    for pair in pairs:
                        if "=" in pair:
                            k, v = pair.split("=", 1)
                            params[unquote_plus(k).lower()] = unquote_plus(v)

                    found = {}
                    for k, v in params.items():
                        if any(pattern in k.lower().encode() for pattern in CRED_PATTERNS):
                            found[k] = v
                    if found:
                        yield {
                            "type": "post_form",
                            "source": http_obj["session"],
                            "url": http_obj["path"],
                            "fields": found,
                        }
                except Exception:  # CWE-703: skip unparseable form data
                    pass

            # JSON body
            if http_obj["headers"].get("Content-Type", "").startswith("application/json"):
                try:
                    json_body = json.loads(body.decode("utf-8", errors="replace"))
                    if isinstance(json_body, dict):
                        found = {}
                        for k, v in json_body.items():
                            kl = k.lower()
                            if any(p in kl.encode() for p in [b"user", b"pass", b"auth", b"login", b"token"]):
                                found[k] = str(v) if not isinstance(v, (str, int, float)) else v
                        if found:
                            yield {
                                "type": "post_json",
                                "source": http_obj["session"],
                                "url": http_obj["path"],
                                "fields": found,
                            }
                except Exception:  # CWE-703: skip unparseable JSON data
                    pass


# ---------------------------------------------------------------------------
# Pipeline stage 6: Cookie extraction
# ---------------------------------------------------------------------------

def cookie_extract(
    http_objects: Generator[Dict[str, Any], None, None]
) -> Generator[Dict[str, Any], None, None]:
    """Yield cookies found in HTTP objects."""
    # Set-Cookie attributes that should not be treated as cookies
    set_cookie_attrs = {
        "path", "domain", "expires", "max-age", "maxage",
        "secure", "httponly", "samesite", "comment",
    }
    for http_obj in http_objects:
        for hdr_name in ("Cookie", "Set-Cookie"):
            val = http_obj["headers"].get(hdr_name, "")
            if not val:
                continue
            for part in val.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    k_stripped = k.strip().lower()
                    # Skip Set-Cookie attributes (path, domain, etc.)
                    if hdr_name == "Set-Cookie" and k_stripped in set_cookie_attrs:
                        continue
                    yield {
                        "type": hdr_name.lower().replace("-", "_"),
                        "source": http_obj["session"],
                        "url": http_obj["path"],
                        "name": k.strip(),
                        "value": v.strip(),
                    }


# ---------------------------------------------------------------------------
# Pipeline stage 7: URL extraction
# ---------------------------------------------------------------------------

def url_extract(
    http_objects: Generator[Dict[str, Any], None, None]
) -> Generator[Dict[str, Any], None, None]:
    """Yield deduplicated URLs from requests."""
    seen = set()
    for http_obj in http_objects:
        if http_obj["method"] in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            host = http_obj["headers"].get("Host", "unknown")
            url_key = f"{http_obj['method']}|{host}{http_obj['path']}"
            if url_key not in seen:
                seen.add(url_key)
                yield {
                    "method": http_obj["method"],
                    "host": host,
                    "path": http_obj["path"],
                    "session": http_obj["session"],
                }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="sniffdog", description="Pcap credential analyzer")
    p.add_argument("-r", "--read", required=True, help="Pcap file to analyze")
    p.add_argument("-o", "--output", help="Output file (default: stdout)")
    p.add_argument("--json", action="store_true", help="JSON output format")
    p.add_argument("--quiet", action="store_true", help="Only print credentials and cookies")
    p.add_argument("--no-sessions", action="store_true", help="Skip session reassembly")
    return p


def _fmt(val: Any) -> str:
    if isinstance(val, bytes):
        val = val.decode("utf-8", errors="replace")
    return str(val)


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.read:
        parser.print_help()
        sys.exit(1)

    # CWE-20/CWE-22: Validate output path before opening
    out_path = _validate_path(args.output, "output") if args.output else None
    out_fh = open(out_path, "w") if out_path else sys.stdout

    try:
        pipeline = pcap_reader(args.read)
        pipeline = http_filter(pipeline)

        if not args.no_sessions:
            pipeline = session_reassembly(pipeline)

        pipeline = http_parse(pipeline)

        # Fork pipeline for extraction
        pipeline_creds = cred_extract(pipeline)
        # We need to tee — but generators don't tee. So collect creds first.
        # This is a design smell. FIXME: rewrite with itertools.tee
        
        # Re-create for cookies/urls
        pipeline2 = pcap_reader(args.read)
        pipeline2 = http_filter(pipeline2)
        if not args.no_sessions:
            pipeline2 = session_reassembly(pipeline2)
        pipeline2 = http_parse(pipeline2)
        pipeline_cookies = cookie_extract(pipeline2)

        pipeline3 = pcap_reader(args.read)
        pipeline3 = http_filter(pipeline3)
        if not args.no_sessions:
            pipeline3 = session_reassembly(pipeline3)
        pipeline3 = http_parse(pipeline3)
        pipeline_urls = url_extract(pipeline3)

        creds = list(pipeline_creds)
        cookies = list(pipeline_cookies)
        urls = list(pipeline_urls)

        if args.json:
            output = {"credentials": creds, "cookies": cookies, "urls": urls}
            json.dump(output, out_fh, indent=2, default=_fmt)
            if out_fh is not sys.stdout:
                out_fh.close()
            return

        if not args.quiet:
            out_fh.write(f"=== SniffDog Report: {args.read} ===\n")
            out_fh.write(f"URLs visited: {len(urls)}\n\n")

            out_fh.write("--- URLs ---\n")
            for u in urls:
                out_fh.write(f"  {u['method']} {u['host']}{u['path']}\n")

            out_fh.write("\n")

        out_fh.write(f"--- Credentials Found: {len(creds)} ---\n")
        for c in creds:
            out_fh.write(f"  [{c['type']}] {c.get('url', '')}\n")
            if "username" in c:
                out_fh.write(f"    username: {c['username']}\n")
                out_fh.write(f"    password: {c['password']}\n")
            if "fields" in c:
                for k, v in c["fields"].items():
                    out_fh.write(f"    {k}: {v}\n")
            out_fh.write(f"    (session: {c['source']})\n")

        if not args.quiet:
            out_fh.write(f"\n--- Cookies: {len(cookies)} ---\n")
            for ck in cookies:
                out_fh.write(f"  {ck['name']}={ck['value']}  [{ck['url']}]\n")

    except Exception as e:
        # CWE-200: User-safe error message (no stack trace)
        print(f"Error: {e}", file=sys.stderr)
        if os.environ.get("SNIFFDOG_DEBUG"):
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        if args.output and out_fh is not sys.stdout:
            out_fh.close()


if __name__ == "__main__":
    main()
