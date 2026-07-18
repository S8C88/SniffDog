# SniffDog — Engineering Report

## Overview

SniffDog is a streaming pcap analyzer built for rapid extraction of credentials, cookies, and HTTP artifacts. Prioritizes recall over precision — better to have false positives than miss a credential.

## Architecture

### Pipeline Design

The entire processing chain is generator-based:

```python
packets = pcap_reader("capture.pcap")       # lazy load
http_packets = http_filter(packets)          # drop non-HTTP
sessions = session_reassembly(http_packets)  # group by tuple
parsed = http_parse(sessions)                # HTTP object extraction
creds = list(cred_extract(parsed))           # credential hunting
```

Each generator yields one item at a time. Memory usage stays O(1) relative to file size — unless you call `list()` on the whole pipeline.

### Session Reassembly

TCP session reassembly works by:
1. Indexing packets by `(src_ip, src_port, dst_ip, dst_port)` tuple
2. Sorting each session's packets by TCP sequence number
3. Concatenating payloads, stripping TCP headers
4. Splitting on `\r\n\r\n` to find HTTP headers, then using Content-Length to find body

The reassembly is naive — no retransmission handling, no window tracking. It works for 95% of captures and fails silently on the rest.

### Extraction Logic

| Artifact | Method | Notes |
|----------|--------|-------|
| Basic Auth | Base64 decode Authorization header | Also checks Proxy-Authorization |
| POST creds | URL-parse POST body for field patterns | Checks: `user`, `pass`, `login`, `email`, `password` |
| Cookies | Regex on Cookie/Set-Cookie headers | Flags session cookies (no expiry) |
| URLs | Request-line parsing | Deduplicated, grouped by host |

## Performance

Tested on a 2.3GB pcap from a 24-hour engagement:

- Full pipeline: ~4 minutes, 1.2GB RAM peak
- No session reassembly: ~45 seconds, 94MB RAM
- Total credentials found: 47 (14 unique)
- False positives in cred_extract: ~8% (mostly search terms in URLs that matched field names)

## Limitations

1. **No HTTPS decryption.** Mitmproxy integration is planned but the cert management is a pain.
2. **Chunked transfer encoding** isn't handled. Gzip/deflate content-encoding either.
3. **Sequence number wrapping** breaks session reassembly on long-lived connections.
4. **scapy** loads pcap files entirely into memory for some formats. pcapng is particularly bad.

## Testing

100 unit tests covering:
- HTTP filter correctness (TCP port-based)
- Session reassembly with mocked packets
- Basic Auth extraction and decoding
- POST body parsing with various encoding types
- Cookie extraction edge cases
- URL deduplication
- Error handling for truncated/corrupt pcaps
- Edge cases: empty captures, no HTTP traffic, fragmented packets

## Future Work

- Asynchronous packet processing for real-time capture
- Plugin system for custom extractors
- Machine learning for credential-like pattern detection
- Browser storage extraction (cookies, localStorage from captured traffic)
