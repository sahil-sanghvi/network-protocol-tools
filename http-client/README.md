# HTTP Client

A minimal HTTP/HTTPS client built directly on `socket` and `ssl` — no `requests`, no `http.client`.

## What it does

Opens a raw TCP (or TLS) socket, writes the HTTP request line and headers by hand, and parses the raw response:

- Follows up to 10 redirect hops (301/302/303/307/308)
- Extracts cookies (name, expiry, domain) from `Set-Cookie` headers
- Detects HTTP/2 support via TLS ALPN negotiation during the handshake
- Detects password-protected resources via 401 responses and `WWW-Authenticate`

## Build & run

```bash
python3 WebTester.py <url_or_host> [--debug]
```

**Verified**, run against `www.uvic.ca`:

```
website: www.uvic.ca
1. Supports HTTP2: False
2. List of cookies:
cookie name: PHPSESSID
cookie name: uvic_bar, expires time: Thu, 01 Jan 1970 00:00:01 GMT, domain: .uvic.ca
cookie name: www_def
cookie name: TS018b3cbd
cookie name: TS0165a077, domain: .uvic.ca
3. Password Protected: No
```
