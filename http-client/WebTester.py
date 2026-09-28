import sys
import socket
import ssl
from urllib.parse import urlparse, urlunparse

MAX_REDIRECTS = 10
READ_BUF = 65536
DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


class ConnectError(Exception):
    pass


def normalize_input_uri(raw):
    """Return (normalized_uri, scheme_provided_bool). If scheme missing, assume HTTP (to observe cookies set on the redirect)."""
    scheme_provided = "://" in raw
    if not scheme_provided:
        raw = "http://" + raw
    return raw, scheme_provided


def validate_hostname(host):
    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Error: Invalid hostname {host}.")
        sys.exit(1)


def pick_port(parsed):
    if parsed.port:
        return parsed.port
    return DEFAULT_HTTPS_PORT if parsed.scheme == "https" else DEFAULT_HTTP_PORT


def build_request(host, path):
    if not path:
        path = "/"
    lines = []
    lines.append(f"GET {path} HTTP/1.1")
    lines.append(f"Host: {host}")
    lines.append("Connection: close")
    lines.append(f"User-Agent: {USER_AGENT}")
    lines.append("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    lines.append("Accept-Language: en-US,en;q=0.9")
    lines.append("Upgrade-Insecure-Requests: 1")
    lines.append("\r\n")
    return "\r\n".join(lines).encode("ascii", errors="ignore")


def recv_until_headers(sock):
    buf = bytearray()
    sep = b"\r\n\r\n"
    sock.settimeout(10)
    while True:
        chunk = sock.recv(READ_BUF)
        if not chunk:
            break
        buf.extend(chunk)
        if sep in buf or b"\n\n" in buf:
            break
    return bytes(buf)


def split_header_body(raw):
    sep = b"\r\n\r\n"
    idx = raw.find(sep)
    if idx == -1:
        sep = b"\n\n"
        idx = raw.find(sep)
    if idx == -1:
        return raw, b""
    return raw[:idx], raw[idx + len(sep):]


def parse_status_line(header_text):
    lines = header_text.splitlines()
    if not lines:
        return "", 0, ""
    first = lines[0].strip()
    parts = first.split(" ", 2)
    if len(parts) < 2:
        return "", 0, ""
    http_version = parts[0]
    try:
        code = int(parts[1])
    except ValueError:
        code = 0
    phrase = parts[2] if len(parts) > 2 else ""
    return http_version, code, phrase


def parse_headers(header_text):
    headers = {}
    for line in header_text.splitlines()[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            key = k.strip().lower()
            val = v.strip()
            headers.setdefault(key, []).append(val)
    return headers


def extract_cookies(headers):
    cookies = []
    for sc in headers.get("set-cookie", []):
        parts = [p.strip() for p in sc.split(";")]
        if not parts:
            continue
        name_part = parts[0]
        cookie_name = name_part.split("=", 1)[0].strip() if "=" in name_part else name_part.strip()
        expires = None
        domain = None
        for attr in parts[1:]:
            low = attr.lower()
            if low.startswith("expires="):
                expires = attr.split("=", 1)[1].strip()
            elif low.startswith("domain="):
                domain = attr.split("=", 1)[1].strip()
        cookies.append((cookie_name, expires, domain))
    return cookies


def tcp_connect(host, port, use_tls, force_http1=False, force_no_alpn=False):
    sock = socket.create_connection((host, port), timeout=10)
    sock.settimeout(10)
    if not use_tls:
        return sock, None
    ctx = ssl.create_default_context()
    try:
        if force_no_alpn:
            # Don’t advertise ALPN at all -> many servers fall back to HTTP/1.1
            pass
        elif force_http1:
            try:
                ctx.set_alpn_protocols(["http/1.1"])
            except Exception:
                pass
        else:
            try:
                ctx.set_alpn_protocols(["h2", "http/1.1"])
            except Exception:
                pass
    except Exception:
        pass
    tls = ctx.wrap_socket(sock, server_hostname=host)
    negotiated = tls.selected_alpn_protocol() if hasattr(tls, "selected_alpn_protocol") else None
    return tls, negotiated


def is_password_protected(status_code, headers):
    if status_code == 401:
        return True
    if "www-authenticate" in headers:
        return True
    return False


def try_fetch_once(parsed):
    use_tls = parsed.scheme == "https"
    port = pick_port(parsed)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    # 1st attempt
    try:
        conn, negotiated = tcp_connect(parsed.hostname, port, use_tls)
    except Exception as e:
        raise ConnectError(str(e))

    # If server chose HTTP/2, reconnect in HTTP/1.1 mode so our text request works
    if negotiated == "h2" and use_tls:
        try:
            try:
                conn.close()
            except Exception:
                pass
            # Try forcing http/1.1 via ALPN
            conn, negotiated = tcp_connect(parsed.hostname, port, use_tls, force_http1=True)
            # If server still insists on h2, try no ALPN at all
            if negotiated == "h2":
                try:
                    conn.close()
                except Exception:
                    pass
                conn, negotiated = tcp_connect(parsed.hostname, port, use_tls, force_no_alpn=True)
        except Exception:
            # Best-effort: if this fails, proceed with the original connection
            pass

    try:
        host_header_value = parsed.netloc if parsed.port else parsed.hostname
        req = build_request(host_header_value, path)
        conn.sendall(req)
        raw = recv_until_headers(conn)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return negotiated, raw


def fetch_no_redirect(uri):
    """Fetch a single request without following redirects, return (status, headers, body, http2_alpn)."""
    parsed = urlparse(uri)
    validate_hostname(parsed.hostname)
    negotiated, raw = try_fetch_once(parsed)
    http2 = (parsed.scheme == "https" and negotiated == "h2")
    header_raw, body = split_header_body(raw)
    header_text = header_raw.decode("iso-8859-1", errors="ignore")
    _, status, _ = parse_status_line(header_text)
    headers = parse_headers(header_text)
    return status, headers, body, http2

def supports_http2(host):
    try:
        s = socket.create_connection((host, 443), timeout=5)
        ctx = ssl.create_default_context()
        try:
            ctx.set_alpn_protocols(["h2","http/1.1"])
        except Exception:
            pass
        t = ctx.wrap_socket(s, server_hostname=host)
        proto = t.selected_alpn_protocol() if hasattr(t,"selected_alpn_protocol") else None
        try: t.close()
        except: pass
        return proto == "h2"
    except Exception:
        return False


def follow_request(uri, allow_http_fallback, DEBUG=False):
    """Returns: (final_uri, final_status, final_headers, final_body, chain_cookies, http2_supported)"""
    chain_cookies = []
    http2_supported = False

    current = urlparse(uri)
    validate_hostname(current.hostname)

    redirects = 0
    while True:
        try:
            negotiated, raw = try_fetch_once(current)
        except ConnectError:
            if allow_http_fallback and current.scheme == "https":
                current = current._replace(scheme="http")
                negotiated, raw = try_fetch_once(current)
            else:
                raise

        if current.scheme == "https" and negotiated == "h2":
            http2_supported = True

        header_raw, body = split_header_body(raw)
        header_text = header_raw.decode("iso-8859-1", errors="ignore")
        _, status, _ = parse_status_line(header_text)
        headers = parse_headers(header_text)
        if DEBUG:
            try:
                print(f"[DEBUG] hop={redirects} scheme={current.scheme} ALPN={'h2' if (current.scheme=='https' and negotiated=='h2') else 'http/1.1'} status={status}", file=sys.stderr)
                if 'www-authenticate' in headers:
                    for v in headers['www-authenticate']:
                        print(f"[DEBUG] WWW-Authenticate: {v}", file=sys.stderr)
                if 'location' in headers:
                    for v in headers['location']:
                        print(f"[DEBUG] Location: {v}", file=sys.stderr)
            except Exception:
                pass

        chain_cookies.extend(extract_cookies(headers))

        if status in (301, 302, 303, 307, 308) and "location" in headers and redirects < MAX_REDIRECTS:
            new_loc = headers["location"][0]
            new_parsed = urlparse(new_loc)
            if not new_parsed.scheme:
                new_abs = urlunparse((current.scheme, current.netloc, new_parsed.path or "", "", new_parsed.query or "", ""))
                current = urlparse(new_abs)
            else:
                current = new_parsed
            redirects += 1
            if current.hostname is not None:
                validate_hostname(current.hostname)
            continue

        return urlunparse(current), status, headers, body, chain_cookies, http2_supported


def main():
    # Optional --debug flag for extra prints (to stderr)
    DEBUG = False
    args = [a for a in sys.argv[1:] if a != '--debug']
    if len(args) != len(sys.argv[1:]):
        DEBUG = True
    if len(args) != 1:
        print("Usage: python3 WebTester.py <url_or_host> [--debug]")
        sys.exit(1)

    raw_input = args[0]
    normalized, scheme_provided = normalize_input_uri(raw_input)
    allow_http_fallback = not scheme_provided

    # Remember the original host exactly as typed (post-normalization for bare-host input)
    parsed_for_print = urlparse(normalized)
    original_host_for_print = parsed_for_print.hostname if parsed_for_print.hostname else raw_input

    # ---- HTTP/2 capability probe (does the origin host support h2 over TLS?) ----
    def supports_http2(host: str) -> bool:
        try:
            # DNS check
            socket.gethostbyname(host)
            # ALPN probe on 443
            s = socket.create_connection((host, 443), timeout=5)
            ctx = ssl.create_default_context()
            try:
                ctx.set_alpn_protocols(["h2", "http/1.1"])
            except Exception:
                pass
            t = ctx.wrap_socket(s, server_hostname=host)
            proto = t.selected_alpn_protocol() if hasattr(t, "selected_alpn_protocol") else None
            try:
                t.close()
            except Exception:
                pass
            return proto == "h2"
        except Exception as e:
            if DEBUG:
                print(f"[DEBUG] h2 capability probe failed for {host}: {e}", file=sys.stderr)
            return False

    h2_capable = supports_http2(original_host_for_print)
    if DEBUG:
        print(f"[DEBUG] h2_capable({original_host_for_print})={h2_capable}", file=sys.stderr)

    # ---- Normal fetch with redirect handling (may force HTTP/1.1 for parsing) ----
    try:
        final_uri, status, headers, body, cookies, http2_supported = follow_request(
            normalized, allow_http_fallback, DEBUG=DEBUG
        )
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

    # If we couldn't parse headers (status==0), try a plain HTTP probe to the same path (best-effort)
    if status == 0:
        try:
            parsed_norm = urlparse(normalized)
            probe_path = parsed_norm.path or "/"
            if parsed_norm.query:
                probe_path += "?" + parsed_norm.query
            probe_http = f"http://{parsed_norm.hostname}{probe_path}"
            if DEBUG:
                print(f"[DEBUG] status==0, attempting plain HTTP probe: {probe_http}", file=sys.stderr)
            st_probe, h_probe, b_probe, h2_probe = fetch_no_redirect(probe_http)
            cookies.extend(extract_cookies(h_probe))
            if st_probe != 0:
                status = st_probe
                headers = h_probe
                if h2_probe:
                    http2_supported = True
                if DEBUG:
                    print(f"[DEBUG] probe returned status={st_probe}", file=sys.stderr)
        except Exception as e:
            if DEBUG:
                print(f"[DEBUG] plain HTTP probe failed: {e}", file=sys.stderr)

    # Best-effort origin-host probes ONLY IF we have zero cookies so far
    try:
        if not cookies:
            p_http = f"http://{original_host_for_print}/"
            st1, h1, b1, h2probe1 = fetch_no_redirect(p_http)
            cookies.extend(extract_cookies(h1))
            p_https = f"https://{original_host_for_print}/"
            st2, h2, b2, h2probe2 = fetch_no_redirect(p_https)
            cookies.extend(extract_cookies(h2))
            if h2probe1 or h2probe2:
                http2_supported = True
    except Exception:
        pass  # probing is optional

    # Determine password protection
    password_protected = is_password_protected(status, headers)

    # Merge the capability probe result so we report "True" if the site CAN do h2
    http2_supported = bool(http2_supported or h2_capable)

    # De-duplicate cookies by (name, domain, expires) — keeps same-named cookies from different domains
    seen = set()
    dedup = []
    for (cookie_name, expires, domain) in cookies:
        key = (cookie_name or "", domain or "", expires or "")
        if key not in seen:
            seen.add(key)
            dedup.append((cookie_name, expires, domain))

    print(f"website: {original_host_for_print}")
    print(f"1. Supports HTTP2: {'True' if http2_supported else 'False'}")
    print("2. List of cookies:")
    for (cookie_name, expires, domain) in dedup:
        line = f"cookie name: {cookie_name}"
        if expires:
            line += f", expires time: {expires}"
        if domain:
            line += f", domain: {domain}"
        print(line)
    print(f"3. Password Protected: {'Yes' if password_protected else 'No'}")


if __name__ == "__main__":
    main()
