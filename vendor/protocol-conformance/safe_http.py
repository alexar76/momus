"""Bounded public-only HTTP for the standalone conformance and interop jobs.

Discovery URLs are untrusted, including URLs relayed by an admitted peer. Resolve
once, validate every DNS answer, and connect to the selected numeric address. A
normal hostname-based client would resolve again and reopen DNS rebinding.

Only the standard library is used. ``AIMARKET_CONFORMANCE_DENY_IPS`` may contain
comma/space-separated IPs or CIDRs, for example the operator's public server IPs.
It is additive: it cannot permit a private address or an unusual destination port.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import queue
import re
import socket
import ssl
import threading
import time
from urllib.parse import quote, urljoin, urlsplit

MAX_BODY_BYTES = 2_000_000
MAX_URL_BYTES = 4096
_PORTS = {"http": 80, "https": 443}
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
# libc DNS resolution has no interruptible timeout. Daemon workers let a caller
# stop waiting, while the fixed bound prevents repeated timeouts spawning an
# unbounded number of still-resolving threads. No executor shutdown may wait for DNS.
_DNS_SLOTS = threading.BoundedSemaphore(4)


class SafeHTTPError(ValueError):
    """A public-safe refusal: messages never contain request URLs or reply bodies."""


class HTTPStatusError(SafeHTTPError):
    def __init__(self, code: int):
        self.code = int(code)
        super().__init__(f"HTTP {self.code}")


def public_error(exc: Exception) -> str:
    """Only our fixed errors/statuses may appear in a public conformance report."""
    if isinstance(exc, SafeHTTPError):
        return str(exc)
    # Also accepts urllib.HTTPError from an injected/offline test transport.
    code = getattr(exc, "code", None)
    if isinstance(code, int) and 100 <= code <= 599:
        return f"HTTP {code}"
    return "request could not be completed"


def _parts(url: str):
    if not isinstance(url, str) or not url or len(url.encode("utf-8")) > MAX_URL_BYTES:
        raise SafeHTTPError("invalid URL")
    if "\\" in url or any(ord(c) <= 32 or 127 <= ord(c) < 160 for c in url):
        raise SafeHTTPError("URL contains forbidden characters")
    try:
        p = urlsplit(url)
        scheme = p.scheme.lower()
        if scheme not in _PORTS or not p.netloc or not p.hostname:
            raise SafeHTTPError("only public HTTP and HTTPS URLs are allowed")
        if p.username is not None or p.password is not None:
            raise SafeHTTPError("URL credentials are forbidden")
        if p.fragment:
            raise SafeHTTPError("URL fragments are forbidden")
        host = p.hostname.lower().rstrip(".")
        if not host or "%" in host:
            raise SafeHTTPError("invalid destination host")
        host = host.encode("idna").decode("ascii")
        port = p.port if p.port is not None else _PORTS[scheme]
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, SafeHTTPError):
            raise
        raise SafeHTTPError("invalid URL") from None
    if port != _PORTS[scheme]:
        raise SafeHTTPError("destination port is forbidden")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan", ".home.arpa")):
        raise SafeHTTPError("destination host is not public")
    return p, scheme, host, port


def same_origin_url(base: str, other: str) -> str:
    """Resolve a manifest URL, refusing cross-origin and unsafe URL syntax first."""
    _, a_scheme, a_host, a_port = _parts(base)
    if not isinstance(other, str) or not other or other.startswith("//"):
        raise SafeHTTPError("manifest URL must stay on the peer origin")
    target = urljoin(base.rstrip("/") + "/", other)
    _, b_scheme, b_host, b_port = _parts(target)
    if (a_scheme, a_host, a_port) != (b_scheme, b_host, b_port):
        raise SafeHTTPError("manifest URL must stay on the peer origin")
    return target


def _denied_networks() -> tuple:
    raw = os.environ.get("AIMARKET_CONFORMANCE_DENY_IPS", "")
    try:
        return tuple(ipaddress.ip_network(part, strict=False)
                     for part in re.split(r"[\s,]+", raw.strip()) if part)
    except ValueError:
        raise SafeHTTPError("invalid operator destination deny list") from None


def _public(addr) -> bool:
    if not addr.is_global or addr.is_multicast:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        # Refuse transition/tunnel spellings even when their embedded IPv4 is
        # public: a standalone status job has no need to route through them.
        if (addr.ipv4_mapped is not None or addr.sixtofour is not None
                or addr.teredo is not None or addr in _NAT64 or addr in _NAT64_LOCAL):
            return False
    return True


def _resolve(host: str, port: int, *, deadline: float):
    deny = _denied_networks()
    left = deadline - time.monotonic()
    if left <= 0:
        raise SafeHTTPError("request deadline exceeded")
    if not _DNS_SLOTS.acquire(blocking=False):
        raise SafeHTTPError("DNS resolver is busy")
    result = queue.Queue(maxsize=1)
    resolve = socket.getaddrinfo

    def resolve_once():
        try:
            result.put_nowait((True, resolve(host, port, type=socket.SOCK_STREAM)))
        except Exception:
            result.put_nowait((False, None))
        finally:
            _DNS_SLOTS.release()

    worker = threading.Thread(target=resolve_once, name="conformance-dns", daemon=True)
    try:
        worker.start()
    except RuntimeError:
        _DNS_SLOTS.release()
        raise SafeHTTPError("DNS resolver is busy") from None
    try:
        ok, infos = result.get(timeout=max(0.0, deadline - time.monotonic()))
    except queue.Empty:
        raise SafeHTTPError("DNS resolution deadline exceeded") from None
    if not ok:
        raise SafeHTTPError("destination could not be resolved") from None
    selected = None
    for family, kind, proto, _canon, sockaddr in infos:
        if time.monotonic() >= deadline:
            raise SafeHTTPError("request deadline exceeded")
        if family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM:
            raise SafeHTTPError("unusable destination address")
        try:
            addr = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            raise SafeHTTPError("unusable destination address") from None
        if not _public(addr):
            raise SafeHTTPError("destination address is not public")
        if any(addr.version == net.version and addr in net for net in deny):
            raise SafeHTTPError("destination is denied by the operator")
        if int(sockaddr[1]) != port:
            raise SafeHTTPError("unusable destination address")
        if selected is None:
            selected = (family, kind, proto, sockaddr)
    if selected is None:
        raise SafeHTTPError("destination has no usable address")
    return selected


def request(url: str, *, method: str = "GET", headers: dict | None = None,
            timeout: float = 15.0, max_bytes: int = MAX_BODY_BYTES) -> tuple[int, bytes, dict]:
    """GET/HEAD a public address, without redirects, proxies, or a second DNS lookup.

    A direct socket connects to the validated numeric sockaddr. HTTPS wraps that
    socket using the original host for SNI and certificate hostname verification.
    No TLS bypass, redirect-following or local-address exception is provided.
    """
    if method not in ("GET", "HEAD"):
        raise SafeHTTPError("request method is forbidden")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise SafeHTTPError("invalid response limit")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 120:
        raise SafeHTTPError("invalid request deadline")
    p, scheme, host, port = _parts(url)
    deadline = time.monotonic() + timeout
    family, kind, proto, sockaddr = _resolve(host, port, deadline=deadline)

    def remaining():
        left = deadline - time.monotonic()
        if left <= 0:
            raise SafeHTTPError("request deadline exceeded")
        return left

    out_headers = {}
    for key, value in (headers or {}).items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise SafeHTTPError("invalid request headers")
        if key.lower() in ("host", "authorization", "proxy-authorization", "cookie", "accept-encoding"):
            raise SafeHTTPError("request header is forbidden")
        if any(ord(c) < 32 or ord(c) == 127 for c in key + value):
            raise SafeHTTPError("invalid request headers")
        out_headers[key] = value
    out_headers["Host"] = f"[{host}]" if ":" in host else host
    out_headers["Accept-Encoding"] = "identity"
    out_headers["Connection"] = "close"
    target = quote(p.path or "/", safe="/%:@!$&'()*+,;=-._~")
    if p.query:
        target += "?" + quote(p.query, safe="/%?:@!$&'()*+,;=-._~")
    sock = None
    conn = None
    response = None
    deadline_timer = None
    try:
        sock = socket.socket(family, kind, proto)
        sock.settimeout(remaining())

        def abort_on_deadline():
            # A socket timeout alone restarts for each header/body read. A peer
            # sending one byte at a time must not extend the whole deadline.
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        deadline_timer = threading.Timer(remaining(), abort_on_deadline)
        deadline_timer.daemon = True
        deadline_timer.start()
        # sockaddr is numeric and was validated above; never connect((host, port)).
        sock.connect(sockaddr)
        if scheme == "https":
            context = ssl.create_default_context()
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise SafeHTTPError("TLS verification must remain enabled")
            sock.settimeout(remaining())
            sock = context.wrap_socket(sock, server_hostname=host)
        conn = http.client.HTTPConnection(host, port, timeout=remaining())
        conn.sock = sock
        conn.request(method, target, headers=out_headers)
        sock.settimeout(remaining())
        # HTTPConnection.getresponse may close its socket immediately for a
        # Connection: close reply. Keep ownership here so deadline updates also
        # work while the response file is being read.
        response = http.client.HTTPResponse(sock, method=method)
        response.begin()
        if not 200 <= response.status < 300:
            # In particular, never follow a Location or return its value publicly.
            raise HTTPStatusError(response.status)
        response_headers = {k.lower(): v for k, v in response.getheaders()}
        encoding = response_headers.get("content-encoding", "identity").strip().lower()
        if encoding not in ("", "identity"):
            raise SafeHTTPError("compressed response is forbidden")
        declared = response_headers.get("content-length")
        if declared is not None:
            try:
                size = int(declared)
            except ValueError:
                raise SafeHTTPError("invalid response length") from None
            if size < 0 or size > max_bytes:
                raise SafeHTTPError("response body exceeds the limit")
        body = bytearray()
        if method != "HEAD":
            while True:
                sock.settimeout(remaining())
                chunk = response.read1(min(65536, max_bytes - len(body) + 1))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise SafeHTTPError("response body exceeds the limit")
            if declared is not None and len(body) != size:
                raise SafeHTTPError("response body was truncated")
        remaining()
        return response.status, bytes(body), response_headers
    except SafeHTTPError:
        raise
    except ssl.SSLCertVerificationError:
        raise SafeHTTPError("TLS certificate verification failed") from None
    except (OSError, http.client.HTTPException, UnicodeError, ValueError):
        raise SafeHTTPError("network request failed") from None
    finally:
        if deadline_timer is not None:
            deadline_timer.cancel()
        if response is not None:
            response.close()
        if conn is not None:
            conn.close()
        if sock is not None:
            sock.close()


def fetch_json(url: str, *, timeout: float = 15.0, headers: dict | None = None,
               max_bytes: int = MAX_BODY_BYTES):
    status, body, _headers = request(url, timeout=timeout, headers=headers, max_bytes=max_bytes)
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise SafeHTTPError("response is not valid JSON") from None
    if not isinstance(data, dict):
        raise SafeHTTPError("response JSON is not an object")
    return status, data


def fetch_text(url: str, *, timeout: float = 20.0, headers: dict | None = None,
               max_bytes: int = MAX_BODY_BYTES) -> str:
    _status, body, _headers = request(url, timeout=timeout, headers=headers, max_bytes=max_bytes)
    try:
        return body.decode("utf-8")
    except UnicodeError:
        raise SafeHTTPError("response is not UTF-8 text") from None
