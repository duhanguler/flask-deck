from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import socket
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger("flask_deck.events")

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True, slots=True)
class DeckEvent:
    """Structured operational lifecycle event emitted by Flask-Deck."""

    name: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    actor_id: str = "system"
    actor_name: str = "System"
    model_slug: str = ""
    record_pk: str = ""
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.name,
            "timestamp": self.timestamp.isoformat(),
            "actor_id": self.actor_id,
            "actor_name": self.actor_name,
            "model_slug": self.model_slug,
            "record_pk": self.record_pk,
            "payload": self.payload,
        }


EventListener = Callable[[DeckEvent], None]


def _is_non_public_ip(ip_obj: _IPAddress) -> bool:
    """Return True if an IP (including IPv4-mapped / 6to4 / Teredo / CGNAT) is non-public."""
    if isinstance(ip_obj, ipaddress.IPv6Address):
        if ip_obj.ipv4_mapped is not None and _is_non_public_ip(ip_obj.ipv4_mapped):
            return True
        if ip_obj.sixtofour is not None and _is_non_public_ip(ip_obj.sixtofour):
            return True
        if ip_obj.teredo is not None:
            server, client = ip_obj.teredo
            if _is_non_public_ip(server) or _is_non_public_ip(client):
                return True
    return (
        not ip_obj.is_global
        or ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def _resolve_and_validate_url(
    url: str,
    *,
    allow_http: bool = False,
    allow_private_ips: bool = False,
) -> tuple[bool, str, str | None]:
    """Validate URL and return ``(ok, reason, pinned_ip)`` to prevent DNS rebinding."""
    parsed = urlsplit(url.strip())
    scheme = parsed.scheme.lower()
    if scheme != "https" and not (allow_http and scheme == "http"):
        return False, "Webhook URL must use https://", None
    host = parsed.hostname
    if not host:
        return False, "Webhook URL is missing hostname", None
    if host.lower() in {"localhost", "metadata.google.internal", "169.254.169.254"} and not allow_private_ips:
        return False, f"Blocked restricted webhook host: {host}", None

    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        return False, f"Invalid webhook port: {exc}", None

    # Direct IP literal check
    try:
        ip_obj = ipaddress.ip_address(host.split("%", 1)[0])
        if not allow_private_ips and _is_non_public_ip(ip_obj):
            return False, f"Blocked non-public IP address: {host}", None
        return True, "", str(ip_obj)
    except ValueError:
        pass

    if allow_private_ips:
        return True, "", None

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as exc:
        return False, f"DNS resolution failed for {host}: {exc}", None

    if not infos:
        return False, f"No IP addresses resolved for {host}", None

    pinned: str | None = None
    for _family, _type, _proto, _canon, sockaddr in infos:
        raw_ip = str(sockaddr[0]).split("%", 1)[0]
        ip_obj = ipaddress.ip_address(raw_ip)
        if _is_non_public_ip(ip_obj):
            return False, f"Blocked DNS resolution to non-public IP: {raw_ip}", None
        if pinned is None:
            pinned = raw_ip

    return True, "", pinned


def is_ssrf_safe_url(
    url: str,
    *,
    allow_http: bool = False,
    allow_private_ips: bool = False,
) -> tuple[bool, str]:
    """Validate webhook destination URL and verify DNS resolves only to globally routable IPs."""
    ok, reason, _pinned = _resolve_and_validate_url(
        url,
        allow_http=allow_http,
        allow_private_ips=allow_private_ips,
    )
    return ok, reason


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse all 3xx redirects so webhooks cannot be bounced to internal/metadata IPs."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"SSRF guard blocked HTTP {code} redirect to {newurl}",
            headers,
            fp,
        )


def _send_pinned_request(
    url: str,
    *,
    pinned_ip: str | None,
    body: bytes,
    headers: dict[str, str],
    timeout: float,
) -> None:
    """Send POST request refusing redirects and connecting directly to the validated IP."""
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    if pinned_ip is None:
        opener = urllib.request.build_opener(_NoRedirectHandler())
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with opener.open(req, timeout=timeout) as resp:
            resp.read(1024)
        return

    # Connect straight to pinned_ip while preserving Host header and TLS SNI/hostname check.
    conn: http.client.HTTPConnection
    if scheme == "https":
        ctx = ssl.create_default_context()

        class _PinnedHTTPSConnection(http.client.HTTPSConnection):
            def connect(self) -> None:
                raw_sock = socket.create_connection((pinned_ip, port), self.timeout)
                self.sock = ctx.wrap_socket(raw_sock, server_hostname=host)

        conn = _PinnedHTTPSConnection(host, port=port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(pinned_ip, port=port, timeout=timeout)

    req_headers = dict(headers)
    default_port = 443 if scheme == "https" else 80
    req_headers.setdefault("Host", host if port == default_port else f"{host}:{port}")
    try:
        conn.request("POST", path, body=body, headers=req_headers)
        resp = conn.getresponse()
        resp.read(1024)
        if 300 <= resp.status < 400:
            raise ValueError(f"SSRF guard blocked webhook HTTP {resp.status} redirect")
    finally:
        conn.close()


def sign_webhook_payload(body: bytes, secret: str) -> str:
    """Compute HMAC-SHA256 webhook signature header value."""
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


class WebhookSink:
    """SSRF-hardened, HMAC-SHA256 signed HTTP webhook sink for DeckEventBus."""

    __slots__ = (
        "_allow_http",
        "_allow_private_ips",
        "_events",
        "_secret",
        "_timeout",
        "_transport",
        "_url",
    )

    def __init__(
        self,
        url: str,
        *,
        secret: str,
        events: Sequence[str] = ("*",),
        timeout: float = 5.0,
        allow_http: bool = False,
        allow_private_ips: bool = False,
        transport: Callable[[str, bytes, dict[str, str], float], int] | None = None,
    ) -> None:
        if not secret or len(secret) < 16:
            raise ValueError("WebhookSink secret must be at least 16 characters")
        self._url = url.strip()
        self._secret = secret
        self._events = frozenset(events)
        self._timeout = max(0.5, float(timeout))
        self._allow_http = allow_http
        self._allow_private_ips = allow_private_ips
        self._transport = transport

    def matches(self, event_name: str) -> bool:
        return "*" in self._events or event_name in self._events

    def __call__(self, event: DeckEvent) -> None:
        if not self.matches(event.name):
            return
        safe, reason, pinned_ip = _resolve_and_validate_url(
            self._url,
            allow_http=self._allow_http,
            allow_private_ips=self._allow_private_ips,
        )
        if not safe:
            raise ValueError(f"SSRF guard blocked webhook delivery: {reason}")

        body = json.dumps(event.to_dict(), default=str, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "flask-deck-webhook/0.3",
            "X-Deck-Event": event.name,
            "X-Deck-Signature": sign_webhook_payload(body, self._secret),
        }
        if self._transport is not None:
            self._transport(self._url, body, headers, self._timeout)
            return

        _send_pinned_request(
            self._url,
            pinned_ip=pinned_ip,
            body=body,
            headers=headers,
            timeout=self._timeout,
        )


class DeckEventBus:
    """In-process fault-isolated lifecycle event dispatcher."""

    __slots__ = ("_listeners",)

    def __init__(self) -> None:
        self._listeners: dict[str, list[EventListener]] = {}

    def subscribe(self, event_name: str, listener: EventListener) -> None:
        self._listeners.setdefault(event_name, []).append(listener)

    def emit(self, event: DeckEvent) -> list[str]:
        """Dispatch event to matching listeners; isolate errors so mutations never break."""
        errors: list[str] = []
        targets = list(self._listeners.get(event.name, ())) + list(self._listeners.get("*", ()))
        for fn in targets:
            try:
                fn(event)
            except Exception as exc:
                logger.warning("Deck event listener error for %s: %s", event.name, exc)
                errors.append(str(exc))
        return errors
