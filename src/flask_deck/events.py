from __future__ import annotations

import contextlib
import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import queue
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import OrderedDict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Literal, Protocol, runtime_checkable
from urllib.parse import urlsplit

import sqlalchemy as sa
from sqlalchemy.engine import Engine

from flask_deck._version import SHORT_VERSION

logger = logging.getLogger("flask_deck.events")

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

WebhookDeliveryStatus = Literal["pending", "delivered", "retrying", "dead_letter"]


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


class WebhookHTTPError(RuntimeError):
    """Raised when a webhook receiver returns a non-2xx HTTP status code."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(slots=True)
class WebhookDeliveryRecord:
    """Tracked webhook delivery attempt + Dead-Letter Queue (DLQ) record."""

    id: str
    webhook_url: str
    event_name: str
    payload_json: str
    status: WebhookDeliveryStatus = "pending"
    attempts: int = 0
    max_attempts: int = 1
    last_status_code: int | None = None
    last_error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    delivered_at: datetime | None = None


@runtime_checkable
class WebhookDeliveryStore(Protocol):
    """Persistence contract for webhook delivery attempts and DLQ replays."""

    def record(self, item: WebhookDeliveryRecord) -> WebhookDeliveryRecord: ...

    def update(self, item: WebhookDeliveryRecord) -> None: ...

    def get(self, delivery_id: str) -> WebhookDeliveryRecord | None: ...

    def list_deliveries(
        self, *, status: str | None = None, limit: int = 100
    ) -> list[WebhookDeliveryRecord]: ...


class InMemoryWebhookDeliveryStore:
    """Thread-safe bounded in-memory webhook delivery & DLQ store."""

    __slots__ = ("_entries", "_lock", "_max_entries")

    def __init__(self, *, max_entries: int = 200) -> None:
        self._max_entries = max(10, int(max_entries))
        self._entries: OrderedDict[str, WebhookDeliveryRecord] = OrderedDict()
        self._lock = threading.Lock()

    def record(self, item: WebhookDeliveryRecord) -> WebhookDeliveryRecord:
        with self._lock:
            self._entries[item.id] = replace(item)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)
            return replace(item)

    def update(self, item: WebhookDeliveryRecord) -> None:
        with self._lock:
            if item.id in self._entries:
                self._entries[item.id] = replace(item)

    def get(self, delivery_id: str) -> WebhookDeliveryRecord | None:
        with self._lock:
            rec = self._entries.get(delivery_id)
            return replace(rec) if rec is not None else None

    def list_deliveries(
        self, *, status: str | None = None, limit: int = 100
    ) -> list[WebhookDeliveryRecord]:
        with self._lock:
            items = [replace(r) for r in reversed(self._entries.values())]
        if status:
            items = [r for r in items if r.status == status]
        return items[: max(1, int(limit))]


class SQLAlchemyWebhookDeliveryStore:
    """Multi-worker SQLAlchemy webhook delivery log and Dead-Letter Queue store."""

    def __init__(
        self,
        engine: Engine,
        *,
        table_name: str = "_flask_deck_webhook_deliveries",
    ) -> None:
        self._engine = engine
        self._meta = sa.MetaData()
        self._table = sa.Table(
            table_name,
            self._meta,
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column("webhook_url", sa.String(512), nullable=False),
            sa.Column("event_name", sa.String(128), nullable=False, index=True),
            sa.Column("payload_json", sa.Text, nullable=False),
            sa.Column("status", sa.String(24), nullable=False, index=True),
            sa.Column("attempts", sa.Integer, nullable=False, default=0),
            sa.Column("max_attempts", sa.Integer, nullable=False, default=1),
            sa.Column("last_status_code", sa.Integer, nullable=True),
            sa.Column("last_error", sa.Text, nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        )
        self._meta.create_all(engine, checkfirst=True)

    @staticmethod
    def _row_to_record(row: Any) -> WebhookDeliveryRecord:
        return WebhookDeliveryRecord(
            id=str(row.id),
            webhook_url=str(row.webhook_url),
            event_name=str(row.event_name),
            payload_json=str(row.payload_json),
            status=row.status,
            attempts=int(row.attempts or 0),
            max_attempts=int(row.max_attempts or 1),
            last_status_code=int(row.last_status_code) if row.last_status_code is not None else None,
            last_error=row.last_error,
            created_at=_ensure_utc(row.created_at) or datetime.now(timezone.utc),
            updated_at=_ensure_utc(row.updated_at) or datetime.now(timezone.utc),
            delivered_at=_ensure_utc(row.delivered_at),
        )

    def record(self, item: WebhookDeliveryRecord) -> WebhookDeliveryRecord:
        with self._engine.begin() as conn:
            conn.execute(
                self._table.insert().values(
                    id=item.id,
                    webhook_url=item.webhook_url,
                    event_name=item.event_name,
                    payload_json=item.payload_json,
                    status=item.status,
                    attempts=item.attempts,
                    max_attempts=item.max_attempts,
                    last_status_code=item.last_status_code,
                    last_error=item.last_error,
                    created_at=item.created_at,
                    updated_at=item.updated_at,
                    delivered_at=item.delivered_at,
                )
            )
        return replace(item)

    def update(self, item: WebhookDeliveryRecord) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                self._table.update()
                .where(self._table.c.id == item.id)
                .values(
                    status=item.status,
                    attempts=item.attempts,
                    max_attempts=item.max_attempts,
                    last_status_code=item.last_status_code,
                    last_error=item.last_error,
                    updated_at=item.updated_at,
                    delivered_at=item.delivered_at,
                )
            )

    def get(self, delivery_id: str) -> WebhookDeliveryRecord | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                sa.select(self._table).where(self._table.c.id == delivery_id)
            ).first()
            return self._row_to_record(row) if row is not None else None

    def list_deliveries(
        self, *, status: str | None = None, limit: int = 100
    ) -> list[WebhookDeliveryRecord]:
        stmt = sa.select(self._table)
        if status:
            stmt = stmt.where(self._table.c.status == status)
        stmt = stmt.order_by(self._table.c.created_at.desc(), self._table.c.id.desc()).limit(
            max(1, int(limit))
        )
        with self._engine.connect() as conn:
            return [self._row_to_record(r) for r in conn.execute(stmt)]


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
) -> int:
    """Send POST request refusing redirects, raising WebhookHTTPError on non-2xx responses."""
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
        try:
            with opener.open(req, timeout=timeout) as resp:
                resp.read(1024)
                status = int(getattr(resp, "status", 200))
                if status < 200 or status >= 300:
                    raise WebhookHTTPError(status, f"Webhook returned HTTP {status}")
                return status
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise ValueError(f"SSRF guard blocked webhook HTTP {exc.code} redirect") from exc
            excerpt = ""
            with contextlib.suppress(Exception):
                excerpt = exc.read(512).decode("utf-8", errors="ignore").strip()
            raise WebhookHTTPError(int(exc.code), f"Webhook HTTP {exc.code}: {excerpt or exc.reason}") from exc

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
    host_hdr = f"[{host}]" if ":" in host else host
    req_headers.setdefault("Host", host_hdr if port == default_port else f"{host_hdr}:{port}")
    try:
        conn.request("POST", path, body=body, headers=req_headers)
        resp = conn.getresponse()
        excerpt = resp.read(1024).decode("utf-8", errors="ignore").strip()
        if 300 <= resp.status < 400:
            raise ValueError(f"SSRF guard blocked webhook HTTP {resp.status} redirect")
        if resp.status < 200 or resp.status >= 300:
            raise WebhookHTTPError(
                int(resp.status),
                f"Webhook HTTP {resp.status}: {excerpt[:200]}",
            )
        return int(resp.status)
    finally:
        conn.close()


def sign_webhook_payload(body: bytes, secret: str) -> str:
    """Compute HMAC-SHA256 webhook signature header value."""
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


class WebhookSink:
    """SSRF-hardened, HMAC-SHA256 signed HTTP webhook sink with optional async retries & DLQ."""

    __slots__ = (
        "_allow_http",
        "_allow_private_ips",
        "_async_delivery",
        "_delivery_store",
        "_events",
        "_max_retries",
        "_queue",
        "_retry_delays",
        "_secret",
        "_stop_event",
        "_timeout",
        "_transport",
        "_url",
        "_worker",
        "_worker_lock",
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
        async_delivery: bool = False,
        max_retries: int = 0,
        retry_delays: Sequence[float] = (0.5, 2.0, 8.0),
        delivery_store: WebhookDeliveryStore | None = None,
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
        self._async_delivery = bool(async_delivery)
        self._max_retries = max(0, int(max_retries))
        self._retry_delays = tuple(max(0.0, float(d)) for d in retry_delays)
        self._delivery_store = delivery_store
        self._queue: queue.Queue[tuple[WebhookDeliveryRecord, bytes, str] | None] = queue.Queue()
        self._stop_event = threading.Event()
        self._worker_lock = threading.Lock()
        self._worker: threading.Thread | None = None

    @property
    def url(self) -> str:
        return self._url

    @property
    def events(self) -> frozenset[str]:
        return self._events

    @property
    def max_retries(self) -> int:
        return self._max_retries

    @property
    def async_delivery(self) -> bool:
        return self._async_delivery

    def set_delivery_store(self, store: WebhookDeliveryStore) -> None:
        if self._delivery_store is None:
            self._delivery_store = store

    def matches(self, event_name: str) -> bool:
        return "*" in self._events or event_name in self._events

    def _ensure_worker(self) -> None:
        with self._worker_lock:
            if self._worker is None or not self._worker.is_alive():
                self._stop_event.clear()
                self._worker = threading.Thread(
                    target=self._worker_loop,
                    name="flask-deck-webhook",
                    daemon=True,
                )
                self._worker.start()

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            if item is None:
                self._queue.task_done()
                break
            rec, body, ev_name = item
            try:
                self._attempt_deliver(rec, body, ev_name, raise_on_failure=False)
            except Exception as exc:
                logger.warning("Unexpected async webhook error: %s", exc)
            finally:
                self._queue.task_done()

    def _deliver_once(self, body: bytes, event_name: str) -> int:
        safe, reason, pinned_ip = _resolve_and_validate_url(
            self._url,
            allow_http=self._allow_http,
            allow_private_ips=self._allow_private_ips,
        )
        if not safe:
            raise ValueError(f"SSRF guard blocked webhook delivery: {reason}")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"flask-deck-webhook/{SHORT_VERSION}",
            "X-Deck-Event": event_name,
            "X-Deck-Signature": sign_webhook_payload(body, self._secret),
        }
        if self._transport is not None:
            status = int(self._transport(self._url, body, headers, self._timeout) or 200)
            if status < 200 or status >= 300:
                raise WebhookHTTPError(status, f"Webhook transport returned HTTP {status}")
            return status

        return _send_pinned_request(
            self._url,
            pinned_ip=pinned_ip,
            body=body,
            headers=headers,
            timeout=self._timeout,
        )

    def _attempt_deliver(
        self,
        rec: WebhookDeliveryRecord,
        body: bytes,
        event_name: str,
        *,
        raise_on_failure: bool,
    ) -> WebhookDeliveryRecord:
        total_attempts = 1 + self._max_retries
        last_exc: Exception | None = None
        for idx in range(total_attempts):
            if self._stop_event.is_set():
                break
            rec.attempts += 1
            rec.updated_at = datetime.now(timezone.utc)
            try:
                status = self._deliver_once(body, event_name)
                rec.status = "delivered"
                rec.last_status_code = status
                rec.last_error = None
                rec.delivered_at = datetime.now(timezone.utc)
                rec.updated_at = rec.delivered_at
                if self._delivery_store is not None:
                    self._delivery_store.update(rec)
                return rec
            except Exception as exc:
                last_exc = exc
                rec.last_error = str(exc)
                rec.last_status_code = exc.status_code if isinstance(exc, WebhookHTTPError) else None
                has_more = idx + 1 < total_attempts
                rec.status = "retrying" if has_more else "dead_letter"
                if self._delivery_store is not None:
                    self._delivery_store.update(rec)
                if has_more and idx < len(self._retry_delays):
                    time.sleep(self._retry_delays[idx])
                elif has_more and self._retry_delays:
                    time.sleep(self._retry_delays[-1])

        if raise_on_failure and last_exc is not None:
            raise last_exc
        return rec

    def _dispatch(self, event: DeckEvent) -> None:
        payload_json = json.dumps(event.to_dict(), default=str, separators=(",", ":"))
        body = payload_json.encode("utf-8")
        rec = WebhookDeliveryRecord(
            id=uuid.uuid4().hex[:16],
            webhook_url=self._url,
            event_name=event.name,
            payload_json=payload_json,
            status="pending",
            max_attempts=1 + self._max_retries,
        )
        if self._delivery_store is not None:
            self._delivery_store.record(rec)

        if self._async_delivery:
            self._ensure_worker()
            self._queue.put((rec, body, event.name))
            return

        # Keep direct synchronous callers strict when no DLQ/retry policy overrides behavior.
        raise_on_fail = self._max_retries == 0 and self._delivery_store is None
        self._attempt_deliver(rec, body, event.name, raise_on_failure=raise_on_fail)

    def __call__(self, event: DeckEvent) -> None:
        if not self.matches(event.name):
            return
        self._dispatch(event)

    def send_test(self, event: DeckEvent) -> None:
        """Dispatch an explicit operator test event even when the sink filters specific event names."""
        self._dispatch(event)

    def redeliver(self, rec: WebhookDeliveryRecord) -> WebhookDeliveryRecord:
        """Manually replay a tracked or dead-letter webhook delivery."""
        body = rec.payload_json.encode("utf-8")
        rec.attempts += 1
        rec.updated_at = datetime.now(timezone.utc)
        try:
            status = self._deliver_once(body, rec.event_name)
            rec.status = "delivered"
            rec.last_status_code = status
            rec.last_error = None
            rec.delivered_at = datetime.now(timezone.utc)
            rec.updated_at = rec.delivered_at
        except Exception as exc:
            rec.status = "dead_letter"
            rec.last_status_code = exc.status_code if isinstance(exc, WebhookHTTPError) else None
            rec.last_error = str(exc)
        if self._delivery_store is not None:
            self._delivery_store.update(rec)
        return rec

    def flush(self, timeout: float = 5.0) -> None:
        """Block up to timeout seconds until queued async deliveries finish."""
        deadline = time.monotonic() + timeout
        while getattr(self._queue, "unfinished_tasks", 0) > 0 and time.monotonic() < deadline:
            time.sleep(0.02)

    def close(self) -> None:
        """Stop async webhook worker cleanly."""
        self._stop_event.set()
        with self._worker_lock:
            worker = self._worker
            self._worker = None
        if worker is not None and worker.is_alive():
            self._queue.put(None)
            worker.join(timeout=2.0)


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
