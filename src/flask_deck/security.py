from __future__ import annotations

import hmac
import ipaddress
import json
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from decimal import Decimal
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

import sqlalchemy as sa
from flask import Request, Response, session
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

CSRF_SESSION_KEY = "_deck_csrf_token"
CSRF_HEADER_NAME = "X-Deck-CSRFToken"
CSRF_FORM_FIELD = "_csrf_token"

DEFAULT_PASSWORD_HASH_METHOD = "pbkdf2:sha256:600000"

# Precomputed dummy hash for constant-time authentication when username does not exist.
_DUMMY_PASSWORD_HASH: str = generate_password_hash(
    "deck-constant-time-dummy-secret-value",
    method=DEFAULT_PASSWORD_HASH_METHOD,
)

DEFAULT_SENSITIVE_PATTERN: re.Pattern[str] = re.compile(
    r"(?:^|_)(?:password|passwd|pwd|secret|token|api_?key|private_?key|access_?key|"
    r"auth_?key|signing_?key|salt|hash(?:es)?|ssn|tckn|iban|cvv|credit_?card|card_?number|"
    r"pin|passphrase|otp|mfa_?secret|recovery_?codes)(?:$|_)",
    re.IGNORECASE,
)

_CSV_FORMULA_PREFIXES: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r", "\n")
_CSP_NONCE_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9+/=_-]{8,128}$")
_CSP_IMG_SOURCE_RE: re.Pattern[str] = re.compile(
    r"^https?://[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]*)?$"
)


def is_valid_csp_img_source(token: str) -> bool:
    """Validate an extra CSP img-src origin token (no wildcards, bare schemes, or control chars)."""
    if not isinstance(token, str) or any(ord(c) <= 32 or ord(c) == 127 for c in token):
        return False
    clean = token.strip()
    if not clean or "*" in clean or ";" in clean or "," in clean or "'" in clean or '"' in clean:
        return False
    if clean in {"blob:", "mediastream:"}:
        return True
    try:
        parsed = urlsplit(clean)
    except ValueError:
        return False
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return False
    return bool(_CSP_IMG_SOURCE_RE.fullmatch(clean))


def generate_nonce() -> str:
    """Return a fresh per-request cryptographic CSP nonce."""
    return secrets.token_urlsafe(16)


def build_csp_header(nonce: str, *, extra_img_sources: Iterable[str] = ()) -> str:
    """Build a strict Content-Security-Policy with zero unsafe-inline directives."""
    safe_nonce = nonce if isinstance(nonce, str) and _CSP_NONCE_RE.fullmatch(nonce) else generate_nonce()
    img_parts = ["'self'", "data:"]
    for src in extra_img_sources:
        clean = src.strip()
        if is_valid_csp_img_source(clean):
            img_parts.append(clean)
    return (
        "default-src 'none'; "
        f"script-src 'self' 'nonce-{safe_nonce}'; "
        "style-src 'self'; "
        f"img-src {' '.join(img_parts)}; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "form-action 'self'"
    )


def apply_security_headers(
    response: Response,
    *,
    nonce: str,
    is_static: bool = False,
    has_version_hash: bool = False,
    extra_img_sources: Iterable[str] = (),
) -> Response:
    """Attach defense-in-depth HTTP security and caching headers to Deck responses."""
    response.headers.setdefault(
        "Content-Security-Policy",
        build_csp_header(nonce, extra_img_sources=extra_img_sources),
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    if is_static:
        if has_version_hash:
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        else:
            response.headers.setdefault("Cache-Control", "public, max-age=3600")
    else:
        if "Cache-Control" not in response.headers:
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"

    return response


def get_csrf_token() -> str:
    """Fetch or create a per-session cryptographic CSRF token."""
    token = session.get(CSRF_SESSION_KEY)
    if not isinstance(token, str) or len(token) < 32:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def rotate_csrf_token() -> str:
    """Generate and persist a new CSRF token (used after authentication changes)."""
    token = secrets.token_urlsafe(32)
    session[CSRF_SESSION_KEY] = token
    return token


def _origin_tuple(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if not scheme or not host:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is None:
        port = 443 if scheme == "https" else (80 if scheme == "http" else 0)
    return scheme, host, port


def _check_origin_headers(req: Request) -> bool:
    """Secondary same-origin verification using Sec-Fetch-Site and Origin headers."""
    sec_fetch_site = req.headers.get("Sec-Fetch-Site", "").strip().lower()
    if sec_fetch_site and sec_fetch_site not in {"same-origin", "none"}:
        return False

    origin = req.headers.get("Origin", "").strip()
    if origin:
        if origin.lower() == "null":
            # Chromium may emit Origin: null on same-origin form posts under strict referrer policies.
            # Allow ONLY when browser explicitly confirms Sec-Fetch-Site: same-origin.
            return sec_fetch_site == "same-origin"
        origin_parts = _origin_tuple(origin)
        host_parts = _origin_tuple(req.host_url)
        if origin_parts is None or host_parts is None or origin_parts != host_parts:
            return False

    return True


check_origin_headers = _check_origin_headers


def validate_csrf(req: Request) -> bool:
    """Validate CSRF token and same-origin headers for any mutating request."""
    if not _check_origin_headers(req):
        return False

    expected = session.get(CSRF_SESSION_KEY)
    if not isinstance(expected, str) or len(expected) < 32:
        return False

    provided = req.headers.get(CSRF_HEADER_NAME)
    if not provided:
        provided = req.form.get(CSRF_FORM_FIELD)
    if not provided and req.is_json:
        payload = req.get_json(silent=True)
        if isinstance(payload, Mapping):
            raw = payload.get(CSRF_FORM_FIELD)
            if isinstance(raw, str):
                provided = raw

    if not isinstance(provided, str) or not provided:
        return False

    return hmac.compare_digest(expected, provided)


def verify_password_constant_time(password_hash: str | None, candidate: str) -> bool:
    """Verify a password hash without leaking username existence via timing."""
    if not password_hash:
        check_password_hash(_DUMMY_PASSWORD_HASH, candidate)
        return False
    return check_password_hash(password_hash, candidate)


def is_safe_redirect_url(target: str | None) -> bool:
    """Allow only strict relative same-origin redirect targets."""
    if not target or not isinstance(target, str):
        return False
    if "\\" in target or any(ord(ch) < 32 or ord(ch) == 127 for ch in target):
        return False
    if not target.startswith("/") or target.startswith("//"):
        return False
    try:
        parsed = urlsplit(target)
    except ValueError:
        return False
    return parsed.scheme == "" and parsed.netloc == ""


def is_safe_display_url(url: str | None) -> bool:
    """Allow only http://, https://, or relative / links to block javascript:/data: XSS."""
    if not url or not isinstance(url, str):
        return False
    if "\\" in url or any(ord(ch) < 32 or ord(ch) == 127 for ch in url):
        return False
    stripped = url.strip()
    if not stripped:
        return False
    if stripped.startswith("/") and not stripped.startswith("//"):
        return True
    try:
        parsed = urlsplit(stripped)
    except ValueError:
        return False
    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)


def sanitize_csv_cell(value: Any, *, enabled: bool = True) -> str:
    """Neutralize spreadsheet formula injection (=, +, -, @, tab, CR, LF) in exported CSV cells."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, Decimal)):
        return str(value)

    text = str(value)
    if not enabled or not text:
        return text

    stripped = text.lstrip(" \t\r\n")
    if text.startswith(("\t", "\r", "\n")) or (stripped and stripped[0] in _CSV_FORMULA_PREFIXES):
        return f"'{text}"
    return text


def is_sensitive_field(
    field_name: str,
    extra_patterns: Iterable[re.Pattern[str]] = (),
) -> bool:
    """Return True if a column name matches built-in or custom sensitive field patterns."""
    if DEFAULT_SENSITIVE_PATTERN.search(field_name):
        return True
    return any(pattern.search(field_name) for pattern in extra_patterns)


def mask_value(value: Any) -> Any:
    """Deterministically mask a field value while preserving minimal operational utility."""
    if value is None:
        return None
    text = str(value)
    if not text:
        return ""
    if "@" in text and "." in text.split("@", 1)[1]:
        local, domain = text.split("@", 1)
        prefix = local[0] if local else "*"
        return f"{prefix}***@{domain}"
    if len(text) <= 4:
        return "••••"
    return f"••••{text[-4:]}"


def redact_mapping(
    data: Mapping[str, Any],
    sensitive_fields: Iterable[str],
    extra_patterns: Iterable[re.Pattern[str]] = (),
) -> dict[str, Any]:
    """Return a copy of mapping with sensitive keys replaced by '[REDACTED]'."""
    sensitive_set = set(sensitive_fields)
    redacted: dict[str, Any] = {}
    for key, val in data.items():
        if key in sensitive_set or is_sensitive_field(key, extra_patterns):
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = val
    return redacted


def escape_like(term: str) -> str:
    """Escape SQL LIKE wildcards (\\, %, _) for safe substring searches."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def check_json_depth(value: Any, max_depth: int, _current: int = 0) -> bool:
    """Return False if a parsed JSON structure exceeds max_depth."""
    if _current > max_depth:
        return False
    if isinstance(value, dict):
        return all(check_json_depth(v, max_depth, _current + 1) for v in value.values())
    if isinstance(value, list):
        return all(check_json_depth(v, max_depth, _current + 1) for v in value)
    return True


def _bucket_keys(ip: str, username: str) -> tuple[str, ...]:
    clean_ip = (ip or "unknown").strip()[:64]
    clean_user = (username or "").strip().lower()[:128]
    if clean_user:
        return (f"ip:{clean_ip}", f"pair:{clean_ip}:{clean_user}", f"user:{clean_user}")
    return (f"ip:{clean_ip}", f"pair:{clean_ip}:")


def _bucket_limit(key: str, max_attempts: int) -> int:
    # IP-only bucket allows 3x threshold (shared NATs); per-user bucket allows 2x
    # to defeat distributed IP-rotation brute force without trivial single-typo lockouts.
    if key.startswith("ip:"):
        return max_attempts * 3
    if key.startswith("user:"):
        return max_attempts * 2
    return max_attempts


@runtime_checkable
class RateLimitStore(Protocol):
    """Multi-worker login brute-force rate limiting contract."""

    def is_locked(self, ip: str, username: str = "") -> tuple[bool, int]: ...

    def record_failure(self, ip: str, username: str = "") -> None: ...

    def record_success(self, ip: str, username: str = "") -> None: ...


class LoginRateLimiter:
    """Thread-safe bounded sliding-window login brute-force throttler."""

    __slots__ = (
        "_attempts",
        "_lock",
        "_lockout_seconds",
        "_lockouts",
        "_max_attempts",
        "_max_keys",
        "_window_seconds",
    )

    def __init__(
        self,
        *,
        max_attempts: int = 5,
        window_seconds: int = 300,
        lockout_seconds: int = 300,
        max_keys: int = 10000,
    ) -> None:
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._lockout_seconds = lockout_seconds
        self._max_keys = max_keys
        self._attempts: OrderedDict[str, list[float]] = OrderedDict()
        self._lockouts: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def _evict_if_needed(self, store: OrderedDict[str, Any]) -> None:
        while len(store) > self._max_keys:
            store.popitem(last=False)

    def is_locked(self, ip: str, username: str = "") -> tuple[bool, int]:
        """Return (locked, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            for key in _bucket_keys(ip, username):
                until = self._lockouts.get(key)
                if until is not None:
                    if until > now:
                        return True, max(1, int(until - now))
                    self._lockouts.pop(key, None)
            return False, 0

    def record_failure(self, ip: str, username: str = "") -> None:
        """Record a failed authentication attempt and engage lockout if threshold is reached."""
        now = time.monotonic()
        cutoff = now - self._window_seconds
        with self._lock:
            for key in _bucket_keys(ip, username):
                limit = _bucket_limit(key, self._max_attempts)
                timestamps = [t for t in self._attempts.get(key, []) if t >= cutoff]
                timestamps.append(now)
                self._attempts[key] = timestamps
                self._attempts.move_to_end(key)
                self._evict_if_needed(self._attempts)
                if len(timestamps) >= limit:
                    self._lockouts[key] = now + self._lockout_seconds
                    self._lockouts.move_to_end(key)
                    self._evict_if_needed(self._lockouts)

    def record_success(self, ip: str, username: str = "") -> None:
        """Clear pair and per-user failure history after a successful authentication."""
        keys = _bucket_keys(ip, username)
        with self._lock:
            for key in keys[1:]:
                self._attempts.pop(key, None)
                self._lockouts.pop(key, None)


InMemoryRateLimitStore = LoginRateLimiter


class SQLAlchemyRateLimitStore:
    """Multi-worker SQLAlchemy sliding-window login rate limiter."""

    def __init__(
        self,
        engine: Engine,
        *,
        max_attempts: int = 5,
        window_seconds: int = 300,
        lockout_seconds: int = 300,
        table_name: str = "_flask_deck_rate_limits",
    ) -> None:
        self._engine = engine
        self._max_attempts = max(1, int(max_attempts))
        self._window_seconds = max(1, int(window_seconds))
        self._lockout_seconds = max(1, int(lockout_seconds))
        self._lock = threading.Lock()
        self._meta = sa.MetaData()
        self._table = sa.Table(
            table_name,
            self._meta,
            sa.Column("bucket_key", sa.String(255), primary_key=True),
            sa.Column("attempts_json", sa.Text, nullable=False, default="[]"),
            sa.Column("locked_until", sa.Float, nullable=True),
        )
        self._meta.create_all(engine, checkfirst=True)

    def is_locked(self, ip: str, username: str = "") -> tuple[bool, int]:
        now = time.time()
        keys = _bucket_keys(ip, username)
        with self._engine.connect() as conn:
            rows = conn.execute(
                sa.select(self._table.c.bucket_key, self._table.c.locked_until).where(
                    self._table.c.bucket_key.in_(keys)
                )
            ).all()
        for _k, locked_until in rows:
            if locked_until is not None and float(locked_until) > now:
                return True, max(1, int(float(locked_until) - now))
        return False, 0

    def record_failure(self, ip: str, username: str = "") -> None:
        now = time.time()
        cutoff = now - self._window_seconds
        use_for_update = self._engine.dialect.name != "sqlite"
        with self._lock:
            for key in _bucket_keys(ip, username):
                limit = _bucket_limit(key, self._max_attempts)
                for attempt in range(3):
                    try:
                        with self._engine.begin() as conn:
                            sel = sa.select(
                                self._table.c.attempts_json,
                                self._table.c.locked_until,
                            ).where(self._table.c.bucket_key == key)
                            if use_for_update:
                                sel = sel.with_for_update()
                            row = conn.execute(sel).first()
                            try:
                                ts_raw = json.loads(row[0]) if row and row[0] else []
                            except Exception:
                                ts_raw = []
                            timestamps = [float(t) for t in ts_raw if float(t) >= cutoff]
                            timestamps.append(now)
                            prev_lock = row[1] if row is not None else None
                            existing_lock = (
                                float(prev_lock)
                                if prev_lock is not None and float(prev_lock) > now
                                else None
                            )
                            if len(timestamps) >= limit:
                                new_lock = now + self._lockout_seconds
                                locked_until: float | None = (
                                    max(existing_lock, new_lock)
                                    if existing_lock is not None
                                    else new_lock
                                )
                            else:
                                locked_until = existing_lock
                            payload = json.dumps(timestamps)
                            if row is None:
                                conn.execute(
                                    self._table.insert().values(
                                        bucket_key=key,
                                        attempts_json=payload,
                                        locked_until=locked_until,
                                    )
                                )
                            else:
                                conn.execute(
                                    self._table.update()
                                    .where(self._table.c.bucket_key == key)
                                    .values(attempts_json=payload, locked_until=locked_until)
                                )
                        break
                    except IntegrityError:
                        if attempt == 2:
                            raise

    def record_success(self, ip: str, username: str = "") -> None:
        keys = _bucket_keys(ip, username)[1:]
        with self._engine.begin() as conn:
            conn.execute(self._table.delete().where(self._table.c.bucket_key.in_(keys)))


_LUA_RECORD_FAILURE = """
local raw = redis.call('GET', KEYS[1])
local now = tonumber(ARGV[1])
local cutoff = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local lockout = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])
local attempts = {}
local existing_lock = nil
if raw then
    local ok, data = pcall(cjson.decode, raw)
    if ok and type(data) == 'table' then
        if type(data['attempts']) == 'table' then
            for _, t in ipairs(data['attempts']) do
                local num = tonumber(t)
                if num and num >= cutoff then
                    attempts[#attempts + 1] = num
                end
            end
        end
        local prev_lock = tonumber(data['locked_until'])
        if prev_lock and prev_lock > now then
            existing_lock = prev_lock
        end
    end
end
attempts[#attempts + 1] = now
local locked_until = cjson.null
if #attempts >= limit then
    local new_lock = now + lockout
    if existing_lock and existing_lock > new_lock then
        locked_until = existing_lock
    else
        locked_until = new_lock
    end
elseif existing_lock then
    locked_until = existing_lock
end
local payload = cjson.encode({ attempts = attempts, locked_until = locked_until })
redis.call('SET', KEYS[1], payload, 'EX', ttl)
return #attempts
"""


class RedisRateLimitStore:
    """Optional Redis multi-worker login rate limiter (requires optional `redis` package or client)."""

    def __init__(
        self,
        redis_url_or_client: str | Any,
        *,
        max_attempts: int = 5,
        window_seconds: int = 300,
        lockout_seconds: int = 300,
        key_prefix: str = "flask_deck:rl:",
    ) -> None:
        self._max_attempts = max(1, int(max_attempts))
        self._window_seconds = max(1, int(window_seconds))
        self._lockout_seconds = max(1, int(lockout_seconds))
        self._prefix = key_prefix
        self._owns_client = isinstance(redis_url_or_client, str)
        if isinstance(redis_url_or_client, str):
            try:
                import redis as redis_lib
            except ImportError as exc:
                raise RuntimeError(
                    "redis is required for RedisRateLimitStore. Install with: pip install 'flask-deck[redis]'"
                ) from exc
            self._client: Any = redis_lib.Redis.from_url(redis_url_or_client, decode_responses=True)
        else:
            self._client = redis_url_or_client

    def close(self) -> None:
        if self._owns_client and hasattr(self._client, "close"):
            self._client.close()

    def _rkey(self, bucket: str) -> str:
        return f"{self._prefix}{bucket}"

    def is_locked(self, ip: str, username: str = "") -> tuple[bool, int]:
        now = time.time()
        for key in _bucket_keys(ip, username):
            raw = self._client.get(self._rkey(key))
            if not raw:
                continue
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            try:
                data = json.loads(raw)
                until = data.get("locked_until")
                if until is not None and float(until) > now:
                    return True, max(1, int(float(until) - now))
            except Exception:
                continue
        return False, 0

    def record_failure(self, ip: str, username: str = "") -> None:
        now = time.time()
        cutoff = now - self._window_seconds
        ttl = max(self._window_seconds, self._lockout_seconds) + 10
        use_lua = hasattr(self._client, "eval")
        for key in _bucket_keys(ip, username):
            rkey = self._rkey(key)
            limit = _bucket_limit(key, self._max_attempts)
            if use_lua:
                self._client.eval(
                    _LUA_RECORD_FAILURE,
                    1,
                    rkey,
                    str(now),
                    str(cutoff),
                    str(limit),
                    str(self._lockout_seconds),
                    str(ttl),
                )
                continue
            raw = self._client.get(rkey)
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            try:
                data = json.loads(raw) if raw else {}
            except Exception:
                data = {}
            timestamps = [float(t) for t in data.get("attempts", []) if float(t) >= cutoff]
            timestamps.append(now)
            prev_lock = data.get("locked_until")
            existing_lock = (
                float(prev_lock)
                if prev_lock is not None and float(prev_lock) > now
                else None
            )
            if len(timestamps) >= limit:
                new_lock = now + self._lockout_seconds
                locked_until: float | None = (
                    max(existing_lock, new_lock) if existing_lock is not None else new_lock
                )
            else:
                locked_until = existing_lock
            self._client.set(
                rkey,
                json.dumps({"attempts": timestamps, "locked_until": locked_until}),
                ex=ttl,
            )

    def record_success(self, ip: str, username: str = "") -> None:
        for key in _bucket_keys(ip, username)[1:]:
            self._client.delete(self._rkey(key))


def mask_ip_address(raw_ip: str) -> str:
    """Mask an IPv4/IPv6 address to a non-identifying prefix for public demo displays."""
    clean = str(raw_ip or "").strip()
    if not clean:
        return "redacted"
    try:
        addr = ipaddress.ip_address(clean)
    except ValueError:
        return "redacted"
    if isinstance(addr, ipaddress.IPv4Address):
        parts = str(addr).split(".")
        return f"{parts[0]}.{parts[1]}.xxx.xxx"
    parts6 = addr.exploded.split(":")
    return f"{parts6[0]}:{parts6[1]}::xxxx"
