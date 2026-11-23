from __future__ import annotations

import fnmatch
import hashlib
import hmac
import ipaddress
import json
import secrets
import threading
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol, runtime_checkable

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from flask_deck.auth import DeckUser


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def hash_api_key(plaintext: str) -> str:
    """Return SHA-256 hex digest of an API key (plaintext is never persisted)."""
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """Generate a new ``(plaintext, prefix, key_hash)`` API key tuple."""
    plaintext = f"dk_live_{secrets.token_hex(24)}"
    prefix = plaintext[:14]
    return plaintext, prefix, hash_api_key(plaintext)


def ip_matches_allowlist(client_ip: str | None, allowed_ips: Sequence[str]) -> bool:
    """Return True if allowlist is empty or ``client_ip`` matches an IP or CIDR entry."""
    clean_entries = [item.strip() for item in allowed_ips if item and item.strip()]
    if not clean_entries:
        return True
    if not client_ip:
        return False
    try:
        addr = ipaddress.ip_address(client_ip.strip())
    except ValueError:
        return False
    for entry in clean_entries:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


@dataclass(slots=True)
class APIKeyRecord:
    """Persistent scoped API credential record (`dk_live_...`, hashed at rest)."""

    id: str
    name: str
    prefix: str
    key_hash: str
    owner_id: str
    owner_name: str
    scopes: tuple[str, ...] = ("*:view",)
    roles: tuple[str, ...] = ("viewer",)
    allowed_ips: tuple[str, ...] = ()
    is_superuser: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None

    @property
    def is_active(self) -> bool:
        if self.revoked_at is not None:
            return False
        exp = _ensure_utc(self.expires_at)
        return exp is None or exp > datetime.now(timezone.utc)


def api_key_allows(rec: APIKeyRecord, permission: str) -> bool:
    """Return True if ``rec.scopes`` authorizes ``permission``."""
    for pat in rec.scopes:
        if pat == "*" or pat == permission or fnmatch.fnmatchcase(permission, pat):
            return True
    return False


def api_key_to_user(rec: APIKeyRecord) -> DeckUser:
    """Materialize a synthetic ``DeckUser`` identity from a verified APIKeyRecord."""
    return DeckUser(
        id=f"apikey:{rec.id}",
        username=f"key:{rec.name}",
        display_name=f"API Key: {rec.name}",
        roles=tuple(rec.roles),
        is_superuser=rec.is_superuser,
        metadata={
            "auth_type": "api_key",
            "api_key_id": rec.id,
            "api_key_prefix": rec.prefix,
            "owner_id": rec.owner_id,
        },
    )


def build_api_key_record(
    *,
    name: str,
    owner_id: str,
    owner_name: str,
    scopes: Sequence[str] = ("*:view",),
    roles: Sequence[str] = ("viewer",),
    allowed_ips: Sequence[str] = (),
    is_superuser: bool = False,
    ttl_days: int | None = None,
) -> tuple[str, APIKeyRecord]:
    """Build a fresh APIKeyRecord and return ``(plaintext_token, record)``."""
    plaintext, prefix, digest = generate_api_key()
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(days=int(ttl_days))) if ttl_days and ttl_days > 0 else None
    clean_scopes = tuple(s.strip() for s in scopes if s and s.strip()) or ("*:view",)
    clean_roles = tuple(r.strip() for r in roles if r and r.strip()) or ("viewer",)
    clean_ips = tuple(ip.strip() for ip in allowed_ips if ip and ip.strip())
    rec = APIKeyRecord(
        id=uuid.uuid4().hex[:16],
        name=name.strip()[:120] or "API Key",
        prefix=prefix,
        key_hash=digest,
        owner_id=owner_id[:128],
        owner_name=owner_name[:128],
        scopes=clean_scopes,
        roles=clean_roles,
        allowed_ips=clean_ips,
        is_superuser=bool(is_superuser),
        created_at=now,
        expires_at=expires_at,
    )
    return plaintext, rec


@runtime_checkable
class APIKeyStore(Protocol):
    """Persistence contract for scoped REST API and MCP Bearer tokens."""

    def create(self, rec: APIKeyRecord) -> APIKeyRecord: ...

    def get(self, key_id: str) -> APIKeyRecord | None: ...

    def list_keys(self, *, owner_id: str | None = None, limit: int = 100) -> list[APIKeyRecord]: ...

    def revoke(self, key_id: str, *, owner_id: str | None = None) -> bool: ...

    def verify_token(
        self, plaintext: str, *, client_ip: str | None = None
    ) -> APIKeyRecord | None: ...


class InMemoryAPIKeyStore:
    """Thread-safe in-memory store for scoped API keys."""

    __slots__ = ("_lock", "_records")

    def __init__(self) -> None:
        self._records: dict[str, APIKeyRecord] = {}
        self._lock = threading.Lock()

    def create(self, rec: APIKeyRecord) -> APIKeyRecord:
        stored = replace(rec, id=rec.id or uuid.uuid4().hex[:16])
        with self._lock:
            self._records[stored.id] = stored
        return replace(stored)

    def get(self, key_id: str) -> APIKeyRecord | None:
        with self._lock:
            rec = self._records.get(key_id)
            return replace(rec) if rec is not None else None

    def list_keys(self, *, owner_id: str | None = None, limit: int = 100) -> list[APIKeyRecord]:
        with self._lock:
            items = [
                replace(r)
                for r in self._records.values()
                if owner_id is None or r.owner_id == owner_id
            ]
        items.sort(key=lambda r: r.created_at, reverse=True)
        return items[: max(1, int(limit))]

    def revoke(self, key_id: str, *, owner_id: str | None = None) -> bool:
        with self._lock:
            rec = self._records.get(key_id)
            if rec is None:
                return False
            if owner_id is not None and rec.owner_id != owner_id:
                return False
            if rec.revoked_at is None:
                rec.revoked_at = datetime.now(timezone.utc)
            return True

    def verify_token(
        self, plaintext: str, *, client_ip: str | None = None
    ) -> APIKeyRecord | None:
        if not plaintext or not plaintext.startswith("dk_live_") or len(plaintext) < 16:
            return None
        candidate_hash = hash_api_key(plaintext)
        matched: APIKeyRecord | None = None
        with self._lock:
            for rec in self._records.values():
                if hmac.compare_digest(rec.key_hash, candidate_hash):
                    matched = rec
                    break
            if matched is None or not matched.is_active:
                return None
            if not ip_matches_allowlist(client_ip, matched.allowed_ips):
                return None
            now = datetime.now(timezone.utc)
            if matched.last_used_at is None or (now - matched.last_used_at).total_seconds() >= 60:
                matched.last_used_at = now
            return replace(matched)


class SQLAlchemyAPIKeyStore:
    """Multi-worker SQLAlchemy store for hashed API keys (`deck_api_keys`)."""

    def __init__(
        self,
        engine: Engine,
        *,
        table_name: str = "deck_api_keys",
    ) -> None:
        self._engine = engine
        self._meta = sa.MetaData()
        self._table = sa.Table(
            table_name,
            self._meta,
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("name", sa.String(120), nullable=False),
            sa.Column("prefix", sa.String(24), nullable=False, index=True),
            sa.Column("key_hash", sa.String(64), nullable=False, unique=True, index=True),
            sa.Column("owner_id", sa.String(128), nullable=False, index=True),
            sa.Column("owner_name", sa.String(128), nullable=False),
            sa.Column("scopes_json", sa.Text, nullable=False),
            sa.Column("roles_json", sa.Text, nullable=False),
            sa.Column("allowed_ips_json", sa.Text, nullable=False),
            sa.Column("is_superuser", sa.Boolean, nullable=False, default=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        )
        self._meta.create_all(engine, checkfirst=True)

    @staticmethod
    def _row_to_rec(row: Any) -> APIKeyRecord:
        now = datetime.now(timezone.utc)
        try:
            scopes = tuple(str(s) for s in json.loads(row.scopes_json or "[]"))
        except Exception:
            scopes = ()
        try:
            roles = tuple(str(r) for r in json.loads(row.roles_json or "[]"))
        except Exception:
            roles = ()
        try:
            allowed_ips = tuple(str(ip) for ip in json.loads(row.allowed_ips_json or "[]"))
        except Exception:
            allowed_ips = ()
        return APIKeyRecord(
            id=str(row.id),
            name=str(row.name),
            prefix=str(row.prefix),
            key_hash=str(row.key_hash),
            owner_id=str(row.owner_id),
            owner_name=str(row.owner_name),
            scopes=scopes,
            roles=roles,
            allowed_ips=allowed_ips,
            is_superuser=bool(row.is_superuser),
            created_at=_ensure_utc(row.created_at) or now,
            expires_at=_ensure_utc(row.expires_at),
            last_used_at=_ensure_utc(row.last_used_at),
            revoked_at=_ensure_utc(row.revoked_at),
        )

    def create(self, rec: APIKeyRecord) -> APIKeyRecord:
        now = rec.created_at or datetime.now(timezone.utc)
        kid = rec.id or uuid.uuid4().hex[:16]
        with Session(self._engine) as sess:
            sess.execute(
                self._table.insert().values(
                    id=kid,
                    name=rec.name[:120],
                    prefix=rec.prefix[:24],
                    key_hash=rec.key_hash[:64],
                    owner_id=rec.owner_id[:128],
                    owner_name=rec.owner_name[:128],
                    scopes_json=json.dumps(list(rec.scopes)),
                    roles_json=json.dumps(list(rec.roles)),
                    allowed_ips_json=json.dumps(list(rec.allowed_ips)),
                    is_superuser=bool(rec.is_superuser),
                    created_at=now,
                    expires_at=rec.expires_at,
                    last_used_at=rec.last_used_at,
                    revoked_at=rec.revoked_at,
                )
            )
            sess.commit()
        return replace(rec, id=kid, created_at=now)

    def get(self, key_id: str) -> APIKeyRecord | None:
        with Session(self._engine) as sess:
            row = sess.execute(
                sa.select(self._table).where(self._table.c.id == key_id)
            ).first()
            return self._row_to_rec(row) if row is not None else None

    def list_keys(self, *, owner_id: str | None = None, limit: int = 100) -> list[APIKeyRecord]:
        stmt = sa.select(self._table)
        if owner_id is not None:
            stmt = stmt.where(self._table.c.owner_id == owner_id)
        stmt = stmt.order_by(self._table.c.created_at.desc()).limit(max(1, int(limit)))
        with Session(self._engine) as sess:
            return [self._row_to_rec(r) for r in sess.execute(stmt)]

    def revoke(self, key_id: str, *, owner_id: str | None = None) -> bool:
        now = datetime.now(timezone.utc)
        conds: list[Any] = [
            self._table.c.id == key_id,
            self._table.c.revoked_at.is_(None),
        ]
        if owner_id is not None:
            conds.append(self._table.c.owner_id == owner_id)
        with Session(self._engine) as sess:
            res = sess.execute(
                self._table.update().where(*conds).values(revoked_at=now)
            )
            sess.commit()
            return bool((getattr(res, "rowcount", 0) or 0) > 0)

    def verify_token(
        self, plaintext: str, *, client_ip: str | None = None
    ) -> APIKeyRecord | None:
        if not plaintext or not plaintext.startswith("dk_live_") or len(plaintext) < 16:
            return None
        candidate_hash = hash_api_key(plaintext)
        with Session(self._engine) as sess:
            row = sess.execute(
                sa.select(self._table).where(self._table.c.key_hash == candidate_hash)
            ).first()
            if row is None:
                return None
            rec = self._row_to_rec(row)
            if not hmac.compare_digest(rec.key_hash, candidate_hash):
                return None
            if not rec.is_active:
                return None
            if not ip_matches_allowlist(client_ip, rec.allowed_ips):
                return None
            now = datetime.now(timezone.utc)
            if rec.last_used_at is None or (now - rec.last_used_at).total_seconds() >= 60:
                sess.execute(
                    self._table.update()
                    .where(self._table.c.id == rec.id)
                    .values(last_used_at=now)
                )
                sess.commit()
                rec.last_used_at = now
            return rec
