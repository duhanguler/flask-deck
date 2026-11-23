from __future__ import annotations

import enum
import hashlib
import json
import re
import threading
import uuid
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import date, datetime, time, timezone
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from sqlalchemy.engine import Engine

from flask_deck.security import escape_like, is_sensitive_field


def serialize_audit_value(
    value: Any,
    *,
    extra_sensitive_patterns: Iterable[re.Pattern[str]] = (),
) -> Any:
    """Normalize SQLAlchemy/Python values into deterministic JSON-serializable primitives."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value.isoformat()
    if isinstance(value, (date, time)):
        return value.isoformat()
    if isinstance(value, (Decimal, uuid.UUID)):
        return str(value)
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            ks = str(k)
            if is_sensitive_field(ks, extra_sensitive_patterns):
                out[ks] = "[REDACTED]"
            else:
                out[ks] = serialize_audit_value(
                    v, extra_sensitive_patterns=extra_sensitive_patterns
                )
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        return [
            serialize_audit_value(v, extra_sensitive_patterns=extra_sensitive_patterns)
            for v in value
        ]
    return str(value)


def compute_diff(
    old_data: Mapping[str, Any],
    new_data: Mapping[str, Any],
    *,
    sensitive_fields: Iterable[str] = (),
    extra_sensitive_patterns: Iterable[re.Pattern[str]] = (),
) -> dict[str, dict[str, Any]]:
    """Compute field-level {field: {'old': ..., 'new': ...}} diff with automatic redaction."""
    sensitive_set = set(sensitive_fields)
    patterns = tuple(extra_sensitive_patterns)
    diff: dict[str, dict[str, Any]] = {}
    all_keys = sorted(set(old_data.keys()) | set(new_data.keys()))
    for key in all_keys:
        old_val = serialize_audit_value(old_data.get(key), extra_sensitive_patterns=patterns)
        new_val = serialize_audit_value(new_data.get(key), extra_sensitive_patterns=patterns)
        if old_val == new_val:
            continue
        if key in sensitive_set or is_sensitive_field(key, patterns):
            diff[key] = {"old": "[REDACTED]", "new": "[REDACTED]"}
        else:
            diff[key] = {"old": old_val, "new": new_val}
    return diff


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """Immutable audit log record capturing who changed what, when, and how."""

    id: str
    timestamp: datetime
    actor_id: str
    actor_name: str
    actor_ip: str
    action: str  # create | update | delete | bulk_action | import | inline_edit | revert
    model_slug: str
    model_label: str
    record_pk: str
    record_repr: str
    changes: dict[str, dict[str, Any]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    entry_hash: str = ""

    @property
    def is_revertible(self) -> bool:
        if self.action not in {"update", "inline_edit"} or not self.changes:
            return False
        # Do not attempt to revert redacted sensitive fields alone if all fields are redacted.
        return any(
            v.get("old") != "[REDACTED]" and v.get("new") != "[REDACTED]"
            for v in self.changes.values()
        )


def _utc_dt(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def compute_audit_entry_hash(entry: AuditEntry, prev_hash: str) -> str:
    """Compute canonical SHA-256 chain digest over an AuditEntry and its predecessor hash."""
    payload = [
        prev_hash,
        entry.id,
        _utc_dt(entry.timestamp).isoformat(timespec="microseconds"),
        entry.actor_id[:128],
        entry.actor_name[:128],
        entry.actor_ip[:64],
        entry.action[:32],
        entry.model_slug[:128],
        entry.model_label[:128],
        entry.record_pk[:256],
        entry.record_repr[:256],
        json.loads(json.dumps(entry.changes, default=str)),
        json.loads(json.dumps(entry.metadata, default=str)),
    ]
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class AuditStore(ABC):
    """Pluggable audit log persistence interface."""

    @abstractmethod
    def record(self, entry: AuditEntry) -> AuditEntry:
        """Persist a new AuditEntry."""

    @abstractmethod
    def list_entries(
        self,
        *,
        model_slug: str | None = None,
        record_pk: str | None = None,
        action: str | None = None,
        actor: str | None = None,
        search: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        excluded_models: frozenset[str] = frozenset(),
        search_changes: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditEntry], int]:
        """Return paginated AuditEntry list (newest first) and total count."""

    @abstractmethod
    def get_entry(self, entry_id: str) -> AuditEntry | None:
        """Fetch a single AuditEntry by ID."""


class InMemoryAuditStore(AuditStore):
    """Thread-safe bounded ring-buffer audit store for tests and ephemeral demos."""

    __slots__ = ("_entries", "_lock", "_max_entries", "hash_chain")

    def __init__(self, max_entries: int = 2000, *, hash_chain: bool = False) -> None:
        self._max_entries = max(10, max_entries)
        self._entries: deque[AuditEntry] = deque(maxlen=self._max_entries)
        self._lock = threading.Lock()
        self.hash_chain = bool(hash_chain)

    def record(self, entry: AuditEntry) -> AuditEntry:
        with self._lock:
            stored = entry
            if self.hash_chain:
                prev_hash = self._entries[0].entry_hash if self._entries else "GENESIS"
                digest = compute_audit_entry_hash(entry, prev_hash)
                stored = AuditEntry(
                    id=entry.id,
                    timestamp=entry.timestamp,
                    actor_id=entry.actor_id,
                    actor_name=entry.actor_name,
                    actor_ip=entry.actor_ip,
                    action=entry.action,
                    model_slug=entry.model_slug,
                    model_label=entry.model_label,
                    record_pk=entry.record_pk,
                    record_repr=entry.record_repr,
                    changes=entry.changes,
                    metadata=entry.metadata,
                    prev_hash=prev_hash,
                    entry_hash=digest,
                )
            self._entries.appendleft(stored)
        return stored

    def verify_chain(self) -> tuple[bool, str | None]:
        """Verify in-memory hash chain integrity from oldest to newest."""
        if not self.hash_chain:
            return True, None
        with self._lock:
            chronological = list(reversed(self._entries))
        expected_prev = "GENESIS"
        for item in chronological:
            if item.prev_hash != expected_prev:
                return False, f"Audit hash-chain break at entry {item.id}: prev_hash mismatch"
            expected_hash = compute_audit_entry_hash(item, expected_prev)
            if item.entry_hash != expected_hash:
                return False, f"Audit entry {item.id} failed integrity digest verification"
            expected_prev = item.entry_hash
        return True, None

    def list_entries(
        self,
        *,
        model_slug: str | None = None,
        record_pk: str | None = None,
        action: str | None = None,
        actor: str | None = None,
        search: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        excluded_models: frozenset[str] = frozenset(),
        search_changes: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditEntry], int]:
        with self._lock:
            snapshot = list(self._entries)

        filtered: list[AuditEntry] = []
        q = (search or "").strip().lower()
        actor_q = (actor or "").strip().lower()
        df = _utc_dt(date_from) if date_from is not None else None
        dt_end = _utc_dt(date_to) if date_to is not None else None
        for item in snapshot:
            ts_utc = _utc_dt(item.timestamp)
            if df is not None and ts_utc < df:
                continue
            if dt_end is not None and ts_utc > dt_end:
                continue
            if excluded_models and item.model_slug in excluded_models:
                continue
            if model_slug and item.model_slug != model_slug:
                continue
            if record_pk and item.record_pk != record_pk:
                continue
            if action and item.action != action:
                continue
            if actor_q and actor_q not in item.actor_name.lower() and actor_q not in item.actor_id.lower():
                continue
            if q:
                matched = (
                    q in item.record_repr.lower()
                    or q in item.record_pk.lower()
                    or q in item.model_label.lower()
                    or q in item.actor_name.lower()
                )
                if not matched and search_changes:
                    matched = q in json.dumps(item.changes).lower()
                if not matched:
                    continue
            filtered.append(item)

        total = len(filtered)
        return filtered[offset : offset + limit], total

    def get_entry(self, entry_id: str) -> AuditEntry | None:
        with self._lock:
            for item in self._entries:
                if item.id == entry_id:
                    return item
        return None


class SQLAlchemyAuditStore(AuditStore):
    """Persistent SQLAlchemy Core audit store with optional tamper-evident SHA-256 hash chain."""

    def __init__(
        self,
        engine: Engine,
        *,
        table_name: str = "flask_deck_audit_logs",
        auto_create: bool = True,
        hash_chain: bool = False,
    ) -> None:
        self._engine = engine
        self.hash_chain = bool(hash_chain)
        self._chain_lock = threading.Lock()
        self._metadata = sa.MetaData()
        self._table = sa.Table(
            table_name,
            self._metadata,
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("seq", sa.Integer, nullable=False, default=0, index=True),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, index=True),
            sa.Column("actor_id", sa.String(128), nullable=False, index=True),
            sa.Column("actor_name", sa.String(128), nullable=False),
            sa.Column("actor_ip", sa.String(64), nullable=False),
            sa.Column("action", sa.String(32), nullable=False, index=True),
            sa.Column("model_slug", sa.String(128), nullable=False, index=True),
            sa.Column("model_label", sa.String(128), nullable=False),
            sa.Column("record_pk", sa.String(256), nullable=False, index=True),
            sa.Column("record_repr", sa.String(256), nullable=False),
            sa.Column("changes_json", sa.Text, nullable=False),
            sa.Column("metadata_json", sa.Text, nullable=False),
            sa.Column("prev_hash", sa.String(64), nullable=False, default=""),
            sa.Column("entry_hash", sa.String(64), nullable=False, default=""),
        )
        if auto_create:
            self._metadata.create_all(self._engine, checkfirst=True)

    def _row_to_entry(self, row: sa.RowMapping) -> AuditEntry:
        ts = row["timestamp"]
        if isinstance(ts, datetime) and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return AuditEntry(
            id=str(row["id"]),
            timestamp=ts,
            actor_id=str(row["actor_id"]),
            actor_name=str(row["actor_name"]),
            actor_ip=str(row["actor_ip"]),
            action=str(row["action"]),
            model_slug=str(row["model_slug"]),
            model_label=str(row["model_label"]),
            record_pk=str(row["record_pk"]),
            record_repr=str(row["record_repr"]),
            changes=json.loads(row["changes_json"] or "{}"),
            metadata=json.loads(row["metadata_json"] or "{}"),
            prev_hash=str(row.get("prev_hash") or ""),
            entry_hash=str(row.get("entry_hash") or ""),
        )

    def record(self, entry: AuditEntry) -> AuditEntry:
        utc_ts = _utc_dt(entry.timestamp)
        with self._chain_lock, self._engine.begin() as conn:
            last_row = conn.execute(
                sa.select(self._table.c.seq, self._table.c.entry_hash)
                .order_by(self._table.c.seq.desc())
                .limit(1)
            ).first()
            next_seq = (int(last_row[0]) + 1) if last_row is not None else 1
            prev_hash = str(last_row[1] or "") if (self.hash_chain and last_row is not None) else ""
            if self.hash_chain and last_row is None:
                prev_hash = "0" * 64
            stamped = replace(entry, timestamp=utc_ts, prev_hash=prev_hash)
            entry_hash = compute_audit_entry_hash(stamped, prev_hash) if self.hash_chain else ""
            stamped = replace(stamped, entry_hash=entry_hash)
            conn.execute(
                self._table.insert().values(
                    id=stamped.id,
                    seq=next_seq,
                    timestamp=utc_ts,
                    actor_id=stamped.actor_id[:128],
                    actor_name=stamped.actor_name[:128],
                    actor_ip=stamped.actor_ip[:64],
                    action=stamped.action[:32],
                    model_slug=stamped.model_slug[:128],
                    model_label=stamped.model_label[:128],
                    record_pk=stamped.record_pk[:256],
                    record_repr=stamped.record_repr[:256],
                    changes_json=json.dumps(stamped.changes, default=str),
                    metadata_json=json.dumps(stamped.metadata, default=str),
                    prev_hash=prev_hash,
                    entry_hash=entry_hash,
                )
            )
        return stamped

    def verify_chain(self) -> tuple[bool, str | None]:
        """Verify cryptographic integrity of all hash-chained audit rows."""
        stmt = sa.select(self._table).order_by(self._table.c.seq.asc(), self._table.c.id.asc())
        with self._engine.connect() as conn:
            rows = conn.execute(stmt).mappings().all()
        if not rows:
            return True, None
        expected_prev = "0" * 64
        for row in rows:
            entry = self._row_to_entry(row)
            if entry.prev_hash != expected_prev:
                return False, f"Tampering detected at audit entry {entry.id}: prev_hash mismatch."
            recomputed = compute_audit_entry_hash(entry, expected_prev)
            if not entry.entry_hash or entry.entry_hash != recomputed:
                return False, f"Tampering detected at audit entry {entry.id}: entry_hash mismatch."
            expected_prev = entry.entry_hash
        return True, None

    def list_entries(
        self,
        *,
        model_slug: str | None = None,
        record_pk: str | None = None,
        action: str | None = None,
        actor: str | None = None,
        search: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        excluded_models: frozenset[str] = frozenset(),
        search_changes: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditEntry], int]:
        t = self._table
        conditions: list[sa.ColumnElement[bool]] = []
        if date_from is not None:
            conditions.append(t.c.timestamp >= _utc_dt(date_from))
        if date_to is not None:
            conditions.append(t.c.timestamp <= _utc_dt(date_to))
        if excluded_models:
            conditions.append(t.c.model_slug.notin_(sorted(excluded_models)))
        if model_slug:
            conditions.append(t.c.model_slug == model_slug)
        if record_pk:
            conditions.append(t.c.record_pk == record_pk)
        if action:
            conditions.append(t.c.action == action)
        if actor:
            like_actor = f"%{escape_like(actor.strip())}%"
            conditions.append(
                sa.or_(
                    t.c.actor_name.ilike(like_actor, escape="\\"),
                    t.c.actor_id.ilike(like_actor, escape="\\"),
                )
            )
        if search:
            like_q = f"%{escape_like(search.strip())}%"
            search_ors: list[sa.ColumnElement[bool]] = [
                t.c.record_repr.ilike(like_q, escape="\\"),
                t.c.record_pk.ilike(like_q, escape="\\"),
                t.c.model_label.ilike(like_q, escape="\\"),
                t.c.actor_name.ilike(like_q, escape="\\"),
            ]
            if search_changes:
                search_ors.append(t.c.changes_json.ilike(like_q, escape="\\"))
            conditions.append(sa.or_(*search_ors))

        count_stmt = sa.select(sa.func.count()).select_from(t)
        rows_stmt = (
            sa.select(t)
            .order_by(t.c.timestamp.desc(), t.c.id.desc())
            .limit(limit)
            .offset(offset)
        )
        if conditions:
            where_clause = sa.and_(*conditions)
            count_stmt = count_stmt.where(where_clause)
            rows_stmt = rows_stmt.where(where_clause)

        with self._engine.connect() as conn:
            total = int(conn.execute(count_stmt).scalar_one() or 0)
            rows = conn.execute(rows_stmt).mappings().all()

        return [self._row_to_entry(r) for r in rows], total

    def get_entry(self, entry_id: str) -> AuditEntry | None:
        stmt = sa.select(self._table).where(self._table.c.id == entry_id).limit(1)
        with self._engine.connect() as conn:
            row = conn.execute(stmt).mappings().first()
        return self._row_to_entry(row) if row is not None else None


def make_audit_entry(
    *,
    actor_id: str,
    actor_name: str,
    actor_ip: str,
    action: str,
    model_slug: str,
    model_label: str,
    record_pk: str,
    record_repr: str,
    changes: dict[str, dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
    timestamp: datetime | None = None,
) -> AuditEntry:
    """Factory creating a UTC-stamped AuditEntry with a fresh UUID."""
    return AuditEntry(
        id=str(uuid.uuid4()),
        timestamp=timestamp or datetime.now(timezone.utc),
        actor_id=actor_id,
        actor_name=actor_name,
        actor_ip=actor_ip,
        action=action,
        model_slug=model_slug,
        model_label=model_label,
        record_pk=record_pk,
        record_repr=record_repr,
        changes=changes or {},
        metadata=metadata or {},
    )
