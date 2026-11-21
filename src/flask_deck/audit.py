from __future__ import annotations

import enum
import json
import re
import threading
import uuid
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
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

    @property
    def is_revertible(self) -> bool:
        if self.action not in {"update", "inline_edit"} or not self.changes:
            return False
        # Do not attempt to revert redacted sensitive fields alone if all fields are redacted.
        return any(
            v.get("old") != "[REDACTED]" and v.get("new") != "[REDACTED]"
            for v in self.changes.values()
        )


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
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditEntry], int]:
        """Return paginated AuditEntry list (newest first) and total count."""

    @abstractmethod
    def get_entry(self, entry_id: str) -> AuditEntry | None:
        """Fetch a single AuditEntry by ID."""


class InMemoryAuditStore(AuditStore):
    """Thread-safe bounded ring-buffer audit store for tests and ephemeral demos."""

    __slots__ = ("_entries", "_lock", "_max_entries")

    def __init__(self, max_entries: int = 2000) -> None:
        self._max_entries = max(10, max_entries)
        self._entries: deque[AuditEntry] = deque(maxlen=self._max_entries)
        self._lock = threading.Lock()

    def record(self, entry: AuditEntry) -> AuditEntry:
        with self._lock:
            self._entries.appendleft(entry)
        return entry

    def list_entries(
        self,
        *,
        model_slug: str | None = None,
        record_pk: str | None = None,
        action: str | None = None,
        actor: str | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditEntry], int]:
        with self._lock:
            snapshot = list(self._entries)

        filtered: list[AuditEntry] = []
        q = (search or "").strip().lower()
        actor_q = (actor or "").strip().lower()
        for item in snapshot:
            if model_slug and item.model_slug != model_slug:
                continue
            if record_pk and item.record_pk != record_pk:
                continue
            if action and item.action != action:
                continue
            if actor_q and actor_q not in item.actor_name.lower() and actor_q not in item.actor_id.lower():
                continue
            if q and (
                q not in item.record_repr.lower()
                and q not in item.record_pk.lower()
                and q not in item.model_label.lower()
                and q not in item.actor_name.lower()
                and q not in json.dumps(item.changes).lower()
            ):
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
    """Persistent SQLAlchemy Core audit store using an isolated metadata table."""

    def __init__(
        self,
        engine: Engine,
        *,
        table_name: str = "flask_deck_audit_logs",
        auto_create: bool = True,
    ) -> None:
        self._engine = engine
        self._metadata = sa.MetaData()
        self._table = sa.Table(
            table_name,
            self._metadata,
            sa.Column("id", sa.String(36), primary_key=True),
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
        )

    def record(self, entry: AuditEntry) -> AuditEntry:
        with self._engine.begin() as conn:
            conn.execute(
                self._table.insert().values(
                    id=entry.id,
                    timestamp=entry.timestamp,
                    actor_id=entry.actor_id[:128],
                    actor_name=entry.actor_name[:128],
                    actor_ip=entry.actor_ip[:64],
                    action=entry.action[:32],
                    model_slug=entry.model_slug[:128],
                    model_label=entry.model_label[:128],
                    record_pk=entry.record_pk[:256],
                    record_repr=entry.record_repr[:256],
                    changes_json=json.dumps(entry.changes, default=str),
                    metadata_json=json.dumps(entry.metadata, default=str),
                )
            )
        return entry

    def list_entries(
        self,
        *,
        model_slug: str | None = None,
        record_pk: str | None = None,
        action: str | None = None,
        actor: str | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditEntry], int]:
        t = self._table
        conditions: list[sa.ColumnElement[bool]] = []
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
            conditions.append(
                sa.or_(
                    t.c.record_repr.ilike(like_q, escape="\\"),
                    t.c.record_pk.ilike(like_q, escape="\\"),
                    t.c.model_label.ilike(like_q, escape="\\"),
                    t.c.actor_name.ilike(like_q, escape="\\"),
                    t.c.changes_json.ilike(like_q, escape="\\"),
                )
            )

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
