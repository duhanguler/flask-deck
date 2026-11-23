from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

import sqlalchemy as sa
from flask import session
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

DECK_SID_SESSION_KEY = "_deck_sid"


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


@dataclass(slots=True)
class SessionRecord:
    """Server-side tracked authenticated session record supporting instant revocation."""

    session_id: str
    user_id: str
    username: str
    ip_address: str
    user_agent: str
    created_at: datetime
    last_seen_at: datetime
    revoked_at: datetime | None = None

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None


@runtime_checkable
class SessionStore(Protocol):
    """Server-side session registry contract for revocation across workers."""

    def register(self, record: SessionRecord) -> SessionRecord: ...

    def is_active(self, session_id: str) -> bool: ...

    def touch(self, session_id: str) -> None: ...

    def list_sessions(
        self, *, user_id: str | None = None, limit: int = 100
    ) -> list[SessionRecord]: ...

    def revoke(self, session_id: str, *, actor_id: str | None = None) -> bool: ...

    def revoke_others(self, user_id: str, *, keep_session_id: str | None = None) -> int: ...


class InMemorySessionStore:
    """Thread-safe in-memory server-side session registry."""

    __slots__ = ("_lock", "_records")

    def __init__(self) -> None:
        self._records: dict[str, SessionRecord] = {}
        self._lock = threading.Lock()

    def register(self, record: SessionRecord) -> SessionRecord:
        with self._lock:
            self._records[record.session_id] = record
            if len(self._records) > 2000:
                revoked_ids = [
                    sid for sid, rec in self._records.items() if rec.revoked_at is not None
                ]
                for sid in revoked_ids[:500]:
                    self._records.pop(sid, None)
        return record

    def is_active(self, session_id: str) -> bool:
        if not session_id:
            return False
        with self._lock:
            rec = self._records.get(session_id)
            return rec is not None and rec.revoked_at is None

    def touch(self, session_id: str) -> None:
        if not session_id:
            return
        now = datetime.now(timezone.utc)
        with self._lock:
            rec = self._records.get(session_id)
            if rec is not None and rec.revoked_at is None:
                rec.last_seen_at = now

    def list_sessions(
        self, *, user_id: str | None = None, limit: int = 100
    ) -> list[SessionRecord]:
        with self._lock:
            items = list(self._records.values())
        if user_id is not None:
            items = [r for r in items if r.user_id == user_id]
        items.sort(key=lambda r: r.last_seen_at, reverse=True)
        return items[: max(1, limit)]

    def revoke(self, session_id: str, *, actor_id: str | None = None) -> bool:
        now = datetime.now(timezone.utc)
        with self._lock:
            rec = self._records.get(session_id)
            if rec is None or rec.revoked_at is not None:
                return False
            if actor_id is not None and rec.user_id != actor_id:
                return False
            rec.revoked_at = now
            return True

    def revoke_others(self, user_id: str, *, keep_session_id: str | None = None) -> int:
        now = datetime.now(timezone.utc)
        count = 0
        with self._lock:
            for rec in self._records.values():
                if (
                    rec.user_id == user_id
                    and rec.revoked_at is None
                    and rec.session_id != keep_session_id
                ):
                    rec.revoked_at = now
                    count += 1
        return count


class SQLAlchemySessionStore:
    """Multi-worker SQLAlchemy session registry backed by ``_flask_deck_sessions``."""

    def __init__(
        self,
        engine: Engine,
        *,
        table_name: str = "_flask_deck_sessions",
    ) -> None:
        self._engine = engine
        self._meta = sa.MetaData()
        self._table = sa.Table(
            table_name,
            self._meta,
            sa.Column("session_id", sa.String(64), primary_key=True),
            sa.Column("user_id", sa.String(128), nullable=False, index=True),
            sa.Column("username", sa.String(128), nullable=False),
            sa.Column("ip_address", sa.String(64), nullable=False),
            sa.Column("user_agent", sa.String(255), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, index=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        )
        self._meta.create_all(engine, checkfirst=True)

    @staticmethod
    def _row_to_record(row: Any) -> SessionRecord:
        now = datetime.now(timezone.utc)
        return SessionRecord(
            session_id=str(row.session_id),
            user_id=str(row.user_id),
            username=str(row.username),
            ip_address=str(row.ip_address),
            user_agent=str(row.user_agent),
            created_at=_ensure_utc(row.created_at) or now,
            last_seen_at=_ensure_utc(row.last_seen_at) or now,
            revoked_at=_ensure_utc(row.revoked_at),
        )

    def register(self, record: SessionRecord) -> SessionRecord:
        with Session(self._engine) as sess:
            sess.execute(self._table.delete().where(self._table.c.session_id == record.session_id))
            sess.execute(
                self._table.insert().values(
                    session_id=record.session_id,
                    user_id=record.user_id,
                    username=record.username,
                    ip_address=record.ip_address[:64],
                    user_agent=record.user_agent[:255],
                    created_at=record.created_at,
                    last_seen_at=record.last_seen_at,
                    revoked_at=record.revoked_at,
                )
            )
            sess.commit()
        return record

    def is_active(self, session_id: str) -> bool:
        if not session_id:
            return False
        with Session(self._engine) as sess:
            row = sess.execute(
                sa.select(self._table.c.revoked_at).where(self._table.c.session_id == session_id)
            ).first()
            return row is not None and row[0] is None

    def touch(self, session_id: str) -> None:
        if not session_id:
            return
        now = datetime.now(timezone.utc)
        with Session(self._engine) as sess:
            sess.execute(
                self._table.update()
                .where(
                    self._table.c.session_id == session_id,
                    self._table.c.revoked_at.is_(None),
                )
                .values(last_seen_at=now)
            )
            sess.commit()

    def list_sessions(
        self, *, user_id: str | None = None, limit: int = 100
    ) -> list[SessionRecord]:
        stmt = sa.select(self._table)
        if user_id is not None:
            stmt = stmt.where(self._table.c.user_id == user_id)
        stmt = stmt.order_by(self._table.c.last_seen_at.desc()).limit(max(1, int(limit)))
        with Session(self._engine) as sess:
            return [self._row_to_record(r) for r in sess.execute(stmt)]

    def revoke(self, session_id: str, *, actor_id: str | None = None) -> bool:
        now = datetime.now(timezone.utc)
        conds: list[Any] = [
            self._table.c.session_id == session_id,
            self._table.c.revoked_at.is_(None),
        ]
        if actor_id is not None:
            conds.append(self._table.c.user_id == actor_id)
        with Session(self._engine) as sess:
            res = sess.execute(self._table.update().where(*conds).values(revoked_at=now))
            sess.commit()
            return bool((getattr(res, "rowcount", 0) or 0) > 0)

    def revoke_others(self, user_id: str, *, keep_session_id: str | None = None) -> int:
        now = datetime.now(timezone.utc)
        conds: list[Any] = [
            self._table.c.user_id == user_id,
            self._table.c.revoked_at.is_(None),
        ]
        if keep_session_id:
            conds.append(self._table.c.session_id != keep_session_id)
        with Session(self._engine) as sess:
            res = sess.execute(self._table.update().where(*conds).values(revoked_at=now))
            sess.commit()
            return int(getattr(res, "rowcount", 0) or 0)


def issue_tracked_session(
    store: SessionStore,
    *,
    user_id: str,
    username: str,
    ip_address: str,
    user_agent: str,
) -> str:
    """Create a fresh session ID, bind it into Flask session cookie, and record it in SessionStore."""
    sid = secrets.token_urlsafe(24)
    now = datetime.now(timezone.utc)
    session[DECK_SID_SESSION_KEY] = sid
    session["_deck_sid_touch"] = int(now.timestamp())
    store.register(
        SessionRecord(
            session_id=sid,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent[:255],
            created_at=now,
            last_seen_at=now,
        )
    )
    return sid
